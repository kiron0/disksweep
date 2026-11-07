"""Exercise real command parsing, private output, and exact approval boundaries."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from test_engine import Fixture
import _cli as cli
import _core as core


class Commands(Fixture):
    def call(self, *arguments, success=True):
        result = subprocess.run([sys.executable, str(core.BASE / "scripts/swipr.py"), *map(str, arguments)],
                                cwd=self.base, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0 if success else 2, result.stdout + result.stderr)
        return result

    def data(self, *arguments):
        response = self.call(*arguments, "--json")
        result = json.loads(response.stdout)
        self.assertTrue(result["ok"])
        return result["result"]

    def save_audit(self, name="audit.json"):
        output = self.base / name
        result = self.data("scan", "developer", "--root", self.root, "--output", output)
        return output, result

    def test_help_and_version_have_no_filesystem_side_effects(self):
        before = set(self.base.rglob("*"))
        self.assertIn("scan", self.call("help").stdout)
        for path in (("scan", "quick"), ("find", "large"), ("inspect", "apps"),
                     ("plan", "create"), ("approve", "purge"), ("clean", "purge"),
                     ("report", "operation"), ("history", "save"), ("profile", "save"), ("catalog", "list")):
            with self.subTest(path=path):
                self.assertIn("usage:", self.call("help", *path).stdout)
        self.assertIn(core.VERSION, self.call("--version").stdout)
        self.assertEqual(before, set(self.base.rglob("*")))

    def test_scan_saves_private_machine_result_and_readable_summary(self):
        output = self.base / "audit.json"
        response = self.call("scan", "quick", "--root", self.root, "--output", output)
        self.assertIn("Storage Audit", response.stdout)
        self.assertIn("Full JSON saved", response.stdout)
        self.assertNotIn(str(self.root), response.stdout)
        result = json.loads(output.read_text())["result"]
        self.assertFalse(result["execution_authorized"])
        self.assertTrue(result["inventory"]["entries"])
        self.assertFalse(self.state.exists())
        if os.name == "posix":
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_missing_roots_and_approval_flags_fail_before_state_creation(self):
        self.call("scan", "quick", success=False)
        self.call("approve", "quarantine", "--state-dir", self.state, "--plan-id", "fake", "--digest", "fake", "--note", "not approval", success=False)
        self.call("clean", "purge", "--state-dir", self.state, "--plan-id", "fake", success=False)
        self.assertFalse(self.state.exists())
        self.assertTrue(self.source.exists())

    def test_filtered_discovery_uses_full_inventory(self):
        old = self.root / "old.zip"; old.write_bytes(b"x" * 200)
        fresh = self.root / "new.zip"; fresh.write_bytes(b"x" * 200)
        other = self.root / "old.txt"; other.write_bytes(b"x" * 200)
        timestamp = time.time() - 40 * 86400
        os.utime(old, (timestamp, timestamp)); os.utime(other, (timestamp, timestamp))
        result = self.data("find", "large", "--root", self.root, "--min-bytes", 128, "--older-than-days", 30, "--extension", "ZIP")
        self.assertEqual([x["path"] for x in result["matches"]], [str(old)])

    def test_directory_discovery_and_catalog_filters(self):
        result = self.data("find", "directories", "--root", self.root, "--top", 1)
        self.assertEqual(result["matches"][0]["path"], str(self.root))
        result = self.data("catalog", "list", "--platform", "linux", "--category", "package-cache")
        self.assertTrue(result["rules"])
        self.assertTrue(all("linux" in r["platforms"] and r["category"] == "package-cache" for r in result["rules"]))

    def test_duplicates_require_separate_content_read_permission(self):
        result = self.call("find", "duplicates", "--root", self.root, "--json", success=False)
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "REFUSED")

    @unittest.skipUnless(os.name == "posix", "Safe content handles are POSIX-only")
    def test_duplicate_command_hashes_only_with_approval(self):
        for name in ("a.bin", "b.bin"):
            (self.root / name).write_bytes(b"same-content")
        result = self.data("find", "duplicates", "--root", self.root, "--allow-content-read")
        self.assertEqual(len(result["matches"]), 1)
        self.assertFalse(result["matches"][0]["automatic_removal"])

    def test_native_commands_refuse_without_scope_permission(self):
        for name in ("apps", "storage", "docker"):
            with self.subTest(name=name):
                result = self.call("inspect", name, "--json", success=False)
                self.assertEqual(json.loads(result.stdout)["error"]["code"], "REFUSED")

    def test_trash_policy_exclusions_are_enforced(self):
        trash = self.root / ".Trash"; trash.mkdir()
        (trash / "keep.txt").write_text("keep")
        policy = self.base / "policy.json"
        policy.write_text(json.dumps({"exclude": [str(trash / "keep.txt")]}))
        result = self.data("inspect", "trash", "--root", trash, "--confirm-scope", "--policy", policy)
        self.assertTrue(all(e["classification"] == "PROTECTED" for e in result["inventory"]["entries"]))
        self.assertFalse(result["inventory"]["entries"])
        self.assertFalse(result["emptying_authorized"])
        outside_policy = self.base / "outside-policy.json"
        outside_policy.write_text(json.dumps({"roots": [str(self.base / "elsewhere")]}))
        self.call("inspect", "trash", "--root", trash, "--confirm-scope", "--policy", outside_policy, success=False)

    def test_existing_output_is_refused_before_dispatch(self):
        output = self.base / "keep.json"; output.write_text("preserve")
        captured = io.StringIO()
        with patch.object(cli, "dispatch", side_effect=AssertionError("must not run")), contextlib.redirect_stdout(captured):
            code = cli.main(["clean", "purge", "--state-dir", str(self.state), "--plan-id", "fake", "--approval-id", "fake", "--output", str(output), "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(captured.getvalue())["error"]["code"], "ALREADY_EXISTS")
        self.assertEqual(output.read_text(), "preserve")
        self.assertFalse(self.state.exists())

    def test_invalid_input_is_sanitized_without_traceback(self):
        file = self.base / "invalid.json"; file.write_text('{"PRIVATE_SECRET": no}')
        result = self.call("report", "audit", "--input", file, "--json", success=False)
        self.assertFalse(json.loads(result.stdout)["ok"])
        self.assertNotIn("PRIVATE_SECRET", result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_budget_errors_are_explicit(self):
        result = self.call("scan", "quick", "--root", self.root, "--top", "0", "--json", success=False)
        self.assertIn("--top", result.stdout)
        self.call("scan", "quick", "--root", self.root, "--max-seconds", "nan", success=False)
        self.call("scan", "quick", "--root", "", success=False)

    def test_invalid_policy_cannot_implicitly_widen_scope_or_budget(self):
        file = self.base / "invalid-policy.json"
        for value in ({"roots": []}, {"roots": [""]}, {"max_seconds": float("nan")}, {"max_depth": -1}, {"max_entries": True}):
            with self.subTest(value=value):
                file.write_text(json.dumps(value))
                result = self.call("profile", "validate", "--input", file, "--json", success=False)
                self.assertEqual(json.loads(result.stdout)["error"]["code"], "REFUSED")

    def test_report_default_is_shareable_markdown(self):
        file, _ = self.save_audit()
        output = self.base / "report.md"
        result = self.call("report", "audit", "--input", file, "--output", output)
        self.assertTrue(output.read_text().startswith("# Swipr Storage Audit"))
        self.assertNotIn(str(self.root), result.stdout)

    def test_reports_reject_injected_storage_measurements(self):
        verified = self.base / "verified.json"; plan = self.base / "plan.json"
        operation = {"verified_at": "fixture", "all_verified": True, "before_free": "![image](https://example.invalid)", "after_free": 0, "observed_free_delta": 0}
        verified.write_text(json.dumps(operation)); plan.write_text("{}")
        result = self.call("report", "operation", "--input", verified, "--plan", plan, "--json", success=False)
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "REFUSED")
        self.assertNotIn("example.invalid", result.stdout)

    @unittest.skipUnless(os.name == "posix", "POSIX links and nonblocking input")
    def test_input_redirects_and_fifos_are_refused(self):
        file = self.base / "data.json"; file.write_text("{}")
        link = self.base / "link.json"; link.symlink_to(file)
        fifo = self.base / "input.fifo"; os.mkfifo(fifo)
        for path in (link, fifo):
            with self.subTest(path=path):
                result = self.call("report", "audit", "--input", path, "--json", success=False)
                self.assertEqual(json.loads(result.stdout)["error"]["code"], "REFUSED")

    @unittest.skipUnless(os.name == "posix", "Private signed state is POSIX-only")
    def test_profile_snapshot_and_comparison_commands(self):
        file, _ = self.save_audit()
        policy = self.base / "policy.json"
        policy.write_text(json.dumps({"roots": [str(self.root)], "max_entries": 1, "never_permanently_delete": True}))
        self.data("profile", "validate", "--input", policy)
        profile = self.data("profile", "save", "--input", policy, "--state-dir", self.state, "--confirm")
        self.assertFalse(self.data("profile", "show", "--state-dir", self.state, "--profile-id", profile["id"])["execution_authorized"])
        limited = self.data("scan", "custom", "--root", self.root, "--profile-id", profile["id"], "--state-dir", self.state)
        self.assertEqual(limited["inventory"]["entries_visited"], 1)
        stored_scope = self.data("scan", "custom", "--profile-id", profile["id"], "--state-dir", self.state)
        self.assertEqual(stored_scope["inventory"]["roots"], [str(self.root)])
        snapshot = self.data("history", "save", "--input", file, "--state-dir", self.state, "--confirm")
        self.assertEqual(self.data("history", "show", "--state-dir", self.state, "--snapshot-id", snapshot["id"])["id"], snapshot["id"])
        self.assertFalse(self.data("history", "compare", "--before", file, "--after", file)["changed"])

    @unittest.skipUnless(os.name == "posix", "Guarded mutations require POSIX handles")
    def test_full_command_lifecycle_and_separate_permanent_approval(self):
        file, scanned = self.save_audit()
        selected = self.candidate(scanned["inventory"])["id"]
        plan_file = self.base / "plan.json"
        plan = self.data("plan", "create", "--input", file, "--candidate", selected, "--state-dir", self.state, "--output", plan_file)
        self.assertEqual(self.data("plan", "show", "--state-dir", self.state, "--plan-id", plan["id"])["digest"], plan["digest"])
        self.assertTrue(self.data("plan", "validate", "--state-dir", self.state, "--plan-id", plan["id"])["valid"])
        approval = self.data("approve", "quarantine", "--state-dir", self.state, "--plan-id", plan["id"], "--digest", plan["digest"], "--confirm", "--workload-stopped", "--note", "Synthetic exact-scope approval")
        operation = self.data("clean", "quarantine", "--state-dir", self.state, "--plan-id", plan["id"], "--approval-id", approval["id"])
        verified_file = self.base / "verified.json"
        verified = self.data("verify", "--state-dir", self.state, "--operation-id", operation["id"], "--output", verified_file)
        self.assertTrue(verified["all_verified"])
        self.assertIn("verified: 1", self.call("report", "operation", "--input", verified_file, "--plan", plan_file).stdout)
        self.assertTrue(self.data("history", "operations", "--state-dir", self.state)["operations"])
        purge_plan = self.data("plan", "purge", "--state-dir", self.state, "--operation-id", operation["id"], "--candidate", selected)
        self.assertTrue(self.data("plan", "validate", "--kind", "purge", "--state-dir", self.state, "--plan-id", purge_plan["id"])["valid"])
        permanent = self.data("approve", "purge", "--state-dir", self.state, "--plan-id", purge_plan["id"], "--digest", purge_plan["digest"], "--confirm", "--acknowledge-irreversible", "--note", "Synthetic separate permanent-removal approval")
        result = self.data("clean", "purge", "--state-dir", self.state, "--plan-id", purge_plan["id"], "--approval-id", permanent["id"])
        self.assertTrue(self.data("verify", "--kind", "purge", "--state-dir", self.state, "--operation-id", result["id"])["all_verified"])
        self.assertTrue(self.source.exists())
        self.assertFalse(self.bytecode.exists())


if __name__ == "__main__":
    unittest.main()

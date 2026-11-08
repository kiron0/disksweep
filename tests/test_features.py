import copy
import json
import os
import unittest
from unittest.mock import patch

from test_engine import Fixture
import _audit as audit
import _core as core
import _native as native
import _remove as removal


class AuditFeatures(Fixture):
    def test_all_modes_have_operational_read_only_workflows(self):
        for mode in sorted(audit.MODES - {"compare"}):
            with self.subTest(mode=mode):
                result = audit.audit({"mode": mode, "roots": [str(self.root)], "content_read_approved": True})
                self.assertEqual(result["mode"], mode)
                self.assertFalse(result["changes_made"])
                self.assertFalse(result["execution_authorized"])
                self.assertTrue(result["inventory"]["entries"])
        before = self.inventory()
        self.source.write_text("answer = 42\nextra = 1\n")
        result = audit.audit({"mode": "compare", "before": before, "after": self.inventory()})
        self.assertTrue(result["changed"])
        self.assertFalse(result["changes_made"])

    def test_directory_sizes_sorting_and_health(self):
        inventory = self.inventory()
        for order in ("size", "oldest", "location", "type", "application", "recoverability"):
            result = core.analyze({"inventory": inventory, "sort_by": order})
            self.assertTrue(result["ranked_files"])
            self.assertTrue(result["directories"])
            self.assertTrue(result["health"])
        with self.assertRaises(core.Refusal):
            core.analyze({"inventory": inventory, "sort_by": "execute"})

    def test_project_artifact_rules_require_project_evidence(self):
        for rule, (markers, paths, app) in audit.PROJECT_RULES.items():
            directory = self.root / rule; directory.mkdir()
            marker = directory / markers[0]; marker.write_text("fixture metadata")
            artifact = directory / paths[0] / "fixture.bin"
            artifact.parent.mkdir(parents=True); artifact.write_bytes(b"build output")
            inventory = self.inventory()
            entry = next((x for x in inventory["entries"] if x["path"] == str(artifact)), None)
            if "node_modules" in artifact.parts:
                self.assertIsNone(entry); continue
            finding = audit.project_finding(entry)
            self.assertEqual(finding["rule_id"], rule)
            self.assertEqual(finding["classification"], "REVIEW")
            marker.unlink()
            self.assertIsNone(audit.project_finding(entry))

    def test_recommendations_do_not_authorize_project_removal(self):
        (self.root / "Cargo.toml").write_text("[package]\n")
        target = self.root / "target"; target.mkdir(); (target / "generated").write_text("build")
        inventory = self.inventory()
        proposal = audit.recommendations({"inventory": inventory})
        row = next(x for x in proposal["candidates"] if x["path"].endswith("generated"))
        self.assertEqual(row["authorization"], "not-approved")
        self.assertEqual(row["classification"], "REVIEW")
        with self.assertRaises(core.Refusal):
            removal.create_plan({"inventory": inventory, "candidate_ids": [row["candidate_id"]]})

    def test_trash_is_inspectable_but_never_executable(self):
        trash = self.root / ".Trash"; trash.mkdir()
        (trash / "pyproject.toml").write_text("fixture")
        (trash / "personal.txt").write_text("recoverable")
        with self.assertRaises(core.Refusal):
            core.scan({"roots": [str(trash)]})
        result = audit.trash({"roots": [str(trash)], "authorized": True})
        self.assertGreater(result["logical_bytes"], 0)
        self.assertFalse(result["emptying_authorized"])
        self.assertTrue(all(x["classification"] == "PROTECTED" for x in result["inventory"]["entries"]))
        self.assertEqual(audit.recommendations({"inventory": result["inventory"]})["candidates"], [])

    def test_protected_metadata_requires_explicit_scope_consent(self):
        with self.assertRaises(core.Refusal):
            core.scan({"roots": [str(self.root)], "protected_metadata_only": True})
        result = core.scan({"roots": [str(self.root)], "protected_metadata_only": True, "scope_review_approved": True})
        self.assertTrue(all(x["classification"] == "PROTECTED" for x in result["entries"]))
        with self.assertRaises(core.Refusal):
            removal.create_plan({"inventory": result, "candidate_ids": [self.candidate(result)["id"]]})

    def test_nan_scan_budget_and_forged_hash_scope_are_rejected(self):
        with self.assertRaises(core.Refusal):
            self.inventory(max_seconds=float("nan"))
        inventory = self.inventory()
        inventory["entries"][0]["root"] = str(self.base)
        with self.assertRaises(core.Refusal):
            core.analyze({"inventory": inventory, "duplicates": True, "content_read_approved": True})

    def test_comparison_does_not_mix_scopes(self):
        before = self.inventory(); after = copy.deepcopy(before); after["roots"] = [str(self.base)]
        with self.assertRaises(core.Refusal):
            audit.compare({"before": before, "after": after})

    def test_policy_is_restrictive_and_cannot_grant_permissions(self):
        with self.assertRaises(core.Refusal):
            audit.policy({"auto_approve": True})
        with self.assertRaises(core.Refusal):
            audit.audit({"roots": [str(self.base)], "policy": {"roots": [str(self.root)]}})
        result = audit.audit({"roots": [str(self.root)], "max_entries": 1000, "policy": {"max_entries": 1}})
        self.assertEqual(result["inventory"]["entries_visited"], 1)
        self.assertFalse(result["inventory"]["complete"])

    @unittest.skipUnless(os.name == "posix", "Private persistent state uses POSIX permissions")
    def test_consented_profiles_and_signed_snapshots(self):
        with self.assertRaises(core.Refusal):
            audit.profiles({"state_dir": str(self.state), "save": True, "policy": {"roots": [str(self.root)]}})
        profile = audit.profiles({"state_dir": str(self.state), "save": True, "user_approved": True,
                                  "policy": {"roots": [str(self.root)], "never_permanently_delete": True}})
        result = audit.audit({"state_dir": str(self.state), "profile_id": profile["id"]})
        self.assertTrue(result["restrictions"]["never_permanently_delete"])
        snapshot = audit.snapshots({"state_dir": str(self.state), "inventory": self.inventory(), "user_approved": True})
        loaded = audit.snapshots({"state_dir": str(self.state), "snapshot_id": snapshot["id"]})
        self.assertEqual(loaded, snapshot)
        self.assertFalse(loaded["execution_authorized"])


class NativeFeatures(Fixture):
    def test_native_queries_require_authorized_scope(self):
        for fn in (native.applications, native.storage, native.activity, native.recycle_bin):
            with self.subTest(function=fn.__name__), self.assertRaises(core.Refusal):
                fn({})

    def test_application_inventory_normalizes_all_three_platforms(self):
        samples = {"linux": "google-chrome\t123\n", "macos": json.dumps({"SPApplicationsDataType": [{"_name": "Google Chrome", "version": "123", "CFBundleIdentifier": "com.google.Chrome"}]}),
                   "windows": json.dumps([{"name": "Google Chrome", "version": "123"}])}
        for pid, metadata in samples.items():
            with patch.object(core, "platform_id", return_value=pid), patch.object(native, "read_command", return_value={"status": "ok", "complete": True, "metadata": metadata}):
                result = native.applications({"authorized": True})
                self.assertTrue(result["applications"])
                self.assertFalse(result["changes_made"])

    def test_native_storage_has_fixed_read_only_interfaces(self):
        for pid in ("linux", "macos", "windows"):
            with patch.object(core, "platform_id", return_value=pid), patch.object(native, "read_command", return_value={"status": "unavailable", "complete": False, "metadata": None}) as run:
                result = native.storage({"authorized": True, "command": "malicious untrusted data"})
                self.assertGreater(run.call_count, 0)
                self.assertFalse(result["changes_made"])
                self.assertFalse(result["snapshot_modification_supported"])
                self.assertFalse(any("malicious" in str(call) for call in run.call_args_list))

    def test_malformed_native_output_is_not_a_complete_inventory(self):
        with patch.object(core, "platform_id", return_value="macos"), patch.object(native, "read_command", return_value={"status": "ok", "complete": True, "metadata": "not json"}):
            self.assertFalse(native.applications({"authorized": True})["complete"])

    def test_missing_native_tool_degrades_without_elevation(self):
        with patch.object(native.shutil, "which", return_value=None):
            result = native.read_command(["nonexistent-fixture-tool"])
        self.assertEqual(result["status"], "unavailable")

    def test_application_absence_only_produces_review(self):
        p = self.root / ".cache/pip"; p.mkdir(parents=True); (p / "wheel").write_text("cache")
        inventory = self.inventory()
        result = audit.leftovers({"inventory": inventory, "applications": {"source": "native-installed-applications", "applications": [], "complete": False}})
        self.assertTrue(result["associations"])
        self.assertTrue(all(x["classification"] == "REVIEW" and not x["automatic_removal"] for x in result["associations"]))

    def test_active_use_absence_remains_unknown(self):
        inventory = self.inventory(); entry = self.candidate(inventory)
        with patch.object(native, "read_command", return_value={"status": "unavailable", "metadata": None, "complete": False}):
            result = native.activity({"authorized": True, "inventory": inventory, "candidate_ids": [entry["id"]]})
        self.assertEqual(result["items"][0]["active_use"], "unknown")

if __name__ == "__main__":
    unittest.main()

import copy
import json
import os
from pathlib import Path
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from test_engine import Fixture
import _audit as audit
import _core as core
import _native as native
import _purge as purge


class AuditFeatures(Fixture):
    def test_all_ten_modes_have_operational_read_only_workflows(self):
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
        if os.name == "posix":
            with self.assertRaises(core.Refusal):
                core.create_plan({"state_dir": str(self.state), "inventory": inventory, "candidate_ids": [row["candidate_id"]]})

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
        if os.name == "posix":
            with self.assertRaises(core.Refusal):
                core.create_plan({"inventory": result, "state_dir": str(self.state), "candidate_ids": [self.candidate(result)["id"]]})

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


@unittest.skipUnless(os.name == "posix", "Permanent cleanup is limited to private POSIX quarantine")
class PermanentCleanup(Fixture):
    def test_journal_space_is_required_before_quarantine(self):
        plan = self.plan(); receipt = self.approval(plan)
        with patch.object(core.shutil, "disk_usage", return_value=SimpleNamespace(free=0)), self.assertRaises(core.Refusal):
            self.execute(plan, receipt)
        self.assertTrue(self.bytecode.exists())

    def prepare(self):
        plan = self.plan(); receipt = self.approval(plan)
        result = self.execute(plan, receipt)
        request = {"state_dir": str(self.state), "operation_id": result["id"], "candidate_ids": [result["items"][0]["candidate_id"]]}
        return result, purge.create_plan(request)

    def authorize(self, plan):
        return purge.approve({"state_dir": str(self.state), "plan_id": plan["id"], "plan_digest": plan["digest"],
                              "user_approved": True, "acknowledge_irreversible": True, "approval_note": "Fixture user approved irreversible deletion of exact quarantine IDs"})

    def test_separately_approved_permanent_cleanup_and_verification(self):
        original_source = self.source.read_bytes()
        result, plan = self.prepare(); receipt = self.authorize(plan)
        outcome = purge.execute({"state_dir": str(self.state), "plan_id": plan["id"], "approval_id": receipt["id"]})
        self.assertEqual(outcome["status"], "complete")
        self.assertTrue(outcome["irreversible"])
        self.assertFalse(Path(result["items"][0]["quarantined"]).exists())
        self.assertEqual(self.source.read_bytes(), original_source)
        verified = purge.verify({"state_dir": str(self.state), "operation_id": outcome["id"]})
        self.assertTrue(verified["all_verified"])
        report = core.human_report({"operation": verified, "plan": plan})
        self.assertIn("verified: 1", report["markdown"])
        self.assertIn("cannot be undone", report["markdown"])
        self.assertNotIn(str(self.state), report["markdown"])

    def test_journal_space_is_required_before_permanent_removal(self):
        result, plan = self.prepare(); receipt = self.authorize(plan)
        with patch.object(core.shutil, "disk_usage", return_value=SimpleNamespace(free=0)), self.assertRaises(core.Refusal):
            purge.execute({"state_dir": str(self.state), "plan_id": plan["id"], "approval_id": receipt["id"]})
        self.assertTrue(Path(result["items"][0]["quarantined"]).exists())

    def test_cleanup_report_requires_verification_and_correct_plan(self):
        result, plan = self.prepare()
        with self.assertRaises(core.Refusal):
            core.human_report({"operation": result, "plan": plan})
        verified = core.verify({"state_dir": str(self.state), "operation_id": result["id"]})
        original_plan = core.Store(str(self.state)).load("plan-" + result["plan_id"] + ".json")
        self.assertIn("verified: 1", core.human_report({"operation": verified, "plan": original_plan})["markdown"])
        with self.assertRaises(core.Refusal):
            core.human_report({"operation": verified, "plan": plan})

    def test_quarantine_approval_cannot_authorize_purge(self):
        result, plan = self.prepare()
        with self.assertRaises((core.Refusal, FileNotFoundError)):
            purge.execute({"state_dir": str(self.state), "plan_id": plan["id"], "approval_id": result["approval_id"]})

    def test_irreversible_acknowledgement_is_mandatory(self):
        _, plan = self.prepare()
        with self.assertRaises(core.Refusal):
            purge.approve({"state_dir": str(self.state), "plan_id": plan["id"], "plan_digest": plan["digest"], "user_approved": True})

    def test_changed_or_linked_quarantine_is_not_deleted(self):
        result, plan = self.prepare(); receipt = self.authorize(plan)
        path = Path(result["items"][0]["quarantined"])
        os.link(path, self.root / "keep-copy")
        with self.assertRaises(core.Refusal):
            purge.execute({"state_dir": str(self.state), "plan_id": plan["id"], "approval_id": receipt["id"]})
        self.assertTrue(path.exists())

    def test_symlink_quarantine_replacement_never_touches_target(self):
        result, plan = self.prepare(); receipt = self.authorize(plan)
        path = Path(result["items"][0]["quarantined"]); path.unlink(); path.symlink_to(self.source)
        with self.assertRaises(core.Refusal):
            purge.execute({"state_dir": str(self.state), "plan_id": plan["id"], "approval_id": receipt["id"]})
        self.assertTrue(self.source.exists())

    def test_no_permanent_delete_profile_blocks_planning(self):
        result, plan = self.prepare()
        with self.assertRaises(core.Refusal):
            purge.create_plan({"state_dir": str(self.state), "operation_id": result["id"], "candidate_ids": [plan["items"][0]["candidate_id"]], "policy": {"never_permanently_delete": True}})

    def test_expired_purge_receipt_rejected(self):
        _, plan = self.prepare(); receipt = self.authorize(plan)
        with patch.object(core.time, "time", return_value=time.time() + 301):
            with self.assertRaises(core.Refusal):
                purge.execute({"state_dir": str(self.state), "plan_id": plan["id"], "approval_id": receipt["id"]})

    def test_purge_approval_is_invalid_after_catalog_change(self):
        _, plan = self.prepare(); receipt = self.authorize(plan)
        changed = [{**r, "reason": r["reason"] + " changed"} for r in core.read_rules()]
        with patch.object(core, "read_rules", return_value=changed), self.assertRaises(core.Refusal):
            purge.execute({"state_dir": str(self.state), "plan_id": plan["id"], "approval_id": receipt["id"]})

    def test_purge_receipt_cannot_be_replayed(self):
        _, plan = self.prepare(); receipt = self.authorize(plan)
        request = {"state_dir": str(self.state), "plan_id": plan["id"], "approval_id": receipt["id"]}
        purge.execute(request)
        with self.assertRaises((core.Refusal, FileNotFoundError, FileExistsError)):
            purge.execute(request)

    def test_native_failure_stops_and_journals(self):
        result, plan = self.prepare(); receipt = self.authorize(plan)
        with patch.object(purge.os, "unlink", side_effect=OSError("fixture failure")):
            outcome = purge.execute({"state_dir": str(self.state), "plan_id": plan["id"], "approval_id": receipt["id"]})
        self.assertEqual(outcome["status"], "partial")
        self.assertTrue(Path(result["items"][0]["quarantined"]).exists())


if __name__ == "__main__":
    unittest.main()

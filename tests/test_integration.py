"""End-to-end JSON helper protocol and distribution regression checks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

from test_engine import Fixture
import _core as core


class IntegrationTests(Fixture):
    def helper(self, name, request):
        proc = subprocess.run([sys.executable, str(core.BASE / "scripts" / (name + ".py"))],
                              input=json.dumps(request), text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        envelope = json.loads(proc.stdout)
        self.assertTrue(envelope["ok"])
        return envelope["result"]

    def test_full_local_protocol_on_temporary_project(self):
        inventory = self.helper("inventory", {"roots": [str(self.root)]})
        candidate = self.candidate(inventory)
        analysis = self.helper("analyze", {"inventory": inventory})
        self.assertTrue(analysis["largest"])
        report = self.helper("report", {"inventory": inventory})
        self.assertNotIn(str(self.root), report["markdown"])
        if os.name != "posix":
            return  # Windows deliberately stops after the audit/report boundary.
        state = {"state_dir": str(self.state)}
        plan = self.helper("plan", {**state, "inventory": inventory, "candidate_ids": [candidate["id"]]})
        self.assertTrue(self.helper("validate", {**state, "plan_id": plan["id"]})["valid"])
        approval = self.helper("approve", {**state, "plan_id": plan["id"], "plan_digest": plan["digest"],
                                            "user_approved": True, "workload_stopped": True,
                                            "approval_note": "Synthetic integration fixture approval"})
        result = self.helper("execute", {**state, "plan_id": plan["id"], "approval_id": approval["id"]})
        verified = self.helper("verify", {**state, "operation_id": result["id"]})
        self.assertTrue(verified["all_verified"])
        restored = self.helper("restore", {**state, "operation_id": result["id"], "user_approved": True})
        self.assertEqual(restored["items"][0]["status"], "restored-quarantine-link-retained")
        self.assertTrue(self.bytecode.exists())
        self.assertEqual(self.source.read_text(), "answer = 42\n")

    def test_skill_archive_is_deterministic_and_contains_runtime_resources(self):
        sys.path.insert(0, str(core.BASE / "scripts"))
        from package_skill import build
        a, b = self.base / "a.skill", self.base / "b.skill"
        build(a); build(b)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        with zipfile.ZipFile(a) as archive:
            names = archive.namelist()
            self.assertIn("swipr/SKILL.md", names)
            self.assertIn("swipr/SECURITY.md", names)
            self.assertIn("swipr/COMMANDS.md", names)
            self.assertIn("swipr/scripts/swipr.py", names)
            self.assertIn("swipr/docs/advanced.md", names)
            self.assertIn("swipr/scripts/_core.py", names)
            self.assertIn("swipr/rules/developer/catalog.json", names)
            self.assertFalse(any("__pycache__" in n or "/.git/" in n or "/tests/" in n for n in names))

    def test_extended_audit_and_permanent_cleanup_json_protocol(self):
        audit = self.helper("audit", {"mode": "developer", "roots": [str(self.root)]})
        self.assertFalse(audit["execution_authorized"])
        inventory = audit["inventory"]
        self.assertTrue(self.helper("recommend", {"inventory": inventory})["candidates"])
        self.assertFalse(self.helper("compare", {"before": inventory, "after": inventory})["changes_made"])
        if os.name != "posix":
            return
        state = {"state_dir": str(self.state)}
        candidate = self.candidate(inventory)
        plan = self.helper("plan", {**state, "inventory": inventory, "candidate_ids": [candidate["id"]]})
        approval = self.helper("approve", {**state, "plan_id": plan["id"], "plan_digest": plan["digest"], "user_approved": True, "workload_stopped": True, "approval_note": "Synthetic quarantine approval"})
        operation = self.helper("execute", {**state, "plan_id": plan["id"], "approval_id": approval["id"]})
        purge_plan = self.helper("purge_plan", {**state, "operation_id": operation["id"], "candidate_ids": [candidate["id"]]})
        purge_approval = self.helper("purge_approve", {**state, "plan_id": purge_plan["id"], "plan_digest": purge_plan["digest"], "user_approved": True, "acknowledge_irreversible": True, "approval_note": "Synthetic separate irreversible approval"})
        result = self.helper("purge_execute", {**state, "plan_id": purge_plan["id"], "approval_id": purge_approval["id"]})
        self.assertTrue(self.helper("purge_verify", {**state, "operation_id": result["id"]})["all_verified"])
        self.assertTrue(self.source.exists())

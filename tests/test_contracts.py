import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from test_engine import Fixture
import _core as core

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None


@unittest.skipUnless(Draft202012Validator, "Install requirements-dev.txt for JSON Schema checks")
class ContractTests(Fixture):
    def validate(self, name, value):
        schema = json.loads((core.BASE / "schemas" / (name + ".schema.json")).read_text())
        Draft202012Validator(schema).validate(value)

    def test_inventory_candidate_and_report(self):
        inventory = self.inventory()
        self.validate("inventory", inventory)
        for entry in inventory["entries"]:
            self.validate("candidate", entry)
        self.validate("report", core.human_report({"inventory": inventory}))

    @unittest.skipUnless(os.name == "posix", "POSIX private-state workflow")
    def test_signed_plan_approval_and_execution_contracts(self):
        plan = self.plan(); receipt = self.approval(plan)
        self.validate("plan", plan)
        self.validate("approval", receipt)
        self.validate("operation", self.execute(plan, receipt))


class RuleTests(Fixture):
    def test_each_audit_signature_and_protected_override(self):
        rules = core.read_rules()
        for rule in rules:
            if rule["strategy"] == "quarantine-bytecode":
                continue
            with self.subTest(rule=rule["id"]), patch.object(core, "platform_id", return_value=rule["platforms"][0]):
                path = self.root / rule["signatures"][0] / "resource.bin"
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"resource")
                info = core.identity(path.stat())
                matched, kind, _ = core.classify(path, self.root, info, [rule])
                self.assertEqual(kind, "REVIEW")
                self.assertEqual(matched["id"], rule["id"])
                self.assertEqual(core.classify(path, self.root, info, [rule], [str(path.parent)])[1], "PROTECTED")
                unknown = path.parent.parent / "unrecognized" / "resource.bin"
                self.assertEqual(core.classify(unknown, self.root, info, [rule])[1], "PROTECTED")

    def test_cross_platform_rule_is_not_promoted(self):
        rule = next(x for x in core.read_rules() if x["id"] == "homebrew-downloads")
        path = self.root / "Library/Caches/Homebrew/file"
        with patch.object(core, "platform_id", return_value="windows"):
            self.assertEqual(core.classify(path, self.root, {}, [rule])[1], "PROTECTED")

    def test_rule_catalog_change_invalidates_plan(self):
        if os.name != "posix":
            self.skipTest("POSIX private state")
        plan = self.plan()
        original = core.read_rules()
        changed = [{**x, "reason": x["reason"] + " changed"} for x in original]
        with patch.object(core, "read_rules", return_value=changed):
            with self.assertRaises(core.Refusal):
                self.approval(plan)

    def test_linux_bind_mount_inventory_and_execution(self):
        with patch.object(core, "mount_points", return_value={self.bytecode.parent}):
            self.assertFalse(any(x["path"] == str(self.bytecode) for x in self.inventory()["entries"]))

    def test_source_is_never_opened_by_inventory(self):
        actual_open = Path.open
        def guarded(path, *args, **kwargs):
            if path == self.source:
                raise AssertionError("Inventory opened project source")
            return actual_open(path, *args, **kwargs)
        with patch.object(Path, "open", guarded):
            self.inventory()

    def test_case_and_reparse_point_protection(self):
        class FakeStat:
            st_mode = 0o100600
            st_file_attributes = 0x400
        self.assertTrue(core.redirect(FakeStat()))
        self.assertTrue(core.protected(self.root / "OneDrive" / "data"))


if __name__ == "__main__":
    unittest.main()

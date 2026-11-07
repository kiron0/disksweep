"""Volume-query restrictions must not discard readable metadata or expose paths."""
import contextlib
import io
import json
from pathlib import Path
from unittest.mock import patch

from test_engine import Fixture
import _audit as audit
import _cli as cli
import _core as core
import _overview as overview


def denied():
    error = PermissionError(13, 'PRIVATE_ERROR_DETAILS', 'PRIVATE_ERROR_PATH')
    error.winerror = 5
    return error


class PermissionHandling(Fixture):
    def test_doctor_retains_capabilities_and_installation_when_volume_query_denied(self):
        output = io.StringIO()
        with patch.object(core.shutil, 'disk_usage', side_effect=denied()), contextlib.redirect_stdout(output):
            status = cli.main(['doctor', '--path', str(self.root), '--json'])
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())['result']
        self.assertIsNone(result['disk']['free'])
        self.assertEqual(result['disk']['status'], 'permission-denied')
        self.assertTrue(result['capabilities']['metadata'])
        self.assertEqual(result['installation']['version'], core.VERSION)
        self.assertNotIn('PRIVATE_ERROR', output.getvalue())

    def test_full_scan_retains_inventory_with_unknown_space_and_health(self):
        with patch.object(core.shutil, 'disk_usage', side_effect=denied()):
            result = overview.run({'roots': [str(self.root)]})
        self.assertTrue(result['inventory']['entries'])
        self.assertTrue(result['inventory']['complete'])
        self.assertIsNone(result['inventory']['disks'][0]['free'])
        self.assertEqual(result['analysis']['health'][0]['storage_pressure'], 'unknown')
        self.assertIn('Disk space: unknown', overview.render(result))
        self.assertFalse(result['changes_made'])
        from jsonschema import Draft202012Validator
        schema = json.loads((core.BASE / 'schemas/inventory.schema.json').read_text())
        Draft202012Validator(schema).validate(result['inventory'])

    def test_comparison_does_not_subtract_unknown_measurements(self):
        before = self.inventory()
        with patch.object(core.shutil, 'disk_usage', side_effect=denied()):
            after = self.inventory()
        for first, second in ((before, after), (after, before), (after, after)):
            result = audit.compare({'before': first, 'after': second})
            self.assertIsNone(result['available_space_deltas'][0]['observed_delta'])

    def test_permission_error_identifies_output_stage_without_guessing_or_paths(self):
        output = io.StringIO()
        with patch.object(cli, 'reserve_output', side_effect=denied()), patch.object(cli, 'dispatch') as dispatched, contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(['doctor', '--output', str(self.base / 'new.json'), '--json']), 2)
        dispatched.assert_not_called()
        detail = json.loads(output.getvalue())['error']
        self.assertEqual(detail['code'], 'PERMISSION_DENIED')
        self.assertEqual(detail['stage'], 'output creation')
        self.assertEqual(detail['winerror'], 5)
        self.assertNotIn('PRIVATE_ERROR', output.getvalue())

    def test_permission_error_identifies_execution_instead_of_blame_on_output(self):
        output = io.StringIO()
        with patch.object(cli, 'dispatch', side_effect=denied()), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(['doctor', '--json']), 2)
        detail = json.loads(output.getvalue())['error']
        self.assertEqual(detail['stage'], 'command execution')
        self.assertIn('sandbox', detail['message'])
        self.assertNotIn('PRIVATE_ERROR', output.getvalue())

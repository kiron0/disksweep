"""One-pass onboarding and Windows review choices, using disposable fixtures only."""
import contextlib
import io
import json
import os
from pathlib import Path
from unittest.mock import patch
import unittest

from test_engine import Fixture
import _cli as cli
import _core as core
import _overview as overview


class Overview(Fixture):
    def test_default_start_scans_fixture_profile_once_without_reading_contents(self):
        for name in ('first.bin', 'second.bin'):
            (self.root / name).write_bytes(b'fixture-only' * 100)
        before = {path: path.stat().st_size for path in self.root.rglob('*') if path.is_file()}
        output = io.StringIO()
        with patch.object(Path, 'home', return_value=self.root), \
             patch.object(overview.audit, 'audit', wraps=overview.audit.audit) as scanned, \
             patch.object(core, 'safe_hash', side_effect=AssertionError('No implicit hashing')), \
             contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(['start', '--json']), 0)
        self.assertEqual(scanned.call_count, 1)
        result = json.loads(output.getvalue())['result']
        self.assertEqual(result['scope']['selection'], 'current-user-profile')
        self.assertEqual(result['inventory']['roots'], [str(self.root)])
        self.assertTrue(result['analysis']['possible_duplicates'])
        self.assertTrue(all(not group['content_verified'] for group in result['analysis']['possible_duplicates']))
        self.assertFalse(result['execution_authorized'])
        self.assertFalse(self.state.exists())
        self.assertEqual(before, {path: path.stat().st_size for path in self.root.rglob('*') if path.is_file()})

    def test_full_scan_respects_explicit_policy_scope_exclusions_and_budget(self):
        with patch.object(overview, 'default_roots', side_effect=AssertionError('Policy must supply scope')):
            result = overview.run({'policy': {'roots': [str(self.root)], 'exclude': [str(self.source)], 'max_entries': 1}})
        self.assertFalse(result['inventory']['complete'])
        self.assertEqual(result['inventory']['entries_visited'], 1)
        self.assertTrue(all(entry['path'] != str(self.source) for entry in result['inventory']['entries']))
        self.assertIn('partial', overview.render(result))
        self.assertEqual(result['scope']['selection'], 'explicit-or-policy')

    def test_windows_review_offers_choices_without_unavailable_deletion(self):
        result = overview.run({'roots': [str(self.root)]})
        result['discovery']['platform'] = 'windows'
        question = overview.review_prompt(result)
        result['removal_plan'] = {'id': 'fixture', 'digest': 'fixture'}
        question = overview.review_prompt(result)
        self.assertEqual(len(question['options']), 3)
        self.assertEqual(question['options'][0]['id'], 'remove_selected')
        self.assertFalse(question['authorizes_cleanup'])
        self.assertIn('Swipr cannot undo removal', overview.render(result))
        self.assertFalse(any('bytecode' in option['id'] for option in question['options']))

    def test_empty_complete_scan_finishes_without_another_question(self):
        empty = self.base / 'empty'; empty.mkdir()
        result = overview.run({'roots': [str(empty)]})
        self.assertFalse(result['review_prompt']['requires_response'])
        self.assertEqual(result['review_prompt']['options'], [])

    def test_missing_secure_handles_does_not_offer_bytecode_cleanup(self):
        result = overview.run({'roots': [str(self.root)]})
        result['discovery']['capabilities']['quarantine'] = False
        self.assertEqual(overview.review_prompt(result)['options'][0]['id'], 'native_cleanup')

    def test_full_scan_command_saves_result_and_reuses_existing_review_inputs(self):
        output = self.base / 'full.json'
        display = io.StringIO()
        with contextlib.redirect_stdout(display):
            self.assertEqual(cli.main(['scan', 'full', '--root', str(self.root), '--output', str(output)]), 0)
        self.assertIn('full user scan', display.getvalue())
        self.assertIn('What would you like', display.getvalue())
        self.assertEqual(cli.inventory(output)['roots'], [str(self.root)])
        self.assertTrue(self.bytecode.exists())
        self.assertFalse(self.state.exists())

    def test_default_scope_refuses_network_and_drive_roots(self):
        for home in (Path('\\\\server\\profile'), Path(self.root.anchor)):
            with self.subTest(home=home), patch.object(Path, 'home', return_value=home):
                with self.assertRaises(core.Refusal):
                    overview.default_roots()

    @unittest.skipUnless(os.name == 'posix', 'Fixture symbolic links')
    def test_default_scope_refuses_redirected_profile(self):
        linked = self.base / 'linked-profile'; linked.symlink_to(self.root, target_is_directory=True)
        with patch.object(Path, 'home', return_value=linked), self.assertRaises(core.Refusal):
            overview.default_roots()

    def test_windows_without_eligible_plan_never_offers_a_removal_choice(self):
        result = overview.run({'roots': [str(self.root)]})
        result['discovery']['platform'] = 'windows'
        result['removal_plan'] = None
        question = overview.review_prompt(result)
        self.assertFalse(any(option['id'] == 'remove_selected' for option in question['options']))


if __name__ == '__main__':
    unittest.main()

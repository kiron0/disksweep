"""Direct removal uses only disposable Windows NTFS fixtures and test approvals."""
import copy
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from test_engine import Fixture
import _core as core
import _remove as removal
import _windows_file as windows
import _overview as overview


class RemovalApproval(Fixture):
    def test_missing_approval_never_opens_a_file(self):
        with patch.object(windows, 'OpenFile') as opened:
            with self.assertRaises(core.Refusal):
                removal.execute({'user_approved': False})
            opened.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_edited_plan_digest_is_refused_before_any_native_open(self):
        plan = {'action': 'permanent-remove', 'id': 'a' * 32, 'expires_at': time.time() + 900}
        plan['digest'] = core.digest(plan)
        plan['action'] = 'edited'
        with patch.object(removal.os, 'name', 'nt'), patch.object(windows, 'OpenFile') as opened:
            with self.assertRaises(core.Refusal):
                removal.execute({'user_approved': True, 'acknowledge_irreversible': True,
                                 'plan': plan, 'plan_digest': plan['digest']})
            opened.assert_not_called()


@unittest.skipUnless(os.name == 'nt', 'Native Windows NTFS handle tests')
class WindowsRemoval(Fixture):
    def setUp(self):
        super().setUp()
        cache = self.root / 'AppData' / 'Local' / 'pip' / 'Cache'
        cache.mkdir(parents=True)
        self.first, self.second = cache / 'first.bin', cache / 'second.bin'
        self.first.write_bytes(b'disposable first cache')
        self.second.write_bytes(b'disposable second cache')
        self.inv = self.inventory()
        self.entries = [entry for entry in self.inv['entries'] if entry['path'] in (str(self.first), str(self.second))]

    def plan(self, **extra):
        return removal.create_plan({'inventory': self.inv, 'candidate_ids': [entry['id'] for entry in self.entries], **extra})

    def request(self, plan, selected=None):
        return {'plan': plan, 'plan_digest': plan['digest'], 'candidate_ids': selected or [entry['id'] for entry in plan['entries']],
                'state_dir': str(self.state), 'user_approved': True, 'acknowledge_irreversible': True}

    def test_only_checked_file_is_removed_verified_and_cannot_be_replayed(self):
        plan = self.plan()
        selected = next(entry['id'] for entry in self.entries if entry['path'] == str(self.first))
        result = removal.execute(self.request(plan, [selected]))
        self.assertTrue(result['all_verified'])
        self.assertFalse(self.first.exists())
        self.assertTrue(self.second.exists())
        self.assertTrue(self.source.exists())
        verified = removal.verify({'state_dir': str(self.state), 'operation_id': result['id']})
        self.assertTrue(verified['all_verified'])
        report = core.human_report({'operation': verified, 'plan': plan})
        self.assertIn('Approved: 1; processed: 1', report['markdown'])
        with self.assertRaises(FileExistsError):
            removal.execute(self.request(plan))
        self.assertTrue(self.second.exists())

    def test_changed_file_stops_preflight_before_any_removal(self):
        plan = self.plan()
        self.second.write_bytes(b'changed after displayed plan')
        with self.assertRaises((core.Refusal, OSError)):
            removal.execute(self.request(plan))
        self.assertTrue(self.first.exists())
        self.assertTrue(self.second.exists())

    def test_exclusive_handle_rejects_locked_file(self):
        with windows.OpenFile(self.entries[0]):
            with self.assertRaises((core.Refusal, OSError)):
                self.plan()
        self.assertTrue(self.first.exists())

    def test_source_secrets_and_unselected_personal_files_are_protected(self):
        for path in (self.source, self.root / '.env', self.root / 'personal.txt'):
            if not path.exists():
                path.write_text('disposable fixture')
        inv = self.inventory()
        for entry in inv['entries']:
            if entry['path'] in (str(self.source), str(self.root / '.env'), str(self.root / 'personal.txt')):
                with self.assertRaises(core.Refusal):
                    removal.create_plan({'inventory': inv, 'candidate_ids': [entry['id']]})
        source = next(entry for entry in inv['entries'] if entry['path'] == str(self.source))
        with self.assertRaises(core.Refusal):
            removal.create_plan({'inventory': inv, 'candidate_ids': [source['id']], 'include_personal': True})

    def test_explicit_personal_selection_can_be_planned_but_never_removed_implicitly(self):
        path = self.root / 'selected-download.zip'; path.write_bytes(b'disposable download')
        inv = self.inventory()
        entry = next(entry for entry in inv['entries'] if entry['path'] == str(path))
        plan = removal.create_plan({'inventory': inv, 'candidate_ids': [entry['id']], 'include_personal': True})
        self.assertTrue(path.exists())
        self.assertTrue(plan['include_personal'])
        self.assertIn('PERMANENT DELETION', plan['warning'])

    def test_policies_block_permanent_and_offline_cache_removal(self):
        for policy in ({'never_permanently_delete': True}, {'preserve_offline': True}):
            with self.subTest(policy=policy), self.assertRaises(core.Refusal):
                self.plan(policy=policy)

    def test_full_scan_prepares_reviewable_plan_without_deleting(self):
        result = overview.run({'roots': [str(self.root)]})
        self.assertIsNotNone(result.get('removal_plan'))
        self.assertEqual(result['review_prompt']['options'][0]['id'], 'remove_selected')
        self.assertTrue(self.first.exists())
        self.assertFalse(self.state.exists())

    def test_metadata_tampering_cannot_change_the_approved_selection(self):
        plan = self.plan()
        edited = copy.deepcopy(plan)
        edited['entries'][0]['path'] = str(self.source)
        with self.assertRaises(core.Refusal):
            removal.execute({**self.request(edited), 'plan_digest': plan['digest']})
        self.assertTrue(self.source.exists())

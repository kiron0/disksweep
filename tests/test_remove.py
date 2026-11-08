"""Direct removal uses only disposable fixtures and test approvals on every supported OS."""
import copy
import os
from pathlib import Path
import time
import subprocess
import unittest
from unittest.mock import patch

from test_engine import Fixture
import _core as core
import _remove as removal
import _overview as overview

CACHE = {'macos': ('Library', 'Caches', 'pip'), 'linux': ('.cache', 'pip'),
         'windows': ('AppData', 'Local', 'pip', 'Cache')}.get(core.platform_id(), ('.cache', 'pip'))


class RemovalApproval(Fixture):
    def test_missing_approval_never_opens_a_file(self):
        with patch.object(removal.files, 'OpenFile') as opened:
            with self.assertRaises(core.Refusal):
                removal.execute({'user_approved': False})
            opened.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_edited_plan_digest_is_refused_before_any_native_open(self):
        plan = {'action': 'permanent-remove', 'id': 'a' * 32, 'expires_at': time.time() + 900}
        plan['digest'] = core.digest(plan)
        plan['action'] = 'edited'
        with patch.object(removal.files, 'OpenFile') as opened:
            with self.assertRaises(core.Refusal):
                removal.execute({'user_approved': True, 'acknowledge_irreversible': True,
                                 'plan': plan, 'plan_digest': plan['digest']})
            opened.assert_not_called()


@unittest.skipUnless(core.removal_supported(), 'Exact removal handles are unavailable on this platform')
class Removal(Fixture):
    def setUp(self):
        super().setUp()
        cache = self.root.joinpath(*CACHE)
        cache.mkdir(parents=True)
        self.first, self.second = cache / 'first.bin', cache / 'second.bin'
        self.first.write_bytes(b'disposable first cache')
        self.second.write_bytes(b'disposable second cache')
        self.own(self.root, recursive=True)
        self.inv = self.inventory()
        self.entries = [entry for entry in self.inv['entries'] if entry['path'] in (str(self.first), str(self.second))]

    def own(self, path, recursive=False):
        if os.name != 'nt':
            return
        import _windows_file as windows
        kernel, security = windows._api()
        sid = windows._current_user(kernel, security)
        arguments = ['icacls', str(path), '/setowner', '*' + sid]
        if recursive:
            arguments.append('/T')
        subprocess.run(arguments, check=True, capture_output=True)

    def plan(self, **extra):
        return removal.create_plan({'inventory': self.inv, 'candidate_ids': [entry['id'] for entry in self.entries], **extra})

    def request(self, plan, selected=None):
        return {'plan': plan, 'plan_digest': plan['digest'], 'candidate_ids': selected or [entry['id'] for entry in plan['entries']],
                'state_dir': str(self.state), 'user_approved': True, 'acknowledge_irreversible': True}

    def bytecode_plan(self, inventory=None):
        inventory = inventory or self.inventory()
        return removal.create_plan({'inventory': inventory, 'candidate_ids': [self.candidate(inventory)['id']]})

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
        records = removal.operations({'state_dir': str(self.state)})
        self.assertEqual([(x['id'], x['status']) for x in records['operations']], [(result['id'], 'complete')])

    def test_bytecode_is_removed_while_source_and_marker_remain(self):
        plan = self.bytecode_plan()
        self.assertEqual(plan['entries'][0]['rule_id'], 'python-bytecode')
        result = removal.execute(self.request(plan))
        self.assertTrue(result['all_verified'])
        self.assertFalse(self.bytecode.exists())
        self.assertTrue(self.source.exists())
        self.assertTrue(self.marker.exists())

    def test_recent_bytecode_is_not_eligible(self):
        os.utime(self.bytecode, None)
        with self.assertRaises(core.Refusal):
            self.bytecode_plan()
        self.assertTrue(self.bytecode.exists())

    def test_forged_inventory_cannot_promote_source(self):
        inventory = self.inventory()
        source = next(x for x in inventory['entries'] if x['path'] == str(self.source))
        source.update(classification='SAFE-CANDIDATE', strategy='remove-exact', rule_id='python-bytecode')
        with self.assertRaises(core.Refusal):
            removal.create_plan({'inventory': inventory, 'candidate_ids': [source['id']]})
        self.assertTrue(self.source.exists())

    def test_changed_file_stops_preflight_before_any_removal(self):
        plan = self.plan()
        self.second.write_bytes(b'changed after displayed plan')
        with self.assertRaises((core.Refusal, OSError)):
            removal.execute(self.request(plan))
        self.assertTrue(self.first.exists())
        self.assertTrue(self.second.exists())

    @unittest.skipIf(os.name == 'nt', 'Symlink privileges vary on Windows')
    def test_symlink_replacement_after_plan_is_refused(self):
        plan = self.bytecode_plan()
        self.bytecode.unlink(); self.bytecode.symlink_to(self.source)
        with self.assertRaises((core.Refusal, OSError)):
            removal.execute(self.request(plan))
        self.assertEqual(self.source.read_text(), 'answer = 42\n')
        self.assertTrue(self.bytecode.is_symlink())

    def test_native_removal_failure_stops_and_keeps_file(self):
        plan = self.plan()
        with patch.object(removal.files, 'mark_for_removal', side_effect=OSError('fixture failure')):
            result = removal.execute(self.request(plan))
        self.assertFalse(result['all_verified'])
        self.assertEqual([item['status'] for item in result['items']], ['failed-stop'])
        self.assertTrue(self.first.exists())
        self.assertTrue(self.second.exists())
        records = removal.operations({'state_dir': str(self.state)})
        self.assertEqual(records['operations'][0]['status'], 'partial')

    def test_name_swapped_after_preflight_is_not_removed(self):
        plan = self.plan()
        selected = next(entry['id'] for entry in self.entries if entry['path'] == str(self.first))
        actual = removal.files.OpenFile
        calls = []
        def swap(entry):
            calls.append(entry['id'])
            if len(calls) == 2:
                self.first.unlink(); self.first.write_bytes(b'concurrent user data')
            return actual(entry)
        with patch.object(removal.files, 'OpenFile', side_effect=swap):
            result = removal.execute(self.request(plan, [selected]))
        self.assertEqual(result['items'][0]['status'], 'failed-stop')
        self.assertEqual(self.first.read_bytes(), b'concurrent user data')

    def test_expired_plan_does_not_remove_anything(self):
        plan = self.plan()
        with patch.object(removal.time, 'time', return_value=plan['expires_at'] + 1):
            with self.assertRaises(core.Refusal):
                removal.execute(self.request(plan))
        self.assertTrue(self.first.exists())
        self.assertFalse(self.state.exists())

    def test_hard_linked_file_is_not_eligible(self):
        os.link(self.first, self.root / 'retained-alias.bin')
        inv = self.inventory()
        entry = next(entry for entry in inv['entries'] if entry['path'] == str(self.first))
        with self.assertRaises(core.Refusal):
            removal.create_plan({'inventory': inv, 'candidate_ids': [entry['id']]})
        self.assertTrue(self.first.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions')
    def test_shared_records_directory_is_refused_before_removal(self):
        plan = self.plan()
        self.state.mkdir(mode=0o755); self.state.chmod(0o755)
        with self.assertRaises(core.Refusal):
            removal.execute(self.request(plan))
        self.assertTrue(self.first.exists())
        self.assertTrue(self.second.exists())

    def test_records_cannot_live_inside_removed_scope(self):
        plan = self.plan()
        with self.assertRaises(core.Refusal):
            removal.execute({**self.request(plan), 'state_dir': str(self.first.parent / 'records')})
        self.assertTrue(self.first.exists())

    def test_denied_journal_space_query_never_reaches_deletion(self):
        plan = self.plan()
        with patch.object(removal.shutil, 'disk_usage', side_effect=PermissionError('fixture denial')), patch.object(removal.files, 'mark_for_removal') as deleted:
            with self.assertRaises(PermissionError):
                removal.execute(self.request(plan))
            deleted.assert_not_called()
        self.assertTrue(self.first.exists())
        self.assertTrue(self.second.exists())

    def test_post_removal_space_denial_keeps_verified_result(self):
        plan = self.plan()
        selected = next(entry['id'] for entry in self.entries if entry['path'] == str(self.first))
        real_usage = removal.shutil.disk_usage
        def measured(path):
            if not self.first.exists():
                raise PermissionError('fixture post-removal denial')
            return real_usage(path)
        with patch.object(removal.shutil, 'disk_usage', side_effect=measured):
            result = removal.execute(self.request(plan, [selected]))
        self.assertTrue(result['all_verified'])
        self.assertIsNone(result['after_free'])
        self.assertIsNone(result['observed_free_delta'])
        self.assertEqual(result['volume_space'][0]['root'], str(self.first.parent))
        self.assertIn('after: unknown', core.human_report({'operation': result, 'plan': plan})['markdown'])

    @unittest.skipUnless(os.name == 'nt', 'Exclusive file handles are a Windows filesystem feature')
    def test_exclusive_handle_rejects_locked_file(self):
        with removal.files.OpenFile(self.entries[0]):
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
        self.own(path)
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
        self.assertTrue(self.bytecode.exists())
        self.assertFalse(self.state.exists())

    def test_cleanup_report_requires_verification_and_matching_plan(self):
        plan = self.plan()
        result = removal.execute(self.request(plan))
        unverified = {key: value for key, value in result.items() if key != 'verified_at'}
        with self.assertRaises(core.Refusal):
            core.human_report({'operation': unverified, 'plan': plan})
        other = {**plan, 'id': 'b' * 32}
        with self.assertRaises(core.Refusal):
            core.human_report({'operation': result, 'plan': other})
        self.assertIn('verified: 2', core.human_report({'operation': result, 'plan': plan})['markdown'])

    def test_metadata_tampering_cannot_change_the_approved_selection(self):
        plan = self.plan()
        edited = copy.deepcopy(plan)
        edited['entries'][0]['path'] = str(self.source)
        with self.assertRaises(core.Refusal):
            removal.execute({**self.request(edited), 'plan_digest': plan['digest']})
        self.assertTrue(self.source.exists())

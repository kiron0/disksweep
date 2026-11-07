"""Explicit permanent Windows removal, bound to a displayed digest and exact IDs."""
import contextlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import time

import _audit as audit
import _core as core
import _windows_file as windows


SOURCE_SUFFIXES = {'.py', '.js', '.jsx', '.ts', '.tsx', '.rs', '.go', '.c', '.h', '.cpp', '.cs', '.java',
                   '.kt', '.swift', '.php', '.rb', '.sh', '.ps1', '.bat', '.cmd', '.toml', '.yaml', '.yml', '.lock'}
SOURCE_NAMES = {'package.json', 'package-lock.json', 'composer.json', 'composer.lock', 'go.mod', 'go.sum',
                'cargo.lock', 'requirements.txt', 'dockerfile', 'makefile'}


def eligible(entry, roots, exclusions, personal=False):
    path, root = core.absolute(entry['path']), core.absolute(entry['root'])
    core.require(str(root) in roots and core.inside(path, root) and path != root, 'File escaped the reviewed scope')
    core.require(not core.protected(path, exclusions), 'Protected data cannot enter permanent removal')
    core.require(path.suffix.casefold() not in SOURCE_SUFFIXES and path.name.casefold() not in SOURCE_NAMES,
                 'Project source, manifests and scripts are protected')
    info = entry['identity']
    core.require(stat.S_ISREG(info['mode']) and info['links'] == 1, 'Select regular single-link files only')
    core.require(entry['id'] == core.digest({'path': str(path), 'identity': info})[:24], 'Invalid candidate identity')
    rule, kind, evidence = core.classify(path, root, info, core.read_rules(), exclusions)
    core.require(rule is not None or personal is True, 'Select a recognized finding, or explicitly select a personal file before planning it')
    if rule:
        core.require(rule['id'] == entry['rule_id'] and evidence == entry['evidence'], 'Rule or evidence changed')
    return path


def create_plan(request):
    core.require(os.name == 'nt', 'Direct selected-file removal currently requires Windows and local NTFS')
    policy = audit.policy(request.get('policy', {}))
    core.require(not policy.get('never_permanently_delete'), 'Policy forbids permanent removal')
    inventory = request['inventory']
    core.require(not inventory.get('protected_metadata_only'), 'Protected metadata cannot become a removal plan')
    selected = request['candidate_ids']
    core.require(selected and len(selected) <= 1000 and len(selected) == len(set(selected)), 'Select 1–1000 distinct files')
    index = {entry['id']: entry for entry in inventory['entries']}
    core.require(all(value in index for value in selected), 'Unknown file selection')
    exclusions = list(dict.fromkeys(inventory.get('exclude', []) + policy.get('exclude', [])))
    if policy.get('roots'):
        allowed = [core.absolute(root) for root in policy['roots']]
        core.require(all(any(core.inside(core.absolute(index[value]['path']), root) for root in allowed) for value in selected), 'Selection exceeds policy scope')
    entries = []
    skipped = []
    for value in selected:
        entry = dict(index[value])
        try:
            eligible(entry, inventory['roots'], exclusions, request.get('include_personal', False))
            core.require(not policy.get('preserve_offline') or 'cache' not in entry['category'], 'Offline-preservation policy protects cached downloads')
            with windows.OpenFile(entry) as opened:
                entry['windows_identity'] = opened.snapshot()
        except (OSError, core.Refusal):
            if not request.get('skip_unavailable'):
                raise
            skipped.append(value); continue
        entries.append(entry)
    core.require(entries, 'No eligible unlocked local NTFS files are available for removal')
    plan = {'schema_version': 1, 'id': secrets.token_hex(16), 'version': core.VERSION,
            'action': 'permanent-remove', 'created_at': core.now(), 'expires_at': time.time() + 900,
            'roots': inventory['roots'], 'exclude': exclusions, 'entries': entries,
            'include_personal': request.get('include_personal') is True,
            'skipped_ids': skipped,
            'rule_catalog_digest': core.digest(core.read_rules()),
            'logical_bytes': sum(entry['logical_bytes'] for entry in entries),
            'warning': 'PERMANENT DELETION: selected files bypass Recycle Bin and cannot be restored by Swipr. Submit approval only for the exact checked files.'}
    plan['digest'] = core.digest(plan)
    return plan


def _save(file, value):
    with os.fdopen(os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=True); stream.flush(); os.fsync(stream.fileno())


def _absent(path):
    try:
        Path(path).lstat()
        return False
    except FileNotFoundError:
        return True


def execute(request):
    core.require(request.get('user_approved') is True and request.get('acknowledge_irreversible') is True,
                 'Submit explicit approval of permanent deletion before executing')
    core.require(os.name == 'nt', 'Direct selected-file removal currently requires Windows and local NTFS')
    plan = request['plan']
    payload = {key: value for key, value in plan.items() if key != 'digest'}
    core.require(plan['action'] == 'permanent-remove' and request['plan_digest'] == plan['digest'] == core.digest(payload), 'Plan differs from the digest shown before approval')
    core.require(time.time() < plan['expires_at'] <= time.time() + 901, 'Removal plan expired or has invalid expiry; review a fresh plan')
    core.require(plan['rule_catalog_digest'] == core.digest(core.read_rules()), 'Rules changed; review a fresh plan')
    selected = request['candidate_ids']
    index = {entry['id']: entry for entry in plan['entries']}
    core.require(selected and len(selected) <= 1000 and len(selected) == len(set(selected)) and all(value in index for value in selected), 'Approve only exact distinct IDs in the reviewed plan')
    core.require(re.fullmatch(r'[a-f0-9]{32}', plan['id']), 'Invalid plan identifier')
    state = Path(os.path.abspath(os.path.expanduser(request['state_dir'])))
    parent = state
    while not parent.exists():
        parent = parent.parent
    core.absolute(parent); state.mkdir(mode=0o700, parents=True, exist_ok=True); core.absolute(state)
    if os.path.lexists(state / ('remove-used-' + plan['id'] + '.json')):
        raise FileExistsError('Removal plan already consumed; inspect records before another review')
    core.require(not any(core.inside(core.absolute(index[value]['path']), state) for value in selected), 'Removal cannot target its own operation records')
    journal_space = shutil.disk_usage(state).free
    core.require(journal_space > 65536 + len(core.canonical(plan)) * 3, 'Insufficient space to journal removal')
    volume_roots = sorted({Path(index[value]['path']).anchor for value in selected})
    before_space = {root: core.disk_metadata(root)['free'] for root in volume_roots}
    operation = {'id': secrets.token_hex(16), 'action': 'permanent-remove', 'plan_id': plan['id'], 'plan_digest': plan['digest'],
                 'created_at': core.now(), 'selected_ids': selected, 'plan': plan, 'irreversible': True}
    # One-use, flushed intent precedes any delete disposition. A crash never grants a retry.
    _save(state / ('remove-used-' + plan['id'] + '.json'), operation)
    items = []
    with contextlib.ExitStack() as stack:
        opened_files = []
        for value in selected:
            entry = index[value]
            eligible(entry, plan['roots'], plan['exclude'], plan['include_personal'])
            opened = stack.enter_context(windows.OpenFile(entry))
            core.require(opened.snapshot() == entry['windows_identity'], 'File changed since the removal plan')
            opened_files.append((entry, opened))
        for entry, opened in opened_files:
            item = {'candidate_id': entry['id'], 'status': 'failed-stop', 'verified_absent': False}
            try:
                core.require(time.time() < plan['expires_at'], 'Plan expired during removal')
                core.require(opened.snapshot() == entry['windows_identity'], 'File changed before removal')
                _save(state / ('remove-attempt-' + operation['id'] + '-' + entry['id'] + '.json'), {'operation_id': operation['id'], 'entry': entry})
                windows.mark_for_removal(opened)
                item['deletion_requested'] = True
                opened.close()
                core.require(_absent(entry['path']), 'Path remains or regenerated; do not retry removal')
                item.update(status='permanently-removed', verified_absent=True)
            except (OSError, core.Refusal):
                item['reason'] = 'Removal stopped; inspect records before any new approval'
            items.append(item)
            if item['status'] == 'failed-stop':
                break
    volume_space = []
    for root in volume_roots:
        before, after = before_space[root], core.disk_metadata(root)['free']
        volume_space.append({'root': root, 'before_free': before, 'after_free': after,
                             'observed_free_delta': after - before if before is not None and after is not None else None})
    measured = volume_space[0] if len(volume_space) == 1 else {'before_free': None, 'after_free': None, 'observed_free_delta': None}
    result = {**{key: value for key, value in operation.items() if key != 'plan'}, 'items': items,
              'before_free': measured['before_free'], 'after_free': measured['after_free'],
              'observed_free_delta': measured['observed_free_delta'], 'volume_space': volume_space,
              'all_verified': len(items) == len(selected) and all(item['verified_absent'] for item in items),
              'changes_made': any(item.get('deletion_requested') for item in items), 'verified_at': core.now(),
              'warning': 'Permanent removal has no Swipr undo. Free-space changes can include unrelated activity.'}
    _save(state / ('remove-result-' + operation['id'] + '.json'), result)
    return result


def verify(request):
    identifier = request['operation_id']
    core.require(re.fullmatch(r'[a-f0-9]{32}', identifier), 'Invalid operation identifier')
    state = core.absolute(request['state_dir'])
    result_file = core.absolute(state / ('remove-result-' + identifier + '.json'))
    core.require(result_file.stat().st_size <= 32 * 1024**2, 'Operation record is too large')
    result = json.loads(result_file.read_text(encoding='utf-8'))
    intent_file = core.absolute(state / ('remove-used-' + result['plan_id'] + '.json'))
    core.require(intent_file.stat().st_size <= 32 * 1024**2, 'Intent record is too large')
    intent = json.loads(intent_file.read_text(encoding='utf-8'))
    core.require(intent['id'] == identifier and intent['plan_digest'] == result['plan_digest'], 'Operation records disagree')
    plan_payload = {key: value for key, value in intent['plan'].items() if key != 'digest'}
    core.require(core.digest(plan_payload) == intent['plan']['digest'] == result['plan_digest'], 'Recorded plan digest changed')
    index = {entry['id']: entry for entry in intent['plan']['entries']}
    for item in result['items']:
        entry = index[item['candidate_id']]
        try:
            core.absolute(Path(entry['path']).parent)
            item['verified_absent'] = item['status'] == 'permanently-removed' and _absent(entry['path'])
        except (OSError, core.Refusal):
            item['verified_absent'] = False
    result['all_verified'] = len(result['items']) == len(intent['selected_ids']) and all(item['verified_absent'] for item in result['items'])
    result['verified_at'] = core.now()
    return result

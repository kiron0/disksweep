"""Explicit permanent removal on every supported OS, bound to a displayed digest and exact IDs."""
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

if os.name == 'nt':
    import _windows_file as files
else:
    import _posix_file as files


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
        core.require(rule['id'] != 'python-bytecode' or time.time_ns() - info['mtime_ns'] >= 86400 * 10**9,
                     'Bytecode is recent; leave it untouched')
    return path


def create_plan(request):
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
            with files.OpenFile(entry) as opened:
                entry['handle_identity'] = opened.snapshot()
        except (OSError, core.Refusal):
            if not request.get('skip_unavailable'):
                raise
            skipped.append(value); continue
        entries.append(entry)
    core.require(entries, 'No eligible unlocked local files are available for removal')
    plan = {'schema_version': 1, 'id': secrets.token_hex(16), 'version': core.VERSION,
            'action': 'permanent-remove', 'created_at': core.now(), 'expires_at': time.time() + 900,
            'roots': inventory['roots'], 'exclude': exclusions, 'entries': entries,
            'include_personal': request.get('include_personal') is True,
            'skipped_ids': skipped,
            'rule_catalog_digest': core.digest(core.read_rules()),
            'logical_bytes': sum(entry['logical_bytes'] for entry in entries),
            'warning': 'PERMANENT DELETION: selected files bypass Trash and Recycle Bin and cannot be restored by Swipr. Submit approval only for the exact checked files.'}
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
    core.require(not any(core.inside(state, Path(root)) or core.inside(Path(root), state) for root in plan['roots']),
                 'Removal records must be outside the scanned roots')
    parent = state
    while not parent.exists():
        parent = parent.parent
    core.absolute(parent); state.mkdir(mode=0o700, parents=True, exist_ok=True); core.absolute(state)
    if os.name == 'posix':
        owner = state.stat()
        core.require(owner.st_uid == os.getuid() and not owner.st_mode & 0o077, 'Removal records directory must be owned by this user with mode 0700')
    if os.path.lexists(state / ('remove-used-' + plan['id'] + '.json')):
        raise FileExistsError('Removal plan already consumed; inspect records before another review')
    core.require(not any(core.inside(core.absolute(index[value]['path']), state) for value in selected), 'Removal cannot target its own operation records')
    journal_space = shutil.disk_usage(state).free
    core.require(journal_space > 65536 + len(core.canonical(plan)) * 3, 'Insufficient space to journal removal')
    volumes = {}
    for value in selected:
        volumes.setdefault(index[value]['identity']['device'], str(Path(index[value]['path']).parent))
    volume_roots = sorted(volumes.values())
    before_space = {root: core.disk_metadata(root)['free'] for root in volume_roots}
    operation = {'id': secrets.token_hex(16), 'action': 'permanent-remove', 'plan_id': plan['id'], 'plan_digest': plan['digest'],
                 'created_at': core.now(), 'selected_ids': selected, 'plan': plan, 'irreversible': True}
    # One-use, flushed intent precedes any delete disposition. A crash never grants a retry.
    _save(state / ('remove-used-' + plan['id'] + '.json'), operation)
    items = []
    for value in selected:
        entry = index[value]
        eligible(entry, plan['roots'], plan['exclude'], plan['include_personal'])
        with files.OpenFile(entry) as opened:
            core.require(opened.snapshot() == entry['handle_identity'], 'File changed since the removal plan')
    for value in selected:
        entry = index[value]
        item = {'candidate_id': entry['id'], 'status': 'failed-stop', 'verified_absent': False}
        try:
            core.require(time.time() < plan['expires_at'], 'Plan expired during removal')
            with files.OpenFile(entry) as opened:
                core.require(opened.snapshot() == entry['handle_identity'], 'File changed before removal')
                _save(state / ('remove-attempt-' + operation['id'] + '-' + entry['id'] + '.json'), {'operation_id': operation['id'], 'entry': entry})
                files.mark_for_removal(opened)
                item['deletion_requested'] = True
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


def operations(request):
    state = core.absolute(request['state_dir'])
    results, intents = {}, {}
    with os.scandir(state) as items:
        for index, item in enumerate(items):
            if index >= 2000:
                break
            match = re.fullmatch(r'remove-(result|used)-([a-f0-9]{32})\.json', item.name)
            if not match or not item.is_file(follow_symlinks=False) or item.stat(follow_symlinks=False).st_size > 32 * 1024**2:
                continue
            value = json.loads(core.absolute(state / item.name).read_text(encoding='utf-8'))
            (results if match[1] == 'result' else intents)[value['id']] = value
    records = []
    for identifier, intent in sorted(intents.items(), key=lambda pair: pair[1]['created_at'], reverse=True)[:100]:
        result = results.get(identifier)
        status = ('interrupted-or-pending' if result is None else 'complete' if result['all_verified'] else 'partial')
        records.append({'id': identifier, 'record': 'remove', 'status': status, 'plan_id': intent['plan_id']})
    return {'operations': records, 'changes_made': False, 'limit': 100}

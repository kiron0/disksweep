"""One-pass current-user overview; no content reads, approvals, or cleanup."""
from collections import defaultdict
import os
from pathlib import Path

import _audit as audit
import _core as core
import _guide as guide
import _remove as removal


def default_roots():
    home = Path.home()
    core.require(not str(home).startswith(('\\\\', '//')), "Choose a local folder; the default profile is on a network path")
    home = core.absolute(home)
    core.require(home != Path(home.anchor) and not core.protected(home), "Choose a local user folder; the default profile is protected or is a drive root")
    if os.name == 'nt':
        import ctypes
        drive_type = ctypes.windll.kernel32.GetDriveTypeW
        drive_type.argtypes = [ctypes.c_wchar_p]
        drive_type.restype = ctypes.c_uint
        core.require(drive_type(str(home.anchor)) == 3,
                     "Choose a local fixed-drive folder; the default profile is on a non-fixed drive")
    return [str(home)]


def possible_duplicates(entries):
    groups = defaultdict(list)
    for entry in entries:
        if entry['unique_inode'] and entry['logical_bytes'] > 0:
            groups[entry['logical_bytes']].append(entry['id'])
    return [{'logical_bytes_each': size, 'candidate_ids': ids[:100], 'file_count': len(ids),
             'content_verified': False, 'automatic_removal': False}
            for size, ids in sorted(groups.items(), reverse=True) if len(ids) > 1][:100]


def review_prompt(result):
    if not result['inventory']['entries'] and result['inventory']['complete']:
        return {'title': 'No recorded files to review.', 'options': [], 'requires_response': False,
                'authorizes_cleanup': False, 'presentation': 'Summarize the scope and finish without a question.'}
    windows = result['discovery']['platform'] == 'windows'
    options = []
    if windows and result.get('removal_plan'):
        options.append({'id': 'remove_selected', 'label': 'Permanently delete selected files',
                        'description': 'Irreversible: bypass Recycle Bin. Execute only the exact checked IDs and the digest displayed in this plan.'})
    elif not windows and result['discovery']['capabilities']['quarantine'] and result['guidance']['recorded_bytecode_candidates']:
        options.append({'id': 'review_bytecode', 'label': 'Review bytecode cleanup',
                        'description': 'Prepare an exact quarantine plan before requesting approval; quarantine frees no space.'})
    elif not windows:
        options.append({'id': 'native_cleanup', 'label': 'Review Windows cleanup' if windows else 'Review native cleanup',
                        'description': 'Review application or OS storage controls; this choice does not authorize file deletion.'})
    options.extend([
        {'id': 'review_files', 'label': 'Review large files', 'description': 'Inspect the largest recorded files and folders without removing them.'},
        {'id': 'finish', 'label': 'Finish without changes', 'description': 'Keep the findings and stop.'},
    ])
    return {'title': 'What would you like to do with these findings?', 'options': options,
            'requires_response': True, 'authorizes_cleanup': False,
            'presentation': 'Use the host question UI when available; otherwise ask one concise choice question. Never require a magic reply phrase.'}


def run(request, output=None):
    request = {'max_entries': 100000, 'max_depth': 32, 'max_seconds': 60, **request}
    inferred = not request.get('roots') and not request.get('policy', {}).get('roots') and not request.get('profile_id')
    if inferred:
        request['roots'] = default_roots()
    scope, _ = audit.resolve_scope(request)
    # Discovery and audit use the same scope. Do not query Docker or other native contexts.
    discovery = core.probe({'path': scope['roots'][0]})
    result = audit.audit({**request, 'mode': 'full'})
    result['proposal_candidate_count'] = len(result['proposal']['candidates'])
    result['proposal']['candidates'] = result['proposal']['candidates'][:100]
    result['proposal_truncated'] = result['proposal_candidate_count'] > 100
    result['discovery'] = discovery
    result['scope'] = {'selection': 'current-user-profile' if inferred else 'explicit-or-policy',
                       'roots': result['inventory']['roots'],
                       'boundary': 'Only the selected scope is inspected; other profiles, additional drives, cloud folders, backups, links and protected trees are not automatically included.'}
    result['analysis']['possible_duplicates'] = possible_duplicates(result['inventory']['entries'])
    result['guidance'] = guide.next_steps(result['inventory'], output)
    if discovery['platform'] == 'windows':
        selected = [entry['candidate_id'] for entry in result['proposal']['candidates'] if entry['classification'] != 'PROTECTED'][:request.get('top', 20)]
        if selected:
            try:
                result['removal_plan'] = removal.create_plan({'inventory': result['inventory'], 'candidate_ids': selected,
                                                           'policy': request.get('policy', {}), 'skip_unavailable': True})
            except (OSError, core.Refusal):
                result['removal_plan'] = None
                result['removal_limit'] = 'No eligible unlocked local NTFS files are available under the selected policy; review findings without removal.'
    result['review_prompt'] = review_prompt(result)
    return result


def render(result, saved=False):
    inventory = result['inventory']
    lines = ['Swipr — full user scan',
             'Scope: ' + ('current user profile' if result['scope']['selection'] == 'current-user-profile' else 'selected folders or policy'),
             'Coverage: ' + ('complete within the reported scope and exclusions' if inventory['complete'] else 'partial; review scan limits and inaccessible locations'),
             'Files recorded: ' + str(len(inventory['entries'])),
             'Possible duplicate size groups: ' + str(len(result['analysis']['possible_duplicates'])) + ' (contents not checked)',
             'Findings: large files, directory totals, cache rules and storage health analyzed in one pass.',
             result['scope']['boundary'], '', core.human_report({'inventory': inventory, 'include_next': False})['markdown']]
    if result['discovery']['platform'] == 'windows':
        lines.append('Windows direct removal requires the exact displayed plan and fresh irreversible approval. Recycle Bin is bypassed; Swipr cannot undo removal.')
        if result.get('removal_plan'):
            lines.append('Prepared permanent-removal plan: ' + result['removal_plan']['id'] + '; digest: ' + result['removal_plan']['digest'])
    if saved:
        lines.append('Full JSON saved privately for review; no files were approved for cleanup.')
    lines.extend(['', result['review_prompt']['title'],
                  *[option['label'] + ': ' + option['description'] for option in result['review_prompt']['options']]])
    return '\n'.join(lines)



# Swipr commands

## Start here

In **Codex chat**, type:

```text
$swipr start
$swipr scan quick --root ~/Downloads
```

In **Claude Code**, use `/swipr` in place of `$swipr`. In other agents, say
`Use Swipr: scan quick --root ~/Downloads`. These are agent instructions;
the invocation prefix depends on your host. An agent must obtain your approval
before using cleanup or content-reading confirmation flags. A clear choice in a
review prompt counts as approval of the action described there; no typed magic
phrase is required. Discovery and metadata analysis run together before that prompt.

For exact terminal commands, run the adapter from a cloned repository:

```sh
python scripts/swipr.py --help
python scripts/swipr.py doctor
python scripts/swipr.py scan quick --root "/path/to/folder" --output audit.json
```

For a project installed with the Skills CLI, the path is normally
`.agents/skills/swipr/scripts/swipr.py`. Global Codex installations commonly use
`~/.agents/skills/swipr/scripts/swipr.py`. Use your installation's actual path.
There is no separate `swipr` executable or npm package to install.

## Command map

| Command | Subcommands | Purpose |
|---|---|---|
| `help` | Any command path | Show help without scanning |
| `start` | `--goal full/quick/developer/emergency/health/large/duplicates`, `--guide` | One-pass scan and review choices; `--guide` only explains |
| `doctor` | — | Check capabilities, disk space and tools |
| `scan` | `full`, `quick`, `deep`, `developer`, `emergency`, `targeted`, `health`, `safe-cleanup`, `custom` | Scoped read-only audit |
| `find` | `large`, `directories`, `duplicates` | Discover storage consumers |
| `explain` | `--input AUDIT_JSON --candidate FULL_ID` | Explain saved findings without rescanning |
| `inspect` | `apps`, `storage`, `docker`, `activity`, `leftovers`, `trash`, `recycle-bin` | Inspect native and protected metadata |
| `plan` | `remove` | Prepare an exact permanent-removal plan |
| `clean` | `remove` | Run the exact approved removal |
| `verify` | `--kind remove` | Verify a removal operation |
| `report` | `audit`, `operation` | Produce Markdown reports |
| `history` | `save`, `show`, `compare`, `operations` | Private snapshots and operation records |
| `profile` | `validate`, `save`, `show` | Restrictive preferences |
| `catalog` | `list` | Browse versioned detection rules |

The terminal examples below omit no installation step: run them from the repository,
or replace `scripts/swipr.py` with your installed helper path. Replace uppercase IDs
and `/path/...` placeholders with actual results and authorized locations.

## Default scan and review

```sh
python scripts/swipr.py start
python scripts/swipr.py start --root "/path/to/project" --output audit.json
python scripts/swipr.py scan full --output audit.json
python scripts/swipr.py start --guide --goal duplicates
```

`start` and `scan full` combine capability discovery, a metadata inventory, file
and directory ranking, cache findings, health and possible duplicate size groups.
They default to the current local user profile, with 100000 entries, depth 32 and
60 seconds as limits. This is a full pass of the selected scope, not every drive
or a guarantee of complete coverage. Links, protected trees and nested mounts
are skipped. Network or redirected default profiles require explicit local scope.

Use `--root` or a restrictive policy/profile to override the default. The same
scan controls below apply. `--goal` records the user's focus; all non-guide goals
reuse the full overview, and `duplicates` never silently hashes content.
`--guide` only suggests arguments and steps, without scanning or writing state.

Full results include `review_prompt` with three navigation choices for a host
question UI. Selecting navigation never authorizes deletion. The agent prepares
any supported exact plan before its actual approval prompt, then executes and
verifies without asking again for every internal step. The terminal adapter
prints choices; it does not create interactive agent widgets by itself.

Every OS offers direct permanent removal when an eligible plan is available,
large-file review, or finishing. The host displays the exact plan and permanent
warning before accepting checked file IDs or a batch choice. Submit approval once;
execution and verification follow without another confirmation or opening Settings.
No destructive choice should be preselected. If no eligible plan exists, offer
review/finish without inventing a removal action.

## Direct permanent removal (every OS)

The full audit contains `removal_plan` for eligible unlocked recognized findings.
Alternatively prepare a specific selection:

```sh
python scripts/swipr.py plan remove --input audit.json --candidate FULL_ID --output remove-plan.json
```

Use `--include-personal` only for files explicitly selected by the human; it never
permits protected data or recognized project source. `--policy FILE` applies
restrictions, including no permanent deletion and offline-cache preservation.

After the exact selected files, effects, digest and expiry are displayed, and the
user submits an explicit **permanent deletion, cannot undo** choice:

```sh
python scripts/swipr.py clean remove --input audit.json --digest DISPLAYED_DIGEST --candidate FIRST_CHECKED_ID --candidate SECOND_CHECKED_ID --confirm-permanent --state-dir "/path/to/private-records" --output removed.json
python scripts/swipr.py verify --kind remove --state-dir "/path/to/private-records" --operation-id OPERATION_ID
```

`--input` accepts the full audit containing `removal_plan`, or a standalone plan.
Only supplied checked IDs are removed. A plan can be consumed once and expires in
15 minutes. Use the digest shown before approval, never a newly reread/edited digest.
Current-user ownership, regular single-link local files and native handles are
required: POSIX directory handles on macOS and Linux, exclusive handles on local
fixed-drive NTFS on Windows. No wildcards, directories, recursion, force, Trash,
Recycle Bin or undo. Locked, changed, protected or unsupported files stop execution.
The records directory must be outside the scanned roots and, on POSIX, owner-only.
Private intent/attempt records precede deletion. Python bytecode must be at least
24 hours old. See the platform references for trust boundaries.

## Help and capability discovery

```sh
python scripts/swipr.py help
python scripts/swipr.py help scan deep
python scripts/swipr.py help clean remove
python scripts/swipr.py --version
python scripts/swipr.py doctor --path "/path/to/volume"
python scripts/swipr.py doctor --json --output capabilities.json
```

## Scan folders

```sh
python scripts/swipr.py scan quick --root "/path/to/folder" --output audit.json
python scripts/swipr.py scan developer --root "/path/to/project" --output developer.json
python scripts/swipr.py scan deep --root "/path/to/folder" --max-depth 20 --max-entries 50000 --max-seconds 30 --output deep.json
python scripts/swipr.py scan health --root "/path/to/folder"
python scripts/swipr.py scan emergency --root "/path/to/cache"
python scripts/swipr.py scan targeted --root "/path/to/cache" --exclude "/path/to/cache/keep"
```

`safe-cleanup` prepares recommendations; it never silently executes them.
`emergency` never weakens protection. Separate mount roots need separate authorization.
All engines use bounded inspection and resolved roots. Only `start` and `scan full`
infer the current user profile; other modes still require roots or a scope policy.

Saved scan results include `guidance`: coverage status, a count and up to five
IDs of recorded bytecode findings, and `explain` argument arrays when `--output`
was supplied. These hints do not validate current eligibility or authorize a plan.
Partial coverage and protected-only results receive appropriate next steps.

## Explain a saved finding

```sh
python scripts/swipr.py explain --input audit.json --candidate FULL_ID
python scripts/swipr.py explain --input audit.json --candidate FIRST_FULL_ID --candidate SECOND_FULL_ID --private
```

Copy full 24-character IDs from the saved audit's `inventory.entries` or
`guidance.sample_candidate_ids`. Prefixes, unknown IDs and duplicate selections
are refused. Select at most 100 findings per explanation.

The result includes classification, risk, logical/allocated bytes, rule version,
reason, recorded evidence fields, side effects, recovery and a planning hint.
Paths and evidence values are omitted unless `--private` is used. Keep private
output local; use `report audit` for a shareable report. Explanation reads only
the saved JSON: changed or missing live files are not rechecked, active use and
current eligibility remain unknown, and no plan or approval is created.

## Scan and find options

Shared scan/find options:

| Option | Meaning |
|---|---|
| `--root PATH` | Override the full scan default; other modes require roots or a scope policy; repeat for separate roots |
| `--exclude PATH` | Repeat to exclude folders |
| `--max-entries N` | Full default 100000; other scans 20000; range 1–100000 |
| `--max-depth N` | Full default 32; other scans 12; range 0–64 |
| `--max-seconds N` | Full default 60; other scans 10; range 0.01–120 |
| `--top N` | Default 20; range 1–100 |
| `--sort ORDER` | `size`, `oldest`, `location`, `type`, `application`, `recoverability` |
| `--policy FILE` | Restrictive policy JSON |
| `--profile-id ID --state-dir PATH` | Saved policy; use instead of `--policy` |
| `--json` | Machine-readable result on stdout |
| `--output FILE` | Save a new private JSON result; never overwrite |

## Find large files, directories and duplicates

```sh
python scripts/swipr.py find large --root "/path/to/Downloads" --min-bytes 104857600 --top 20
python scripts/swipr.py find large --root "/path/to/Downloads" --older-than-days 30 --extension .zip --extension .dmg --sort oldest
python scripts/swipr.py find directories --root "/path/to/project" --top 10
python scripts/swipr.py find duplicates --root "/path/to/Downloads" --allow-content-read --max-hash-bytes 268435456 --output duplicates.json
```

`find large` filters the full bounded inventory before ranking. Its age/size/type
filters are discovery tools, not deletion criteria. Terminal matches include local
paths; use a redacted report for sharing. Duplicate hashing reads content only after
approval, is bounded, and is unavailable on Windows in the current backend.
Duplicate groups are never automatically removed.

## Native and protected inspection

```sh
python scripts/swipr.py inspect apps --allow-native --output apps.json
python scripts/swipr.py inspect storage --allow-native --output storage.json
python scripts/swipr.py inspect docker --allow-native --output docker.json
python scripts/swipr.py inspect leftovers --input audit.json --applications apps.json
python scripts/swipr.py inspect activity --input audit.json --candidate CANDIDATE_ID --allow-native
python scripts/swipr.py inspect trash --root "/path/to/Trash/files" --confirm-scope
```

On Windows, pass a drive root to the native current-user Recycle Bin query:

```powershell
python scripts/swipr.py inspect recycle-bin --volume 'C:\' --confirm-scope
```

Native consent is separate from cleanup approval. Docker uses your configured
context, which may be remote. No native inspection command mutates storage,
force-closes an app, empties Trash, prunes Docker, or requests administrator access.
Unknown active use and possible leftovers remain uncertain.

## Reports

```sh
python scripts/swipr.py report audit --input audit.json --output report.md
python scripts/swipr.py report audit --input audit.json --private --output private-report.md
python scripts/swipr.py report operation --input verified.json --plan remove-plan.json --output cleanup-report.md
```

Audit reports are redacted by default. Verified operation reports use opaque IDs.
`--private` includes local paths; keep that report private. Report output is Markdown;
add `--json` to save a JSON envelope instead. Existing output files are never overwritten.
An output file is reserved before changes, so an existing file cannot cause a plan
to be consumed or an operation to run without saving its result.

## Profiles and history

Create a policy JSON containing only restrictions:

```json
{
  "roots": ["/path/to/project"],
  "exclude": ["/path/to/project/private"],
  "max_entries": 10000,
  "max_seconds": 10,
  "preserve_offline": true,
  "never_permanently_delete": true
}
```

```sh
python scripts/swipr.py profile validate --input policy.json
python scripts/swipr.py profile save --input policy.json --state-dir "/path/to/private-state" --confirm
python scripts/swipr.py profile show --profile-id PROFILE_ID --state-dir "/path/to/private-state"
python scripts/swipr.py scan custom --root "/path/to/project" --profile-id PROFILE_ID --state-dir "/path/to/private-state"
python scripts/swipr.py scan custom --profile-id PROFILE_ID --state-dir "/path/to/private-state"
python scripts/swipr.py history save --input audit.json --state-dir "/path/to/private-state" --confirm
python scripts/swipr.py history show --snapshot-id SNAPSHOT_ID --state-dir "/path/to/private-state"
python scripts/swipr.py history compare --before before.json --after after.json
python scripts/swipr.py history operations --state-dir "/path/to/private-state"
```

Policies cannot grant auto-approval or widen saved scope/budgets. Private saved state
requires POSIX; Windows can use session policy files. Comparisons require identical
scope and exclusions. Operation records support inspection, not automatic resumption.

## Rule catalog

```sh
python scripts/swipr.py catalog list
python scripts/swipr.py catalog list --platform linux
python scripts/swipr.py catalog list --category package-cache --json
```

## Windows access diagnostics

`doctor --json` reports the active runtime version and installation directory.
A project-local installation and an older global installation can coexist; use
helpers from the directory selected for this invocation. Updating one scope does
not implicitly update the other.

Unavailable volume queries return null space values and `permission-denied` or
`unavailable` status. Readable file inventories, rankings, health and comparisons
continue; unknown space is never zero. File traversal completeness is separate
from availability of volume measurements. Windows operation space figures refer
to each target volume, not the journal drive; multi-volume totals remain unknown.

Permission errors identify output creation, command execution or result saving,
with a sanitized Windows error number when available. Do not assume a relative
path is the cause. Request only necessary scoped host/sandbox access if traversal
is blocked. The skill cannot bypass host restrictions. Deletion still requires a
successful journal-space check and all existing approval and identity gates.
A denied optional measurement after deletion cannot discard its verified result.

## Results and errors

Terminal JSON input is bounded at 256 MiB to support full inventories. Internal
single-request JSON helpers retain their 32 MiB limit. Full overviews retain the
complete bounded inventory but limit proposal rows to 100; `proposal_truncated`
and `proposal_candidate_count` disclose that limit. Possible duplicate groups are
limited to 100 groups and 100 displayed IDs per group; `file_count` gives each
group's recorded total. No content match or physical savings is implied.

Successful JSON: `{"ok":true,"result":{...}}`. Refused/failed execution returns
`{"ok":false,"error":{"code":"...","message":"..."}}` with exit code 2.
Argument errors also exit 2 and show command help. `--help` and `--version` do not scan.
Input is bounded JSON; redirects and nonregular inputs are refused. Saved files use
owner-only permissions where supported. An error never authorizes an automatic retry.

[Advanced recipes](docs/advanced.md) · [Platform support](docs/implementation-status.md) ·
[Internal JSON protocol](references/helper-protocol.md)

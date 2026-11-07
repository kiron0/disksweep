# Advanced recipes

Run these with your agent's Swipr invocation or the documented Python adapter.
See [COMMANDS.md](../COMMANDS.md) for all flags and approval requirements.

## Choose a workflow and review evidence

```sh
python scripts/swipr.py start --goal developer --root "/path/to/project" --output audit.json
python scripts/swipr.py explain --input audit.json --candidate FULL_ID
```

The first command discovers capabilities and audits the project in one pass.
Use `start --guide` to suggest steps without scanning. Copy the actual full ID from the saved
audit; review reason, recorded evidence, effects and recovery. Use `--private`
only for local inspection of recorded paths and source/project metadata.
If the file has changed, explanation still describes the snapshot. A new plan
must revalidate the live file; approval is a separate step. If guidance reports
partial coverage or only protected findings, address those limits before proposing
cleanup. Quarantine alone recovers no space.

## Audit several volumes

```sh
python scripts/swipr.py scan deep --root "/volume-one/project" --root "/volume-two/cache" --exclude "/volume-one/project/offline" --max-entries 50000 --max-seconds 30 --output multi-volume.json
```

Each selected root is separately authorized. Nested mounts are skipped; a quarantine
plan may use only one filesystem and private state on that same filesystem.

## Review archived downloads

```sh
python scripts/swipr.py find large --root "/path/to/Downloads" --min-bytes 524288000 --older-than-days 90 --extension .zip --extension .iso --sort oldest --output archives.json
```

These are protected user files to review, not automatic deletion candidates.

## Preserve offline work

Save a policy with `preserve_offline:true`, exclusions for critical projects, and
`never_permanently_delete:true`. Apply it using `--policy policy.json` or save a
profile with consent. Package stores, dependencies and toolchains stay excluded from
automated cleanup. Use separate reviewed native controls for other categories.

## Track storage growth

```sh
python scripts/swipr.py scan developer --root "/path/to/project" --output before.json
# Later, after normal work:
python scripts/swipr.py scan developer --root "/path/to/project" --output after.json
python scripts/swipr.py history compare --before before.json --after after.json --output growth.json
```

Compare identical scopes. Logical growth, regenerated caches and observed free-space
changes are evidence to investigate, not proof of a process or performance problem.

## Bound duplicate reading

```sh
python scripts/swipr.py find duplicates --root "/path/to/media" --allow-content-read --max-hash-bytes 1073741824 --output duplicates.json
```

Review skipped hashes and budget exhaustion. Hard links are not counted as independent
copies. Shared blocks and snapshots make physical savings uncertain. Keep every copy
until the user makes a separate decision; no duplicate-delete command exists.

## Review application leftovers

```sh
python scripts/swipr.py inspect apps --allow-native --output apps.json
python scripts/swipr.py scan targeted --root "/path/to/known-cache" --output cache-audit.json
python scripts/swipr.py inspect leftovers --input cache-audit.json --applications apps.json --output leftovers.json
```

Native inventories can omit portable or manually installed tools. Possible leftovers
remain REVIEW; a missing executable is not enough evidence to delete application data.

## Export a shareable report

```sh
python scripts/swipr.py report audit --input cache-audit.json --output shareable.md
```

Use the redacted Markdown, not raw inventories, private reports, approval notes or journals,
when sharing. Saving and external sharing need the user's consent.

## Inspect an interrupted operation

```sh
python scripts/swipr.py history operations --state-dir "/path/to/private-state" --json
```

Inspect intent, item and result records plus the actual original/quarantine locations.
A move or unlink can complete before its outcome record is saved. Reconcile what
happened before any new action; obtain fresh approval for a changed or expired scope.

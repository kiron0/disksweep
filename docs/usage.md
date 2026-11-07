# Using Swipr

## Installation

Install with the Skills CLI:

```sh
npx skills add kiron0/swipr --skill swipr
```

Alternatively, clone this repository into your agent's skill directory as
`swipr/`. Common locations are `~/.agents/skills/swipr/` for Codex and
`~/.claude/skills/swipr/` for Claude Code. Follow your agent's installation
instructions if it uses a different location.

You need Python 3.10+ and permission for the agent to inspect local files.
Swipr's helpers run locally without accounts, telemetry, or runtime packages.
The hosting agent and installer have their own privacy settings.

## Start with an audit

> Use Swipr to audit my storage. Start with known caches and show a report without changing files.

Your agent proposes folders to inspect. Choose the scope and name anything to
exclude, such as cloud folders, backups, work projects, or offline dependencies.
Scans are bounded; the report identifies skipped or inaccessible locations.

The report explains file sizes, known cache associations, risks, side effects,
and possible next steps. Candidate sizes are estimates, not guaranteed savings.

## Common requests

**Large files**

> Show the largest files in Downloads. Keep everything in place.

**Exact duplicates**

> Check Downloads for exact duplicates. Ask me before reading file contents, and keep all copies.

Duplicate checks need separate content-reading approval. Safe hashing is available
on macOS and Linux; Windows currently supports metadata audits only.

**Developer storage**

> Review Python, Node.js, Rust, and Xcode caches. Preserve sources, dependencies, configurations, and anything I need offline.

**Browser storage**

> Inspect browser resource caches. Preserve passwords, sessions, bookmarks, and offline website data.

Browser findings lead to the browser's own cache controls. Swipr does not
delete browser profiles or automate browser cleanup.

**Docker storage**

> Review storage in my local Docker context. Keep every volume and database.

Your agent confirms the Docker context before optional read-only queries.
Swipr does not prune Docker resources.

## Approve a supported move

On macOS and Linux, eligible stale Python bytecode can be moved to a private
quarantine. Your source files remain in place. The agent shows each exact file,
its size, expected effects, recovery option, and the plan's expiration.

Approve only after reviewing that plan and stopping the generating Python workload:

> I approve the displayed quarantine plan. My Python workload is stopped.

Plans expire after 15 minutes. Approval receipts last at most five minutes and
can be used once. Changed files require a new plan and approval.

**Quarantine retains files and frees no disk space.** To recover its allocation,
ask the agent to prepare a separate permanent-removal plan for exact quarantined
bytecode IDs. Review it and explicitly acknowledge that removal cannot be undone.
The earlier quarantine approval cannot authorize permanent removal. Files that
changed, gained hard links, or were restored are rejected.

Trash emptying and browser, package, Docker, or OS maintenance use native user-guided
controls with their own scope review. They are not covered by bytecode approval.

## Verify or restore

> Verify the approved operation and show what changed.

The agent checks each result and reports successful, failed, and unattempted
items, plus observed free-space changes. Unrelated system activity can affect
those measurements.

> Restore the bytecode from the completed quarantine operation.

Restoration requires your approval, skips existing originals, and retains a
quarantine hard link. Both names then refer to the same underlying file. If an
operation was interrupted, ask the agent to inspect its journal before any retry.

## Save or share a report

> Save a redacted storage report without filenames, usernames, or local paths.

Reports are redacted by default. Saving a report requires your consent;
unredacted inventories and operation journals should stay private.

See [platform support](implementation-status.md) for capability details and
[recovery](../references/recovery.md) for interrupted-operation handling.

## More workflows

> Run a deep audit with directory-size distribution and native storage information. Ask before expanding scope.

> Check for possible application leftovers using the installed-app inventory. Preserve settings and support data.

> Inspect my Trash usage and retention options without emptying it.

> Compare this audit with the previous snapshot and show storage growth or regenerated caches.

> Use a custom policy: scan only this project, exclude cloud folders, preserve offline caches, and never permanently delete files.

All ten modes and their implementations are listed in [feature coverage](feature-coverage.md).
Saving a policy or inventory snapshot needs consent; stored preferences never approve
future file changes. Protected backups and application state can be inspected in an
explicit metadata-only scope, and remain ineligible for cleanup.

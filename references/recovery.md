# Recovery and interrupted operations

Permanent removal is the only file-changing action, on every OS. It bypasses Trash
and Recycle Bin and keeps no copy, so Swipr cannot undo it. Recover regenerated data
from its source: Python recompiles bytecode, package managers refetch caches, and
build tools rebuild outputs where their inputs and tooling remain available.
Snapshots, shared blocks and open handles can limit the observed free-space change.

Before removing anything, `execute.py` writes `remove-used-<plan-id>.json` in the
private records directory. It holds the full plan and the selected IDs, and its
exclusive creation consumes the plan, so a crash can never silently replay the same
approval. Each attempted file gets `remove-attempt-<operation-id>-<id>.json` before
its removal is requested. A completed invocation writes `remove-result-<operation-id>.json`.

After interruption, run `history operations` with the same records directory. An
operation without a result record is `interrupted-or-pending`. Compare its attempt
records with the actual file names: a removal can finish before its result is written.
Do not assume a missing result means no action occurred. Do not edit records or
blindly rerun. Rescan, prepare a fresh plan and obtain fresh approval for any new action.
Automatic interrupted-operation resumption is not provided.

A malicious concurrent process or a modified records directory is beyond the trust
boundary. Never promise undo for removed files, native browser clears, cache purges,
Trash emptying, or irreversible OS maintenance.

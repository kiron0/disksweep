# Recovery and interrupted operations

Quarantine is a same-filesystem rename, not Trash and not a backup. It retains all
allocated data, so its expected immediate reclamation is zero. The store must be
outside every scan root, on the candidate's filesystem, and private to the user.
No space-consuming copy fallback or automatic retention expiration exists. Retain
quarantine until the user resolves it; permanent purge is unsupported in this release.

Before moving anything, `execute.py` writes signed `operation-<id>.json` containing
intent and every pending member. Each attempted item gets a signed `item-<id>.json`.
A completed invocation writes `result-<operation-id>.json`. Receipt consumption occurs
before actions, so a crash cannot silently replay the same approval.

After interruption, inspect the operation intent, item journals, exact source names,
and `quarantine-<operation-id>/`. A move can finish before its item journal is written.
Do not assume missing journal rows mean no action occurred. Do not edit signatures,
blindly rerun, or delete either copy. Reconcile identity metadata and obtain fresh
approval for any new actions. Automatic interrupted-operation resumption is not provided.

For a completed result, `restore.py` requires user approval and verifies saved quarantine
identities. It uses a hard link to restore each original name without replacing anything.
The quarantine link is retained, so restoration does not allocate a second copy and
later writes through either link affect the same inode. Restoration is limited to
disposable bytecode; it is not a general document recovery tool. If the original file
has already been regenerated or a parent changed, restoration skips it. Inspect failures.

Quarantine objects are not read-only snapshots. A malicious concurrent process or a
modified state store is beyond the trust boundary. Never promise undo for native
browser clears, cache purges, Trash emptying, or irreversible OS maintenance.

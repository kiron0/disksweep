# Safety policy

Unknown data stays protected. Eligibility, user authorization, and execution capability
are three separate gates. No confidence score overrides any gate.

## Scope and traversal

- Require resolved engine roots; reject duplicates, overlaps, protected roots, and
  linked roots. The default `start`/`scan full` workflow resolves and announces the
  current local user profile without a separate metadata-scan question. Explicit
  roots and restrictions take priority; other drives/profiles require separate scope.
- Do not traverse symlinks, junctions, reparse points, or nested mounts. POSIX scans pin
  directory handles. Windows metadata traversal is best effort. Selected-file removal uses
  the same approved protocol on every OS with native handles; content hashing remains
  disabled on Windows. Same-device bind mounts are separately checked on Linux.
- Prune credentials, repositories' VCS metadata, dependencies, virtual environments,
  backup folders, and recognized cloud directory names. Custom cloud roots, unusual
  backup names, and network mounts require user-supplied exclusions; autodetection is incomplete.
- Inspect metadata without opening contents. Only user-approved duplicate hashing reads
  contents. No scan runs scripts from a project.
- Limits must produce a partial result, never an assertion that a drive is clean.

## Cleanup eligibility

A file can enter an exact removal plan only when a versioned catalog rule recognizes it
or the human explicitly selects it with `include_personal`. `python-bytecode` is the one
`SAFE-CANDIDATE` rule: a CPython-tagged `.pyc` under `__pycache__`, a corresponding
regular `.py` source, and an ancestor `pyproject.toml`, `setup.py`, or `setup.cfg` within
scope. These markers are never executed or parsed. Bytecode must be at least 24 hours old.
Cache-signature rules are `REVIEW` findings: they may enter a plan for explicit approval,
but location and age are not proof that every contained file is disposable.

Every planned file must be a regular, single-link file owned by the current user, outside
protected scopes, and not source, a manifest, a lockfile or a script. A missing
application is not proof of orphaned data. Temp files, Trash, downloads, sources,
backups, and unknown files cannot be promoted into removal by editing an inventory:
classification and identity are recomputed when the plan is built and again at execution.

## Authorization

Plans expire in 15 minutes and bind exact objects, handle identities, rule evidence,
exclusions, the rule catalog, and a digest. The agent displays this proposal and
obtains one fresh, affirmative, explicitly irreversible user approval of that exact plan.
A general “clean my computer” request is not that approval. Preferences only restrict scope.

`user_approved` and `acknowledge_irreversible` are agent assertions, not cryptographic
proof of human intent. A hosting agent must enforce the conversation boundary. The digest
detects an edited plan; it does not defend against a malicious agent, a compromised
account, or an attacker already able to replace code.

## Execution and races

The records directory must be outside every scanned root and, on POSIX, owner-only.
Execution writes the one-use intent record first, rechecks every file before removing
any, then reopens, rechecks and removes one file at a time, stopping on the first failure.
POSIX pins the parent directory with `O_NOFOLLOW` handles, confirms the name still maps
to the planned inode, and removes it relative to that directory handle. Portable POSIX
has no delete-by-handle, so a hostile writer racing that last check is beyond the trust
boundary; stop the workload first. Windows holds an exclusive NTFS handle and sets the
delete disposition on that handle. Arbitrary file deletion, recursive directory
deletion, forced shutdown, elevation, Docker volume mutation, registry changes and
arbitrary shell execution are excluded.

# Safety policy

Unknown data stays protected. Eligibility, user authorization, and execution capability
are three separate gates. No confidence score overrides any gate.

## Scope and traversal

- Require resolved engine roots; reject duplicates, overlaps, protected roots, and
  linked roots. The default `start`/`scan full` workflow resolves and announces the
  current local user profile without a separate metadata-scan question. Explicit
  roots and restrictions take priority; other drives/profiles require separate scope.
- Do not traverse symlinks, junctions, reparse points, or nested mounts. POSIX scans pin
  directory handles. Windows metadata traversal is best effort; content hashing and moves
  use a separate approved NTFS-handle protocol there; POSIX hashing/moves remain
  disabled on Windows. Same-device bind mounts are separately checked on Linux.
- Prune credentials, repositories' VCS metadata, dependencies, virtual environments,
  backup folders, and recognized cloud directory names. Custom cloud roots, unusual
  backup names, and network mounts require user-supplied exclusions; autodetection is incomplete.
- Inspect metadata without opening contents. Only user-approved duplicate hashing and
  approved bytecode magic validation read contents. No scan runs scripts from a project.
- Limits must produce a partial result, never an assertion that a drive is clean.

## Cleanup eligibility

The only POSIX executable catalog rule is `python-bytecode`: a CPython-tagged `.pyc` under
`__pycache__`, a corresponding regular `.py` source, and an ancestor `pyproject.toml`,
`setup.py`, or `setup.cfg` within scope. These markers are never executed or parsed.
The object must be at least 24 hours old, owned by the current user, and have a single
hard link. Protected scopes are excluded. Execution additionally checks the four-byte
magic against the running Python interpreter. Different CPython versions fail closed.
Source and marker identities are bound into the plan and revalidated.

Other cache signatures support recommendations only. Cache location and age are not
proof that every contained file is disposable. A missing application is not proof of
orphaned data. Temp files, Trash, downloads, sources, backups, and unknown files cannot
be promoted into executable actions by editing an inventory.

## Authorization

Plans persist in a private local store, expire in 15 minutes, and bind exact objects,
source evidence, exclusions, rules, and a digest. The agent displays this proposal,
obtains fresh affirmative user approval and stopped-workload confirmation, then records
an approval note. One-use receipts expire in at most five minutes. A general “clean
my computer” request is not that approval. Preferences only restrict scope.

The receipt is an agent assertion, not cryptographic proof of human intent. A hosting
agent must enforce the conversation boundary. HMAC signatures detect modified reports
and state when the private key is intact; they do not defend against a malicious agent,
a compromised account, or an attacker already able to replace code/key material.

## Execution and races

Quarantine uses POSIX handles with `O_NOFOLLOW`, metadata checks before and after rename,
and signed intent/per-item/result journals. It stops on the first failure. A final-name
race cannot be eliminated by portable POSIX rename. If a different object was moved,
it attempts to restore the original name with a non-overwriting hard link and retains
the quarantine object. Inspect both locations before proceeding. Workload quiescence
is mandatory; hostile concurrent writers require a snapshot or no execution.

Only purge_execute.py can permanently remove exact verified private bytecode quarantine,
using a separate signed irreversible approval. Arbitrary file deletion, recursive
directory deletion, forced shutdown, elevation, Docker volume mutation, registry
changes and arbitrary shell execution are excluded.

## Windows direct-removal update (0.1.3)

Windows additionally supports exact approved permanent removal on local NTFS.
The full scan prepares eligible recognized files for one irreversible choice;
submitting exact checked IDs and the previously displayed digest executes and
verifies directly. No Settings UI, recursion, force, or raw shell fallback.
See [Windows protocol](windows.md) for ownership, exclusive-handle, identity, protection and one-use intent gates.
This is separate from the POSIX quarantine/purge protocol.

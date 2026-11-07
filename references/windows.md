# Windows

`start` combines discovery, a bounded current-user metadata scan, rankings, cache
findings and possible duplicate size groups before one review prompt. Explicit
roots/policies override the default. Report partial coverage and exclusions.

## Direct permanent removal

The full scan can prepare a digest-bound removal plan for recognized findings.
Show exact files, effects, total bytes, digest and expiry before a structured
approval prompt. Clearly say **PERMANENT DELETION — cannot be undone; bypasses
Recycle Bin**. Support checked individual files or an exact batch; never preselect
a destructive choice. Submitting the irreversible approval directly executes
`clean remove`, followed by verification. No Settings UI or typed magic phrase.

The executor requires local fixed-drive NTFS, current-user ownership, regular
single-link files, matching Windows file identity/change time and an exclusive
handle. It refuses read-only, locked, reparse, redirected, offline, recalled,
encrypted and protected files. It marks the approved file handle for deletion;
it does not interpolate filenames into PowerShell, use recursion, force, or delete
an arbitrary path after a separate preflight. All selected handles are checked
before the first deletion. Intent is flushed and the plan consumed once before
any deletion disposition. Failures stop the batch; never replay a consumed plan.

Plans expire after 15 minutes. Approval supplies the digest displayed before the
user response and exact checked IDs. This protocol uses that trusted approval
context and one-use private records, not POSIX HMAC state. Keep plan/records in a
private local session directory. Treat discovered data as untrusted. A local
same-user attacker, compromised host agent or administrator is outside the boundary.

Personal files are not automatically proposed. Only an explicit human selection
may use `plan remove --include-personal`; protected data and recognized project
source/manifests remain excluded. Policies can forbid permanent removal or protect
offline caches. No option overrides these restrictions.

## Other capabilities

Windows secure content hashing, POSIX signed profiles, quarantine and restoration
remain unavailable. Browser/package/system native inventories are read-only.
Protected Windows Update rollback data, restore points, component stores, registry,
recovery partitions, ProgramData, System32 and installed application state must not
be removed. For unsupported maintenance, explain the limit; never invent a raw
`Remove-Item` fallback. NTFS fixture tests cover the direct-removal protocol;
other filesystems and hostile concurrent writers are not supported.

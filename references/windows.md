# Windows

Audit explicit user paths using Python 3.10+ and metadata only. Inspect recognized pip,
npm, default-profile browser resource cache paths and user CrashDumps. TEMP contents
are unknown/protected unless a future verified rule recognizes their generating app.
Junctions, symbolic links, and FILE_ATTRIBUTE_REPARSE_POINT objects are skipped.
Windows metadata traversal has best-effort race checks, not native pinned handles.

Use Windows Settings → System → Storage → Temporary files / Storage Sense for
user-controlled native maintenance. Explain each chosen category before the user acts.
Do not alter Windows Update rollback data, restore points, component stores, registry,
recovery partitions, ProgramData, System32, or installed application state.

Windows content hashing, signed persistent state, quarantine, and restore are disabled.
The agent may present an audit proposal, but must not bypass this using PowerShell
Remove-Item, a different Python script, or a copied POSIX plan. Native Windows cleanup
requires a future rule with ACL, reparse-point, locked-file and handle-based validation.

Windows CI checks portable audits, rules and JSON interfaces. It does not certify
Windows 10/11 native cleanup, case-insensitive edge cases, or every network filesystem.

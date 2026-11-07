# Windows

Default to `start` for the current local user profile, or use explicitly selected
paths, with Python 3.10+ and metadata only. Inspect recognized pip,
npm, default-profile browser resource cache paths and user CrashDumps. TEMP contents
remain protected; application-specific temporary signatures produce review findings only.
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

## Default interaction

Announce the profile scope, run discovery/scan/find together, and present the
coverage and findings before asking anything. Use the host question UI with
**Review Windows cleanup**, **Review large files**, **Finish without changes**.
Do not require a typed confirmation phrase or ask the user to copy candidate IDs.

Choosing Windows cleanup permits `inspect cleanup --allow-native` to open the
fixed Storage Settings URI. Do not ask a second question just to open Settings.
Explain suggested categories together; the user reviews exact categories and
confirms removal there. Downloads and Recycle Bin require separate category review.
No raw removal commands are a fallback for this flow.

Windows CI checks portable audits, rules and JSON interfaces. It does not certify
Windows 10/11 native cleanup, case-insensitive edge cases, or every network filesystem.

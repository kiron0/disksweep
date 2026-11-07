# Operational workflow

1. **Discover:** determine OS, free storage, relevant tools, access, exclusions, and mode.
   Probe output is informational; suggested cache roots do not authorize scans.
2. **Analyze:** inventory exact roots with bounded time, depth and entry limits. Report
   permission errors and partial coverage. `classify.py` is an alias for a fresh inventory
   and classification, not a promotion API for externally supplied findings.
3. **Classify:** explain rule ID/version, application association, evidence, unknown
   active-use state, and protection. Folder signatures are audit hints only.
4. **Recommend:** present sizes, risks, side effects, recovery, and mechanism. Review
   offline needs, active debugging, cloud scope, and upcoming builds.
5. **Plan:** select exact eligible IDs; revalidate and persist a signed plan outside scan
   roots on the same filesystem. Temporary private review artifacts are part of the
   requested workflow; durable reports/history require consent.
6. **Approve:** display the plan members, digest, expiration, and zero immediate free-space
   warning. Obtain fresh user approval and confirmation that Python work has stopped.
7. **Execute:** validate the plan and receipt again; consume the receipt atomically before
   the first action. Move sequentially; stop on any anomaly. Never expand selection.
8. **Verify:** inspect signed results and actual filesystem state; distinguish processed,
   failed, and unattempted items. Report disk deltas as observations, not attribution.
9. **Recover:** offer non-overwriting restoration. Permanent removal needs a new
   purge plan, separate irreversible acknowledgement and a fresh one-use receipt;
   quarantine approval cannot authorize it.

A partial scan may still support a narrow plan if its individual candidates revalidate;
it cannot establish that unvisited storage is safe. A changed candidate, source, rule,
policy, or expired approval requires a new plan and approval. Re-running an expired
plan is not an extension of the old permission.

No helper automatically executes native maintenance. For a platform/browser/package
operation, present the supported native UI or a reviewed dry-run and let the user
choose its separate scope. Do not reuse a bytecode approval for native maintenance.

Default interaction combines phases 1–4 without individual questions. Use one host
choice prompt for the exact reviewed action, combine workload confirmation with
quarantine approval when clearly labeled, and continue through verification after
approval. Never require magic reply strings. Separate irreversible purge and changed
plans still need a fresh prompt. On Windows, the exact irreversible file choice executes direct NTFS removal,
then verification, without opening Settings.

## Windows direct-removal update (0.1.3)

Windows additionally supports exact approved permanent removal on local NTFS.
The full scan prepares eligible recognized files for one irreversible choice;
submitting exact checked IDs and the previously displayed digest executes and
verifies directly. No Settings UI, recursion, force, or raw shell fallback.
See [Windows protocol](windows.md) for ownership, exclusive-handle, identity, protection and one-use intent gates.
This is separate from the POSIX quarantine/purge protocol.

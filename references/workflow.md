# Operational workflow

The same flow runs on macOS, Linux and Windows. Only the native file-handle backend differs.

1. **Discover:** determine OS, free storage, relevant tools, access, exclusions, and mode.
   Probe output is informational; suggested cache roots do not authorize scans.
2. **Analyze:** inventory exact roots with bounded time, depth and entry limits. Report
   permission errors and partial coverage. `classify.py` is an alias for a fresh inventory
   and classification, not a promotion API for externally supplied findings.
3. **Classify:** explain rule ID/version, application association, evidence, unknown
   active-use state, and protection. Folder signatures are audit hints only.
4. **Recommend:** present sizes, risks, side effects, recovery, and mechanism. Review
   offline needs, active debugging, cloud scope, and upcoming builds.
5. **Plan:** the full scan prepares `removal_plan` for eligible recognized files, or
   `plan remove` builds one for exact IDs. Each file is revalidated and pinned with native
   handles. The plan expires in 15 minutes and carries a digest.
6. **Approve:** display the plan members, total bytes, digest, expiration and the
   permanent-deletion warning. Obtain one fresh, explicit user approval of that plan.
7. **Execute:** call `clean remove` with only the checked IDs and the displayed digest.
   The one-use intent record is written first; every file is rechecked before any
   removal, then each is reopened, rechecked and removed in turn. Stop on any anomaly.
   Never expand the selection.
8. **Verify:** confirm every removed name is absent; distinguish removed, failed and
   unattempted items. Report disk deltas per volume as observations, not attribution.
9. **Recover:** removal cannot be undone. Explain how each removed item regenerates
   and inspect records after any interruption; see [recovery](recovery.md).

A partial scan may still support a narrow plan if its individual candidates revalidate;
it cannot establish that unvisited storage is safe. A changed candidate, source, rule,
policy, or expired plan requires a new plan and approval. Re-running an expired
plan is not an extension of the old permission.

No helper automatically executes native maintenance. For a platform/browser/package
operation, present the supported native UI or a reviewed dry-run and let the user
choose its separate scope. Do not reuse a removal approval for native maintenance.

Default interaction combines phases 1–5 without individual questions. Use one host
choice prompt for the exact reviewed removal and continue through verification after
approval. Never require magic reply strings, and never open Settings instead.
A changed plan still needs a fresh prompt.

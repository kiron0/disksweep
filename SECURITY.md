# Security

DiskSweep 0.4.1 supports local audits and restricted bytecode quarantine. No permanent
deletion is implemented. An independent security audit has not been performed.
Read references/safety-policy.md and references/recovery.md before enabling execution.

## Threat model

Treat inventory/report input, filenames, project files, and native tool output as
untrusted. Enforce protection in the engine even if a caller edits classifications.
Private HMAC-signed plans/receipts prevent tampering without the local key and bind
fixed identities. One-use receipts prevent replay; they cannot prove a human approved.
The host agent must enforce that conversational boundary. Protect its execution permissions.

The local account, installed skill code, private state key, and Python runtime are
trusted. The engine does not defend against a malicious same-user process replacing
these components, compromised agents, administrator attacks, hostile filesystem
servers, or kernel bugs. POSIX namespace races are reduced with pinned handles and
checks; concurrent final-name replacement triggers stop and best-effort non-overwriting
name restoration. Quiescent workloads are required. No guarantees apply to hostile
concurrent writers; use a read-only audit or an externally managed snapshot instead.

Windows execution and content hashing are disabled pending native safety support.
OS/path detection cannot discover every custom cloud, backup, or network location.
Use explicit exclusions. Reports and Docker metadata can contain private information.

## Report a vulnerability

Use the repository's **Security → Advisories → Report a vulnerability** feature when
available: https://github.com/kiron0/disksweep/security/advisories/new . If private
reporting is unavailable, open a minimal issue requesting a private contact method,
without exploit details, credentials, local paths, or inventories. Do not post sensitive
proof-of-concept data publicly. No response-time guarantee is currently offered.

Supported fixes target the latest 0.4.x release. Review changes before updating an
installed skill, and discard old plans whenever code or policy changes.

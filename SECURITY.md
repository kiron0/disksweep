# Security

Swipr supports local audits, restricted bytecode quarantine, and a separate
permanent-removal protocol for exact verified private bytecode quarantine. An
independent security audit has not been performed.
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

Windows direct execution and content hashing are unavailable in the current backend;
native user-guided maintenance remains available.
OS/path detection cannot discover every custom cloud, backup, or network location.
Use explicit exclusions. Reports and Docker metadata can contain private information.

## Report a vulnerability

Use the repository's **Security → Advisories → Report a vulnerability** feature when
available: https://github.com/kiron0/swipr/security/advisories/new . If private
reporting is unavailable, open a minimal issue requesting a private contact method,
without exploit details, credentials, local paths, or inventories. Do not post sensitive
proof-of-concept data publicly. No response-time guarantee is currently offered.

Supported fixes target the latest 0.1.x release. Review changes before updating an
installed skill, and discard old plans whenever code or policy changes.

Permanent removal has a distinct signed plan and short-lived one-use approval,
requires explicit irreversible acknowledgement, and validates each current-user,
single-link bytecode object inside its derived private quarantine directory. It
cannot target original files or arbitrary paths. The sole unlink call is guarded
by identity, ownership, type, magic, directory-handle and approval checks. Private
state and quiescent workloads are trusted; hostile same-user mutation remains outside
the boundary. A failed or interrupted purge must be reconciled, never blindly replayed.

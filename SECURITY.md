# Security

Swipr supports local audits and one digest-bound exact selected-file permanent-removal
protocol on macOS, Linux and Windows. An
independent security audit has not been performed.
Read references/safety-policy.md and references/recovery.md before enabling execution.

## Threat model

Treat inventory/report input, filenames, project files, and native tool output as
untrusted. Enforce protection in the engine even if a caller edits classifications.
Removal plans bind fixed identities and a digest that the host must display before
approval. One-use intent records prevent replay; they cannot prove a human approved.
The host agent must enforce that conversational boundary. Protect its execution permissions.

The local account, installed skill code, private records directory, and Python runtime are
trusted. The engine does not defend against a malicious same-user process replacing
these components, compromised agents, administrator attacks, hostile filesystem
servers, or kernel bugs. POSIX namespace races are reduced with pinned directory handles
and an inode check immediately before the directory-relative removal; portable POSIX has
no delete-by-handle. Quiescent workloads are required. No guarantees apply to hostile
concurrent writers; use a read-only audit or an externally managed snapshot instead.

Windows content hashing remains unavailable. Exact selected-file permanent removal
uses POSIX directory handles on macOS and Linux and exclusive handles on local
fixed-drive NTFS on Windows. Every OS requires current-user ownership, unchanged
identity, a displayed plan digest, fresh irreversible approval, exact selected IDs,
a records directory outside the scanned roots and one-use private intent.
The host must retain the digest shown BEFORE approval; a plan file alone is not
authorization. No recursion, shell interpolation, force, Trash or Recycle Bin is used;
Swipr cannot undo the removal. See references/safety-policy.md and the platform
references for the protocol and unsupported file types.
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

The sole POSIX unlink call and the sole Windows delete disposition each live in one
guarded handle primitive, enforced by the project's AST check. Each is reached only after
digest, expiry, rule-catalog, eligibility and identity checks and the one-use intent
record. Hostile same-user mutation remains outside the boundary. A failed or interrupted
removal must be reconciled, never blindly replayed.

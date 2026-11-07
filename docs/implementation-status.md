# Implementation status — 0.4.0 preview

The project brief describes a staged roadmap through v1.0. This initial implementation
combines the audit/planning foundation with one narrowly scoped quarantine strategy.
It is not a stable v1.0 or a claim of mature cross-platform destructive cleanup.

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| OS/tool/free-space discovery | Implemented | Implemented | Implemented |
| Bounded metadata inventory and audit rules | Implemented | Implemented | Implemented, best-effort traversal races |
| Large-file reporting and redacted reports | Implemented | Implemented | Implemented |
| Approved SHA-256 duplicate audit | POSIX handles | POSIX handles | Disabled |
| Signed plans, approval, validation | Implemented | Implemented | Disabled pending ACL support |
| Stale source-backed bytecode quarantine | POSIX only | POSIX only | Disabled |
| Non-overwriting restore, verification | Implemented | Implemented | Disabled |
| Docker metadata | Optional native interface | Optional native interface | Optional native interface |
| Browser/package/OS maintenance | Native guidance | Native guidance | Native guidance |
| Permanent deletion, Trash emptying | Disabled | Disabled | Disabled |

## Validation boundaries

Local development runs use Linux and temporary filesystem fixtures. GitHub Actions
contains Linux/macOS/Windows and Python 3.10/3.12 matrix jobs; a configured matrix is
not proof that remote runs passed. See the Actions page for current evidence.
No real browser profile, Docker daemon, APFS snapshot, Windows servicing store,
Intel/Apple Silicon release matrix, or user home is modified by tests.

Agent Skills metadata and installation layout are validated. Codex, Claude Code,
Cursor and Gemini CLI are potential hosts, not individually certified integrations.
Behavioral eval prompts are included but require human or host-agent evaluation;
static evaluation files are not evidence of live agent compliance. skills.sh discovery
compatibility is targeted; a registry listing is not guaranteed by this repository.

## Remaining roadmap

- Native Windows ACL/handle safety and junction race tests.
- Verified native cleanup rules with fixed inventories and explicit irreversible approval.
- Reliable active-use checks, comprehensive profile discovery and installed-app association.
- OS-native Trash inventory, filesystem clone/snapshot accounting, orphan-app evidence.
- More ecosystems and native tool-version fixtures; live host-agent behavior evaluation.
- Independent security review and broad native platform testing before stable v1.0.

No release date or compatibility claim should be inferred from these planned items.

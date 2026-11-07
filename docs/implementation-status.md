# Supported features — 0.4.1

Version 0.4.1 is the stable release of the features below: local storage audits,
cleanup proposals, and a narrowly scoped POSIX bytecode-quarantine workflow.
The broader v1.0 roadmap remains separate from this release's supported scope.

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

Tests use temporary filesystem fixtures. GitHub Actions runs Linux, macOS, and
Windows jobs with Python 3.10 and 3.12. All six platform/version jobs passed for
the preceding implementation; each release commit must pass the same matrix.
See the [Actions page](https://github.com/kiron0/disksweep/actions) for current results.
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

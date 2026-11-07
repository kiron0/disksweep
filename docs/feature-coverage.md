# Feature coverage

Swipr follows the five public skill collections recorded in
[structure research](structure-research.md): a concise entry point, progressive
references, focused helpers, versioned rules, schemas, assets, and executable tests.

## Workflow phases

| Phase | Implementation | Evidence |
|---|---|---|
| Discover | system_probe.py, applications.py, native_storage.py | Capability and native-interface tests |
| Analyze | inventory.py, analyze.py, audit.py | Bounded filesystem, directory-size and mode tests |
| Classify | Versioned catalogs and project-marker rules | Positive, negative and protected-override fixtures |
| Recommend | recommend.py; exact IDs, effects and recovery | Proposal and source-protection tests |
| Approve | plan.py / approve.py; separate purge_plan.py / purge_approve.py | Signature, expiry, scope and replay tests |
| Execute | execute.py / restore.py; guarded purge_execute.py | Exact-identity, failure, link and source-preservation tests |
| Verify | verify.py, purge_verify.py, compare.py and report.py | End-to-end helpers and observed-space reporting |

## Cleanup categories

| Original category | Support and safe handling |
|---|---|
| Temporary files | Known pip/SDK temporary-path rules; age and active-use review. Arbitrary temp contents remain protected. |
| Application caches | Browser, editor, thumbnail, package and IDE catalog rules; associations use native inventories. |
| Browsers | Chrome, Edge, Chromium, Brave, Firefox and Safari cache signatures, including selected secondary profiles; use browser-native cache controls. |
| Logs / diagnostics | macOS reports, Windows WER/dumps, VS Code logs and systemd usage; preserve retention and use native maintenance. |
| Application leftovers | applications.py + leftovers.py compares known app associations with native inventories; absence is REVIEW, never deletion proof. |
| Large files / directories | Ranked files, six sort orders, directory distributions, sparse/hard-link accounting and unknown physical-savings reporting. |
| Duplicates | Size/inode prefilter, approved SHA-256, stable identity checks, bounded reads and a heuristic reference copy; never automatic removal. |
| Trash / Recycle Bin | trash_audit.py and recycle_bin.py inspect recoverable usage; direct bin emptying is user-guided and separately authorized. |

## Developer ecosystems

| Ecosystem | Detection and policy |
|---|---|
| Node.js, npm, pnpm, Yarn, Bun | Download/store signatures; shared and offline dependencies remain excluded from automated cleanup. |
| Next.js, Vite, Turbo, Webpack | Project marker plus exact generated-output paths; REVIEW with native clean guidance. |
| Python | Source-backed bytecode, pip, pytest/mypy/ruff; virtual environments and source stay protected. |
| Rust | Registry archives and Cargo-marked target outputs; preserve source, manifests, lockfiles and toolchains. |
| Java / JVM | Gradle/Maven paths and marked build output; local artifacts may be irreplaceable. |
| Xcode / simulators | DerivedData and CoreSimulator caches; preserve archives, signing material and device/user data. |
| Docker | Fixed native storage/build-cache queries; native review only; volumes and Desktop disks protected. |
| Go, .NET, Ruby, PHP, Android, Flutter, Kotlin | Versioned cache/store signatures and project-marker rules where applicable; native review and offline protection. |
| Homebrew, Linux packages, IDEs | Dedicated download, journal, editor-cache and diagnostic rules; native controls for maintenance. |

## Advanced behavior

All eleven modes are routed by audit.py: full, quick, deep, safe-cleanup, developer,
emergency, targeted, duplicates, health, compare, and custom. Every scan needs
resolved roots; modes grant no action permission. `start` / `scan full` infer the
current local user profile unless roots or a scope policy are selected. They combine
discovery and analysis before one review prompt. Other modes require explicit scope.
Resource limits and partial coverage
are reported. Additional depth needs reviewed scope and limits.

Profiles only restrict scope and budgets. profiles.py and snapshots.py persist signed
local state with consent on POSIX; session policies work on all platforms. compare.py
tracks added/removed/changed files, growth and observed storage deltas. Repeated
regeneration is a comparison finding, not proof of a performance cause.

activity.py reports observed open handles where lsof is available; absence stays
unknown. native_storage.py reports volume/filesystem, journal and snapshot information
through platform interfaces. Protected metadata-only audits can measure selected
backups, dependencies and application state without making them cleanup candidates.

## Release boundary

POSIX executable deletion is limited to exact previously verified private bytecode
quarantine, with a new irreversible plan and approval. Windows supports a separate
digest-bound exact selected-file NTFS removal protocol with fresh irreversible approval. Other integrations
provide operational audit and native user-guided maintenance. They do not acquire
permission to delete arbitrary cache trees, backups, personal data, Docker volumes,
or system state. Platform/tool failures degrade explicitly as required by the brief.

Tests cover engine behavior and native adapters using fixtures. Independent security
review, every native app/version, hardware combination, filesystem clone mechanism,
and live behavior of each host agent are not asserted by this coverage map.

## Windows direct-removal update (0.1.3)

Windows additionally supports exact approved permanent removal on local NTFS.
The full scan prepares eligible recognized files for one irreversible choice;
submitting exact checked IDs and the previously displayed digest executes and
verifies directly. No Settings UI, recursion, force, or raw shell fallback.
See [Windows protocol](../references/windows.md) for ownership, exclusive-handle, identity, protection and one-use intent gates.
This is separate from the POSIX quarantine/purge protocol.

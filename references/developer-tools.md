# Developer storage

| Ecosystem | Read-only inspection | Protected by default |
|---|---|---|
| Python | Project `__pycache__`, `pip cache info`, `pip cache list` | venvs, source, secrets, locally built wheels |
| Node.js | Known npm/Yarn/Bun paths; native cache-path queries | node_modules, lockfiles, .env, pnpm shared stores |
| Frameworks | User-selected .next, Vite, Turbo and build output metadata | source, config, unknown output, active builds |
| Rust | Cargo registry archives and selected build metadata | manifests, lockfiles, toolchains, target until reviewed |
| JVM | Gradle metadata and explicit build outputs | Maven local artifacts, configs and toolchains |
| Apple | Xcode DerivedData | signing material, archives, simulator user data |
| Go/.NET/Ruby/PHP/Android/Flutter | Specific requested trees only | shared stores, SDKs, project state; no cleanup rules |

No tool executable found by scanning a project is executed. `system_probe.py` uses
PATH presence only; it does not claim compatible tool versions or that paths are disposable.
Before native maintenance, inspect the installed tool's documentation/version and a
supported preview where available. Offline dependencies may be irreplaceable today.

Python bytecode is the single SAFE-CANDIDATE rule. Project-marker evidence, source
identity, age, link count and ownership are independent gates before exact approved
removal. The interpreter recompiles removed bytecode. Recognized package and build
caches are REVIEW findings that may enter an exact plan for explicit approval;
project build outputs and other developer categories stay REVIEW or PROTECTED.

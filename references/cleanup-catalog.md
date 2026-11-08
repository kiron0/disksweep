# Cleanup catalog

Rules are versioned JSON under `rules/<group>/catalog.json`. All strategies are fixed
enums; no rule can supply an executable command. The engine action is the same on
every OS; rules only differ in which platforms their path signatures apply to. Runtime reads the catalog from the
installed skill, validates IDs and strategies, and binds its digest into each plan.

| Group | Recognized artifacts | Engine action |
|---|---|---|
| Python | Source-backed CPython bytecode in a marked project | SAFE-CANDIDATE; exact approved removal |
| Package downloads | pip, npm, Yarn, Bun, Cargo archives | REVIEW; exact approved removal |
| Development | Gradle caches, Xcode DerivedData | REVIEW; exact approved removal |
| Browsers | Selected Chromium default-profile paths, Firefox cache roots, Safari | REVIEW; exact approved removal with the browser closed |
| Linux | Freedesktop thumbnail cache | REVIEW; exact approved removal |
| macOS | Homebrew downloads, user diagnostic reports | REVIEW; exact approved removal |
| Windows | User crash dumps | REVIEW; exact approved removal |
| Other | Large files, downloads, arbitrary temp/log/cache paths, Trash | Informational/protected |

No generic `Cache`, `.next`, `target`, `dist`, `node_modules`, or `.m2` rule makes a
project tree deletable. Maven local repositories may contain irreplaceable artifacts;
pnpm stores may be shared. Recognize them in discussion, preserve them by default.

Unsupported browser profiles and custom tool cache paths require application-specific
inspection. Do not relabel unknown locations to force a match. New executable rules
must pass the release gate in CONTRIBUTING.md.

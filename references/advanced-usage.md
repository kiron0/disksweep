# Modes and protection profiles

- **Quick scan:** narrow known user-cache roots with default bounded metadata inspection.
- **Deep scan:** expand only explicitly requested roots and limits in stages. Explain
  unvisited directories; do not silently cross mounts or hash a whole disk.
- **Safe cleanup:** exact approved bytecode quarantine plan only; other items remain proposals.
- **Developer audit:** use category guidance, preserve offline dependencies and active work.
- **Storage emergency:** identify high-value native storage options quickly. Quarantine
  cannot free space; emergency pressure never authorizes irreversible actions.
- **Targeted:** limit roots/exclusions to the requested application or folder.
- **Duplicate audit:** ask before content hashing, choose byte budget, report protected groups.
- **System health:** explain storage pressure; do not promise performance improvements,
  disable services, clean RAM, or tune registries.
- **Before/after:** compare signed operation result and current verification. Distinguish
  unrelated storage changes, retained quarantine, regenerated caches, and failed actions.
- **Custom profile:** translate user restrictions to explicit roots/exclusions per request.
  Save a persistent profile only with consent; profile files grant no action permission.

Examples: “Preserve every cloud folder and project”; “Skip browser caches while I am
offline”; “Inspect only Downloads and show large files”; “Keep diagnostics while we
debug this crash.” Custom roots with unusual names must be explicitly excluded where
appropriate; cloud/backup recognition is conservative but incomplete.

Use compare.py and snapshots.py for consented history, applications.py / leftovers.py
for possible residual associations, and trash_audit.py / recycle_bin.py for recoverable
storage accounting. native_storage.py inspects snapshots and filesystems where supported.
Physical clone/snapshot savings and proof of orphan status remain unknown. There is
no automatic quarantine expiration or deletion.

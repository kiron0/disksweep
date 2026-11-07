# Changelog

## 0.4.1 — 2026-11-07

- Publish the first stable release of the currently supported audit and limited
  bytecode-quarantine features.
- Simplify the README to installation, usage, and cleanup support.
- Add a practical usage guide for audits, approval, verification, and restoration.
- Include the linked security documentation in the installable skill archive.
- Correct capability discovery so content hashing is advertised only when safe
  POSIX directory handles are available.

Windows supports metadata audits. Quarantine and content hashing require POSIX;
permanent deletion and automatic native maintenance remain unavailable.

## 0.4.0 preview — 2026-11-07

- Add a portable Agent Skills entry point and progressive reference documentation.
- Add bounded local inventory, deterministic classification, large-file ranking,
  optional approved duplicate hashing, and redacted reports.
- Add 15 versioned audit rules and one narrowly scoped bytecode quarantine strategy.
- Add signed plans, expiring one-use receipts, revalidation, journals, verification,
  and restoration without overwriting existing files.
- Add JSON schemas, temporary-filesystem regression tests, behavioral eval cases,
  multi-platform CI, and security checks.
- Use complete Windows filesystem metadata rather than directory-entry identity
  caches, and keep symlink fixtures independent of macOS temporary-directory prefixes.

Permanent deletion and automatic native maintenance are not enabled. This is a
preview of the brief's staged rollout, not a claim that all v1.0 goals are complete.

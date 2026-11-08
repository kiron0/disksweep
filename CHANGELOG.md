# Changelog

## 0.1.5 — 2026-11-08

- Make `start --guide` without folders suggest `start` for the bounded current-user
  scan, matching the default workflow, instead of `scan full --root PATH` and doctor.
- Render `find large`, `find directories` and `find duplicates` matches as readable
  tables with root-relative locations instead of raw JSON, and show non-normal
  storage health in scan summaries. JSON output is unchanged.
- Publish the repository as a Claude Code plugin marketplace with
  `.claude-plugin/marketplace.json` and `.claude-plugin/plugin.json`, so
  `/plugin marketplace add kiron0/swipr` and `/plugin install swipr@swipr` work.
  Project validation keeps both manifest versions equal to the skill version.
- Speed up scanning and analysis about tenfold: indexed rule-signature matching,
  component-prefix scope checks, cached rule catalogs, no mount probe for regular
  files, per-directory project-marker caching and a linear duplicate reference lookup.
  A 50,000-file audit dropped from about 50 to 4.5 seconds on the test machine.
- Project build-artifact analysis now covers up to 100,000 entries, matching the full
  scan limit, instead of reporting partial analysis after 20,000.
- Use one cleanup flow on macOS, Linux and Windows: scan, exact digest-bound removal
  plan, one irreversible approval, permanent removal and verification. A new POSIX
  directory-handle backend matches the Windows NTFS-handle backend; only that native
  primitive differs per OS. The full scan now prepares `removal_plan` on every OS.
- Remove the POSIX bytecode quarantine, restore and separate purge workflow, including
  `plan create/show/validate/purge`, `approve`, `clean quarantine/restore/purge`,
  their helper scripts and schemas. Bytecode is now removed through the same exact
  plan and still must be at least 24 hours old.
- Removal checks every selected file before removing any, then reopens and rechecks
  each one before removal, so large plans no longer hold one handle per file.
  Records must be outside the scanned roots and owner-only on POSIX. Free space is
  measured per volume. `history operations` lists removal records on every OS.
- Offer native cleanup review on any OS when no permanent-removal plan is available.

## 0.1.4 — 2026-11-08

- Continue read-only discovery, inventory, analysis and comparison when volume-space
  queries are denied; report unknown measurements without losing collected files.
- Distinguish permission, missing-file and existing-output errors by failed stage,
  retain sanitized Windows error numbers, and report the active installation.
- Measure Windows removal space on target volumes, preserve verified outcomes when
  optional post-removal queries fail, and keep journal-space checks mandatory.
  No permission bypass or automatic retry.

## 0.1.3 — 2026-11-07

- Make `start` and the new `scan full` combine discovery, current-user metadata
  scanning, file/directory rankings, cache findings, health and possible duplicate
  size groups before one review prompt. Explicit scopes and policies take priority.
- Use structured host choices instead of magic reply phrases and per-step questions;
  retain exact-plan approval, workload confirmation and separate irreversible approval.
- Add `start --guide` for onboarding without a scan. Add direct Windows NTFS
  permanent removal of exact checked files after one irreversible review choice,
  with exclusive handles, digest/identity checks, one-use intent and verification.
- Increase the bounded terminal JSON reader to 256 MiB for full inventories;
  disclose scan coverage, proposal truncation and unverified duplicate groups.

## 0.1.2 — 2026-11-07

- Add guided `start` workflows without implicit scans or permissions.
- Add `explain` for exact saved findings, with optional private evidence.
- Give scoped audits contextual review steps, partial-coverage warnings and
  protected-only guidance without implying current execution eligibility.
- Clarify skill capability limits, command routing, and concise response guidance.
- Redesign the README with Hopilo's Unbounded/Onest typography, task-based commands,
  a platform matrix, expandable terminal instructions, and the official skills.sh
  link. Organize the evaluation guide.
- Clarify why skills.sh installations use the GitHub source name.
- Expand ignore rules for private state, local reports, environments, caches, and
  generated files. Remove the unused editable cover and move release-only notes
  outside the installable skill assets.

## 0.1.1 — 2026-11-07

- Add documented commands and subcommands for every workflow through one optional
  adapter, including help, discovery, scans, filtered file discovery, native inspection,
  exact plans, approval, cleanup, verification, reports, history, profiles, and rules.
- Add complete command examples and an advanced usage cookbook.
- Preserve explicit scope and approval gates; reserve private output files before
  operations, refuse overwrites, and bound JSON input.
- Use version-only release titles and document skills.sh listing steps.

## 0.1.0 — 2026-11-07

First published stable release.

- Provide all seven workflow phases and ten natural-language usage modes.
- Add bounded inventories, directory distributions, six file sort orders, exact
  duplicate audits, health findings and before/after comparisons.
- Expand versioned application, browser, temporary, diagnostics and developer rules,
  including project-marker evidence and installed-application association checks.
- Add authorized native volume, filesystem, log, snapshot, application and active-use
  queries, plus protected Trash/Recycle Bin inspection.
- Add restrictive policies, consented signed snapshots, exact approval plans,
  quarantine, non-overwriting restoration and operation journals.
- Add a separate irreversible approval workflow for permanent removal of exact
  verified private bytecode quarantine; preserve source, personal data and system state.
- Keep the README focused on installation and usage; document feature coverage,
  supported backends and native user-guided maintenance separately.
- Include schemas, behavioral cases, adversarial fixtures and multi-platform CI.

# DiskSweep

**Intelligent system cleanup for AI agents**

*Reclaim space. Remove clutter. Protect what matters.*

[![Tests](https://github.com/kiron0/disksweep/actions/workflows/tests.yml/badge.svg)](https://github.com/kiron0/disksweep/actions/workflows/tests.yml)
[![Validate](https://github.com/kiron0/disksweep/actions/workflows/validate.yml/badge.svg)](https://github.com/kiron0/disksweep/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

DiskSweep is an open [Agent Skill](https://agentskills.io/specification) that helps
a local AI agent understand disk usage, identify known caches, protect important
data, and present an evidence-based cleanup proposal. It runs offline with
Python's standard library. There are no accounts, telemetry, or background services.

**Current release: 0.4.0 preview.** Audits work on Linux, macOS, and Windows.
The sole executable cleanup rule quarantines stale, source-backed CPython
bytecode on POSIX after approval of a signed, fixed plan. Quarantine preserves
files and frees **no disk space**. Permanent deletion is intentionally unavailable.
Browser, OS, package, and Docker maintenance remain audit and native-guidance
workflows. See [what is implemented and tested](docs/implementation-status.md).

## Install

Using the open-source [Skills CLI](https://github.com/vercel-labs/skills):

```sh
npx skills add kiron0/disksweep --skill disksweep
```

Or clone this repository into your agent's skill directory as `disksweep/`, using
the skill-installation instructions for that agent. For example, Codex uses
`~/.agents/skills/disksweep/` and Claude Code uses
`~/.claude/skills/disksweep/`. Review the skill before enabling local execution.
Agents need local filesystem access and Python 3.10+. A chat-only agent can
explain the workflow but cannot inspect or clean your computer.

The repository is structured for skill discovery by skills.sh tooling; no
registry listing, agent certification, or native Windows execution is claimed.

## Use natural language

> Use DiskSweep to audit my disk usage. Start with known caches, preserve my
> projects and browser sessions, and show a cleanup proposal without changing files.

> Find the largest files in Downloads. Ask before reading content to detect duplicates.

> Review my Python, Node.js, Rust, Xcode, and Docker storage. Preserve dependencies,
> databases, signing identities, and anything I might need offline.

Your agent discovers capabilities, agrees on scope, scans metadata, explains the
findings, and asks for fresh approval before a supported move. SAFE-CANDIDATE
means eligible for review, never permission to execute. Preferences cannot
authorize future cleanup.

## What you get

- Bounded metadata inventory with exclusions, mount/link checks, and partial-scan reporting.
- Versioned rules for CPython, pip, npm, Yarn, Bun, Cargo, Gradle, Xcode,
  browser cache paths, Linux thumbnails, Homebrew, and diagnostics.
- Large-file ranking; optional bounded SHA-256 duplicate analysis with explicit content-read approval.
- Logical versus allocated storage accounting, hard-link deduplication, and redacted Markdown reports.
- Signed local plans and short-lived one-use approval receipts; exact identity and policy revalidation.
- Limited quarantine, signed operation journals, before/after verification, and non-overwriting restoration.
- Optional read-only Docker storage queries using fixed native arguments.

No broad deletion of temp folders, arbitrary caches, Downloads, application
support, browser profiles, or system files is provided. Docker volumes remain protected.
No operation is run on your machine simply by installing the skill.

## Structure

```text
disksweep/
├── SKILL.md                 # concise agent entry point
├── agents/openai.yaml       # Codex display metadata
├── references/              # workflow, safety, platforms, category guidance
├── scripts/                 # offline internal JSON helpers; stdlib only
├── rules/                   # versioned declarative catalogs; no shell commands
├── schemas/                 # inventory, candidate, plan, approval, result contracts
├── assets/                  # report template
├── evals/                   # natural-language behavioral evaluation cases
├── tests/                   # temporary fixtures and adversarial regressions
└── .github/workflows/       # validation, platform matrix, security checks
```

The structure follows patterns researched in five leading public skill
collections. [Sources, star-count snapshot, and design decisions](docs/structure-research.md)
are recorded with commit-pinned links. DiskSweep's implementation is original;
upstream skill text and code are not bundled.

## Develop

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_project.py
```

Runtime helpers require no third-party packages. For schema and YAML validation:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/check_project.py --strict
```

On Windows use `.venv\Scripts\python.exe`. Tests only touch temporary fixtures.
The [internal helper protocol](references/helper-protocol.md) includes a complete
audit, approval, execution, verification, and restore walkthrough for integrators.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before adding a rule and
[SECURITY.md](SECURITY.md) for the threat model and disclosure process.

Licensed under [MIT](LICENSE).

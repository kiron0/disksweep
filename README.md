# Swipr

Audit local storage and plan safe cleanup with your AI agent.

## Install

```sh
npx skills add kiron0/swipr --skill swipr
```

Requires Python 3.10+ and an agent with local filesystem access.
Storage audits support macOS, Windows, and Linux.

## Usage

Ask your agent:

> Use Swipr to check my storage and show cleanup opportunities. Don't change any files.

> Find large files in Downloads. Ask before reading contents to check for duplicates.

> Review my developer caches. Preserve projects, dependencies, databases, and browser sessions.

Swipr scans the folders you choose, explains its findings, and presents a plan.
Every supported file move requires your approval of the exact plan.

## Cleanup support

Eligible Python bytecode can be quarantined on macOS and Linux. Quarantine retains
files and frees no space. Clearing that quarantine permanently requires a separate
approval. Other categories use audit findings and native cleanup guidance.

[Usage guide](docs/usage.md) · [Platform support](docs/implementation-status.md) ·
[Releases](https://github.com/kiron0/swipr/releases) · [Security](SECURITY.md) · [MIT license](LICENSE)

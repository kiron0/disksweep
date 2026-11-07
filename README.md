# Swipr

Local storage audits and safe cleanup through your AI agent.

[skills.sh](https://skills.sh/kiron0/swipr/swipr) · [Commands](COMMANDS.md) · [Advanced usage](docs/advanced.md)

## Install

```sh
npx skills add kiron0/swipr --skill swipr
```

Update an existing installation with `npx skills update swipr`.

Requires Node.js 22.20+ for installation, Python 3.10+ for helpers, and an agent
with local filesystem access. Supports macOS, Windows, and Linux audits.

## Use

In Codex chat:

```text
$swipr help
$swipr scan quick --root ~/Downloads
$swipr find large --root ~/Downloads --min-bytes 104857600
$swipr scan developer --root ~/Projects/my-app
```

In Claude Code, use `/swipr` instead of `$swipr`. Other agents can use
`Use Swipr: help`. Choose your own folders.

See [all commands and options](COMMANDS.md) for scans, plans, approval, cleanup,
verification, reports, profiles, and history.

Scans are read-only. File changes need an exact reviewed plan and fresh approval.
Quarantine retains files; permanent removal needs separate irreversible approval.
See [platform support](docs/implementation-status.md) for available operations.

[Releases](https://github.com/kiron0/swipr/releases) · [Security](SECURITY.md) · [MIT](LICENSE)

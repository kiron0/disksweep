# Swipr

Local storage audits and safe cleanup, through your AI agent.

## Install

```sh
npx skills add kiron0/swipr --skill swipr
```

Use Node.js 22.20+ for the installer, Python 3.10+ for helpers, and an agent with
local filesystem access. Audits support macOS, Windows, and Linux.

## Start using it

In **Codex chat**:

```text
$swipr help
$swipr scan quick --root ~/Downloads
$swipr find large --root ~/Downloads --min-bytes 104857600
$swipr scan developer --root ~/Projects/my-app
```

In **Claude Code**, use `/swipr` instead of `$swipr`. Other agents can use
`Use Swipr: help`. Replace the example folders with your authorized scope.

## Commands

| Group | Subcommands |
|---|---|
| `help`, `doctor` | Help and capability checks |
| `scan` | `quick`, `deep`, `developer`, `emergency`, `targeted`, `health`, `safe-cleanup`, `custom` |
| `find` | `large`, `directories`, `duplicates` |
| `inspect` | `apps`, `storage`, `docker`, `activity`, `leftovers`, `trash`, `recycle-bin` |
| `plan` | `create`, `purge`, `show`, `validate` |
| `approve` | `quarantine`, `purge` |
| `clean` | `quarantine`, `restore`, `purge` |
| `verify`, `report` | Verify results; export audit or operation reports |
| `history` | `save`, `show`, `compare`, `operations` |
| `profile`, `catalog` | Restrictive preferences and detection rules |

[Full commands, options and examples](COMMANDS.md) · [Advanced recipes](docs/advanced.md)

For terminal use from a clone:

```sh
python scripts/swipr.py help
python scripts/swipr.py scan quick --root "/path/to/folder" --output audit.json
```

Scans never approve cleanup. File changes require an exact reviewed plan and fresh
approval. Quarantine retains bytecode; permanent removal requires separate irreversible
approval. Other categories use native cleanup guidance. See [platform support](docs/implementation-status.md).

[Usage](docs/usage.md) · [skills.sh listing steps](docs/publishing.md) ·
[Releases](https://github.com/kiron0/swipr/releases) · [Security](SECURITY.md) · [MIT](LICENSE)

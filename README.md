# Swipr

Local storage audits and safe cleanup through your AI agent.

## Install

```sh
npx skills add kiron0/swipr --skill swipr
```

skills.sh lists Swipr; `kiron0/swipr` identifies its source repository.
Update an existing installation with `npx skills update swipr`.

Requires Node.js 22.20+ for installation, Python 3.10+ for helpers, and an agent
with local filesystem access. Supports macOS, Windows, and Linux audits.

## Use

In Codex chat:

```text
$swipr start
$swipr scan quick --root ~/Downloads
$swipr find large --root ~/Downloads --min-bytes 104857600
$swipr scan developer --root ~/Projects/my-app
```

In Claude Code, use `/swipr` instead of `$swipr`. Other agents can use
`Use Swipr: help`. Choose your own folders.

Scans are read-only. File changes need an exact reviewed plan and fresh approval.
Quarantine retains files; permanent removal needs separate irreversible approval.

MIT License. Copyright (c) 2026 Toufiq Hasan Kiron.

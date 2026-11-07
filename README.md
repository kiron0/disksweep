<p align="center">
  <img src="assets/readme-cover.svg" alt="Swipr: less guesswork, more clarity. Audit your storage and review every change." width="1200" />
</p>

<p align="center">
  <a href="https://skills.sh/kiron0/swipr/swipr">View Swipr on skills.sh</a>
</p>

# Swipr

**Understand your disk. Review what can go.**

An agent skill for local storage audits and carefully approved cleanup.
Find large files, investigate developer storage, and understand the evidence
before making changes.

## Install

```sh
npx skills add kiron0/swipr --skill swipr
```

Update with `npx skills update swipr`.
skills.sh lists the skill; `kiron0/swipr` identifies its source repository.

**Requirements:** Node.js 22.20+ for installation, Python 3.10+ for helpers,
and an AI agent with local filesystem access.

## Start in your agent

```text
$swipr start
```

Swipr scans your current local user profile, finds storage opportunities, then
shows one review prompt. Explicit folders or policies override that default.
The full scan includes discovery and analysis; it never approves removal.

On Windows, review the exact proposed files and choose **Permanently delete
selected files**. Submitting that choice executes and verifies removal directly.
The prompt clearly warns that deletion **cannot be undone** and bypasses Recycle Bin.
Agents with a question UI show selectable choices; no magic reply phrase is required.

| Agent | Invocation |
| :--- | :--- |
| Codex | `$swipr start` |
| Claude Code | `/swipr start` |
| Other agents | `Use Swipr: start` |

## Choose a task

These examples use Codex. Replace the folders with your own authorized locations.

| You want to… | Ask Swipr |
| :--- | :--- |
| Quick audit | `$swipr scan quick --root ~/Downloads` |
| Files over 100 MiB | `$swipr find large --root ~/Downloads --min-bytes 104857600` |
| Developer storage | `$swipr scan developer --root ~/Projects/my-app` |
| Storage health | `$swipr scan health --root ~/Projects/my-app` |
| Possible duplicates | `$swipr start --goal duplicates` |
| Commands and options | `$swipr help` |

The default scan groups same-size files without reading contents. Exact duplicate
hashing requires separate approval and a supported POSIX platform.

## Review before changing anything

1. **Audit** your user profile or selected folders within time, depth, and entry limits.
2. **Understand** findings, recorded evidence, side effects, and recovery options.
3. **Choose** the next action in one review prompt. Supported changes require an
   exact plan and fresh approval; submitting the irreversible Windows choice runs it directly.

The full pass has limits of 100,000 entries, 32 levels, and 60 seconds. Coverage
can be partial. Additional drives, other profiles and protected areas are excluded
unless separately scoped. Use `$swipr start --guide` for help without scanning.

Personal files, source, dependencies, credentials, backups, and system state stay
protected from automated cleanup. Most application and system maintenance uses
reviewed native controls. POSIX changes are limited to eligible Python bytecode. Windows supports exact
approved removal of owned files on local NTFS, with no folder recursion or force.

> Quarantine keeps files on the same disk and frees no space. Permanent removal
> requires a separate exact plan and explicit irreversible approval on POSIX.
> Windows direct removal is permanent from the start; Swipr cannot undo it.

## Compatibility

| Capability | macOS / Linux | Windows |
| :--- | :--- | :--- |
| Audits and reports | Supported | Supported |
| Duplicate hashing | POSIX handles required | Unavailable |
| Bytecode quarantine / purge | POSIX handles required | Unavailable |
| Exact selected-file permanent removal | Use bytecode workflow | Local NTFS; explicit approval |
| Native guidance | OS dependent | OS dependent |

<details>
<summary><strong>Terminal usage and detailed documentation</strong></summary>

From a cloned repository:

```sh
python scripts/swipr.py start
python scripts/swipr.py doctor
python scripts/swipr.py scan quick --root "/path/to/folder" --output audit.json
```

For a Skills CLI project installation, the adapter is normally at
`.agents/skills/swipr/scripts/swipr.py`. Use your installation's actual path.

`COMMANDS.md` contains every command, subcommand, option, and approval flow.
`docs/advanced.md` contains recipes for policies, profiles, reports, and history.
`docs/implementation-status.md` records platform limits and supported actions.

</details>

---

MIT License · Copyright (c) 2026 Toufiq Hasan Kiron.

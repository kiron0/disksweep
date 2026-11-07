# Listing Swipr on skills.sh

Swipr is distributed from the public [kiron0/swipr repository](https://github.com/kiron0/swipr).
There is no separate skill-file upload step for the skills.sh directory.
The [official FAQ](https://skills.sh/docs/faq) says directory listings are generated
from anonymous Skills CLI installation events.

## Your next step

1. Use Node.js 22.20+ and keep the repository public with its root `SKILL.md`.
2. Run a normal install on your computer and choose your agent:

   ```sh
   npx skills add kiron0/swipr --skill swipr
   ```

   To select Codex directly:

   ```sh
   npx skills add kiron0/swipr --skill swipr -a codex
   ```

3. Check discovery and the directory page after processing:

   ```sh
   npx skills find swipr
   ```

   Expected page: [skills.sh/kiron0/swipr/swipr](https://skills.sh/kiron0/swipr/swipr).
   Installation success is not proof that the directory page is indexed yet.

`--list` only checks discovery. Downloading a GitHub release archive or installing
manually does not produce a Skills CLI install event. If you intentionally set
`DISABLE_TELEMETRY` or `DO_NOT_TRACK`, that install does not contribute listing data;
choose those settings deliberately. Do not generate fake or repeated installs to
inflate the ranking.

## If the listing does not appear

- Confirm `npx skills add kiron0/swipr --list` discovers `swipr`.
- Confirm the actual install completed successfully.
- Check that your network permits the installer's connection to skills.sh. A proxy
  can allow Git clone while blocking Node's registration request. Configure your
  runtime to use your network's proxy without sharing credentials in reports.
- Allow for directory processing and caching. The service does not provide a
  guaranteed listing time in its FAQ. Persistent indexing problems belong with
  the skills.sh maintainers; share the public repository URL, not local inventories.

## Release files

[Releases](https://github.com/kiron0/swipr/releases) include the versioned `.skill`
archive and `SHA256SUMS`. A `.skill` file is a ZIP containing the `swipr/` folder.
Extract it into your agent's skills directory for manual installation. The release
asset can be ready and usable while directory indexing is still pending.

Sources: [Skills CLI](https://github.com/vercel-labs/skills),
[listing FAQ](https://skills.sh/docs/faq).

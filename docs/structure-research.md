# Public skill structure research

Research date: 2026-11-07.

Selection: five leading multi-skill collections in the first 15 results of GitHub repository search `agent skills in:name,description`, sorted by stars descending. Curated application lists and single-purpose skill repositories were excluded. This is a documented comparison set, not a claim of an authoritative universal “top five” leaderboard. Star counts change.

Only structural ideas were used; no upstream implementation or skill prose is redistributed. Swipr is independently written and MIT licensed. Anthropic’s example skill-creator has its own Apache-2.0 license; do not infer a repository-wide license from GitHub metadata.

| Collection | Stars at inspection | Inspected skill / pinned revision | Applied structure |
|---|---:|---|---|
| mattpocock/skills | 317,137 | [skills/engineering/ask-matt/SKILL.md](https://github.com/mattpocock/skills/blob/4ae2317ddb22b046e26455e4f9c9b3aaaf62212d/skills/engineering/ask-matt/SKILL.md) | Concise triggers and a workflow-oriented entry point with links to narrower skills. |
| obra/superpowers | 313,830 | [skills/verification-before-completion/SKILL.md](https://github.com/obra/superpowers/blob/22f0b463e7a5e579904dd6211a520321035526f7/skills/verification-before-completion/SKILL.md) | Explicit gates and verification evidence before declaring success. |
| affaan-m/ECC | 298,834 | [.agents/skills/coding-standards/SKILL.md](https://github.com/affaan-m/ECC/blob/d2ef2680594f9a17526a6e1a2e18b3d242c5d17b/.agents/skills/coding-standards/SKILL.md) | Clear activation and scope boundaries, with reusable rules outside the entry point. |
| anthropics/skills | 188,338 | [skills/skill-creator/SKILL.md](https://github.com/anthropics/skills/blob/2c5958ecac7cee2b583967a2c4981d0f4a75c579/skills/skill-creator/SKILL.md) | Progressive disclosure into scripts, references and assets; evaluation fixtures. |
| addyosmani/agent-skills | 113,811 | [skills/browser-testing-with-devtools/SKILL.md](https://github.com/addyosmani/agent-skills/blob/301b02b12bff98e4688e6984af6556802322bbde/skills/browser-testing-with-devtools/SKILL.md) | Concrete examples, tool-capability requirements, and explicit security boundaries. |

## Resulting decisions

- Root `SKILL.md` with portable name/description/license/compatibility metadata.
- Keep procedural gates in the entry point; load platform and category references on demand.
- Put deterministic filesystem and approval behavior in small Python helpers.
- Use versioned non-executable rules and JSON contracts rather than natural-language deletion guesses.
- Include behavioral eval prompts as well as filesystem/security regression tests.
- Preserve the user brief’s repository docs and staged rollout; do not claim stable v1.0 readiness.

Additional specification reference: https://agentskills.io/specification . Codex UI metadata follows the public `agents/openai.yaml` pattern in https://github.com/openai/skills . These are supporting references, outside the five-collection comparison.

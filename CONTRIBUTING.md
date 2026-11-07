# Contributing

Start with an issue describing a reproducible storage problem and expected protection
boundaries. Use synthetic paths and redacted metadata. Do not submit personal inventories.

Runtime must remain offline and standard-library-only (Python 3.10+). Helpers accept
one JSON object on stdin and emit an envelope on stdout. Do not add a standalone
installed product, telemetry, arbitrary shell execution, or a background
service. The optional noninteractive command adapter delegates to these same helpers;
it must preserve every scope, policy, approval, revalidation, and journaling gate.

## Development

Install the development-only validators, then run the checks:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/check_project.py --strict
```

On Windows use `.venv\Scripts\python.exe`. Build a local skill archive with
`python3 scripts/package_skill.py dist/swipr.skill`.

## Rule release gate

Every rule must document its supported OS/tool versions, validated location and
application evidence, classification, exclusions, side effects, recovery mechanism,
authorization boundary, implementation strategy, and post-action verification.
Add positive, negative and adversarial fixtures. An executable rule additionally
needs identity/race, interruption, permission, fixed-inventory, approval expiration,
replay, recovery, and failure-path tests. A filename, age, or absent app is insufficient.
No broad cache/temp/project cleanup rule will be accepted without deterministic evidence.

Run `python3 -m unittest discover -s tests -v` and
`python3 scripts/check_project.py --strict` with requirements-dev.txt installed.
Tests must only operate on disposable temporary fixtures. Update schemas, references,
implementation status, and CHANGELOG for behavior changes. Increment rule versions when
semantics change. The whole catalog digest invalidates older plans.

Use clear commits explaining the problem and resulting behavior. Security reports
belong in the private disclosure channel described in SECURITY.md.

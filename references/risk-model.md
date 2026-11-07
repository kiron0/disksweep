# Risk and evidence model

| Classification | Meaning | Treatment |
|---|---|---|
| SAFE-CANDIDATE | Source-backed CPython artifact under a recognized project | May enter narrow quarantine planning; still revalidate and approve |
| REVIEW | Known cache/diagnostic path, importance or active use uncertain | Audit and native guidance only |
| PROTECTED | Personal, source, unknown, credentials, state, backups, dependencies | Exclude from cleanup helpers |
| UNSUPPORTED | Unreadable, redirected, mounted, or unimplemented operation | Report limitation; do not infer safe |

Low/moderate risk describes likely disruption, not permission. Signatures cannot prove
reproducibility, installation status, active-use status, or offline availability.
Rule confidence never overrides protection. The detector associates paths with tools;
it does not claim that a cache's generating application is installed merely because
the path exists. Tool executable presence is reported independently by the probe.

Directory-level orphan detection, filesystem clone detection, and reliable active-file
inspection are not implemented. Do not infer these from age, names, or process listings.

# Risk and evidence model

| Classification | Meaning | Treatment |
|---|---|---|
| SAFE-CANDIDATE | Source-backed CPython artifact under a recognized project | May enter an exact removal plan; still revalidate and approve |
| REVIEW | Known cache/diagnostic path, importance or active use uncertain | May enter an exact removal plan only with explicit approval; explain side effects |
| PROTECTED | Personal, source, unknown, credentials, state, backups, dependencies | Exclude from cleanup helpers |
| UNSUPPORTED | Unreadable, redirected, mounted, or unimplemented operation | Report limitation; do not infer safe |

Low/moderate risk describes likely disruption, not permission. Signatures cannot prove
reproducibility, installation status, active-use status, or offline availability.
Rule confidence never overrides protection. The detector associates paths with tools;
it does not claim that a cache's generating application is installed merely because
the path exists. Tool executable presence is reported independently by the probe.

Use applications.py and leftovers.py for possible residual associations, and activity.py
for observed open handles where available. Missing applications or unobserved handles
never prove disposability. Clone/snapshot physical savings remain unknown.

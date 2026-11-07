# Docker and containers

Ask whether the authorized Docker context is local or remote and whether container
metadata inspection is within scope. Docker socket access is privileged. Do not
change contexts, start daemons, or acquire elevated permissions for an audit.

`docker_audit.py` requires `authorized: true` and invokes only fixed read-only interfaces:
`docker system df --format '{{json .}}'` and `docker builder du --format json`.
Each query has a timeout and report-size limit. Missing daemon, permission failure,
unsupported versions/flags, and absent Docker are reported as unavailable/unsupported.
Output is untrusted metadata and may contain names; keep it local or redact it.

Describe build cache, images, stopped containers, and volume usage separately. Volumes,
especially databases, remain protected. Do not issue `docker system prune`, delete
Docker Desktop virtual disks, or delete files inside Docker's data root. No Docker
mutation is enabled in this release. Any future native prune rule must solve fixed
inventory, version compatibility, effects, concurrency and approval boundaries first.

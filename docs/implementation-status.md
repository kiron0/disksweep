# Supported features

All seven phases are provided: discover, analyze, classify, recommend, approve,
execute, and verify. The [feature coverage](feature-coverage.md) maps the original
brief to helpers, references, and tests. Platform capabilities determine which
operations the agent can perform locally.

| Feature | macOS / Linux | Windows |
|---|---|---|
| Bounded metadata audits, sizes, large files, risk classification | Automated | Automated |
| Ten modes, project-artifact detection, comparisons and health findings | Automated | Automated |
| Installed-app associations and potential leftovers | Authorized native inventory | Authorized native inventory |
| Trash / Recycle Bin usage | Explicit protected metadata scope | Native current-user bin query |
| Filesystem, logs, snapshots and volume discovery | Authorized native queries | Authorized native queries |
| Duplicate hashing | Approved safe-handle hashing | Metadata only; content hashing unavailable |
| Persistent signed policies and snapshots | Private local state | Session policies; persistent helper unavailable |
| Bytecode quarantine, restoration, signed approval and journaling | Automated after exact approval | Native user-guided cleanup |
| Permanent removal of verified private bytecode quarantine | Separate irreversible approval | Native user-guided cleanup |
| Browser, package, Docker and system maintenance | Native user-guided cleanup | Native user-guided cleanup |

## What the checks establish

Fixture tests cover rule matching, all modes, proposals, comparison, policies,
private snapshots, native-output handling, protected Trash, approval, revalidation,
quarantine, restoration, permanent-removal boundaries, and failure handling.
CI runs Python 3.10 and 3.12 on Linux, macOS and Windows. The Actions page records
results for each commit; Windows skips tests for unavailable POSIX mutation APIs.

Native tools are queried only with scope approval. Missing tools, version differences,
permissions, or unavailable interfaces produce explicit partial/unsupported results.
Tests use synthetic filesystem and native-output fixtures, not every application
version or real user profile. There is no claim of independent security review,
individual host-agent certification, or precise clone/snapshot-aware physical savings.

The original document's v0.1–v1.0 milestones describe development stages, not the
release numbering. This project's first published stable version is 0.1.0.

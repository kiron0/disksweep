# Linux

Start with exact known user-cache directories such as `~/.cache/pip` and
`~/.cache/thumbnails`, plus requested projects. Honor XDG_CACHE_HOME for discovery;
unrecognized custom layouts remain protected rather than matching a generic cache name.

Protect `/etc`, `/usr`, `/boot`, `/var/lib`, package databases, server data, and
container-host storage. Do not sweep `/tmp` or `/var/tmp`, even if files are old.
The inventory skips separate filesystems, links and detected Linux bind mounts;
an explicitly selected mount root is its own separate authorization scope.

Read-only native probes may include `journalctl --disk-usage` or a distribution's
package-cache inventory. System log retention and package maintenance must use the
native manager after separate scope review. Do not invoke blanket package purges,
`rm -rf`, journal vacuuming, or Docker pruning from this skill's bytecode approval.

POSIX bytecode quarantine requires user-owned single-link artifacts, a corresponding
source and project marker, same-filesystem private state, stopped workloads, exact
approval, and runtime-matching bytecode magic. Root privilege is never requested.

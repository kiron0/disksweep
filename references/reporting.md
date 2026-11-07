# Storage reporting

Report scope, OS, scan limits, completeness, errors, logical size, allocated bytes where
available, classification, rule evidence, application association, side effects, recovery,
and next actions. Use `assets/report-template.md` as a narrative template.

Inventory JSON has exact paths for local planning. Markdown is shareable by default:
it replaces all file paths and names with opaque item IDs and reports root counts.
Use `shareable: false` only for a private local report the user requests. Do not paste
unredacted inventory, Docker metadata, usernames, or approval notes into public issues.
Save reports only with consent, owner-only file permissions, and an agreed retention policy.

Sizes count each device/inode pair once. Sparse files can have fewer allocated than
logical bytes. Compression, clones, snapshots, reflinks, deduplicated blocks, remote
filesystems and delayed release can invalidate naive savings calculations. Allocated
bytes are not necessarily uniquely owned or physically recoverable. Unsupported
allocation measurement is `null`, not zero-sized storage.

After execution, report approved count, successful/verified moves, failed attempts,
unattempted IDs, before and after available bytes, observed delta, reversibility,
quarantine location, and follow-up. A positive delta may be unrelated system activity;
quarantine itself frees no file allocation and journal writes can reduce free space.
No performance improvement is guaranteed.

# macOS

Start with user-selected locations under `~/Library/Caches`, downloads metadata,
Homebrew downloads, user DiagnosticReports, or specific developer projects. The probe
suggests existing known roots without granting permission to scan all of Library.

Never broadly delete `/System`, `/Library`, `~/Library`, application containers,
Application Support, Keychains, signing certificates, provisioning profiles, device
backups, or simulator data. Treat Xcode DerivedData as REVIEW, preserve archives,
and use Xcode-supported controls for simulator content.

For system storage, guide the user to System Settings → General → Storage.
APFS snapshots/purgeable storage are system-managed and are not generic file cleanup
candidates. No snapshot deletion or system database edits are implemented. APFS clones
and snapshots mean file allocation does not guarantee recoverable physical bytes.

POSIX bytecode quarantine can run when safe directory handles and a matching CPython
runtime are available. OS release, Apple Silicon/Intel compatibility, and native app
versions still require separate testing; local validation does not establish all of them.

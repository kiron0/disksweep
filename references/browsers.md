# Browser storage

Recognized paths are audit hints, not a complete inventory of every browser version.
Chromium includes selected Chrome, Edge, Brave, and Chromium default-profile resource
cache paths. Firefox cache roots and Safari's resource cache have separate signatures.
Other profiles, custom cache flags, and managed installations require native inspection.

Protect cookies, sessions, passwords, autofill, History, Bookmarks, extensions,
Preferences, IndexedDB, Local Storage, Service Worker state, and offline website data.
Never delete or move a browser profile wholesale. Absence of a visible browser process
does not prove files are unused. Do not force-close browsers.

Offer the browser's supported Clear Browsing Data / cache-only control for the user's
own review. Clearly distinguish cached images/files from cookies and website data.
Warn that cache regeneration can cost network and CPU, and offline pages may be affected.
Swipr does not automate that UI or claim a fixed bytecode plan authorizes it.

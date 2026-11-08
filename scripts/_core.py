"""Swipr's offline, standard-library-only filesystem and policy engine.

Source-backed bytecode can be quarantined, then permanently removed through a
separate approval protocol. Other rules are informational; arbitrary deletion
and automatic Trash emptying are excluded.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import hmac
import html
import importlib.util
import fnmatch
import getpass
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import time
from collections import defaultdict

VERSION = "0.1.5"
BASE = Path(__file__).resolve().parent.parent
KINDS = {"SAFE-CANDIDATE", "REVIEW", "PROTECTED", "UNSUPPORTED"}
PRUNE = {".git", ".svn", ".hg", ".ssh", ".aws", ".gnupg", ".azure",
         "node_modules", ".venv", "venv", "env", "site-packages", ".swipr", ".disksweep",
         "onedrive", "dropbox", "google drive", "googledrive", "icloud drive",
         "mobile documents", "cloudstorage", "backups", "backup", "time machine"}
PROTECTED_PARTS = PRUNE | {"system32", "winsxs", "windowsapps", "keychains",
                          "credentials", "indexeddb", "local storage", "sessions",
                          "certificates", "volumes", "databases", ".trash", "trash", "$recycle.bin"}
PROTECTED_NAMES = {"cookies", "login data", "bookmarks", "history", "preferences",
                   "web data", "wallet.dat", "id_rsa", "id_ed25519"}
SYSTEM_ROOTS = ("/etc", "/usr", "/boot", "/var/lib", "/proc", "/sys", "/dev",
                "/System", "/Library", "/bin", "/sbin", "/lib", "/lib64")
SYSTEM_ROOT_PATHS = tuple(Path(x) for x in SYSTEM_ROOTS)
WINDOWS_SYSTEM_PARTS = {"windows", "program files", "program files (x86)", "programdata"}
_RULES_CACHE = {}
_SIGNATURE_CACHE = {}


class Refusal(ValueError):
    """An operation failed a deterministic safety check."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(canonical(data)).hexdigest()


def platform_id():
    return {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(platform.system(), "unsupported")


def identity(s):
    return {"device": s.st_dev, "inode": s.st_ino, "mode": s.st_mode,
            "size": s.st_size, "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns,
            "links": s.st_nlink}


def redirect(s):
    return stat.S_ISLNK(s.st_mode) or bool(getattr(s, "st_file_attributes", 0) & 0x400)


def absolute(path):
    p = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    # Resolve no links: every existing component must be a real directory/file.
    for part in [*reversed(p.parents), p]:
        require(not redirect(part.lstat()), "Symbolic links and reparse points are excluded")
    return p


def inside(path, root):
    child, parent = path.parts, root.parts
    if len(child) < len(parent):
        return False
    if os.name == "nt":
        return all(a.lower() == b.lower() for a, b in zip(child, parent))
    return child[:len(parent)] == parent


def protected(path, exclusions=()):
    parts = {x.casefold() for x in path.parts}
    if parts & PROTECTED_PARTS or path.name.casefold() in PROTECTED_NAMES:
        return True
    if path.name.startswith(".env") or path.suffix.casefold() in {".db", ".sqlite", ".sqlite3", ".pem", ".key", ".p12", ".pfx", ".kdbx"}:
        return True
    if any(inside(path, x if isinstance(x, Path) else Path(x)) for x in exclusions):
        return True
    if os.name != "nt" and any(inside(path, x) for x in SYSTEM_ROOT_PATHS):
        return True
    if os.name == "nt" and parts & WINDOWS_SYSTEM_PARTS:
        return True
    return False


def read_rules():
    files = sorted((BASE / "rules").glob("*/*.json"))
    key = []
    for file in files:
        s = file.stat()
        key.append((str(file), s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns))
    key = tuple(key)
    if key not in _RULES_CACHE:
        _RULES_CACHE.clear()
        _RULES_CACHE[key] = json.dumps(_load_rules(files))
    return json.loads(_RULES_CACHE[key])


def _load_rules(files):
    rules = []
    seen = set()
    for file in files:
        for rule in json.loads(file.read_text(encoding="utf-8")):
            require(rule["id"] not in seen, "Duplicate rule identifier")
            require(rule["strategy"] in {"audit-only", "quarantine-bytecode"}, "Unsupported rule strategy")
            require(rule["classification"] in KINDS and rule["version"] == 1, "Invalid rule")
            require(rule["classification"] == ("SAFE-CANDIDATE" if rule["strategy"] == "quarantine-bytecode" else "REVIEW"), "Contradictory rule")
            require(rule["strategy"] != "quarantine-bytecode" or rule["id"] == "python-bytecode", "Only verified bytecode quarantine is implemented")
            require(not ({"command", "script", "shell"} & rule.keys()), "Executable rule data is forbidden")
            if rule.get("project_markers"):
                require(rule["strategy"] == "audit-only" and isinstance(rule["project_markers"], list) and isinstance(rule.get("artifact_paths"), list), "Invalid project rule")
                require(all(isinstance(p, str) and p and not Path(p).is_absolute() and ".." not in Path(p).parts for p in rule["project_markers"] + rule["artifact_paths"]), "Unsafe project rule path")
            seen.add(rule["id"])
            rules.append(rule)
    return rules


def mount_points():
    """Linux mountinfo includes same-device bind mounts missed by ismount()."""
    mounts = set()
    if platform_id() == "linux":
        try:
            for line in Path("/proc/self/mountinfo").read_text().splitlines():
                mount = line.split(" - ", 1)[0].split()[4]
                mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), mount)
                mounts.add(Path(mount))
        except (OSError, IndexError):
            pass
    return mounts


def project_for_bytecode(path, root):
    if path.parent.name != "__pycache__" or path.suffix != ".pyc":
        return None
    # The CPython cache tag and source file must agree; names alone are not evidence.
    match = re.fullmatch(r"(.+)\.cpython-\d{2,3}(?:\.opt-[12])?\.pyc", path.name)
    if not match:
        return None
    source = path.parent.parent / (match[1] + ".py")
    try:
        source = absolute(source)
        if not stat.S_ISREG(source.lstat().st_mode) or protected(source):
            return None
        for parent in [source.parent, *source.parent.parents]:
            if not inside(parent, root):
                break
            for name in ("pyproject.toml", "setup.py", "setup.cfg"):
                marker = parent / name
                if marker.exists() and not redirect(marker.lstat()) and marker.is_file():
                    return {"source": str(source), "source_identity": identity(source.stat()),
                            "project": str(parent), "marker": str(marker),
                            "marker_identity": identity(marker.stat())}
    except (OSError, Refusal):
        return None
    return None


def signature_index(signatures):
    index = _SIGNATURE_CACHE.get(signatures)
    if index is None:
        literal, wildcard = defaultdict(list), []
        for order, signature in enumerate(signatures):
            segments = tuple((x, any(c in x for c in "*?[")) for x in signature.casefold().split("/"))
            (wildcard if segments[0][1] else literal[segments[0][0]]).append((order, segments))
        index = _SIGNATURE_CACHE[signatures] = (dict(literal), wildcard)
    return index


def first_signature(parts, signatures):
    literal, wildcard = signature_index(signatures)
    best = None
    for i, part in enumerate(parts):
        for order, segments in (*literal.get(part, ()), *wildcard):
            if best is not None and order >= best or i + len(segments) > len(parts):
                continue
            if all(fnmatch.fnmatchcase(parts[i + k], x) if glob else parts[i + k] == x
                   for k, (x, glob) in enumerate(segments)):
                best = order
    return best


def classify(path, root, info, rules, exclusions=()):
    if protected(path, exclusions):
        return None, "PROTECTED", None
    evidence = project_for_bytecode(path, root)
    parts = [x.casefold() for x in path.parts]
    current = platform_id()
    active = [rule for rule in rules if current in rule["platforms"]]
    owners = [(rule, x) for rule in active if rule["id"] != "python-bytecode" for x in rule["signatures"]]
    match = first_signature(parts, tuple(x for _, x in owners))
    for rule in active:
        if rule["id"] == "python-bytecode":
            if evidence and info["links"] == 1:
                return rule, "SAFE-CANDIDATE", evidence
            continue
        # Exact documented path signatures; a directory called Cache is not a rule.
        if match is not None and owners[match][0] is rule:
            return rule, "REVIEW", {"signature": owners[match][1], "active_use": "unknown"}
    return None, "PROTECTED", None


def disk_metadata(path):
    """Optional read-only volume measurements; failure never means zero free space."""
    try:
        usage = shutil.disk_usage(path)
        return {'total': usage.total, 'used': usage.used, 'free': usage.free, 'status': 'available'}
    except OSError as error:
        return {'total': None, 'used': None, 'free': None,
                'status': 'permission-denied' if isinstance(error, PermissionError) else 'unavailable'}


def probe(request):
    home = Path.home()
    pid = platform_id()
    cache = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))
    roots = {"linux": [cache / "pip", cache / "thumbnails", home / ".npm" / "_cacache",
                        cache / "google-chrome", cache / "chromium", cache / "mozilla"],
             "macos": [home / "Library/Caches/pip", home / "Library/Caches/Homebrew",
                        home / "Library/Developer/Xcode/DerivedData", home / "Library/Caches/Google/Chrome",
                        home / "Library/Caches/com.apple.Safari", home / ".npm/_cacache"],
             "windows": [Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local")) / p
                         for p in ("pip/Cache", "npm-cache/_cacache", "Google/Chrome/User Data", "Microsoft/Edge/User Data")]}
    selected = Path(request.get("path", home))
    disk = disk_metadata(selected)
    suggestions = []
    for path in roots.get(pid, []):
        try:
            if path.is_dir():
                suggestions.append(str(path))
        except OSError:
            pass
    mounts = []
    if pid == "linux":
        try:
            for line in Path("/proc/self/mountinfo").read_text().splitlines()[:256]:
                left, right = line.split(" - ", 1)
                fields = left.split()
                mounts.append({"path": fields[4], "filesystem": right.split()[0]})
        except OSError:
            pass
    tools = {name: bool(shutil.which(name)) for name in ("python3", "node", "npm", "pnpm", "yarn", "bun", "pip", "cargo", "rustc", "go", "dotnet", "gradle", "mvn", "docker", "brew", "xcodebuild")}
    return {"version": VERSION, "platform": pid, "os_version": platform.release(),
            "current_user": getpass.getuser(),
            "home": str(home), "disk": disk,
            'installation': {'version': VERSION, 'directory': str(BASE)},
            "access": {"read": os.access(selected, os.R_OK), "write": os.access(selected, os.W_OK), "administrator_requested": False},
            "backup_snapshot_tools": {name: bool(shutil.which(name)) for name in ("tmutil", "diskutil", "btrfs", "zfs", "vssadmin", "wbadmin")},
            "mounts": mounts, "tools": tools,
            "suggested_roots": suggestions,
            "capabilities": {"metadata": True,
                             "content_hashing": os.name == "posix" and os.open in os.supports_dir_fd,
                             "quarantine": os.name == "posix" and os.open in os.supports_dir_fd,
                             "direct_remove": os.name == 'nt',
                             "permanent_delete": os.name == 'nt' or (os.name == "posix" and os.open in os.supports_dir_fd),
                             "permanent_delete_scope": 'exact approved current-user local NTFS files' if os.name == 'nt' else "separately approved private bytecode quarantine only",
                             "active_use_detection": bool(shutil.which("lsof")) if os.name == "posix" else False,
                             "native_maintenance": "agent-guided; no automatic execution"},
            "notes": ["Suggested roots are proposals; scan only user-authorized scope.",
                      "Filesystem type and mounts are best effort; no mount is automatically authorized."]}


def scan(request):
    metadata_only = request.get("protected_metadata_only", False)
    require(not metadata_only or request.get("scope_review_approved") is True, "Protected metadata inspection requires explicit scope review")
    require(isinstance(request.get("roots"), list) and request["roots"], "Explicit roots are required")
    roots = [absolute(x) for x in request["roots"]]
    require(len(roots) <= 32, "At most 32 roots per scan")
    require(len(set(roots)) == len(roots), "Duplicate roots")
    require(not any(inside(a, b) for a in roots for b in roots if a != b), "Overlapping roots")
    exclusions = [os.path.abspath(os.path.expanduser(x)) for x in request.get("exclude", [])]
    excluded = [Path(x) for x in exclusions]
    windows = platform_id() == "windows"
    rules = read_rules()
    mounts = mount_points()
    limit = min(max(int(request.get("max_entries", 20000)), 1), 100000)
    seconds = float(request.get("max_seconds", 10))
    require(math.isfinite(seconds), "Scan time budget must be finite")
    seconds = min(max(seconds, 0.01), 120)
    depth = min(max(int(request.get("max_depth", 12)), 0), 64)
    started = time.monotonic()
    entries, issues, seen, count = [], [], set(), 0
    devices = {}
    complete = True
    for root in roots:
        require(root.is_dir() and (metadata_only or not protected(root, exclusions)), "Scan root is protected or not a directory")
        require(not any(inside(root, x) for x in excluded), "Scan root is excluded")
        rootdev = root.stat().st_dev
        devices[str(root)] = rootdev
        stack = [(root, 0)]
        while stack:
            directory, level = stack.pop()
            if time.monotonic() - started > seconds or count >= limit:
                issues.append({"path": str(directory), "reason": "resource-limit"}); complete = False; break
            try:
                # lstat all components on every expansion; never intentionally follow redirections.
                absolute(directory)
                require(directory.stat().st_dev == rootdev, "mount-boundary")
                secure_dir = directory_fd(directory) if os.name == "posix" else contextlib.nullcontext(directory)
                with secure_dir as directory_handle, os.scandir(directory_handle) as iterator:
                    for item in iterator:
                        if count >= limit or time.monotonic() - started > seconds:
                            issues.append({"path": str(directory), "reason": "resource-limit"}); complete = False; break
                        count += 1
                        path = directory / item.name
                        try:
                            if any(inside(path, x) for x in excluded):
                                issues.append({"path": str(path), "reason": "protected"}); continue
                            # Windows DirEntry.stat caches zero device/inode/link IDs.
                            # lstat() retrieves the complete filesystem identity there.
                            s = path.lstat() if windows else item.stat(follow_symlinks=False)
                            is_dir = stat.S_ISDIR(s.st_mode)
                            if redirect(s) or s.st_dev != rootdev or path in mounts or (is_dir and os.path.ismount(path)):
                                issues.append({"path": str(path), "reason": "redirection-or-mount"}); continue
                            if is_dir:
                                if path.name.casefold() in PRUNE or (not metadata_only and protected(path, excluded)):
                                    issues.append({"path": str(path), "reason": "protected"})
                                elif level < depth:
                                    stack.append((path, level + 1))
                                else:
                                    issues.append({"path": str(path), "reason": "depth-limit"}); complete = False
                                continue
                            if not stat.S_ISREG(s.st_mode):
                                continue
                            info = identity(s)
                            rule, kind, evidence = (None, "PROTECTED", None) if metadata_only else classify(path, root, info, rules, excluded)
                            allocated = getattr(s, "st_blocks", None)
                            allocated = allocated * 512 if allocated is not None else None
                            key = (s.st_dev, s.st_ino)
                            unique = key not in seen; seen.add(key)
                            candidate = {"path": str(path), "root": str(root), "identity": info,
                                         "created_ns": getattr(s, "st_birthtime_ns", None),
                                         "logical_bytes": s.st_size, "allocated_bytes": allocated,
                                         "unique_inode": unique, "classification": kind,
                                         "rule_id": rule["id"] if rule else None,
                                         "rule_version": rule["version"] if rule else None,
                                         "application": rule["application"] if rule else "unknown",
                                         "category": rule["category"] if rule else "personal-or-unknown",
                                         "risk": rule["risk"] if rule else "high",
                                         "reason": rule["reason"] if rule else "No verified disposable-artifact rule",
                                         "side_effects": rule["side_effects"] if rule else "Potential loss of user or application data",
                                         "recovery": rule["recovery"] if rule else "Unknown; preserve",
                                         "strategy": rule["strategy"] if rule else "audit-only",
                                         "evidence": evidence, "active_use": "unknown"}
                            candidate["id"] = digest({"path": str(path), "identity": info})[:24]
                            entries.append(candidate)
                        except (OSError, Refusal):
                            issues.append({"path": str(path), "reason": "unreadable-or-changed"}); complete = False
            except (OSError, Refusal):
                issues.append({"path": str(directory), "reason": "unreadable-or-changed"}); complete = False
    disks = []
    for root in roots:
        measurement = disk_metadata(root)
        disks.append({'root': str(root), 'device': devices[str(root)], 'free': measurement['free'],
                      'total': measurement['total'], 'space_status': measurement['status']})
        if measurement['status'] != 'available':
            issues.append({'path': str(root), 'reason': 'disk-space-' + measurement['status']})
    for issue in issues:
        issue["classification"] = "PROTECTED" if issue["reason"] == "protected" else "UNSUPPORTED"
    return {"schema_version": 1, "version": VERSION, "created_at": now(), "roots": list(map(str, roots)),
            "protected_metadata_only": bool(metadata_only),
            "exclude": exclusions, "complete": complete, "entries_visited": count,
            "entries": entries, "issues": issues, "disks": disks,
            "summary": summarize(entries), "changes_made": False}


def summarize(entries):
    out = {k: {"count": 0, "logical_bytes": 0, "allocated_bytes_known": 0} for k in sorted(KINDS)}
    for entry in entries:
        row = out[entry["classification"]]
        row["count"] += 1
        if entry["unique_inode"]:
            row["logical_bytes"] += entry["logical_bytes"]
            row["allocated_bytes_known"] += entry["allocated_bytes"] or 0
    return out


def safe_hash(entry, budget, read_counter=None):
    path = absolute(entry["path"])
    require(not protected(path), "Protected content cannot be hashed")
    require(entry["identity"]["size"] <= budget, "Hash byte budget exhausted")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with directory_fd(path.parent) as parent_fd:
        fd = os.open(path.name, flags, dir_fd=parent_fd)
        try:
            require(identity(os.fstat(fd)) == entry["identity"], "File changed before hashing")
            hasher = hashlib.sha256()
            remaining = entry["identity"]["size"]
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                require(chunk, "File changed during hashing")
                if read_counter is not None:
                    read_counter[0] += len(chunk)
                hasher.update(chunk); remaining -= len(chunk)
            require(identity(os.fstat(fd)) == entry["identity"], "File changed during hashing")
            return hasher.hexdigest()
        finally:
            os.close(fd)


def analyze(request):
    inventory = request["inventory"]
    entries = inventory["entries"]
    out = {"schema_version": 1, "summary": summarize(entries),
           "largest": sorted(entries, key=lambda x: x["logical_bytes"], reverse=True)[:min(int(request.get("top", 20)), 100)],
           "duplicates": [], "hash_bytes_read": 0, "hash_budget_charged_bytes": 0, "issues": [], "changes_made": False}
    if request.get("duplicates"):
        require(request.get("content_read_approved") is True, "Duplicate hashing requires explicit content-read approval")
        budget = min(max(int(request.get("max_hash_bytes", 256 * 1024**2)), 0), 4 * 1024**3)
        groups = defaultdict(list)
        by_id = {e["id"]: e for e in entries}
        for entry in entries:
            require(entry["root"] in inventory["roots"] and inside(Path(entry["path"]), Path(entry["root"])), "Hash candidate escaped inventory scope")
            if entry["unique_inode"] and entry["logical_bytes"] and not protected(Path(entry["path"]), inventory.get("exclude", [])):
                groups[entry["logical_bytes"]].append(entry)
        for group in groups.values():
            if len(group) < 2:
                continue
            matches = defaultdict(list)
            for entry in group:
                counter = [0]
                try:
                    remaining = budget - out["hash_budget_charged_bytes"]
                    require(entry["logical_bytes"] <= remaining, "Hash byte budget exhausted")
                    # Charge the allowance even if the post-read identity check fails.
                    out["hash_budget_charged_bytes"] += entry["logical_bytes"]
                    key = safe_hash(entry, remaining, counter)
                    matches[key].append(entry["id"])
                except (OSError, Refusal):
                    out["issues"].append({"id": entry["id"], "reason": "hash-skipped"})
                finally:
                    out["hash_bytes_read"] += counter[0]
            for hash_, ids in matches.items():
                if len(ids) > 1:
                    reference = min((by_id[x] for x in ids), key=lambda e: e["identity"]["mtime_ns"])
                    out["duplicates"].append({"sha256": hash_, "candidate_ids": ids,
                                              "reference_candidate_id": reference["id"], "reference_basis": "oldest modified copy; heuristic, not proof of origin",
                                              "classification": "PROTECTED", "automatic_removal": False,
                                              "physical_savings": None})
    from _audit import enrich_analysis
    out.update(enrich_analysis(inventory, request))
    if request.get("previous_inventory"):
        from _audit import compare
        out["comparison"] = compare({"before": request["previous_inventory"], "after": inventory})
    return out


class Store:
    """Private local trust anchor, separate from inventories and report files."""
    def __init__(self, path):
        require(os.name == "posix", "Private signed state requires POSIX permissions; Windows supports audit proposals only")
        self.path = Path(os.path.abspath(os.path.expanduser(path)))
        existing = self.path
        while not existing.exists():
            existing = existing.parent
        absolute(existing)
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        absolute(self.path)
        s = self.path.stat()
        if os.name == "posix":
            require(s.st_uid == os.getuid() and not s.st_mode & 0o077, "State directory must be owned by this user with mode 0700")
        keypath = self.path / "key"
        try:
            self.write_exclusive("key", secrets.token_bytes(32), raw=True)
        except FileExistsError:
            pass
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(keypath, flags)
        try:
            s = os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_size == 32 and s.st_nlink == 1, "Invalid state key")
            if os.name == "posix":
                require(s.st_uid == os.getuid() and not s.st_mode & 0o077, "Insecure state key")
            self.key = os.read(fd, 32)
        finally:
            os.close(fd)

    def write_exclusive(self, name, value, raw=False):
        data = value if raw else canonical(value)
        fd = os.open(self.path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())

    def signed(self, value):
        return {"payload": value, "signature": hmac.new(self.key, canonical(value), hashlib.sha256).hexdigest()}

    def save(self, name, value):
        self.write_exclusive(name, self.signed(value))

    def load(self, name):
        require(re.fullmatch(r"[a-z]+-[a-f0-9]{32}\.json", name), "Invalid state identifier")
        file = absolute(self.path / name)
        require(file.stat().st_size < 32 * 1024**2, "State object too large")
        value = json.loads(file.read_text(encoding="utf-8"))
        expected = self.signed(value["payload"])["signature"]
        require(hmac.compare_digest(expected, value["signature"]), "State object signature mismatch")
        return value["payload"]


def revalidate(entry, exclusions=()):
    path, root = absolute(entry["path"]), absolute(entry["root"])
    require(inside(path, root) and path != root, "Candidate escaped scope")
    require(not protected(path, exclusions), "Protected candidate")
    require(path.stat().st_dev == root.stat().st_dev, "Candidate crossed filesystem")
    mounts = mount_points()
    require(not any(p in mounts or os.path.ismount(p) for p in path.parents if inside(p, root) and p != root), "Candidate crosses a nested mount")
    require(identity(path.lstat()) == entry["identity"], "Candidate changed since inventory")
    require(os.name == "posix" and path.lstat().st_uid == os.getuid(), "Candidate must belong to the current user")
    rule, kind, evidence = classify(path, root, identity(path.lstat()), read_rules(), exclusions)
    require(rule and kind == "SAFE-CANDIDATE" and rule["strategy"] == "quarantine-bytecode", "Candidate is not executable")
    require(entry["rule_id"] == rule["id"] and entry["rule_version"] == rule["version"], "Rule changed")
    require(evidence == entry["evidence"], "Project or source changed")
    require(time.time_ns() - path.stat().st_mtime_ns >= 86400 * 10**9, "Bytecode is recent; leave it untouched")
    return path


def create_plan(request):
    inventory = request["inventory"]
    require(not inventory.get("protected_metadata_only"), "Protected metadata audits cannot authorize cleanup plans")
    store = Store(request["state_dir"])
    roots = [absolute(x) for x in inventory["roots"]]
    require(not any(inside(store.path, r) or inside(r, store.path) for r in roots), "State must be outside scan roots")
    selected = request.get("candidate_ids", [])
    require(selected and len(selected) == len(set(selected)) and len(selected) <= 1000, "Select 1–1000 distinct candidates")
    index = {e["id"]: e for e in inventory["entries"]}
    require(all(x in index for x in selected), "Unknown candidate identifier")
    entries = [index[x] for x in selected]
    for entry in entries:
        require(entry["root"] in inventory["roots"], "Candidate root is not in inventory scope")
        require(entry["id"] == digest({"path": entry["path"], "identity": entry["identity"]})[:24], "Forged candidate identity")
        revalidate(entry, inventory.get("exclude", []))
    require(len({x["identity"]["device"] for x in entries}) == 1, "Plan must use a single filesystem")
    require(entries[0]["identity"]["device"] == store.path.stat().st_dev, "Quarantine must use the same filesystem")
    plan = {"schema_version": 1, "id": secrets.token_hex(16), "created_at": now(),
            "expires_at": time.time() + 900, "action": "quarantine", "entries": entries,
            "rule_catalog_digest": digest(read_rules()),
            "exclude": inventory.get("exclude", []), "roots": inventory["roots"],
            "estimated_immediate_free_bytes": 0,
            "warning": "Quarantine moves files on the same filesystem and frees no disk space. Permanent removal requires a separate, newly approved purge plan.",
            "requires": "User approval of this exact plan after stopping the generating Python workload"}
    plan["digest"] = digest(plan)
    store.save("plan-" + plan["id"] + ".json", plan)
    return plan


def load_plan(store, plan_id):
    plan = store.load("plan-" + plan_id + ".json")
    require(time.time() < plan["expires_at"], "Plan expired; rescan and ask for approval again")
    require(plan["action"] == "quarantine", "Only quarantine is supported")
    require(plan["rule_catalog_digest"] == digest(read_rules()), "Rule catalog changed; rescan")
    for entry in plan["entries"]:
        revalidate(entry, plan["exclude"])
    return plan


def approve(request):
    store = Store(request["state_dir"])
    plan = load_plan(store, request["plan_id"])
    require(request.get("plan_digest") == plan["digest"], "Approval must match the displayed plan digest")
    require(request.get("user_approved") is True and request.get("workload_stopped") is True, "Fresh user approval and stopped-workload confirmation required")
    require(isinstance(request.get("approval_note"), str) and 1 <= len(request["approval_note"]) <= 1000, "Record a minimal approval note, without private transcript content")
    receipt = {"id": secrets.token_hex(16), "plan_id": plan["id"], "plan_digest": plan["digest"],
               "candidate_ids": [x["id"] for x in plan["entries"]], "expires_at": min(plan["expires_at"], time.time() + 300),
               "approval_note": request["approval_note"], "action": "quarantine", "workload_stopped": True}
    store.save("approval-" + receipt["id"] + ".json", receipt)
    return receipt


@contextlib.contextmanager
def directory_fd(path):
    """Pin every POSIX directory component, refusing symlinks throughout."""
    require(os.name == "posix" and os.open in os.supports_dir_fd, "Secure quarantine is unsupported on this platform")
    path = Path(path)
    require(path.is_absolute(), "Absolute path required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            new = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = new
        yield fd
    finally:
        os.close(fd)


def execute(request):
    require(os.name == "posix", "Windows execution is disabled; audit and plan only")
    store = Store(request["state_dir"])
    receipt = store.load("approval-" + request["approval_id"] + ".json")
    require(not os.path.lexists(store.path / ("used-" + receipt["id"] + ".json")), "Approval already used; inspect operation records before preparing a fresh plan")
    plan = load_plan(store, request["plan_id"])
    require(receipt["plan_id"] == plan["id"] and receipt["plan_digest"] == plan["digest"], "Approval does not match plan")
    require(receipt["candidate_ids"] == [x["id"] for x in plan["entries"]], "Approval scope mismatch")
    require(time.time() < receipt["expires_at"], "Approval expired")
    require(shutil.disk_usage(store.path).free >= len(canonical(plan)) * 4 + 65536, "Insufficient free space for safe operation journals; use reviewed native storage controls")
    # Atomic consumption prevents parallel/replayed execution, even after interruption.
    store.write_exclusive("used-" + receipt["id"] + ".json", {"started_at": now()})
    operation = {"schema_version": 1, "id": secrets.token_hex(16), "plan_id": plan["id"],
                 "approval_id": receipt["id"], "started_at": now(), "status": "running", "items": [],
                 "before_free": shutil.disk_usage(store.path).free, "after_free": None,
                 "observed_free_delta": None, "estimated_immediate_free_bytes": 0}
    quarantine = store.path / ("quarantine-" + operation["id"])
    quarantine.mkdir(mode=0o700)
    # Journal intent BEFORE the first move. Retain it for interrupted-operation recovery.
    store.save("operation-" + operation["id"] + ".json", {**operation, "pending": plan["entries"]})
    with directory_fd(quarantine) as target_fd:
        for entry in plan["entries"]:
            row = {"candidate_id": entry["id"], "original": entry["path"],
                   "quarantined": str(quarantine / entry["id"]), "identity": entry["identity"]}
            try:
                path = revalidate(entry, plan["exclude"])
                with directory_fd(path.parent) as source_fd:
                    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                    fd = os.open(path.name, flags, dir_fd=source_fd)
                    try:
                        require(identity(os.fstat(fd)) == entry["identity"], "Candidate changed before move")
                        # Reading four bytes is essential validation, only after approval.
                        require(os.read(fd, 4) == importlib.util.MAGIC_NUMBER, "Unrecognized bytecode magic for this Python runtime")
                        require(identity(os.stat(path.name, dir_fd=source_fd, follow_symlinks=False)) == entry["identity"], "Candidate changed before move")
                        os.rename(path.name, entry["id"], src_dir_fd=source_fd, dst_dir_fd=target_fd)
                        moved = os.stat(entry["id"], dir_fd=target_fd, follow_symlinks=False)
                        # Rename changes ctime; device/inode/type/size/mtime must agree.
                        expected = entry["identity"]
                        matched = all(identity(moved)[k] == expected[k] for k in ("device", "inode", "mode", "size", "mtime_ns", "links"))
                        if not matched:
                            # Restore the original name without overwriting a concurrent file.
                            # Retain the quarantine link as evidence; never unlink unknown data.
                            try:
                                os.link(entry["id"], path.name, src_dir_fd=target_fd,
                                        dst_dir_fd=source_fd, follow_symlinks=False)
                                row["concurrent_name_restored"] = True
                            except OSError:
                                row["concurrent_name_restored"] = False
                        require(matched, "Concurrent replacement detected; stop and inspect quarantine")
                        row["quarantine_identity"] = identity(moved)
                        row["status"] = "quarantined"
                    finally:
                        os.close(fd)
            except (OSError, Refusal):
                row["status"] = "failed-stop"
                row["reason"] = "Revalidation, bytecode validation, filesystem operation, or post-move identity check failed; inspect original and quarantine before retrying"
                operation["items"].append(row)
                store.save("item-" + secrets.token_hex(16) + ".json", {"operation_id": operation["id"], **row})
                break
            operation["items"].append(row)
            store.save("item-" + secrets.token_hex(16) + ".json", {"operation_id": operation["id"], **row})
    operation["after_free"] = shutil.disk_usage(store.path).free
    operation["observed_free_delta"] = operation["after_free"] - operation["before_free"]
    operation["status"] = "complete" if len(operation["items"]) == len(plan["entries"]) and all(x["status"] == "quarantined" for x in operation["items"]) else "partial"
    operation["finished_at"] = now()
    store.save("result-" + operation["id"] + ".json", operation)
    return operation


def verify(request):
    store = Store(request["state_dir"])
    result = store.load("result-" + request["operation_id"] + ".json")
    for item in result["items"]:
        if item["status"] == "quarantined":
            try:
                p = absolute(item["quarantined"])
                item["verified"] = identity(p.lstat()) == item["quarantine_identity"] and not os.path.lexists(item["original"])
            except (OSError, Refusal):
                item["verified"] = False
    result["verified_at"] = now()
    result["all_verified"] = result["status"] == "complete" and all(x.get("verified", False) for x in result["items"])
    result["free_now"] = shutil.disk_usage(store.path).free
    result["warning"] = "Free-space deltas include unrelated activity. Quarantine retains data and does not reclaim its allocation."
    return result


def restore(request):
    require(request.get("user_approved") is True, "Restoration requires user approval")
    store = Store(request["state_dir"])
    result = store.load("result-" + request["operation_id"] + ".json")
    rows = []
    for item in result["items"]:
        if item["status"] != "quarantined":
            continue
        row = {"candidate_id": item["candidate_id"], "status": "skipped"}
        try:
            path = absolute(item["quarantined"])
            original = Path(item["original"])
            require(identity(path.lstat()) == item["quarantine_identity"], "Quarantine object changed")
            require(not protected(original), "Restoration location is now protected")
            with directory_fd(path.parent) as source_fd, directory_fd(original.parent) as dest_fd:
                # link() is atomic and fails if the original name already exists.
                os.link(path.name, original.name, src_dir_fd=source_fd, dst_dir_fd=dest_fd, follow_symlinks=False)
            row["status"] = "restored-quarantine-link-retained"
        except (OSError, Refusal):
            row["reason"] = "Original exists, parent changed, or quarantine could not be validated"
        rows.append(row)
    restored = {"schema_version": 1, "id": secrets.token_hex(16), "operation_id": result["id"],
                "created_at": now(), "items": rows, "quarantine_retained": True}
    store.save("restore-" + restored["id"] + ".json", restored)
    return restored


def docker_audit(request):
    require(request.get("authorized") is True, "Docker socket inspection requires explicit scope authorization")
    require(shutil.which("docker"), "Docker is not installed")
    # Fixed arguments only. Honor the user's Docker context; no daemon mutation.
    commands = [["docker", "system", "df", "--format", "{{json .}}"],
                ["docker", "builder", "du", "--format", "json"]]
    results = []
    for args in commands:
        try:
            with __import__("tempfile").TemporaryFile() as stdout:
                proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 15
                while proc.poll() is None:
                    if time.monotonic() > deadline or os.fstat(stdout.fileno()).st_size > 1024 * 1024:
                        proc.kill(); proc.wait(); break
                    time.sleep(0.02)
                code = proc.returncode
                stdout.seek(0); data = stdout.read(1024 * 1024 + 1)
                truncated = len(data) > 1024 * 1024
            results.append({"interface": " ".join(args[:3]), "status": "ok" if code == 0 else "unsupported-or-unavailable",
                            "truncated": truncated,
                            "metadata": data[:1024 * 1024].decode("utf-8", errors="replace") if code == 0 else None})
        except OSError:
            results.append({"interface": " ".join(args[:3]), "status": "unavailable", "metadata": None})
    return {"results": results, "changes_made": False, "volumes_protected": True}


def human_report(request):
    if "operation" in request:
        from _audit import operation_report
        return operation_report(request)
    inventory = request["inventory"]
    shareable = request.get("shareable", True)
    def location(entry):
        if shareable:
            return "item-" + entry["id"][:8]
        # Untrusted names must never become Markdown links, images or HTML.
        value = html.escape(entry["path"].replace("\n", "\\n").replace("\r", "\\r"))
        return re.sub(r"([\\`*_{}\[\]()#+.!|>-])", r"\\\1", value)
    lines = ["# Swipr Storage Audit", "", "Status: read-only; no cleanup performed.",
             "Scope: " + str(len(inventory["roots"])) + " resolved roots.",
             "Coverage: " + ("complete within configured depth" if inventory["complete"] else "partial — inspect issues and limits"),
             "Skipped or limited locations: " + str(len(inventory["issues"])),
             "", "| Classification | Files | Logical bytes | Known allocated bytes |",
             "|---|---:|---:|---:|"]
    for kind, summary in inventory["summary"].items():
        lines.append(f"| {kind} | {summary['count']} | {summary['logical_bytes']} | {summary['allocated_bytes_known']} |")
    lines += ["", "Sizes count hard-linked inodes once. Shared blocks, clones, compression, snapshots and open files make physical savings uncertain.",
              "Quarantine's estimated immediate free-space increase is **0 bytes**.", "", "| Item | Logical bytes | Classification | Mechanism |", "|---|---:|---|---|"]
    if any(disk.get('free') is None for disk in inventory['disks']):
        lines.insert(7, 'Disk space: unknown for some roots; volume measurements were unavailable. File traversal coverage is reported separately.')
    for entry in sorted(inventory["entries"], key=lambda x: x["logical_bytes"], reverse=True)[:30]:
        lines.append(f"| {location(entry)} | {entry['logical_bytes']} | {entry['classification']} | {entry['strategy']} |")
    if request.get('include_next', True):
        lines += ["", "Next: review exact candidates, side effects and recovery. Approval applies only to a fixed, unexpired plan.",
                  "Native browser, package, Docker, OS, and Trash cleanup is guided review only. Unknown data remains protected."]
    return {"markdown": "\n".join(lines) + "\n", "shareable": shareable}

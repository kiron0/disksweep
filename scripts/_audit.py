"""Read-only advanced storage analysis and capability-aware skill modes."""
from collections import defaultdict
from pathlib import Path
import math
import os
import time

import _core as core

MODES = {"quick", "deep", "safe-cleanup", "developer", "emergency", "targeted",
         "duplicates", "health", "compare", "custom"}
POLICY_KEYS = {"roots", "exclude", "max_entries", "max_depth", "max_seconds",
               "max_hash_bytes", "preserve_offline", "never_permanently_delete"}
PROJECT_RULES = {rule["id"]: (tuple(rule["project_markers"]), tuple(rule["artifact_paths"]), rule["application"])
                 for rule in core.read_rules() if rule.get("project_markers")}


def policy(value):
    core.require(isinstance(value, dict) and not (set(value) - POLICY_KEYS), "Policy may restrict scan scope only; it cannot grant execution permission")
    for name in ("roots", "exclude"):
        if name in value:
            core.require(isinstance(value[name], list) and all(isinstance(x, str) and x for x in value[name]), "Policy paths must be nonempty strings in lists")
            core.require(name != "roots" or value[name], "A roots restriction cannot be empty")
    for name in ("preserve_offline", "never_permanently_delete"):
        if name in value:
            core.require(isinstance(value[name], bool), "Policy restrictions must be booleans")
    limits = {"max_entries": (1, 100000), "max_depth": (0, 64), "max_seconds": (.01, 120), "max_hash_bytes": (0, 4 * 1024**3)}
    for name, (minimum, maximum) in limits.items():
        if name in value:
            number = value[name]
            core.require(type(number) in ((int, float) if name == "max_seconds" else (int,)) and math.isfinite(number) and minimum <= number <= maximum, "Policy budget is outside supported limits")
    return value


def operation_report(request):
    result, plan = request["operation"], request["plan"]
    core.require("verified_at" in result and "all_verified" in result, "Verify the operation before generating a final cleanup report")
    core.require(isinstance(result["all_verified"], bool) and all(type(result[k]) is int for k in ("before_free", "after_free", "observed_free_delta")), "Invalid verification or storage measurements")
    core.require(result["plan_id"] == plan["id"], "Report plan and operation do not match")
    entries = plan.get("entries", plan.get("items", []))
    approved = {e.get("id", e.get("candidate_id")) for e in entries}
    core.require(all(isinstance(x, str) and core.re.fullmatch(r"[a-f0-9]{24}", x) for x in approved), "Invalid report candidate identifiers")
    core.require(isinstance(result["id"], str) and core.re.fullmatch(r"[a-f0-9]{32}", result["id"]), "Invalid report operation identifier")
    attempted = {x["candidate_id"] for x in result["items"]}
    core.require(attempted <= approved, "Operation contains items outside the reported plan")
    core.require(all(x["status"] in {"quarantined", "permanently-removed", "failed-stop"} for x in result["items"]), "Invalid operation status")
    successful = [x for x in result["items"] if x["status"] in {"quarantined", "permanently-removed"}]
    verified = sum(bool(x.get("verified", x.get("verified_absent", False))) for x in successful)
    failed = sum(x["status"] == "failed-stop" for x in result["items"])
    irreversible = result.get("irreversible", False)
    lines = ["# Swipr Cleanup Report", "", "Operation: " + result["id"],
             "Status: " + ("verified" if result["all_verified"] else "partial or verification incomplete"),
             "", f"Approved: {len(approved)}; processed: {len(successful)}; verified: {verified}; failed: {failed}; unattempted: {len(approved - attempted)}.",
             f"Available bytes before: {result['before_free']}; after: {result['after_free']}; observed delta: {result['observed_free_delta']}.",
             "Observed changes include journal writes and unrelated activity; shared blocks and snapshots can limit physical recovery.", "",
             "| Candidate ID | Status |", "|---|---|"]
    lines += [f"| {x['candidate_id']} | {x['status']} |" for x in result["items"]]
    lines += [f"| {x} | unattempted |" for x in sorted(approved - attempted)]
    lines += ["", "Permanent removal cannot be undone from quarantine." if irreversible else "Quarantine retains allocation. Restoration requires approval and skips existing originals; no immediate space is reclaimed."]
    return {"markdown": "\n".join(lines) + "\n", "shareable": True}


def project_finding(entry):
    path, root = Path(entry["path"]), Path(entry["root"])
    if core.protected(path):
        return None
    try:
        core.absolute(path)
        if core.identity(path.lstat()) != entry["identity"]:
            return None
    except (OSError, core.Refusal):
        return None
    for directory in [path.parent, *path.parent.parents]:
        if not core.inside(directory, root):
            break
        for rule_id, (markers, artifacts, app) in PROJECT_RULES.items():
            marker = None
            for name in markers:
                candidate = directory / name
                try:
                    if candidate.is_file() and not core.redirect(candidate.lstat()):
                        marker = candidate; break
                except OSError:
                    pass
            # Project-local .NET files are detected by metadata, never executed.
            if rule_id == "dotnet-build" and marker is None:
                try:
                    with os.scandir(directory) as items:
                        for index, item in enumerate(items):
                            if index >= 200:
                                break
                            if item.name.endswith((".csproj", ".fsproj", ".vbproj")) and item.is_file(follow_symlinks=False):
                                marker = directory / item.name; break
                except OSError:
                    pass
            if marker is None:
                continue
            if any(core.inside(path, directory / artifact) for artifact in artifacts):
                return {"candidate_id": entry["id"], "category": "project-build", "rule_id": rule_id,
                        "classification": "REVIEW", "application": app, "project": str(directory),
                        "marker": str(marker), "marker_identity": core.identity(marker.lstat()),
                        "mechanism": "Review the tool's supported clean/preview interface with this project stopped",
                        "side_effects": "Rebuild cost, test output loss, or unavailable offline dependencies; not automatically removable"}
    return None


def directory_totals(inventory):
    totals = {}
    seen = defaultdict(set)
    for entry in inventory["entries"]:
        root, path = Path(entry["root"]), Path(entry["path"])
        for parent in path.parents:
            if not core.inside(parent, root):
                break
            row = totals.setdefault(str(parent), {"path": str(parent), "files": 0, "logical_bytes": 0,
                                                  "allocated_bytes_known": 0, "coverage_complete": inventory["complete"]})
            key = (entry["identity"]["device"], entry["identity"]["inode"])
            if key not in seen[str(parent)]:
                seen[str(parent)].add(key)
                row["files"] += 1; row["logical_bytes"] += entry["logical_bytes"]
                row["allocated_bytes_known"] += entry["allocated_bytes"] or 0
    return sorted(totals.values(), key=lambda x: x["logical_bytes"], reverse=True)


def compare(request):
    before, after = request["before"], request["after"]
    core.require(before["roots"] == after["roots"] and before.get("exclude", []) == after.get("exclude", []), "Compare snapshots of the same scope and exclusions")
    old = {x["path"]: x for x in before["entries"]}; new = {x["path"]: x for x in after["entries"]}
    changed = [{"id": new[p]["id"], "path": p,
                "logical_delta": new[p]["logical_bytes"] - old[p]["logical_bytes"],
                "category": new[p]["category"]}
               for p in old.keys() & new.keys() if old[p]["identity"] != new[p]["identity"]]
    disks = {(x["root"], x["device"]): x["free"] for x in before["disks"]}
    return {"schema_version": 1, "added": [new[p]["id"] for p in new.keys() - old.keys()],
            "removed": [old[p]["id"] for p in old.keys() - new.keys()], "changed": changed,
            "available_space_deltas": [{"root": x["root"], "observed_delta": x["free"] - disks[(x["root"], x["device"])]}
                                       for x in after["disks"] if (x["root"], x["device"]) in disks],
            "coverage_complete": before["complete"] and after["complete"], "changes_made": False,
            "log_growth": [x for x in changed if x["category"] == "diagnostics" and x["logical_delta"] > 0],
            "regenerated_cache_candidates": [x["id"] for x in changed if "cache" in x["category"]],
            "warning": "Metadata changes do not prove abandonment, performance impact, or deletion eligibility"}


def recommendations(request):
    inventory = request["inventory"]
    rows = []
    cached = request.get("project_artifacts")
    project_index = {x["candidate_id"]: x for x in cached} if cached is not None else None
    started = time.monotonic()
    complete = request.get("project_analysis_complete", True)
    for index, entry in enumerate(inventory["entries"]):
        if inventory.get("protected_metadata_only"):
            continue
        if project_index is not None:
            project = project_index.get(entry["id"])
        elif index < 20000 and time.monotonic() - started < 10:
            project = project_finding(entry)
        else:
            project = None; complete = False
        kind = project["classification"] if project else entry["classification"]
        category = project["category"] if project else entry["category"]
        if kind == "PROTECTED" and not project:
            continue
        rows.append({"candidate_id": entry["id"], "path": entry["path"], "category": category,
                     "application": project["application"] if project else entry["application"],
                     "classification": kind, "logical_bytes": entry["logical_bytes"],
                     "allocated_bytes": entry["allocated_bytes"], "potential_reclaimable_upper_bound": entry["allocated_bytes"],
                     "estimated_immediate_free_bytes": 0 if entry["strategy"] == "quarantine-bytecode" else None,
                     "mechanism": entry["strategy"] if not project else project["mechanism"],
                     "evidence": project or entry["evidence"], "reason": entry["reason"] if not project else "Recognized project marker and exact tool output path",
                     "side_effects": project["side_effects"] if project else entry["side_effects"],
                     "recovery": entry["recovery"] if not project else "Rebuild where dependencies and tooling remain available",
                     "authorization": "not-approved"})
    rows.sort(key=lambda x: (x["classification"] != "SAFE-CANDIDATE", -x["logical_bytes"]))
    return {"schema_version": 1, "inventory_digest": core.digest(inventory), "candidates": rows,
            "project_analysis_complete": complete,
            "changes_made": False, "warning": "Recommendation is not execution authority; native actions require their own exact, reviewed scope"}


def sort_entries(entries, sort_by="size"):
    keys = {"size": lambda e: -e["logical_bytes"], "oldest": lambda e: e["identity"]["mtime_ns"],
            "location": lambda e: e["path"], "type": lambda e: Path(e["path"]).suffix.lower(),
            "application": lambda e: e["application"], "recoverability": lambda e: (e["strategy"] != "quarantine-bytecode", e["recovery"])}
    core.require(sort_by in keys, "Unsupported sort order")
    return sorted(entries, key=keys[sort_by])


def enrich_analysis(inventory, request):
    entries = inventory["entries"]
    sort_by = request.get("sort_by", "size")
    directories = directory_totals(inventory)
    projects = []
    started = time.monotonic()
    inspected = 0
    for entry in entries:
        if inspected >= 20000 or time.monotonic() - started > 10:
            break
        inspected += 1
        finding = project_finding(entry)
        if finding:
            projects.append(finding)
    health = []
    for disk in inventory["disks"]:
        try:
            usage = core.shutil.disk_usage(disk["root"])
            ratio = usage.free / usage.total if usage.total else 0
            health.append({"root": disk["root"], "free_bytes": usage.free, "free_ratio": ratio,
                           "storage_pressure": "critical" if ratio < .03 else "low-free-space" if ratio < .1 else "normal"})
        except OSError:
            health.append({"root": disk["root"], "storage_pressure": "unknown"})
    return {"ranked_files": sort_entries(entries, sort_by)[:min(max(int(request.get("top", 20)), 1), 100)],
            "directories": directories[:100], "project_artifacts": projects, "health": health,
            "project_analysis_complete": inspected == len(entries),
            "temporary_candidates": [{"candidate_id": e["id"], "age_seconds": max(0, (time.time_ns() - e["identity"]["mtime_ns"]) / 10**9),
                                       "stale_for_review": time.time_ns() - e["identity"]["mtime_ns"] >= 7 * 86400 * 10**9,
                                       "active_use": "unknown", "classification": "REVIEW", "automatic_removal": False}
                                      for e in entries if e["category"] == "application-temporary"],
            "limitations": ["Metadata does not prove a file is inactive", "Clone/snapshot/shared-block savings are unknown",
                            "Storage cleanup is not a universal performance fix"]}


def leftovers(request):
    inventory, applications = request["inventory"], request["applications"]
    core.require(isinstance(applications, dict) and applications.get("source") == "native-installed-applications", "Supply a native application inventory")
    names = "\n".join(str(x.get("name", "")) + " " + str(x.get("id", "")) for x in applications.get("applications", [])).casefold()
    aliases = {"pip": ("python",), "CPython": ("python",), "npm": ("node", "npm"), "Yarn": ("yarn",),
               "Bun": ("bun",), "Cargo": ("rust", "cargo"), "Gradle": ("gradle",), "Xcode": ("xcode",),
               "Firefox": ("firefox",), "Safari": ("safari",), "Homebrew": ("homebrew",),
               "Chromium family": ("chrome", "chromium", "edge", "brave")}
    rows = []
    for entry in inventory["entries"]:
        app = entry["application"]
        if app not in aliases:
            continue
        found = any(alias in names for alias in aliases[app])
        rows.append({"candidate_id": entry["id"], "application": app,
                     "association": "present-in-native-inventory" if found else "not-observed-in-native-inventory",
                     "possible_leftover": not found, "classification": "REVIEW", "automatic_removal": False,
                     "inventory_complete": applications.get("complete", False),
                     "reason": "A missing executable or incomplete installed inventory never establishes safe deletion"})
    return {"associations": rows, "changes_made": False}


def trash(request):
    core.require(request.get("authorized") is True, "Trash inspection requires selected scope approval")
    scope, _ = resolve_scope(request)
    inventory = core.scan({**scope, "protected_metadata_only": True, "scope_review_approved": True})
    # Contents remain recoverable personal data, irrespective of apparent age/type.
    return {"schema_version": 1, "inventory": inventory,
            "logical_bytes": sum(x["logical_bytes"] for x in inventory["entries"] if x["unique_inode"]),
            "allocated_bytes_known": sum(x["allocated_bytes"] or 0 for x in inventory["entries"] if x["unique_inode"]),
            "classification": "PROTECTED", "emptying_authorized": False, "changes_made": False,
            "warning": "Retention preserves recovery. Moving to Trash usually does not free space on the same filesystem; emptying is irreversible and needs separate approval"}


def profiles(request):
    value = policy(request.get("policy", {}))
    if not request.get("save"):
        return {"policy": value, "execution_authorized": False}
    core.require(request.get("user_approved") is True, "Saving preferences requires user consent")
    store = core.Store(request["state_dir"])
    profile = {"id": core.secrets.token_hex(16), "policy": value, "created_at": core.now(), "execution_authorized": False}
    store.save("profile-" + profile["id"] + ".json", profile)
    return profile


def snapshots(request):
    store = core.Store(request["state_dir"])
    if request.get("snapshot_id"):
        return store.load("snapshot-" + request["snapshot_id"] + ".json")
    core.require(request.get("user_approved") is True, "Saving a private inventory snapshot requires consent")
    snapshot = {"id": core.secrets.token_hex(16), "created_at": core.now(), "inventory": request["inventory"],
                "execution_authorized": False}
    store.save("snapshot-" + snapshot["id"] + ".json", snapshot)
    return snapshot


def resolve_scope(request):
    restrictions = policy(request.get("policy", {}))
    if request.get("profile_id"):
        restrictions = policy(core.Store(request["state_dir"]).load("profile-" + request["profile_id"] + ".json")["policy"])
    roots = request.get("roots", restrictions.get("roots"))
    core.require(roots, "Explicit roots are required for every mode")
    if restrictions.get("roots"):
        allowed = [Path(os.path.abspath(os.path.expanduser(x))) for x in restrictions["roots"]]
        core.require(all(any(core.inside(Path(os.path.abspath(os.path.expanduser(r))), a) for a in allowed) for r in roots), "Requested root exceeds profile scope")
    scan_request = {k: request[k] for k in ("max_entries", "max_seconds", "max_depth") if k in request}
    for key in ("max_entries", "max_seconds", "max_depth"):
        if key in restrictions:
            scan_request[key] = min(scan_request.get(key, restrictions[key]), restrictions[key])
    scan_request.update(roots=roots, exclude=list(dict.fromkeys(request.get("exclude", []) + restrictions.get("exclude", []))))
    return scan_request, restrictions


def audit(request):
    mode = request.get("mode", "quick")
    core.require(mode in MODES, "Unknown audit mode")
    if mode == "compare":
        return compare(request)
    scan_request, restrictions = resolve_scope(request)
    inventory = core.scan(scan_request)
    analysis_request = {"inventory": inventory, "top": request.get("top", 20), "sort_by": request.get("sort_by", "size")}
    if mode == "duplicates" or request.get("duplicates"):
        analysis_request.update(duplicates=True, content_read_approved=request.get("content_read_approved", False),
                                max_hash_bytes=min(request.get("max_hash_bytes", 256 * 1024**2), restrictions.get("max_hash_bytes", 4 * 1024**3)))
    analysis = core.analyze(analysis_request)
    return {"schema_version": 1, "mode": mode, "inventory": inventory, "analysis": analysis,
            "proposal": recommendations({"inventory": inventory, "project_artifacts": analysis["project_artifacts"],
                                         "project_analysis_complete": analysis["project_analysis_complete"]}), "changes_made": False,
            "execution_authorized": False,
            "restrictions": {"preserve_offline": restrictions.get("preserve_offline", False),
                             "never_permanently_delete": restrictions.get("never_permanently_delete", False)},
            "next": "Review the exact proposal; this audit grants no execution permission"}

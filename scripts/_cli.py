"""Command adapter over Swipr's existing deterministic helpers and approval gates."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import sys
import stat
import time

import _audit as audit
import _core as core
import _native as native
import _purge as purge
import _guide as guide
import _overview as overview
import _remove as removal


def load(path):
    file = Path(path).expanduser()
    core.require(not core.redirect(file.lstat()), "Input must be a regular JSON file, not a redirect")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(file, flags)
    with os.fdopen(fd, "rb") as stream:
        core.require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Input must be a regular JSON file")
        raw = stream.read(256 * 1024**2 + 1)
    core.require(len(raw) <= 256 * 1024**2, "Input exceeds 256 MiB")
    data = json.loads(raw)
    if isinstance(data, dict) and "ok" in data:
        core.require(data["ok"] is True, "Input contains a failed operation")
        data = data["result"]
    core.require(isinstance(data, dict), "Input must contain a JSON object")
    return data


def inventory(path):
    data = load(path)
    if "inventory" in data:
        data = data["inventory"]
    core.require("entries" in data and "roots" in data, "Input is not an inventory or audit")
    return data


def state(args):
    return {"state_dir": args.state_dir}


def existing_store(args):
    core.require(Path(args.state_dir).expanduser().is_dir(), "State directory does not exist")
    return core.Store(args.state_dir)


def parser():
    root = argparse.ArgumentParser(prog="swipr", description="Local storage audits and exactly approved cleanup. Start with: start")
    root.add_argument("--version", action="version", version="swipr " + core.VERSION)
    commands = root.add_subparsers(dest="command", metavar="COMMAND")

    def leaf(parent, name, route, description):
        p = parent.add_parser(name, help=description, description=description)
        p.set_defaults(route=route)
        p.add_argument("--json", action="store_true", help="Print the machine-readable JSON envelope")
        p.add_argument("--output", metavar="FILE", help="Save a new private result file; existing files are never overwritten")
        return p

    def group(name, description):
        p = commands.add_parser(name, help=description, description=description)
        return p.add_subparsers(required=True, dest="action", metavar="SUBCOMMAND")

    def add_scope(p):
        p.add_argument("--root", action="append", metavar="PATH", help="Authorized root; required unless an explicit policy/profile supplies roots")
        p.add_argument("--exclude", action="append", default=[], metavar="PATH")
        p.add_argument("--max-entries", type=int, default=20000)
        p.add_argument("--max-depth", type=int, default=12)
        p.add_argument("--max-seconds", type=float, default=10)
        p.add_argument("--top", type=int, default=20)
        p.add_argument("--sort", choices=("size", "oldest", "location", "type", "application", "recoverability"), default="size")
        p.add_argument("--policy", metavar="FILE", help="Restrictive policy JSON")
        p.add_argument("--profile-id", help="Saved restrictive profile ID")
        p.add_argument("--state-dir", help="Private state for a saved profile; no default home writes")

    def add_state(p):
        p.add_argument("--state-dir", required=True, metavar="PATH")

    def add_plan(p):
        add_state(p); p.add_argument("--plan-id", required=True)

    def add_operation(p):
        add_state(p); p.add_argument("--operation-id", required=True)

    p = commands.add_parser("help", help="Show command help without scanning")
    p.add_argument("topic", nargs="*")
    p.set_defaults(route="help")
    p = leaf(commands, "start", "start", "Scan and analyze the current user profile, then present review choices")
    p.add_argument("--goal", choices=tuple(guide.GOALS), default="full")
    p.add_argument("--guide", action="store_true", help="Only suggest a workflow; do not scan")
    add_scope(p)
    p.set_defaults(max_entries=100000, max_depth=32, max_seconds=60)
    p = leaf(commands, "explain", "explain", "Explain exact findings from a saved audit without rescanning")
    p.add_argument("--input", required=True, metavar="AUDIT_JSON")
    p.add_argument("--candidate", required=True, action="append", metavar="FULL_ID")
    p.add_argument("--private", action="store_true", help="Include recorded local paths and evidence values")
    p = leaf(commands, "doctor", "doctor", "Check OS, storage, tools, and supported capabilities")
    p.add_argument("--path", default=str(Path.home()))

    scans = group("scan", "Run a read-only scoped audit")
    for mode in ("full", "quick", "deep", "developer", "emergency", "targeted", "health", "safe-cleanup", "custom"):
        p = leaf(scans, mode, "scan", mode + " audit; no file changes")
        p.set_defaults(mode=mode); add_scope(p)
        if mode == "full":
            p.set_defaults(max_entries=100000, max_depth=32, max_seconds=60)

    finds = group("find", "Find files, directories, or exact duplicates without removal")
    for name in ("large", "directories", "duplicates"):
        p = leaf(finds, name, "find", "Read-only " + name + " discovery")
        add_scope(p)
        if name == "large":
            p.add_argument("--min-bytes", type=int, default=0)
            p.add_argument("--older-than-days", type=int, default=0)
            p.add_argument("--extension", action="append", default=[], metavar="EXT")
        if name == "duplicates":
            p.add_argument("--allow-content-read", action="store_true", help="Explicitly approve content hashing within the selected roots")
            p.add_argument("--max-hash-bytes", type=int, default=256 * 1024**2)

    inspections = group("inspect", "Inspect native tools, recoverable data, or application associations")
    for name in ("apps", "storage", "docker", "activity", "leftovers", "trash", "recycle-bin"):
        p = leaf(inspections, name, "inspect", "Inspect " + name + " without cleanup")
        if name in {"apps", "storage", "docker", "activity"}:
            p.add_argument("--allow-native", action="store_true", help="Authorize the fixed read-only native interface")
        if name in {"activity", "leftovers"}:
            p.add_argument("--input", required=True, metavar="AUDIT_JSON")
        if name == "activity":
            p.add_argument("--candidate", action="append", required=True, metavar="ID")
        if name == "leftovers":
            p.add_argument("--applications", required=True, metavar="APPS_JSON")
        if name == "trash":
            add_scope(p); p.add_argument("--confirm-scope", action="store_true")
        if name == "recycle-bin":
            p.add_argument("--volume", action="append", required=True, metavar="DRIVE_ROOT")
            p.add_argument("--confirm-scope", action="store_true")

    plans = group("plan", "Create, review, or revalidate exact plans without executing them")
    p = leaf(plans, 'remove', 'plan', 'Prepare exact permanent Windows removal for a review prompt')
    p.add_argument('--input', required=True, metavar='AUDIT_JSON')
    p.add_argument('--candidate', action='append', required=True, metavar='FULL_ID')
    p.add_argument('--include-personal', action='store_true', help='Only for personal files explicitly selected by the user; never inferred from size or age')
    p.add_argument('--policy', metavar='FILE')
    p = leaf(plans, "create", "plan", "Create a signed exact bytecode quarantine plan")
    add_state(p); p.add_argument("--input", required=True, metavar="AUDIT_JSON")
    p.add_argument("--candidate", action="append", required=True, metavar="ID")
    p = leaf(plans, "purge", "plan", "Prepare a separate irreversible plan for verified private quarantine")
    add_operation(p); p.add_argument("--candidate", action="append", required=True, metavar="ID")
    p.add_argument("--policy", metavar="FILE"); p.add_argument("--profile-id")
    for name in ("show", "validate"):
        p = leaf(plans, name, "plan", name.capitalize() + " a signed plan")
        add_plan(p); p.add_argument("--kind", choices=("quarantine", "purge"), default="quarantine")

    approvals = group("approve", "Record fresh approval of a reviewed exact plan")
    for name in ("quarantine", "purge"):
        p = leaf(approvals, name, "approve", "Record explicit " + name + " approval; never infer it")
        add_plan(p); p.add_argument("--digest", required=True)
        p.add_argument("--note", required=True, help="Minimal approval record, not a private transcript")
        p.add_argument("--confirm", action="store_true", required=True)
        p.add_argument("--workload-stopped" if name == "quarantine" else "--acknowledge-irreversible", action="store_true", required=True)

    cleans = group("clean", "Execute only an existing exact approval, or restore without overwriting")
    for name in ("quarantine", "purge", "restore", "remove"):
        p = leaf(cleans, name, "clean", "Permanently delete exact checked Windows files; cannot undo" if name == 'remove' else name.capitalize() + " exact approved bytecode artifacts")
        if name == 'remove':
            add_state(p)
            p.add_argument('--input', required=True, metavar='PLAN_OR_FULL_AUDIT_JSON')
            p.add_argument('--digest', required=True, help='Exact digest shown before the fresh permanent-deletion approval')
            p.add_argument('--candidate', action='append', required=True, metavar='FULL_ID')
            p.add_argument('--confirm-permanent', action='store_true', required=True)
        elif name == "restore":
            add_operation(p); p.add_argument("--confirm", action="store_true", required=True)
        else:
            add_plan(p); p.add_argument("--approval-id", required=True)

    p = leaf(commands, "verify", "verify", "Verify a completed quarantine, purge, or Windows removal operation")
    add_operation(p); p.add_argument("--kind", choices=("quarantine", "purge", "remove"), default="quarantine")

    reports = group("report", "Produce an audit or verified cleanup report")
    for name in ("audit", "operation"):
        p = leaf(reports, name, "report", name.capitalize() + " Markdown report")
        p.add_argument("--input", required=True, metavar="RESULT_JSON")
        if name == "audit":
            p.add_argument("--private", action="store_true", help="Include exact local paths; keep this report private")
        else:
            p.add_argument("--plan", required=True, metavar="PLAN_JSON")

    history = group("history", "Save private snapshots, compare audits, or inspect operation records")
    p = leaf(history, "save", "history", "Save a consented private inventory snapshot")
    add_state(p); p.add_argument("--input", required=True); p.add_argument("--confirm", action="store_true", required=True)
    p = leaf(history, "show", "history", "Read a signed inventory snapshot")
    add_state(p); p.add_argument("--snapshot-id", required=True)
    p = leaf(history, "compare", "history", "Compare audits or snapshot files from the same scope")
    p.add_argument("--before", required=True); p.add_argument("--after", required=True)
    p = leaf(history, "operations", "history", "List up to 100 signed operation records; no automatic retry")
    add_state(p)

    profiles = group("profile", "Validate or save restrictive preferences; profiles cannot authorize actions")
    for name in ("validate", "save", "show"):
        p = leaf(profiles, name, "profile", name.capitalize() + " a restrictive profile")
        if name != "show":
            p.add_argument("--input", required=True, metavar="POLICY_JSON")
        if name in {"show", "save"}:
            add_state(p)
        if name == "save":
            p.add_argument("--confirm", action="store_true", required=True)
        if name == "show":
            p.add_argument("--profile-id", required=True)

    catalog = group("catalog", "Browse versioned detection rules")
    p = leaf(catalog, "list", "catalog", "List rule IDs, categories, applications and strategies")
    p.add_argument("--category"); p.add_argument("--platform", choices=("linux", "macos", "windows"))
    return root


def scoped(args, allow_default=False):
    core.require((args.root is None or all(args.root)) and all(args.exclude), "Scan and exclusion paths cannot be empty")
    core.require(1 <= args.top <= 100, "--top must be between 1 and 100")
    core.require(1 <= args.max_entries <= 100000 and 0 <= args.max_depth <= 64 and .01 <= args.max_seconds <= 120, "Invalid scan budget: entries 1–100000, depth 0–64, seconds 0.01–120")
    core.require(not (args.policy and args.profile_id), "Choose --policy or --profile-id, not both")
    core.require(allow_default or args.root or args.policy or args.profile_id, "Specify --root, or an explicit policy/profile containing authorized roots")
    request = {"exclude": args.exclude, "max_entries": args.max_entries,
               "max_depth": args.max_depth, "max_seconds": args.max_seconds, "top": args.top, "sort_by": args.sort}
    if args.root:
        request["roots"] = args.root
    if args.policy:
        request["policy"] = load(args.policy)
    if args.profile_id:
        core.require(args.state_dir, "A saved profile requires --state-dir")
        request.update(profile_id=args.profile_id, state_dir=args.state_dir)
    return request


def dispatch(args):
    route, action = args.route, getattr(args, "action", None)
    if route == "start":
        if args.guide:
            return guide.start(args.goal, args.root)
        result = overview.run(scoped(args, allow_default=True), args.output)
        result['requested_goal'] = args.goal
        return result
    if route == "explain":
        return guide.explain(inventory(args.input), args.candidate, args.private)
    if route == "doctor":
        return core.probe({"path": args.path})
    if route in {"scan", "find"}:
        if route == 'scan' and args.mode == 'full':
            return overview.run(scoped(args, allow_default=True), args.output)
        request = scoped(args)
        request["mode"] = args.mode if route == "scan" else "targeted"
        if route == "find" and action == "duplicates":
            core.require(0 <= args.max_hash_bytes <= 4 * 1024**3, "Hash budget must be between 0 and 4294967296 bytes")
            request.update(mode="duplicates", content_read_approved=args.allow_content_read, max_hash_bytes=args.max_hash_bytes)
        if route == "find" and action == "large":
            core.require(args.min_bytes >= 0 and args.older_than_days >= 0, "Find filters must be nonnegative")
        result = audit.audit(request)
        if route == "find":
            if action == "directories":
                result["matches"] = result["analysis"]["directories"][:args.top]
            elif action == "duplicates":
                result["matches"] = result["analysis"]["duplicates"]
            else:
                extensions = {"." + x.lower().lstrip(".") for x in args.extension}
                entries = [e for e in result["inventory"]["entries"] if e["logical_bytes"] >= args.min_bytes
                           and (not args.older_than_days or time.time_ns() - e["identity"]["mtime_ns"] >= args.older_than_days * 86400 * 10**9)
                           and (not extensions or Path(e["path"]).suffix.lower() in extensions)]
                result["matches"] = audit.sort_entries(entries, args.sort)[:min(args.top, 100)]
        result["guidance"] = guide.next_steps(result["inventory"], args.output)
        return result
    if route == "inspect":
        request = {"authorized": getattr(args, "allow_native", False)}
        if action in {"apps", "storage", "docker"}:
            return {"apps": native.applications, "storage": native.storage, "docker": core.docker_audit}[action](request)
        if action == "activity":
            return native.activity({**request, "inventory": inventory(args.input), "candidate_ids": args.candidate})
        if action == "leftovers":
            return audit.leftovers({"inventory": inventory(args.input), "applications": load(args.applications)})
        if action == "trash":
            return audit.trash({**scoped(args), "authorized": args.confirm_scope})
        return native.recycle_bin({"authorized": args.confirm_scope, "volumes": args.volume})
    if route == "plan":
        if action == 'remove':
            return removal.create_plan({'inventory': inventory(args.input), 'candidate_ids': args.candidate,
                                        'include_personal': args.include_personal, 'policy': load(args.policy) if args.policy else {}})
        if action == "create":
            return core.create_plan({**state(args), "inventory": inventory(args.input), "candidate_ids": args.candidate})
        if action == "purge":
            return purge.create_plan({**state(args), "operation_id": args.operation_id, "candidate_ids": args.candidate,
                                      "policy": audit.policy(load(args.policy)) if args.policy else {}, "profile_id": args.profile_id})
        store = existing_store(args)
        if action == "show":
            return store.load(("purgeplan-" if args.kind == "purge" else "plan-") + args.plan_id + ".json")
        plan = (purge.load_plan if args.kind == "purge" else core.load_plan)(store, args.plan_id)
        return {"valid": True, "plan_id": plan["id"], "digest": plan["digest"], "candidate_count": len(plan.get("entries", plan.get("items", [])))}
    if route == "approve":
        request = {**state(args), "plan_id": args.plan_id, "plan_digest": args.digest,
                   "user_approved": args.confirm, "approval_note": args.note}
        if action == "quarantine":
            return core.approve({**request, "workload_stopped": args.workload_stopped})
        return purge.approve({**request, "acknowledge_irreversible": args.acknowledge_irreversible})
    if route == "clean":
        if action == 'remove':
            data = load(args.input)
            plan = data.get('removal_plan', data)
            core.require(isinstance(plan, dict), 'No direct-removal plan is available')
            return removal.execute({**state(args), 'plan': plan, 'plan_digest': args.digest,
                                    'candidate_ids': args.candidate, 'user_approved': args.confirm_permanent,
                                    'acknowledge_irreversible': args.confirm_permanent})
        if action == "restore":
            return core.restore({**state(args), "operation_id": args.operation_id, "user_approved": args.confirm})
        return (purge.execute if action == "purge" else core.execute)({**state(args), "plan_id": args.plan_id, "approval_id": args.approval_id})
    if route == "verify":
        if args.kind == 'remove':
            return removal.verify({**state(args), 'operation_id': args.operation_id})
        return (purge.verify if args.kind == "purge" else core.verify)({**state(args), "operation_id": args.operation_id})
    if route == "report":
        return core.human_report({"inventory": inventory(args.input), "shareable": not args.private}) if action == "audit" else core.human_report({"operation": load(args.input), "plan": load(args.plan)})
    if route == "history":
        if action == "compare":
            return audit.compare({"before": inventory(args.before), "after": inventory(args.after)})
        if action == "save":
            return audit.snapshots({**state(args), "inventory": inventory(args.input), "user_approved": args.confirm})
        if action == "show":
            existing_store(args)
            return audit.snapshots({**state(args), "snapshot_id": args.snapshot_id})
        store = existing_store(args); records = []
        with os.scandir(store.path) as files:
            for index, item in enumerate(files):
                if index >= 2000 or len(records) >= 100:
                    break
                if item.name.startswith(("operation-", "result-", "purgeoperation-", "purgeresult-")) and item.name.endswith(".json"):
                    value = store.load(item.name)
                    records.append({"id": value["id"], "record": item.name.split("-", 1)[0], "status": value.get("status", "interrupted-or-pending"), "plan_id": value["plan_id"]})
        return {"operations": records, "changes_made": False, "limit": 100}
    if route == "profile":
        if action == "show":
            return existing_store(args).load("profile-" + args.profile_id + ".json")
        request = {"policy": load(args.input)}
        if action == "save":
            request.update(state(args), save=True, user_approved=args.confirm)
        return audit.profiles(request)
    rules = core.read_rules()
    return {"rules": [r for r in rules if (not args.category or r["category"] == args.category) and (not args.platform or args.platform in r["platforms"])], "changes_made": False}


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def relative(path, roots):
    for index, root in enumerate(roots, 1):
        try:
            rest = os.path.relpath(path, root)
        except ValueError:
            continue
        if rest == "." or not (rest == ".." or rest.startswith(".." + os.sep)):
            return f"root {index}" + ("" if rest == "." else "/" + Path(rest).as_posix())
    return "outside recorded roots"


def render_health(health, roots):
    lines = []
    for item in health:
        pressure = item.get("storage_pressure", "unknown")
        if pressure == "normal":
            continue
        label = relative(item["root"], roots)
        if item.get("free_bytes") is None or item.get("free_ratio") is None:
            lines.append(f"- {label}: free space unknown")
        else:
            lines.append(f"- {label}: {item['free_bytes']} bytes free ({item['free_ratio']:.1%}), {pressure}")
    return ("\nStorage health:\n" + "\n".join(lines) + "\n") if lines else ""


def render_matches(action, matches, roots):
    if not matches:
        return "\nMatches: none within the recorded scope.\n"
    if action == "directories":
        rows = ["| Directory | Files | Logical bytes | Coverage |", "|---|---:|---:|---|"]
        rows += [f"| {cell(relative(m['path'], roots))} | {m['files']} | {m['logical_bytes']} | {'complete' if m.get('coverage_complete') else 'partial'} |" for m in matches]
    elif action == "duplicates":
        rows = ["| SHA-256 | Copies | Reference ID | Other IDs |", "|---|---:|---|---|"]
        rows += [f"| {m['sha256'][:16]} | {len(m['candidate_ids'])} | {m['reference_candidate_id']} | "
                 + ", ".join(i for i in m["candidate_ids"] if i != m["reference_candidate_id"]) + " |" for m in matches]
        rows.append("\nExact content matches stay PROTECTED; the reference copy is a heuristic and nothing is removed automatically.")
    else:
        rows = ["| ID | Logical bytes | Modified (UTC) | Classification | Location |", "|---|---:|---|---|---|"]
        rows += [f"| {m['id']} | {m['logical_bytes']} | "
                 + time.strftime('%Y-%m-%d', time.gmtime(m['identity']['mtime_ns'] / 10**9))
                 + f" | {m['classification']} | {cell(relative(m['path'], roots))} |" for m in matches]
        rows.append("\nLarge files are informational; size alone never makes a file removable.")
    return "\nMatches:\n\n" + "\n".join(rows) + "\n"


def reserve_output(path):
    file = Path(os.path.abspath(os.path.expanduser(path)))
    existing = file.parent
    while not existing.exists():
        existing = existing.parent
    core.absolute(existing)
    file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    core.absolute(file.parent)
    return os.fdopen(os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "w", encoding="utf-8")


def main(argv=None):
    root = parser(); args = root.parse_args(argv)
    if not getattr(args, "route", None):
        root.print_help(); return 0
    if args.route == "help":
        root.parse_args([*args.topic, "--help"]); return 0
    output = None
    stage = 'output creation' if args.output else 'command execution'
    try:
        if args.output:
            output = reserve_output(args.output)
        stage = 'command execution'
        result = dispatch(args)
        encoded = json.dumps({"ok": True, "result": result}, ensure_ascii=True)
        text = result.get("markdown") if isinstance(result, dict) else None
        if args.json:
            display = encoded
        elif args.route == "start" and args.guide:
            display = guide.render_start(result)
        elif 'review_prompt' in result:
            display = overview.render(result, saved=bool(args.output))
        elif args.route == "doctor":
            caps = result["capabilities"]
            display = "\n".join(["Swipr " + core.VERSION, "System: " + result["platform"] + " " + result["os_version"],
                                 f"Active installation: {result['installation']['directory']}",
                                 (f"Storage: {result['disk']['free']} bytes available of {result['disk']['total']}" if result['disk']['free'] is not None else 'Storage: unknown (' + result['disk']['status'] + '); metadata scans can still run where access is available'),
                                 "Metadata audit: available", "Content hashing: " + ("available" if caps["content_hashing"] else "unavailable"),
                                 "Bytecode quarantine/purge: " + ("available with exact approval" if caps["quarantine"] else "native guidance only"),
                                 "Next: scan quick --root PATH. Use --json for complete discovery metadata."])
        elif args.route == "catalog":
            display = "\n".join(["ID | Category | Application | Strategy", *[f"{r['id']} | {r['category']} | {r['application']} | {r['strategy']}" for r in result["rules"]]])
        elif args.route in {"scan", "find"}:
            display = core.human_report({"inventory": result["inventory"]})["markdown"]
            display += render_health(result["analysis"].get("health", []), result["inventory"]["roots"])
            if "matches" in result:
                display += render_matches(getattr(args, "action", None), result["matches"], result["inventory"]["roots"])
            if not result["analysis"].get("project_analysis_complete", True):
                display += "\nProject evidence analysis is partial; review JSON limits.\n"
            if result["analysis"]["issues"]:
                display += "\nSome hashes were skipped or limited. An empty match list does not prove there are no duplicates.\n"
            display += "\n" + ("Full JSON saved. " if args.output else "Use --output audit.json to save the complete audit. ")
            display += result["guidance"]["message"] + " Nothing was approved.\n"
        else:
            display = text or json.dumps(result, ensure_ascii=True, indent=2)
        if output:
            stage = 'result saving'
            output.write(text if args.route == "report" and not args.json else encoded + "\n")
            output.flush(); os.fsync(output.fileno())
        print(display)
        return 0
    except (core.Refusal, OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        code = "REFUSED" if isinstance(error, core.Refusal) else "ALREADY_EXISTS" if isinstance(error, FileExistsError) else 'PERMISSION_DENIED' if isinstance(error, PermissionError) else 'NOT_FOUND' if isinstance(error, FileNotFoundError) else "INVALID_OR_UNAVAILABLE"
        message = str(error) if isinstance(error, core.Refusal) else ('Permission denied during ' + stage + '. Check scoped host filesystem/sandbox access; do not automatically retry changes.' if isinstance(error, PermissionError) else 'Output or one-use operation record already exists; inspect its status before retrying.' if isinstance(error, FileExistsError) else 'Required filesystem object was not found during ' + stage + '.' if isinstance(error, FileNotFoundError) else 'Invalid request or unavailable filesystem during ' + stage + '. Inspect operation records before retrying changes.')
        detail = {'code': code, 'message': message, 'stage': stage}
        if isinstance(getattr(error, 'winerror', None), int):
            detail['winerror'] = error.winerror
        encoded = json.dumps({"ok": False, "error": detail})
        if output:
            with contextlib.suppress(OSError):
                output.write(encoded + "\n"); output.flush()
        print(encoded if args.json else "swipr: " + message, file=sys.stdout if args.json else sys.stderr)
        return 2
    finally:
        if output:
            with contextlib.suppress(OSError):
                output.close()

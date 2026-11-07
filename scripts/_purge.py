"""Separate permanent-removal authorization for verified private bytecode quarantine.

This module cannot delete arbitrary paths, original files, directories, or Trash.
The sole unlink call takes a signed candidate ID in a pinned private directory.
"""
import importlib.util
import os
from pathlib import Path
import stat
import time

import _core as core


def candidate(store, operation_id, item):
    core.require(os.name == "posix", "Permanent bytecode cleanup requires secure POSIX handles")
    expected_path = store.path / ("quarantine-" + operation_id) / item["candidate_id"]
    core.require(item["quarantined"] == str(expected_path), "Quarantine location mismatch")
    path = core.absolute(expected_path)
    value = path.lstat()
    core.require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.getuid(), "Only current-user single-link bytecode quarantine is eligible")
    core.require(core.identity(value) == item["quarantine_identity"], "Quarantined object changed")
    return path


def create_plan(request):
    core.require(not request.get("policy", {}).get("never_permanently_delete", False), "Session policy forbids permanent deletion")
    store = core.Store(request["state_dir"])
    if request.get("profile_id"):
        profile = store.load("profile-" + request["profile_id"] + ".json")
        core.require(not profile["policy"].get("never_permanently_delete", False), "Profile forbids permanent deletion")
    result = store.load("result-" + request["operation_id"] + ".json")
    source_plan = store.load("plan-" + result["plan_id"] + ".json")
    eligible = {e["id"] for e in source_plan["entries"] if e["rule_id"] == "python-bytecode" and e["strategy"] == "quarantine-bytecode"}
    selected = request.get("candidate_ids", [])
    core.require(selected and len(selected) == len(set(selected)) and len(selected) <= 1000, "Select exact quarantined IDs")
    index = {x["candidate_id"]: x for x in result["items"] if x["status"] == "quarantined"}
    core.require(all(x in index and x in eligible for x in selected), "Unknown or ineligible quarantine candidate")
    items = [index[x] for x in selected]
    for item in items:
        candidate(store, result["id"], item)
    plan = {"schema_version": 1, "id": core.secrets.token_hex(16), "created_at": core.now(),
            "rule_catalog_digest": core.digest(core.read_rules()),
            "operation_id": result["id"], "action": "permanent-delete-quarantined-bytecode",
            "items": items, "expires_at": time.time() + 900, "irreversible": True,
            "warning": "Permanently delete only these exact quarantined bytecode files. This cannot be undone. Free-space recovery is measured after execution and may be limited by snapshots or shared blocks."}
    plan["digest"] = core.digest(plan)
    store.save("purgeplan-" + plan["id"] + ".json", plan)
    return plan


def load_plan(store, plan_id):
    plan = store.load("purgeplan-" + plan_id + ".json")
    core.require(plan["action"] == "permanent-delete-quarantined-bytecode" and plan["irreversible"] is True, "Invalid permanent-removal plan")
    core.require(time.time() < plan["expires_at"], "Permanent-removal plan expired")
    core.require(plan["rule_catalog_digest"] == core.digest(core.read_rules()), "Rule catalog changed; prepare a fresh permanent-removal plan")
    for item in plan["items"]:
        candidate(store, plan["operation_id"], item)
    return plan


def approve(request):
    store = core.Store(request["state_dir"])
    plan = load_plan(store, request["plan_id"])
    core.require(request.get("plan_digest") == plan["digest"], "Approval must match the displayed permanent-removal plan")
    core.require(request.get("user_approved") is True and request.get("acknowledge_irreversible") is True, "Separate explicit permanent-deletion approval is required")
    note = request.get("approval_note", "")
    core.require(isinstance(note, str) and 1 <= len(note) <= 1000, "Record a minimal approval note")
    receipt = {"id": core.secrets.token_hex(16), "plan_id": plan["id"], "digest": plan["digest"],
               "action": plan["action"], "expires_at": min(plan["expires_at"], time.time() + 300),
               "approval_note": note, "acknowledge_irreversible": True}
    store.save("purgeapproval-" + receipt["id"] + ".json", receipt)
    return receipt


def execute(request):
    store = core.Store(request["state_dir"])
    plan = load_plan(store, request["plan_id"])
    receipt = store.load("purgeapproval-" + request["approval_id"] + ".json")
    core.require(receipt["plan_id"] == plan["id"] and receipt["digest"] == plan["digest"] and receipt["action"] == plan["action"], "Permanent-removal approval mismatch")
    core.require(time.time() < receipt["expires_at"] and receipt["acknowledge_irreversible"] is True, "Permanent-removal approval expired or incomplete")
    core.require(core.shutil.disk_usage(store.path).free >= len(core.canonical(plan)) * 4 + 65536, "Insufficient space for safe permanent-removal journals")
    store.write_exclusive("used-" + receipt["id"] + ".json", {"started_at": core.now(), "action": plan["action"]})
    operation = {"schema_version": 1, "id": core.secrets.token_hex(16), "plan_id": plan["id"],
                 "action": plan["action"], "started_at": core.now(), "items": [],
                 "before_free": core.shutil.disk_usage(store.path).free, "irreversible": True}
    store.save("purgeoperation-" + operation["id"] + ".json", {**operation, "pending": plan["items"]})
    for item in plan["items"]:
        row = {"candidate_id": item["candidate_id"], "quarantined": item["quarantined"]}
        try:
            path = candidate(store, plan["operation_id"], item)
            with core.directory_fd(path.parent) as directory:
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                try:
                    core.require(core.identity(os.fstat(fd)) == item["quarantine_identity"], "Quarantine changed before permanent removal")
                    core.require(os.read(fd, 4) == importlib.util.MAGIC_NUMBER, "Only runtime-validated bytecode can be purged")
                    core.require(core.identity(os.stat(path.name, dir_fd=directory, follow_symlinks=False)) == item["quarantine_identity"], "Quarantine changed before permanent removal")
                    os.unlink(path.name, dir_fd=directory)
                finally:
                    os.close(fd)
            row["status"] = "permanently-removed"
            row["verified_absent"] = not os.path.lexists(path)
            if not row["verified_absent"]:
                row["status"] = "failed-stop"
                row["reason"] = "A quarantine name unexpectedly reappeared after removal; stop and inspect"
        except (OSError, core.Refusal):
            row["status"] = "failed-stop"
            row["reason"] = "Revalidation or exact-file removal failed; inspect signed intent and quarantine"
        operation["items"].append(row)
        store.save("purgeitem-" + core.secrets.token_hex(16) + ".json", {"operation_id": operation["id"], **row})
        if row["status"] == "failed-stop":
            break
    operation["after_free"] = core.shutil.disk_usage(store.path).free
    operation["observed_free_delta"] = operation["after_free"] - operation["before_free"]
    operation["status"] = "complete" if len(operation["items"]) == len(plan["items"]) and all(x.get("verified_absent") for x in operation["items"]) else "partial"
    operation["finished_at"] = core.now()
    operation["warning"] = "Deleted bytecode cannot be restored from quarantine. Observed free-space changes include journal writes and unrelated system activity."
    store.save("purgeresult-" + operation["id"] + ".json", operation)
    return operation


def verify(request):
    store = core.Store(request["state_dir"])
    result = store.load("purgeresult-" + request["operation_id"] + ".json")
    for item in result["items"]:
        item["verified_absent"] = item["status"] == "permanently-removed" and not os.path.lexists(item["quarantined"])
    result["all_verified"] = result["status"] == "complete" and all(x["verified_absent"] for x in result["items"])
    result["verified_at"] = core.now()
    return result

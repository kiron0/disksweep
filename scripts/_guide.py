"""Read-only workflow guidance. Saved findings never establish current eligibility."""
import json
import os
import re

import _core as core


GOALS = {
    "full": ("scan", "full"),
    "quick": ("scan", "quick"),
    "developer": ("scan", "developer"),
    "emergency": ("scan", "emergency"),
    "health": ("scan", "health"),
    "large": ("find", "large"),
    "duplicates": ("find", "duplicates"),
}


def start(goal, roots=None):
    core.require(goal in GOALS, "Unknown workflow goal")
    core.require(roots is None or (isinstance(roots, list) and 1 <= len(roots) <= 100
                 and all(isinstance(p, str) and p.strip() for p in roots)), "Supply 1–100 nonempty folders")
    arguments = list(GOALS[goal])
    for path in roots or ["PATH"]:
        arguments.extend(["--root", path])
    arguments.extend(["--output", "audit.json"])
    return {"goal": goal, "scope_required": not bool(roots), "suggested_arguments": arguments,
            "steps": ["Choose the exact folders you authorize; start with a narrow scope.",
                      "Run doctor to check local capabilities, then review the suggested command.",
                      "For duplicates, obtain separate content-hashing approval before adding --allow-content-read."
                      if goal == "duplicates" else "Run the scoped metadata audit; review coverage and limits.",
                      "Use explain with full candidate IDs from the saved audit to review evidence, effects and recovery.",
                      "Only supported findings can enter a freshly validated exact plan. Review it before approving changes."],
            "warning": "Suggestions are argument arrays, never shell scripts. Nothing has been inspected or approved.",
            "changes_made": False, "execution_authorized": False}


def render_start(result):
    return "\n".join(["Swipr — " + result["goal"],
                      *[f"{i}. {step}" for i, step in enumerate(result["steps"], 1)],
                      "Suggested arguments: " + json.dumps(result["suggested_arguments"], ensure_ascii=True),
                      "Replace PATH with an authorized folder." if result["scope_required"] else "Folders have not been inspected.",
                      result["warning"]])


def planning_hint(entry, metadata_only=False):
    if metadata_only or entry["classification"] == "PROTECTED":
        return "preserve"
    if entry["classification"] == "SAFE-CANDIDATE" and entry["strategy"] == "quarantine-bytecode":
        return "requires-fresh-quarantine-plan" if os.name == "posix" else "native-guidance-only"
    return "manual-or-native-review" if entry["classification"] == "REVIEW" else "preserve"


def next_steps(inventory, output=None):
    ids = [entry["id"] for entry in inventory["entries"]
           if planning_hint(entry, inventory.get("protected_metadata_only", False)) == "requires-fresh-quarantine-plan"]
    complete = inventory["complete"]
    if ids:
        message = "Review recorded bytecode findings with explain; a fresh plan must revalidate every selected file. Quarantine frees no space."
    else:
        message = "No supported bytecode plan candidates were recorded. Preserve protected files; review other findings using application or system storage controls."
    if not complete:
        message = "Coverage is partial; review audit issues and limits before drawing conclusions. " + message
    return {"message": message, "coverage_complete": complete,
            "recorded_bytecode_candidates": len(ids), "sample_candidate_ids": ids[:5],
            "suggested_arguments": [["explain", "--input", output, "--candidate", value] for value in ids[:5]] if output else [],
            "current_eligibility": "not-checked", "execution_authorized": False}


def explain(inventory, selected, private=False):
    core.require(isinstance(selected, list) and 1 <= len(selected) <= 100
                 and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{24}", value) for value in selected)
                 and len(set(selected)) == len(selected), "Select 1–100 distinct full candidate IDs; prefixes are not accepted")
    entries = inventory["entries"]
    core.require(isinstance(entries, list) and all(isinstance(e, dict) and isinstance(e.get("id"), str) for e in entries), "Invalid saved inventory")
    index = {entry["id"]: entry for entry in entries}
    core.require(len(index) == len(entries), "Saved inventory has duplicate candidate IDs")
    core.require(all(value in index for value in selected), "Candidate ID is absent from this saved inventory")
    rows = []
    for value in selected:
        entry = index[value]
        evidence = entry.get("evidence")
        recorded = [name for name in ("source", "source_identity", "project", "marker", "marker_identity")
                    if isinstance(evidence, dict) and name in evidence]
        row = {"candidate_id": value, "location": entry["path"] if private else "item-" + value[:8],
               "classification": entry["classification"], "risk": entry["risk"],
               "logical_bytes": entry["logical_bytes"], "allocated_bytes": entry["allocated_bytes"],
               "rule_id": entry["rule_id"], "rule_version": entry["rule_version"],
               "reason": entry["reason"], "side_effects": entry["side_effects"], "recovery": entry["recovery"],
               "evidence_recorded": bool(evidence), "recorded_evidence_fields": recorded,
               "planning_hint": planning_hint(entry, inventory.get("protected_metadata_only", False)),
               "active_use": "not-checked", "current_eligibility": "not-checked"}
        if private:
            row["evidence"] = evidence
        rows.append(row)
    return {"candidates": rows, "paths_included": private, "coverage_complete": inventory["complete"],
            "warning": "Saved snapshot only: files, rules and active use have not been rechecked. This is not a plan or approval. Quarantine frees no space.",
            "changes_made": False, "execution_authorized": False}

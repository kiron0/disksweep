"""Validate skill metadata, references, rule policy, schemas and helper AST.

Development tool only. --strict requires PyYAML and jsonschema.
"""
import ast
import json
from pathlib import Path
import re
import sys

BASE = Path(__file__).resolve().parent.parent


def check():
    strict = "--strict" in sys.argv
    text = (BASE / "SKILL.md").read_text(encoding="utf-8")
    assert text.startswith("---\n"), "Missing frontmatter"
    _, front, body = text.split("---", 2)
    try:
        import yaml
        meta = yaml.safe_load(front)
    except ImportError:
        assert not strict, "Install requirements-dev.txt for strict validation"
        meta = dict(re.findall(r"^(name|description|license|compatibility): (.+)$", front, re.M))
    assert meta["name"] == "swipr"
    assert 0 < len(meta["description"]) <= 1024 and "<" not in meta["description"]
    assert meta["license"] == "MIT" and len(meta["compatibility"]) <= 500
    assert set(meta) <= {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
    assert len(body.splitlines()) < 500, "Keep the entry point concise"
    for file in BASE.rglob("*.md"):
        if ".git" in file.parts or ".venv" in file.parts:
            continue
        for target in re.findall(r"\]\(([^)]+)\)", file.read_text(encoding="utf-8")):
            if re.match(r"[a-z]+://", target) or target.startswith("#"):
                continue
            assert (file.parent / target.split("#")[0]).exists(), f"Broken reference in {file.name}: {target}"
    from _core import read_rules, VERSION
    if "metadata" in meta:
        assert meta["metadata"]["version"] == VERSION, "Skill and helper versions must match"
    plugin = json.loads((BASE / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
    market = json.loads((BASE / ".claude-plugin/marketplace.json").read_text(encoding="utf-8"))
    entry = next((p for p in market["plugins"] if p["name"] == meta["name"]), None)
    assert plugin["name"] == meta["name"] and entry and entry["source"] == "./", "Plugin manifests must publish this skill"
    assert plugin["version"] == entry["version"] == VERSION, "Plugin and helper versions must match"
    rules = read_rules()
    required = {"id", "version", "category", "application", "platforms", "risk", "classification", "strategy", "signatures", "reason", "side_effects", "recovery", "exclusions", "supported_versions", "post_check"}
    for rule in rules:
        assert required <= set(rule) <= required | {"project_markers", "artifact_paths"}, f"Missing or unexpected rule fields: {rule['id']}"
        assert rule["platforms"] and set(rule["platforms"]) <= {"linux", "macos", "windows"}
        assert rule["risk"] in {"low", "moderate", "high", "critical"}
        assert all(isinstance(s, str) and s and ".." not in s.split("/") for s in rule["signatures"])
        assert rule["signatures"] or rule["id"] == "python-bytecode" or rule.get("project_markers")
        if rule.get("project_markers"):
            assert rule["strategy"] == "audit-only" and rule.get("artifact_paths")
            assert all(not Path(p).is_absolute() and ".." not in Path(p).parts for p in rule["project_markers"] + rule["artifact_paths"])
    schemas = list((BASE / "schemas").glob("*.json"))
    try:
        from jsonschema import Draft202012Validator
        for file in schemas:
            Draft202012Validator.check_schema(json.loads(file.read_text(encoding="utf-8")))
    except ImportError:
        assert not strict, "Install requirements-dev.txt for strict validation"
        for file in schemas:
            json.loads(file.read_text(encoding="utf-8"))
    forbidden = {"eval", "exec", "unlink", "remove", "rmdir", "rmtree"}
    for file in (BASE / "scripts").glob("*.py"):
        tree = ast.parse(file.read_text(encoding="utf-8"))
        native_deletes = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                          and n.func.attr == 'SetFileInformationByHandle']
        if native_deletes:
            assert file.name == '_windows_file.py' and len(native_deletes) == 1, 'Only one native Windows removal disposition is permitted'
            guard = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'mark_for_removal')
            assert native_deletes[0] in list(ast.walk(guard)), 'Native removal must stay in its guarded handle primitive'
        if file.name == "_posix_file.py":
            removals = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "unlink"]
            guard = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "mark_for_removal")
            assert len(removals) == 1 and removals[0] in list(ast.walk(guard)), "Only one guarded POSIX handle removal is permitted"
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            permitted = file.name == "_posix_file.py" and name == "unlink" and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"
            assert name not in forbidden or permitted, f"Forbidden runtime operation: {file.name}:{node.lineno}"
            assert not (name == "system" and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"), "OS shell execution forbidden"
            assert not any(k.arg == "shell" and not (isinstance(k.value, ast.Constant) and k.value.value is False) for k in node.keywords), "Shell execution forbidden"
    cases = json.loads((BASE / "evals/evals.json").read_text(encoding="utf-8"))
    assert len(cases["evals"]) >= 8
    assert len({x["id"] for x in cases["evals"]}) == len(cases["evals"])
    print(f"Validated swipr: metadata, Markdown links, {len(rules)} rules, {len(schemas)} schemas, runtime AST, {len(cases['evals'])} behavioral cases")


if __name__ == "__main__":
    check()

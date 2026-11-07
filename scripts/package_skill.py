"""Build a deterministic local skill archive; no upload or registry mutation."""
import sys
from pathlib import Path
import zipfile

BASE = Path(__file__).resolve().parent.parent


def build(destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    included = {"SKILL.md", "README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md"}
    folders = {"agents", "references", "scripts", "rules", "schemas", "assets", "docs"}
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(BASE.rglob("*")):
            relative = path.relative_to(BASE)
            if not path.is_file() or "__pycache__" in relative.parts:
                continue
            if str(relative) not in included and relative.parts[0] not in folders:
                continue
            info = zipfile.ZipInfo("swipr/" + relative.as_posix(), (2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    print(f"Built {destination.name}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Development use: python scripts/package_skill.py OUTPUT.skill")
    build(sys.argv[1])

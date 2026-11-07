"""Fixed read-only platform interfaces. No arbitrary command protocol."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import _core as core


def read_command(arguments):
    if not shutil.which(arguments[0]):
        return {"status": "unavailable", "metadata": None, "complete": False}
    with tempfile.TemporaryFile() as output:
        try:
            child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 10
            stopped = False
            while child.poll() is None:
                if time.monotonic() >= deadline or os.fstat(output.fileno()).st_size > 1024**2:
                    child.kill(); child.wait(); stopped = True; break
                time.sleep(.02)
            output.seek(0); raw = output.read(1024**2 + 1)
            complete = not stopped and len(raw) <= 1024**2 and child.returncode == 0
            return {"status": "ok" if complete else "unsupported-or-partial", "complete": complete,
                    "metadata": raw[:1024**2].decode("utf-8", errors="replace") if child.returncode == 0 else None}
        except OSError:
            return {"status": "unavailable", "metadata": None, "complete": False}


def applications(request):
    core.require(request.get("authorized") is True, "Installed application inventory requires scope approval")
    pid = core.platform_id()
    if pid == "linux":
        commands = [["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                    ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"],
                    ["flatpak", "list", "--columns=application,version"]]
    elif pid == "macos":
        commands = [["system_profiler", "SPApplicationsDataType", "-json", "-detailLevel", "mini"]]
    elif pid == "windows":
        script = "@(Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object @{n='name';e={$_.DisplayName}},@{n='version';e={$_.DisplayVersion}}) | ConvertTo-Json -Compress"
        commands = [["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]]
    else:
        commands = []
    results, apps = [], []
    for args in commands:
        result = {"interface": args[0], **read_command(args)}; results.append(result)
        raw = result["metadata"]
        if not raw:
            continue
        try:
            if pid == "macos":
                rows = json.loads(raw).get("SPApplicationsDataType", [])
                apps.extend({"name": x.get("_name", ""), "id": x.get("CFBundleIdentifier", x.get("path", "")), "version": x.get("version", "unknown")} for x in rows)
            elif pid == "windows":
                rows = json.loads(raw); rows = rows if isinstance(rows, list) else [rows]
                apps.extend({"name": x.get("name", ""), "id": x.get("name", ""), "version": x.get("version", "unknown")} for x in rows if isinstance(x, dict))
            else:
                for line in raw.splitlines():
                    fields = line.split("\t", 1)
                    if len(fields) == 2:
                        apps.append({"name": fields[0], "id": fields[0], "version": fields[1]})
        except (ValueError, TypeError, AttributeError):
            result["complete"] = False
    return {"source": "native-installed-applications", "created_at": core.now(), "applications": apps,
            "complete": bool(results) and any(x["complete"] for x in results),
            "interfaces": results, "changes_made": False,
            "warning": "Inventories may omit portable, manually installed, or per-user applications; absence is not deletion evidence"}


def storage(request):
    core.require(request.get("authorized") is True, "Native system storage inspection requires approval")
    pid = core.platform_id()
    commands = {"linux": [["findmnt", "-J", "-o", "TARGET,FSTYPE,SOURCE,OPTIONS"], ["journalctl", "--disk-usage"]],
                "macos": [["diskutil", "info", "-plist", "/"], ["tmutil", "listlocalsnapshots", "/"]],
                "windows": [["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                             "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,FileSystem,Size,FreeSpace,DriveType | ConvertTo-Json -Compress"],
                            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                             "Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Select-Object ID,VolumeName,InstallDate | ConvertTo-Json -Compress"]]}
    results = [{"interface": " ".join(args[:2]), **read_command(args)} for args in commands.get(pid, [])]
    return {"platform": pid, "results": results, "changes_made": False,
            "snapshot_modification_supported": False,
            "warning": "Snapshot/purgeable space is system-managed. Permission failures do not authorize elevation"}


def activity(request):
    core.require(request.get("authorized") is True, "Active-use inspection requires approval")
    inventory = request["inventory"]
    selected = set(request.get("candidate_ids", []))
    entries = [x for x in inventory["entries"] if x["id"] in selected]
    core.require(entries and len(entries) == len(selected) and len(entries) <= 100, "Select 1–100 exact inventory IDs")
    paths = [str(core.absolute(x["path"])) for x in entries]
    result = read_command(["lsof", "-nP", "-F", "pn", "--", *paths]) if os.name == "posix" else {"status": "unsupported", "metadata": None, "complete": False}
    opened = set()
    for line in (result["metadata"] or "").splitlines():
        if line.startswith("n"):
            opened.add(line[1:])
    return {"items": [{"id": e["id"], "active_use": "observed-open" if e["path"] in opened else "unknown"} for e in entries],
            "interface": result, "changes_made": False,
            "warning": "No visible open handle does not prove a file is unused; never force-close applications"}


def recycle_bin(request):
    core.require(request.get("authorized") is True, "Recycle Bin inspection requires approval")
    core.require(core.platform_id() == "windows", "Use trash_audit.py with explicit roots on this platform")
    import ctypes
    from ctypes import wintypes
    class Info(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]
    query = ctypes.windll.shell32.SHQueryRecycleBinW
    query.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(Info)]; query.restype = ctypes.c_long
    rows = []
    for volume in request.get("volumes", []):
        core.require(isinstance(volume, str) and len(volume) == 3 and volume[0].isalpha() and volume[1:] == ":\\", "Select drive roots, such as C:\\")
        value = Info(); value.cbSize = ctypes.sizeof(value)
        status = query(volume, ctypes.byref(value))
        rows.append({"volume": volume, "status": "ok" if status == 0 else "unavailable",
                     "logical_bytes": value.i64Size if status == 0 else None,
                     "items": value.i64NumItems if status == 0 else None})
    core.require(rows, "Explicit volume scope is required")
    return {"volumes": rows, "classification": "PROTECTED", "changes_made": False,
            "warning": "Emptying destroys recovery and requires separate user authorization; this helper cannot empty the bin"}

"""Bounded JSON protocol for agent-internal helpers; no interactive CLI."""
import json
import sys

import _core


def run(function):
    try:
        raw = sys.stdin.buffer.read(32 * 1024 * 1024 + 1)
        _core.require(len(raw) <= 32 * 1024 * 1024, "Request exceeds 32 MiB")
        request = json.loads(raw or b"{}")
        _core.require(isinstance(request, dict), "Request must be a JSON object")
        result = function(request)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=True))
    except _core.Refusal as error:
        print(json.dumps({"ok": False, "error": {"code": "REFUSED", "message": str(error)}}))
        sys.exit(2)
    except FileExistsError:
        print(json.dumps({"ok": False, "error": {"code": "ALREADY_EXISTS", "message": "Removal plan already consumed or output already exists; inspect records before retrying"}}))
        sys.exit(2)
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        print(json.dumps({"ok": False, "error": {"code": "INVALID_OR_UNAVAILABLE", "message": "Invalid request, inaccessible filesystem, or unsupported capability; no automatic retry"}}))
        sys.exit(2)

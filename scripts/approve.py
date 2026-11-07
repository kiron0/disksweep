"""Agent-internal DiskSweep approve helper; one JSON request on stdin."""
from _protocol import run
from _core import approve

if __name__ == "__main__":
    run(approve)

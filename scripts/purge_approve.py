"""Agent-internal DiskSweep purge_approve; one JSON request on stdin."""
from _protocol import run
from _purge import approve

if __name__ == "__main__":
    run(approve)

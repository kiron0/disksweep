"""Agent-internal DiskSweep trash_audit; one JSON request on stdin."""
from _protocol import run
from _audit import trash

if __name__ == "__main__":
    run(trash)

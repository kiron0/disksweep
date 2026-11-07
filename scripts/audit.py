"""Agent-internal DiskSweep audit; one JSON request on stdin."""
from _protocol import run
from _audit import audit

if __name__ == "__main__":
    run(audit)

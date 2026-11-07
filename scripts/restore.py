"""Agent-internal DiskSweep restore helper; one JSON request on stdin."""
from _protocol import run
from _core import restore

if __name__ == "__main__":
    run(restore)

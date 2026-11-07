"""Agent-internal DiskSweep classify helper; one JSON request on stdin."""
from _protocol import run
from _core import scan

if __name__ == "__main__":
    run(scan)

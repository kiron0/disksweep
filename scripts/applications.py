"""Agent-internal DiskSweep applications; one JSON request on stdin."""
from _protocol import run
from _native import applications

if __name__ == "__main__":
    run(applications)

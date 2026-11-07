"""Agent-internal DiskSweep purge_execute; one JSON request on stdin."""
from _protocol import run
from _purge import execute

if __name__ == "__main__":
    run(execute)

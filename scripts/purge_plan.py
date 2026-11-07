"""Agent-internal DiskSweep purge_plan; one JSON request on stdin."""
from _protocol import run
from _purge import create_plan

if __name__ == "__main__":
    run(create_plan)

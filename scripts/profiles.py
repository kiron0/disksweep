"""Agent-internal DiskSweep profiles; one JSON request on stdin."""
from _protocol import run
from _audit import profiles

if __name__ == "__main__":
    run(profiles)

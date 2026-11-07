"""Agent-internal DiskSweep system_probe helper; one JSON request on stdin."""
from _protocol import run
from _core import probe

if __name__ == "__main__":
    run(probe)

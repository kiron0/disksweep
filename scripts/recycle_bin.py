"""Agent-internal DiskSweep recycle_bin; one JSON request on stdin."""
from _protocol import run
from _native import recycle_bin

if __name__ == "__main__":
    run(recycle_bin)

"""Agent-internal DiskSweep native_storage; one JSON request on stdin."""
from _protocol import run
from _native import storage

if __name__ == "__main__":
    run(storage)

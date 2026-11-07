"""Agent-internal Swipr activity; one JSON request on stdin."""
from _protocol import run
from _native import activity

if __name__ == "__main__":
    run(activity)

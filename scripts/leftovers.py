"""Agent-internal Swipr leftovers; one JSON request on stdin."""
from _protocol import run
from _audit import leftovers

if __name__ == "__main__":
    run(leftovers)

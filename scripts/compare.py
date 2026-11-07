"""Agent-internal Swipr compare; one JSON request on stdin."""
from _protocol import run
from _audit import compare

if __name__ == "__main__":
    run(compare)

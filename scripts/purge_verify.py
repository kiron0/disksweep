"""Agent-internal Swipr purge_verify; one JSON request on stdin."""
from _protocol import run
from _purge import verify

if __name__ == "__main__":
    run(verify)

"""Agent-internal Swipr verify helper; one JSON request on stdin."""
from _protocol import run
from _core import verify

if __name__ == "__main__":
    run(verify)

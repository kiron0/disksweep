"""Agent-internal Swipr analyze helper; one JSON request on stdin."""
from _protocol import run
from _core import analyze

if __name__ == "__main__":
    run(analyze)

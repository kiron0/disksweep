"""Agent-internal Swipr execute helper; one JSON request on stdin."""
from _protocol import run
from _core import execute

if __name__ == "__main__":
    run(execute)

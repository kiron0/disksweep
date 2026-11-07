"""Agent-internal Swipr plan helper; one JSON request on stdin."""
from _protocol import run
from _core import create_plan

if __name__ == "__main__":
    run(create_plan)

"""Agent-internal Swipr report helper; one JSON request on stdin."""
from _protocol import run
from _core import human_report

if __name__ == "__main__":
    run(human_report)

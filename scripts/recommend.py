"""Agent-internal Swipr recommend; one JSON request on stdin."""
from _protocol import run
from _audit import recommendations

if __name__ == "__main__":
    run(recommendations)

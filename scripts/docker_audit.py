"""Agent-internal Swipr docker_audit helper; one JSON request on stdin."""
from _protocol import run
from _core import docker_audit

if __name__ == "__main__":
    run(docker_audit)

"""
Toggles which dispatch path is live: the real LLM Orchestrator (Person B's
host) for "full" runs, or this project's baseline-dispatcher (local,
pipeline host) for "baseline" runs. Exactly one should ever be consuming
`incidents` at a time — running both together double-dispatches every
incident.

Person B runs the orchestrator as a raw Python process via PowerShell
scripts (start_orchestrator.ps1 / stop_orchestrator.ps1), not Docker —
confirmed directly, not assumed. Stop/start go through those scripts over
SSH, same approach Watchdog already uses for this exact host.
"""

import os
import subprocess
import time

import paramiko
import requests

import redis
_r = redis.Redis(host=os.environ["REDIS_HOST"], port=6379, decode_responses=True)


ORCHESTRATOR_HOST = os.environ["ORCHESTRATOR_HOST"]          # Person B's Tailscale IP
ORCHESTRATOR_SSH_USER = os.environ.get("ORCHESTRATOR_SSH_USER", "hp")
SSH_KEY_PATH = os.environ["SSH_KEY_PATH"]
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))

ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", f"http://{ORCHESTRATOR_HOST}:8000")

BASELINE_CONTAINER_NAME = "baseline-dispatcher"


def _ssh_run(host, user, command, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, username=user, key_filename=SSH_KEY_PATH,
                        port=SSH_PORT, timeout=timeout)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_status = stdout.channel.recv_exit_status()
        return exit_status, stdout.read().decode(), stderr.read().decode()
    finally:
        client.close()


ORCHESTRATOR_CONTAINER = os.environ["ORCHESTRATOR_CONTAINER"]

def stop_orchestrator():
    # at the start of the stop_orchestrator() function:
    _r.set("watchdog:paused:orchestrator", "1", ex=7200)   # auto-expires after 2h as a safety net
    print(f"[MODE] stopping orchestrator container `{ORCHESTRATOR_CONTAINER}` on {ORCHESTRATOR_HOST}")
    code, out, err = _ssh_run(ORCHESTRATOR_HOST, ORCHESTRATOR_SSH_USER,
                               f"docker stop {ORCHESTRATOR_CONTAINER}")
    if code != 0:
        raise RuntimeError(f"failed to stop orchestrator: {err}")


def start_orchestrator():
    print(f"[MODE] starting orchestrator container `{ORCHESTRATOR_CONTAINER}` on {ORCHESTRATOR_HOST}")
    code, out, err = _ssh_run(ORCHESTRATOR_HOST, ORCHESTRATOR_SSH_USER,
                               f"docker start {ORCHESTRATOR_CONTAINER}")
    if code != 0:
        raise RuntimeError(f"failed to start orchestrator: {err}")

    # keep the /health polling loop exactly as it is now
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            resp = requests.get(f"{ORCHESTRATOR_URL}/health", timeout=3)
            if resp.status_code == 200 and resp.json().get("status") == "running":
                print("[MODE] orchestrator /health confirmed up")
                # at the end of the start_orchestrator() function, after /health confirms:
                _r.delete("watchdog:paused:orchestrator")
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError("orchestrator did not report healthy within 60s of start")


def start_baseline_dispatcher():
    # Requires /var/run/docker.sock mounted into this container — see
    # docker-compose.yml. Container must already exist (built once via
    # `docker compose --profile tools build baseline-dispatcher`).
    print("[MODE] starting local baseline-dispatcher")
    subprocess.run(["docker", "start", BASELINE_CONTAINER_NAME], check=True)
    time.sleep(5)


def stop_baseline_dispatcher():
    print("[MODE] stopping local baseline-dispatcher")
    subprocess.run(["docker", "stop", BASELINE_CONTAINER_NAME], check=False)


def set_mode(mode: str):
    """mode: 'full' or 'baseline'. Ensures exactly one dispatch path is live."""
    if mode == "full":
        stop_baseline_dispatcher()
        start_orchestrator()
    elif mode == "baseline":
        stop_orchestrator()
        start_baseline_dispatcher()
    else:
        raise ValueError(f"unknown mode: {mode}")
    print(f"[MODE] now in '{mode}' mode")
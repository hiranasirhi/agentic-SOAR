# watchdog/watchdog.py
#
# Self-Healing Watchdog (Phase 5) — Person A
#
# Agents and orchestrator run on remote hosts (Person C / Person B), reached
# over Tailscale via SSH — NOT via the local Docker socket. AGENT_CONTAINER_MAP
# and ORCHESTRATOR_CONFIG entries are dicts: {"host", "user", "container"}.
#   - check_orphan_tasks(): implemented against Person C's confirmed contract
#     (agent:{name}:in_progress via LPUSH/LREM, claimed_at ISO8601 UTC). Still
#     assumes task_status:{task_id} is a plain Redis string set to "pending" —
#     needs a one-line confirmation from Person B before treating as fully verified.

# STILL PENDING CONFIRMATION (do not treat as working yet):
#   - reprocess_stalled_incidents(): needs Person B to expose a
#     POST /incidents/{id}/resume endpoint + an inflight marker key
#     (e.g. orchestrator:inflight:{incident_id}). Current version resubmits
#     via /incidents/process instead, which reruns reasoning from scratch —
#     acceptable as a fallback, but not real checkpoint resume.

import json
import os
import time
import traceback

import paramiko
import psycopg2
import redis
import requests
from dotenv import load_dotenv
from datetime import datetime, timezone

import sys
sys.path.append('/app')

from shared.constants import REDIS_AGENT_HEARTBEAT, AGENT_HEARTBEAT_TTL

load_dotenv()

# ============================================
# CONFIG
# ============================================

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

POLL_INTERVAL_SECONDS = int(os.getenv("WATCHDOG_POLL_INTERVAL_SECONDS", "15"))
HEARTBEAT_STALE_SECONDS = int(os.getenv("WATCHDOG_HEARTBEAT_STALE_SECONDS", str(AGENT_HEARTBEAT_TTL)))
RESTART_COOLDOWN_SECONDS = int(os.getenv("WATCHDOG_RESTART_COOLDOWN_SECONDS", "120"))
TASK_ORPHAN_SECONDS = int(os.getenv("WATCHDOG_TASK_ORPHAN_SECONDS", "120"))

# Per-agent overrides, since Person C configures TASK_ORPHAN_SECONDS
# individually per agent (e.g. Investigation needs longer due to
# VirusTotal rate limiting). Falls back to TASK_ORPHAN_SECONDS above
# if an agent isn't listed. e.g. {"investigation": 180}
AGENT_ORPHAN_SECONDS_OVERRIDES = json.loads(os.getenv("AGENT_ORPHAN_SECONDS_OVERRIDES", "{}"))
RECOVERY_WAIT_SECONDS = int(os.getenv("WATCHDOG_RECOVERY_WAIT_SECONDS", "30"))
REPEATED_FAILURE_THRESHOLD = int(os.getenv("WATCHDOG_REPEATED_FAILURE_THRESHOLD", "3"))

# {"triage": {"host": "100.103.120.48", "user": "HP", "container": "protego-triage"}, ...}
AGENT_CONTAINER_MAP = json.loads(os.getenv("AGENT_CONTAINER_MAP", "{}"))

# {"host": "<person B tailscale ip>", "user": "<ssh user>", "container": "orchestrator"}
ORCHESTRATOR_CONFIG = json.loads(os.getenv("ORCHESTRATOR_CONFIG", "{}"))

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8000")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "/app/ssh/watchdog_id_ed25519")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_TIMEOUT_SECONDS = int(os.getenv("SSH_TIMEOUT_SECONDS", "10"))

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", 5432)
POSTGRES_DB = os.getenv("POSTGRES_DB", "soar_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "soar_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "soar_password123")

# ============================================
# CLIENTS
# ============================================

redis_client = redis.Redis(
    host=REDIS_HOST, port=REDIS_PORT, decode_responses=True,
    socket_connect_timeout=5, socket_timeout=5, socket_keepalive=True,
    health_check_interval=30, retry_on_timeout=True,
)

# Keyed by agent_name (string, always hashable) — NOT by container name,
# since container names live on different hosts and the config is a dict.
_last_restart = {}          # {agent_name: last_restart_epoch}
_first_miss_time = {}       # {agent_name: epoch of first missed heartbeat in this outage}
_consecutive_failures = {}  # {agent_name: count of restarts that never recovered}


def get_db():
    return psycopg2.connect(
        host=POSTGRES_HOST, port=POSTGRES_PORT, dbname=POSTGRES_DB,
        user=POSTGRES_USER, password=POSTGRES_PASSWORD,
    )


def log_healing_event_pg(agent_name, event_type, docker_exit_code=None,
                          log_summary=None, recovery_time_seconds=None):
    """Matches init.sql healing_events schema exactly."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO healing_events
                (agent_name, event_type, docker_exit_code, log_summary, recovery_time_seconds)
            VALUES (%s, %s, %s, %s, %s)
        """, (agent_name, event_type, docker_exit_code, log_summary, recovery_time_seconds))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[WATCHDOG] Postgres log failed: {e}")


def send_slack_alert(text: str):
    if not SLACK_WEBHOOK_URL:
        print(f"[WATCHDOG] (no SLACK_WEBHOOK_URL set) would alert:\n{text}")
        return
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=5)
    except Exception as e:
        print(f"[WATCHDOG] Slack alert failed: {e}")


# ============================================
# SSH HELPERS — restart / inspect / logs on remote hosts
# ============================================

def _ssh_run(host: str, user: str, command: str, timeout: int = SSH_TIMEOUT_SECONDS):
    """Run a single command on a remote host over SSH. Returns (exit_status, stdout, stderr)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, username=user, key_filename=SSH_KEY_PATH,
            port=SSH_PORT, timeout=timeout,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return exit_status, out, err
    finally:
        client.close()

def _build_restart_command(agent_config: dict) -> str:
    if "restart_command" in agent_config:
        return agent_config["restart_command"]
    return f"docker restart {agent_config['container']}"


def _build_logs_command(agent_config: dict):
    if "logs_command" in agent_config:
        return agent_config["logs_command"]
    if "container" in agent_config:
        return f"docker logs --tail 100 {agent_config['container']}"
    return None


def get_container_exit_info(agent_config: dict):
    host, user = agent_config["host"], agent_config["user"]
    try:
        exit_code = None
        if "container" in agent_config:
            _, exit_code_out, _ = _ssh_run(
                host, user, f"docker inspect --format={{{{.State.ExitCode}}}} {agent_config['container']}"
            )
            raw = exit_code_out.strip().strip("'\"") or None
            try:
                exit_code = int(raw) if raw is not None else None
            except ValueError:
                exit_code = None
        # non-container targets (e.g. Person B's raw process) have no
        # equivalent concept — exit_code stays None, and that's expected;
        # recovery for the orchestrator is confirmed via /health, not exit code.

        logs = None
        logs_cmd = _build_logs_command(agent_config)
        if logs_cmd:
            _, logs_out, logs_err = _ssh_run(host, user, logs_cmd)
            logs = (logs_out + logs_err).strip()

        return exit_code, logs
    except Exception as e:
        return None, f"could not read container info via SSH ({host}): {e}"


def _restart_remote_container(agent_config: dict) -> bool:
    host, user = agent_config["host"], agent_config["user"]
    try:
        exit_status, out, err = _ssh_run(host, user, _build_restart_command(agent_config))
        return exit_status == 0
    except Exception as e:
        print(f"[WATCHDOG] SSH restart failed for {agent_config.get('container', '(process)')}@{host}: {e}")
        return False


# ============================================
# HEARTBEAT POLLING + DOCKER RESTART (agents + orchestrator)
# ============================================

def check_agent_heartbeats():
    for agent_name, agent_config in AGENT_CONTAINER_MAP.items():
        heartbeat_key = REDIS_AGENT_HEARTBEAT.format(name=agent_name)

        try:
            heartbeat_value = redis_client.get(heartbeat_key)
        except Exception as e:
            print(f"[WATCHDOG] Redis error checking heartbeat for {agent_name}: {e}")
            continue

        if heartbeat_value is not None:
            _first_miss_time.pop(agent_name, None)
            continue

        if agent_name not in _first_miss_time:
            _first_miss_time[agent_name] = time.time()

        print(f"[WATCHDOG] {agent_name} heartbeat missing/stale - considering restart")
        _restart_container(agent_name, agent_config)


def _restart_container(agent_name: str, agent_config: dict):
    now = time.time()
    last = _last_restart.get(agent_name, 0)

    if now - last < RESTART_COOLDOWN_SECONDS:
        remaining = int(RESTART_COOLDOWN_SECONDS - (now - last))
        print(f"[WATCHDOG] {agent_name} restarted recently, "
              f"cooldown {remaining}s remaining - skipping")
        return

    container = agent_config.get("container", "?")
    host = agent_config.get("host", "?")

    exit_code, log_excerpt = get_container_exit_info(agent_config)
    log_summary = log_excerpt[-1000:] if log_excerpt else None

    print(f"[WATCHDOG] {agent_name} ({container}@{host}) restarting via SSH...")
    restarted = _restart_remote_container(agent_config)
    if restarted:
        _last_restart[agent_name] = now

    if not restarted:
        log_healing_event_pg(agent_name, "restart_failed", docker_exit_code=exit_code,
                              log_summary=log_summary)
        send_slack_alert(
            f":rotating_light: *{agent_name}* restart FAILED (SSH to `{host}`). "
            f"Manual intervention needed.\nExit code: `{exit_code}`"
        )
        return

    # confirm real recovery — wait for heartbeat/health to actually return
    recovered = False
    if agent_name != "orchestrator":
        for _ in range(RECOVERY_WAIT_SECONDS):
            time.sleep(1)
            if redis_client.get(REDIS_AGENT_HEARTBEAT.format(name=agent_name)) is not None:
                recovered = True
                break
    else:
        for _ in range(RECOVERY_WAIT_SECONDS):
            time.sleep(1)
            try:
                resp = requests.get(f"{ORCHESTRATOR_URL}/health", timeout=3)
                if resp.status_code == 200 and resp.json().get("status") == "running":
                    recovered = True
                    break
            except requests.exceptions.RequestException:
                continue

    miss_start = _first_miss_time.get(agent_name, now)
    recovery_time = (time.time() - miss_start) if recovered else None

    log_healing_event_pg(
        agent_name, "restart",
        docker_exit_code=exit_code, log_summary=log_summary,
        recovery_time_seconds=recovery_time,
    )

    send_slack_alert(
        f":rotating_light: *Agent Down* — `{agent_name}` (`{container}`@`{host}`)\n"
        f"Exit code: `{exit_code}`\n"
        f"Last logs:\n```{(log_summary or 'n/a')[-500:]}```\n"
        f"Recovery: {'confirmed in ' + str(round(recovery_time, 1)) + 's' if recovered else f'NOT CONFIRMED after {RECOVERY_WAIT_SECONDS}s'}"
    )

    if recovered:
        _first_miss_time.pop(agent_name, None)
        _consecutive_failures[agent_name] = 0
    else:
        _consecutive_failures[agent_name] = _consecutive_failures.get(agent_name, 0) + 1
        if _consecutive_failures[agent_name] >= REPEATED_FAILURE_THRESHOLD:
            send_slack_alert(
                f":x: *ESCALATION* — `{agent_name}` has failed to recover "
                f"{_consecutive_failures[agent_name]} times in a row. "
                f"Human intervention required."
            )

# ============================================
# ORPHAN TASK DETECTION — matches Person C's confirmed contract:
# agents maintain agent:{name}:in_progress via LPUSH (base_agent.py
# _claim_task), release via LREM on completion. Dispatch itself is
# HTTP-poll based against task_status:{task_id} on the orchestrator —
# there is no pending_tasks list to push back onto. "Requeue" means
# resetting task_status:{task_id} to "pending" so the orchestrator's
# get_agent_tasks() picks it up on the agent's next poll.
# (task_status:{task_id} key format still pending confirmation from
# Person B — assumed to be a plain Redis string, not JSON.)
# ============================================

def _agent_is_alive(agent_name: str) -> bool:
    try:
        return redis_client.get(REDIS_AGENT_HEARTBEAT.format(name=agent_name)) is not None
    except Exception:
        return False


def check_orphan_tasks():
    for agent_name, agent_config in AGENT_CONTAINER_MAP.items():
        in_progress_key = f"agent:{agent_name}:in_progress"
        orphan_threshold = AGENT_ORPHAN_SECONDS_OVERRIDES.get(agent_name, TASK_ORPHAN_SECONDS)

        try:
            claims = redis_client.lrange(in_progress_key, 0, -1)
        except Exception as e:
            print(f"[WATCHDOG] Redis error scanning {in_progress_key}: {e}")
            continue

        for claim_json in claims:
            try:
                claim = json.loads(claim_json)
            except json.JSONDecodeError:
                continue

            claimed_at_raw = claim.get("claimed_at")
            task_id = claim.get("task_id")
            if claimed_at_raw is None or task_id is None:
                continue

            try:
                claimed_at = datetime.fromisoformat(claimed_at_raw)
                if claimed_at.tzinfo is None:
                    claimed_at = claimed_at.replace(tzinfo=timezone.utc)
                age_seconds = (datetime.now(timezone.utc) - claimed_at).total_seconds()
            except ValueError:
                continue

            if age_seconds < orphan_threshold:
                continue  # legitimately still in progress — too young to judge
            if _agent_is_alive(agent_name):
                continue  # agent's alive and heartbeating — trust it's still working

            print(f"[WATCHDOG] ORPHAN TASK: task={task_id} agent={agent_name} "
                  f"age={int(age_seconds)}s, agent DEAD - resetting to pending")

            try:
                redis_client.set(f"task_status:{task_id}", "pending")
                redis_client.lrem(in_progress_key, 1, claim_json)
            except Exception as e:
                print(f"[WATCHDOG] Failed to reset task_status for {task_id}: {e}")
                continue

            _restart_container(agent_name, agent_config)

# ============================================
# ORCHESTRATOR HEALTH (HTTP-based) + STALLED INCIDENT RECOVERY
# (fallback resubmit — real checkpoint resume pending Person B's
#  /incidents/{id}/resume endpoint + inflight marker key)
# ============================================

def check_orchestrator_health():
    if redis_client.get("watchdog:paused:orchestrator"):
        return  # orchestrator intentionally stopped for a baseline evaluation run
    if not ORCHESTRATOR_CONFIG:
        return  # not configured yet — waiting on Person B's SSH details

    try:
        resp = requests.get(f"{ORCHESTRATOR_URL}/health", timeout=5)
        alive = resp.status_code == 200 and resp.json().get("status") == "running"
    except requests.exceptions.RequestException:
        alive = False

    if alive:
        _first_miss_time.pop("orchestrator", None)
        return

    if "orchestrator" not in _first_miss_time:
        _first_miss_time["orchestrator"] = time.time()

    print("[WATCHDOG] orchestrator /health unreachable - considering restart")
    _restart_container("orchestrator", ORCHESTRATOR_CONFIG)

    time.sleep(5)
    reprocess_stalled_incidents()


def reprocess_stalled_incidents():
    """
    An incident stored at incident:{id}:context with no matching
    taskplan:{id} means the orchestrator died mid-reasoning for it.
    Resubmit those only.
    TODO: replace with POST /incidents/{id}/resume once Person B exposes
    real checkpoint resume — this still reruns reasoning from scratch.
    """
    resubmitted = 0
    for key in redis_client.scan_iter("incident:*:context"):
        parts = key.split(":")
        if len(parts) != 3:
            continue  # not the shape we expect, skip defensively
        incident_id = parts[1]

        if redis_client.exists(f"taskplan:{incident_id}"):
            continue  # reasoning completed fine — not stalled

        incident_data = redis_client.get(key)
        if not incident_data:
            continue

        print(f"[WATCHDOG] STALLED INCIDENT: {incident_id} has no TaskPlan - resubmitting")

        try:
            resp = requests.post(
                f"{ORCHESTRATOR_URL}/incidents/process",
                json=json.loads(incident_data),
                timeout=30,
            )
            if resp.status_code == 200:
                resubmitted += 1
                log_healing_event_pg("orchestrator", "incident_resubmit")
            else:
                print(f"[WATCHDOG] resubmit for {incident_id} returned {resp.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[WATCHDOG] could not resubmit {incident_id}: {e}")

    if resubmitted:
        send_slack_alert(
            f":arrows_counterclockwise: Resubmitted {resubmitted} stalled incident(s) "
            f"after orchestrator restart (no TaskPlan had been generated before it died)."
        )


# ============================================
# MAIN LOOP
# ============================================

def run_watchdog_loop():
    print("=" * 60)
    print("Self-Healing Watchdog starting")
    print(f"Monitoring agents: {list(AGENT_CONTAINER_MAP.keys()) or '(none configured!)'}")
    print(f"Monitoring orchestrator: {ORCHESTRATOR_CONFIG or '(not configured yet)'}")
    print("=" * 60)

    if not AGENT_CONTAINER_MAP:
        print('[WATCHDOG] WARNING: AGENT_CONTAINER_MAP is empty. Example:\n'
              '  AGENT_CONTAINER_MAP=\'{"triage":{"host":"100.103.120.48","user":"HP","container":"protego-triage"}}\'')

    while True:
        cycle_start = time.time()
        try:
            check_agent_heartbeats()
            check_orphan_tasks()
            check_orchestrator_health()
        except Exception:
            print("[WATCHDOG] Unhandled error in cycle:")
            traceback.print_exc()

        time.sleep(max(0, POLL_INTERVAL_SECONDS - (time.time() - cycle_start)))


if __name__ == "__main__":
    run_watchdog_loop()
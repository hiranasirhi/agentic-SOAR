"""
Self-Healing Recovery Time measurement — automation only, per your
correction: healing_events already has recovery_time_seconds computed and
written by the Watchdog on every real restart (miss_start -> confirmed
recovery). Nothing needs to change in the Watchdog itself.

This script:
  1. Deliberately kills a specialist agent container (controlled failure
     injection) via SSH to the agents host.
  2. Waits for the Watchdog to detect + restart + confirm recovery on its
     own (no polling of the agent directly — that would just re-implement
     the Watchdog's own logic here).
  3. Reads the resulting row back from healing_events and reports
     recovery_time_seconds, exactly as the Watchdog computed it.

Usage:
  docker compose run --rm evaluation python measure_self_healing.py --agent triage
  docker compose run --rm evaluation python measure_self_healing.py --agent all --repeats 3
"""

import argparse
import os
import time
from datetime import datetime, timezone

import paramiko
import psycopg2
import psycopg2.extras

AGENTS_HOST = os.environ["AGENTS_HOST"]          # Tailscale IP of the agents host
AGENTS_SSH_USER = os.environ.get("AGENTS_SSH_USER", "atomicred")
SSH_KEY_PATH = os.environ["SSH_KEY_PATH"]
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
PG_DSN = os.environ["POSTGRES_DSN"]

# Container names on the agents host — confirm exact names match your compose file.
AGENT_CONTAINERS = {
    "triage": "protego-triage",
    "investigation": "protego-investigation",
    "response": "protego-response",
    "containment": "protego-containment",
    "notification": "protego-notification",
    "learning": "protego-learning",
}

# Give the Watchdog enough time to: notice the missed heartbeats (TTL expiry),
# hit its cooldown/restart logic, restart over SSH, and confirm recovery.
# Comfortably above (heartbeat_ttl + restart_cooldown + recovery_wait) —
# adjust to match your actual constants.py values.
WAIT_FOR_WATCHDOG_SECONDS = int(os.environ.get("WAIT_FOR_WATCHDOG_SECONDS", "180"))


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


def kill_agent(agent_name: str):
    container = AGENT_CONTAINERS[agent_name]
    print(f"[SELF-HEAL-TEST] killing {container} on {AGENTS_HOST} (controlled failure injection)")
    code, out, err = _ssh_run(AGENTS_HOST, AGENTS_SSH_USER, f"docker kill {container}")
    if code != 0:
        raise RuntimeError(f"failed to kill {container}: {err}")


def fetch_latest_healing_event(agent_name: str, after: datetime):
    """Polls healing_events for the row the Watchdog writes once it confirms
    (or fails to confirm) recovery for this agent, created after `after`."""
    deadline = time.time() + WAIT_FOR_WATCHDOG_SECONDS
    conn = psycopg2.connect(PG_DSN)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            while time.time() < deadline:
                cur.execute(
                    """
                    SELECT * FROM healing_events
                    WHERE agent_name = %s AND recovered_at >= %s
                    ORDER BY recovered_at DESC
                    LIMIT 1
                    """,
                    (agent_name, after),
                )
                row = cur.fetchone()
                if row:
                    return row
                time.sleep(5)
    finally:
        conn.close()
    return None


def run_single_test(agent_name: str):
    injected_at = datetime.now(timezone.utc)
    kill_agent(agent_name)

    event = fetch_latest_healing_event(agent_name, injected_at)
    if event is None:
        print(f"[SELF-HEAL-TEST] {agent_name}: NO healing_events row appeared within "
              f"{WAIT_FOR_WATCHDOG_SECONDS}s — Watchdog may not have detected the kill, "
              f"or is still mid-recovery. Check watchdog logs.")
        return None

    if event["recovery_time_seconds"] is None:
        print(f"[SELF-HEAL-TEST] {agent_name}: Watchdog logged event_type="
              f"'{event['event_type']}' but recovery was NOT confirmed "
              f"(exit_code={event['docker_exit_code']}). Recovery time: n/a")
        return event

    print(f"[SELF-HEAL-TEST] {agent_name}: recovered in "
          f"{event['recovery_time_seconds']:.1f}s (event_type={event['event_type']})")
    return event


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True, choices=list(AGENT_CONTAINERS) + ["all"])
    parser.add_argument("--repeats", type=int, default=1)
    args = parser.parse_args()

    targets = list(AGENT_CONTAINERS) if args.agent == "all" else [args.agent]
    results = []

    for agent_name in targets:
        for i in range(args.repeats):
            print(f"\n[SELF-HEAL-TEST] === {agent_name} run {i+1}/{args.repeats} ===")
            result = run_single_test(agent_name)
            results.append((agent_name, result))
            # cooldown between injections so the Watchdog's own restart cooldown
            # (RESTART_COOLDOWN_SECONDS) doesn't suppress the next kill's restart
            time.sleep(150)  # must exceed Watchdog's RESTART_COOLDOWN_SECONDS (120s default)
            
    print("\n=== SUMMARY ===")
    for agent_name, event in results:
        if event and event.get("recovery_time_seconds") is not None:
            print(f"  {agent_name:15s}: {event['recovery_time_seconds']:.1f}s")
        else:
            print(f"  {agent_name:15s}: NOT CONFIRMED")

    print("\nFor the full historical picture (not just this run), query directly:")
    print("  SELECT agent_name, recovery_time_seconds, recovered_at FROM healing_events "
          "WHERE event_type = 'restart' ORDER BY recovered_at DESC;")


if __name__ == "__main__":
    main()

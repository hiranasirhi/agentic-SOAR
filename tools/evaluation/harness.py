"""
Full evaluation harness — §10.1.

For a given mode ('full' or 'baseline'):
  1. Ensure the correct dispatch path is live (mode_control.py).
  2. For each of the 12 scenarios (scenarios.py):
       a. Fire the Atomic Red Team test on the correct victim VM over SSH.
       b. Record attack_fired_at.
       c. Poll Postgres for a matching Incident row until it appears or
          TIMEOUT_SECONDS elapses.
       d. If found: compute MTTD (incident detected - attack fired), then
          keep polling for the response/verification step to complete to
          compute MTTR.
       e. Write one row to evaluation_runs per scenario/mode.
  3. Print a summary; compute_metrics.py does the P/R/F1 pass afterward.

Usage:
  docker compose run --rm evaluation python harness.py --mode full
  docker compose run --rm evaluation python harness.py --mode baseline
  docker compose run --rm evaluation python harness.py --mode full --scenarios linux_ssh_bruteforce,windows_rdp_bruteforce
"""

import argparse
import json
import os
import time
import uuid
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

import mode_control
from scenarios import SCENARIOS
from ssh_exec import run_atomic_test

PG_DSN = os.environ["POSTGRES_DSN"]

# How long to wait for an Incident to appear after firing the attack.
DETECTION_TIMEOUT_SECONDS = int(os.environ.get("DETECTION_TIMEOUT_SECONDS", "180"))
# How long, after detection, to wait for the response action to be confirmed.
RESPONSE_TIMEOUT_SECONDS = int(os.environ.get("RESPONSE_TIMEOUT_SECONDS", "600"))
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "5"))

# Matches the real init.sql: incidents has `hostname` (not target_host)
# and `created_at` (not detected_at) — no response_status /
# response_completed_at columns exist on incidents at all. Response
# completion lives separately in the `metrics` table (see
# poll_for_response_completion below).
INCIDENT_POLL_SQL = """
    SELECT incident_id, mitre_technique, created_at
    FROM incidents
    WHERE hostname = %s AND created_at >= %s
    ORDER BY created_at ASC
    LIMIT 1
"""


def get_pg_conn():
    return psycopg2.connect(PG_DSN)


def poll_for_incident(conn, target_host: str, fired_at: datetime, timeout_s: int):
    deadline = time.time() + timeout_s
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        while time.time() < deadline:
            cur.execute(INCIDENT_POLL_SQL, (target_host, fired_at))
            row = cur.fetchone()
            if row:
                return row
            time.sleep(POLL_INTERVAL_SECONDS)
    return None


def poll_for_response_completion(conn, incident_id: str, timeout_s: int):
    """Response completion lives in `metrics`, not `incidents` — poll for
    a row whose response_complete_time has been set. Use the system's own
    mttr_seconds directly if it's already computed there, rather than
    recomputing it ourselves."""
    deadline = time.time() + timeout_s
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        while time.time() < deadline:
            cur.execute(
                "SELECT response_complete_time, mttr_seconds FROM metrics WHERE incident_id = %s",
                (incident_id,),
            )
            row = cur.fetchone()
            if row and row["response_complete_time"] is not None:
                return row
            time.sleep(POLL_INTERVAL_SECONDS)
    return None

def record_run(conn, run_batch_id, mode, scenario, fired_at, incident_row, response_row):
    with conn, conn.cursor() as cur:
        if incident_row is None:
            cur.execute(
                """
                INSERT INTO evaluation_runs
                    (run_batch_id, mode, scenario_id, environment, expected_technique,
                     attack_fired_at, outcome, raw_result)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (run_batch_id, mode, scenario["id"], scenario["environment"],
                 scenario["technique"], fired_at, "missed", json.dumps({})),
            )
            return

        mttd = (incident_row["created_at"] - fired_at).total_seconds()
        detected_technique = incident_row["mitre_technique"]
        outcome = "detected" if detected_technique == scenario["technique"] else "wrong_technique"

        mttr = None
        response_completed_at = None
        if response_row and response_row.get("response_complete_time"):
            response_completed_at = response_row["response_complete_time"]
            # prefer the system's own computed mttr_seconds; fall back to
            # computing it ourselves only if that column is null
            mttr = response_row.get("mttr_seconds")
            if mttr is None:
                mttr = (response_completed_at - incident_row["created_at"]).total_seconds() / 60.0

        cur.execute(
            """
            INSERT INTO evaluation_runs
                (run_batch_id, mode, scenario_id, environment, expected_technique,
                 attack_fired_at, incident_id, incident_detected_at, detected_technique,
                 mttd_seconds, response_completed_at, mttr_seconds, outcome, raw_result)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (run_batch_id, mode, scenario["id"], scenario["environment"], scenario["technique"],
             fired_at, incident_row["incident_id"], incident_row["created_at"], detected_technique,
             mttd, response_completed_at, mttr, outcome, json.dumps(dict(incident_row), default=str)),
        )


def run_scenario(conn, run_batch_id, mode, scenario):
    ssh_host = os.environ[scenario["host_env_var"]]  # IP — used only for SSH
    # incidents.hostname is the victim's OS hostname string, NOT its IP —
    # these are two different values. Add LINUX_VICTIM_HOSTNAME /
    # WINDOWS_VICTIM_HOSTNAME to .env (the actual `hostname` output on
    # each victim VM), alongside the existing LINUX_VICTIM_HOST / IP vars.
    incident_hostname = (
        os.environ["LINUX_VICTIM_HOSTNAME"] if scenario["environment"] == "linux"
        else os.environ["WINDOWS_VICTIM_HOSTNAME"]
    )
    fired_at = datetime.now(timezone.utc)

    print(f"[HARNESS] [{mode}] firing {scenario['id']} ({scenario['technique']}) on {ssh_host}")
    exec_result = run_atomic_test(ssh_host, scenario["atomic_test"], scenario["environment"])
    if exec_result["exit_status"] != 0:
        print(f"[HARNESS] WARNING: atomic test exited {exec_result['exit_status']} — "
              f"stderr: {exec_result['stderr'][:300]}")

    incident_row = poll_for_incident(conn, incident_hostname, fired_at, DETECTION_TIMEOUT_SECONDS)
    if incident_row is None:
        print(f"[HARNESS] [{mode}] {scenario['id']}: NOT DETECTED within {DETECTION_TIMEOUT_SECONDS}s")
        record_run(conn, run_batch_id, mode, scenario, fired_at, None, None)
        return

    mttd = (incident_row["created_at"] - fired_at).total_seconds()
    print(f"[HARNESS] [{mode}] {scenario['id']}: detected as {incident_row['mitre_technique']} "
          f"in {mttd:.1f}s (incident_id={incident_row['incident_id']})")

    response_row = poll_for_response_completion(conn, incident_row["incident_id"], RESPONSE_TIMEOUT_SECONDS)
    if response_row is None:
        print(f"[HARNESS] [{mode}] {scenario['id']}: response not confirmed within {RESPONSE_TIMEOUT_SECONDS}s")

    record_run(conn, run_batch_id, mode, scenario, fired_at, incident_row, response_row)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["full", "baseline"], required=True)
    parser.add_argument("--scenarios", default=None,
                         help="comma-separated scenario ids to run; default = all 12")
    parser.add_argument("--run-batch-id", default=None)
    args = parser.parse_args()

    run_batch_id = args.run_batch_id or f"{args.mode}-{uuid.uuid4().hex[:8]}"
    selected_ids = None if (not args.scenarios or args.scenarios.lower() == "all") else set(args.scenarios.split(","))
    scenarios_to_run = [s for s in SCENARIOS if selected_ids is None or s["id"] in selected_ids]

    print(f"[HARNESS] run_batch_id={run_batch_id} mode={args.mode} "
          f"scenarios={[s['id'] for s in scenarios_to_run]}")

    mode_control.set_mode(args.mode)

    conn = get_pg_conn()
    try:
        for scenario in scenarios_to_run:
            run_scenario(conn, run_batch_id, args.mode, scenario)
            # brief settle time between scenarios so events don't overlap/get misattributed
            time.sleep(15)
    finally:
        conn.close()

    print(f"[HARNESS] done. run_batch_id={run_batch_id}")
    print(f"[HARNESS] next: docker compose run --rm evaluation python compute_metrics.py --run-batch-id {run_batch_id}")


if __name__ == "__main__":
    main()

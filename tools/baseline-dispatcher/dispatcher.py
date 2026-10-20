"""
baseline-dispatcher
====================
Stands in for the LLM Orchestrator during "baseline" evaluation runs
(§10.1, condition 2). Consumes confirmed incidents directly from the
`incidents` Kafka topic and dispatches a fixed rule-based action —
no ChromaDB retrieval, no ReAct loop, no Qwen 2.5 call.

Only ONE of these two ever runs at a time:
  - "full" mode  -> real Orchestrator (Person B's host) is up, this container
                    is stopped.
  - "baseline" mode -> this container is up, real Orchestrator is stopped
                    (via harness's mode_control.py, over SSH).
The evaluation harness handles that toggle — this script assumes it is the
only thing serving tasks when it's running.

*** UPDATED: no longer writes to Redis directly. ***
Instead of guessing at the Orchestrator's Redis key shape, this now runs
its OWN HTTP server (FastAPI, in a background thread) exposing the exact
same contract base_agent.py's polling loop already expects:
  GET  /agents/{agent_name}/tasks   -> drains pending tasks for that agent
  POST /orchestrator/results        -> agents post results here
  GET  /health                      -> liveness check
Agents don't need to know or care whether they're talking to the real
Orchestrator or this dispatcher — same endpoints, same shapes.

Requires fastapi + uvicorn — add both to
tools/baseline-dispatcher/requirements.txt and rebuild before testing.

Port 8000 — confirm nothing else on this host is already bound to it
(`docker ps`) before deploying.
"""

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from fastapi import FastAPI
import uvicorn
from kafka import KafkaConsumer

from rules import resolve_action

KAFKA_BROKER = os.environ["KAFKA_BROKER"]
INCIDENTS_TOPIC = os.environ.get("INCIDENTS_TOPIC", "incidents")
PG_DSN = os.environ["POSTGRES_DSN"]  # e.g. "host=... dbname=... user=... password=..."
HTTP_PORT = int(os.environ.get("BASELINE_DISPATCHER_PORT", "8000"))

# --- in-memory task store, shared between the Kafka consumer thread and
#     the HTTP server thread — protected by _lock throughout ---
_lock = threading.Lock()
_pending_tasks = {}       # {agent_name: [task_dict, ...]}
_results = {}              # {task_id: result_dict}
_expected_actions = {}     # {incident_id: remaining_count} — resolves the
                            # "how do we know an incident is fully handled"
                            # gap: decremented as results land, incident
                            # closed when it hits zero.


def build_task(incident: dict, rule: dict) -> dict:
    """Shape matches what base_agent.py's task executor expects —
    task_id/incident_id/action carried over from the original version,
    plus incident_context bundled in so agents never need a separate
    call back to this dispatcher to get incident details."""
    return {
        "task_id": str(uuid.uuid4()),
        "incident_id": incident["incident_id"],
        "action": rule["action"],
        "mode": "baseline",
        "target_vm": incident.get("target_host") or incident.get("asset") or incident.get("hostname"),
        "malicious_ip": incident.get("source_ip"),
        "severity": rule["severity_default"],
        "dispatched_at": datetime.now(timezone.utc).isoformat(),
        "incident_context": incident,
    }


def queue_task_for_agent(agent_name: str, task: dict):
    with _lock:
        _pending_tasks.setdefault(agent_name, []).append(task)
        incident_id = task["incident_id"]
        _expected_actions[incident_id] = _expected_actions.get(incident_id, 0) + 1


def dispatch(incident: dict):
    technique = incident.get("mitre_technique") or incident.get("technique")
    if not technique:
        print(f"[BASELINE] incident {incident.get('incident_id')} has no technique field, skipping")
        return

    rule = resolve_action(technique)
    task = build_task(incident, rule)
    queue_task_for_agent(rule["agent"], task)

    print(
        f"[BASELINE] incident={incident['incident_id']} technique={technique} "
        f"-> agent={rule['agent']} action={rule['action']} task_id={task['task_id']}"
    )

    log_dispatch_pg(incident, task, rule)


def log_dispatch_pg(incident: dict, task: dict, rule: dict):
    """Kept from the original — independent, persistent record of what
    was dispatched, since the in-memory task store empties out once
    agents drain it (nothing here relies on Redis anymore)."""
    try:
        conn = psycopg2.connect(PG_DSN)
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO baseline_dispatch_log
                    (incident_id, technique, agent, action, dispatched_at)
                VALUES (%s, %s, %s, %s, NOW())
                """,
                (incident["incident_id"], incident.get("mitre_technique"), rule["agent"], rule["action"]),
            )
        conn.close()
    except Exception as e:
        print(f"[BASELINE] failed to log dispatch to postgres: {e}")


def _close_incident_in_pg(incident_id: str):
    try:
        conn = psycopg2.connect(PG_DSN)
        with conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE incidents SET closed_at = NOW(), status = 'closed' WHERE incident_id = %s",
                (incident_id,),
            )
        conn.close()
        print(f"[BASELINE] incident {incident_id} closed — all dispatched actions completed")
    except Exception as e:
        print(f"[BASELINE] failed to close incident {incident_id} in postgres: {e}")


def _maybe_close_incident(incident_id: str):
    """Resolves the original stub: tracks how many actions were dispatched
    per incident (_expected_actions, incremented in queue_task_for_agent),
    decrements as each result lands, and closes the incident once every
    dispatched action has reported back — not just on the first result."""
    if incident_id is None:
        return
    with _lock:
        remaining = _expected_actions.get(incident_id)
        if remaining is None:
            return  # result for an incident we have no record of dispatching
        remaining -= 1
        if remaining <= 0:
            del _expected_actions[incident_id]
            should_close = True
        else:
            _expected_actions[incident_id] = remaining
            should_close = False
    if should_close:
        _close_incident_in_pg(incident_id)


# --- HTTP server: same contract base_agent.py already polls against ---
app = FastAPI()


@app.get("/agents/{agent_name}/tasks")
def get_tasks(agent_name: str):
    with _lock:
        tasks = _pending_tasks.get(agent_name, [])
        _pending_tasks[agent_name] = []  # drain on read, same as a real poll
    return {"tasks": tasks}


@app.post("/orchestrator/results")
def post_result(result: dict):
    with _lock:
        _results[result["task_id"]] = result
    _maybe_close_incident(result.get("incident_id"))
    return {"success": True}


@app.get("/health")
def health():
    return {"status": "running"}


def run_http_server():
    uvicorn.run(app, host="0.0.0.0", port=HTTP_PORT)


def main_loop():
    consumer = KafkaConsumer(
        INCIDENTS_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        auto_offset_reset="latest",
        enable_auto_commit=True,
        group_id="baseline-dispatcher-group",
    )
    print(f"[BASELINE] listening on {INCIDENTS_TOPIC} ...")
    for message in consumer:
        try:
            dispatch(message.value)
        except Exception as e:
            print(f"[BASELINE] error dispatching incident: {e}")


if __name__ == "__main__":
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()
    main_loop()
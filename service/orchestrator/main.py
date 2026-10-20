# ============================================
# orchestrator/main.py
# PROTEGO Orchestrator Service
# ============================================

import asyncio
import json
import os
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import redis
import psycopg2
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from kafka import KafkaConsumer, KafkaProducer
from pydantic import ValidationError

from orchestrator.react_engine import run_react_loop, resume_checkpoint
from orchestrator.memory import (
    store_incident,
    store_false_positive,
    check_false_positive,
    get_memory_stats,
)
from shared.constants import (
    AGENT_TRIAGE,
    AGENT_INVESTIGATION,
    AGENT_RESPONSE,
    AGENT_CONTAINMENT,
    AGENT_NOTIFICATION,
)
from shared.models import TaskPlan, AgentResult

print("=" * 70)
print("LOADED REACT_ENGINE FROM:")
print(__file__)
print("=" * 70)

class ResumeCheckpointRequest(BaseModel):
    incident_id: str



# ============================================
# LOAD ENVIRONMENT
# ============================================

load_dotenv()

# Verbose per-action dispatch logging (was unconditional before; it
# floods the log because get_agent_tasks() runs on every single agent
# poll for every action in every stored plan). Off by default -
# set ORCHESTRATOR_DEBUG_DISPATCH=1 to re-enable while debugging.
DEBUG_DISPATCH = os.getenv("ORCHESTRATOR_DEBUG_DISPATCH", "0") == "1"

# How many Kafka incidents can be processed concurrently. Processing
# used to run inline in the consumer's for-loop, so one incident that
# was slow (or, pre-fix, hung) stalled ingestion of every message
# behind it. Now each message is handed off to a worker pool instead.
INCIDENT_WORKER_COUNT = int(os.getenv("ORCHESTRATOR_INCIDENT_WORKERS", "4"))

# ============================================
# FASTAPI APPLICATION
# ============================================

app = FastAPI(
    title="PROTEGO Orchestrator",
    description="Autonomous Security Incident Response Orchestrator",
    version="1.0.0",
)

@app.post("/checkpoints/resume")
def resume_checkpoint_endpoint(request: ResumeCheckpointRequest):
    """
    Called by the Module 3 Watchdog after the orchestrator
    has restarted.
    """

    incident_id = request.incident_id

    try:
        print(
            f"[CHECKPOINT RESUME] "
            f"Watchdog requested resume for {incident_id}"
        )

        task_plan = resume_checkpoint(incident_id)

        return {
            "status": "resumed",
            "incident_id": incident_id,
            "task_plan": task_plan,
        }

    except ValueError as e:
        raise HTTPException(
            status_code=404,
            detail=str(e),
        )

    except Exception as e:
        print(
            f"[CHECKPOINT RESUME] Error for {incident_id}: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail=str(e),
        )

@app.post("/incidents/{incident_id}/resume")
def resume_incident(incident_id: str):
    """
    Resume an interrupted incident from its LangGraph checkpoint.
    """

    try:
        print(
            f"[LANGGRAPH RESUME] "
            f"Resume requested for {incident_id}"
        )

        task_plan = resume_checkpoint(incident_id)

        return {
            "status": "resumed",
            "incident_id": incident_id,
            "message": "Resume successful",
            "task_plan": task_plan,
        }

    except ValueError as e:
        raise HTTPException(
            status_code=404,
            detail=str(e),
        )

    except Exception as e:
        print(
            f"[LANGGRAPH RESUME] "
            f"Error for {incident_id}: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail=str(e),
        )

# ============================================
# REDIS CONNECTION
# ============================================

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "100.71.186.0"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    decode_responses=True,

    # Connection timeout:
    # how long Python waits to establish the Redis connection.
    socket_connect_timeout=5,

    # Read timeout:
    # how long Python waits for Redis to answer a command.
    socket_timeout=10,

    # Automatically retry a failed connection when appropriate.
    retry_on_timeout=True,

    # Keep TCP connections alive.
    health_check_interval=30,
)
try:
    redis_client.ping()
    print(
        f"[REDIS] Connected to "
        f"{os.getenv('REDIS_HOST', '100.71.186.0')}:"
        f"{os.getenv('REDIS_PORT', '6379')}"
    )
except Exception as e:
    print(f"[REDIS] WARNING: Redis connection failed: {e}")
    
# ============================================
# POSTGRESQL CONNECTION
# ============================================

POSTGRES_HOST = os.getenv(
    "POSTGRES_HOST",
    "100.71.186.0"
)

POSTGRES_PORT = int(
    os.getenv("POSTGRES_PORT", "5432")
)

POSTGRES_DB = os.getenv(
    "POSTGRES_DB",
    "soar_db"
)

POSTGRES_USER = os.getenv(
    "POSTGRES_USER",
    "soar_user"
)

POSTGRES_PASSWORD = os.getenv(
    "POSTGRES_PASSWORD",
    "soar_password123"
)

def _get_postgres_connection():
    """
    Create a PostgreSQL connection.

    PostgreSQL is the durable incident record.
    Failure here must never block Redis/task dispatch.
    """

    try:
        return psycopg2.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            connect_timeout=5,
        )

    except Exception as e:
        print(
            f"[POSTGRES] Connection failed: {e}"
        )
        return None


def _insert_incident_into_postgres(
    incident: dict,
    detected_at=None,
):
    """
    Insert the incident into the durable PostgreSQL
    incidents table.

    Redis remains the operational source of truth.
    PostgreSQL failure must never stop dispatch.
    """

    connection = None

    try:

        connection = _get_postgres_connection()

        if connection is None:
            return False

        raw_event = dict(incident)

        # Internal Kafka metadata should not become
        # part of the original event.
        raw_event.pop(
            "_kafka_detected_at",
            None
        )

        source_ip = incident.get(
            "source_ip",
            incident.get("src_ip")
        )

        destination_ip = incident.get(
            "destination_ip",
            incident.get("dst_ip")
        )

        mitre_technique = incident.get(
            "mitre_technique",
            incident.get(
                "mitre_id",
                incident.get("technique_id")
            )
        )

        mitre_tactic = incident.get(
            "mitre_tactic"
        )

        severity = incident.get(
            "composite_severity",
            incident.get("severity")
        )

        asset_criticality = incident.get(
            "asset_criticality"
        )

        hostname = incident.get(
            "hostname"
        )

        username = incident.get(
            "username"
        )

        event_source = incident.get(
            "event_source",
            incident.get("source")
        )

        connection.autocommit = False

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO incidents (
                incident_id,
                source_ip,
                destination_ip,
                mitre_technique,
                mitre_tactic,
                severity,
                asset_criticality,
                hostname,
                username,
                event_source,
                status,
                false_positive,
                raw_event,
                detected_at
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                'open',
                FALSE,
                %s::jsonb,
                %s
            )
            ON CONFLICT (incident_id)
            DO NOTHING
            """,
            (
                incident["incident_id"],
                source_ip,
                destination_ip,
                mitre_technique,
                mitre_tactic,
                severity,
                asset_criticality,
                hostname,
                username,
                event_source,
                json.dumps(
                    raw_event,
                    default=str
                ),
                detected_at or datetime.now(),
            )
        )

        connection.commit()

        cursor.close()

        print(
            f"[POSTGRES] Incident inserted: "
            f"{incident['incident_id']}"
        )

        return True

    except Exception as e:

        print(
            f"[POSTGRES] Incident insert failed "
            f"for {incident.get('incident_id')}: {e}"
        )

        if connection:
            try:
                connection.rollback()
            except Exception:
                pass

        return False

    finally:

        if connection:
            try:
                connection.close()
            except Exception:
                pass


def _update_incident_status(
    incident_id: str,
    status: str,
):
    """
    Update durable PostgreSQL incident state.

    PostgreSQL failure must never block
    Redis/task dispatch.
    """

    connection = None

    try:

        connection = _get_postgres_connection()

        if connection is None:
            return False

        cursor = connection.cursor()

        if status == "closed":

            cursor.execute(
                """
                UPDATE incidents
                SET
                    status = 'closed',
                    closed_at = NOW()
                WHERE incident_id = %s
                  AND status IN ('open', 'dispatched')
                """,
                (incident_id,)
            )

        else:

            cursor.execute(
                """
                UPDATE incidents
                SET status = %s
                WHERE incident_id = %s
                  AND status = 'open'
                """,
                (
                    status,
                    incident_id
                )
            )

        connection.commit()

        print(
            f"[POSTGRES] Incident {incident_id} "
            f"status -> {status}"
        )

        cursor.close()

        return True

    except Exception as e:

        print(
            f"[POSTGRES] Status update failed "
            f"for {incident_id}: {e}"
        )

        if connection:
            try:
                connection.rollback()
            except Exception:
                pass

        return False

    finally:

        if connection:
            try:
                connection.close()
            except Exception:
                pass

# ============================================
# KAFKA CONSUMER (created lazily, with retry)
# ============================================

KAFKA_RETRY_MIN_SECONDS = int(os.getenv("KAFKA_RETRY_MIN_SECONDS", "2"))
KAFKA_RETRY_MAX_SECONDS = int(os.getenv("KAFKA_RETRY_MAX_SECONDS", "30"))

# Reported by /health. Kafka being down must never make the orchestrator "unhealthy".
kafka_state = {
    "connected": False,
    "last_error": None,
    "last_message_at": None,
    "reconnect_attempts": 0,
}


def _create_consumer() -> KafkaConsumer:
    return KafkaConsumer(
        os.getenv("KAFKA_TOPIC", "incidents"),
        bootstrap_servers=os.getenv("KAFKA_BROKER", "100.71.186.0:9092"),
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="latest",
        enable_auto_commit=True,
        group_id="protego-orchestrator",
    )
    
# ============================================
# INCIDENT WORKER POOL
# ============================================

incident_executor = ThreadPoolExecutor(
    max_workers=INCIDENT_WORKER_COUNT,
    thread_name_prefix="incident-worker",
)

# ============================================
# KAFKA LISTENER
# ============================================

def _process_incident_in_thread(incident: dict):
    """
    Runs in a worker thread from incident_executor. Each thread gets
    its own asyncio event loop via asyncio.run(), so incidents can be
    processed concurrently instead of one at a time on the consumer
    thread. A hang or long LLM call in run_react_loop() (see
    react_engine.py's LLM_TIMEOUT_SECONDS) now only ties up one worker
    slot instead of blocking Kafka message consumption entirely.
    """
    incident_id = incident.get("incident_id", "UNKNOWN")
    try:
        asyncio.run(process_incident_logic(incident))
        print(f"Incident processing finished: {incident_id}")
    except Exception:
        print(f"\nERROR processing incident {incident_id}")
        traceback.print_exc()


def kafka_listener():
    """
    Supervisor loop: connect, consume, and on ANY Kafka failure back off
    and reconnect. The thread never exits, and nothing here can take down
    the API, Redis dispatch or in-flight task plans.
    """
    backoff = KAFKA_RETRY_MIN_SECONDS

    while True:
        consumer = None
        try:
            print("===================================")
            print("Connecting to Kafka topic: incidents")
            print("Kafka Broker:", os.getenv("KAFKA_BROKER", "100.71.186.0:9092"))
            print(f"Incident worker pool size: {INCIDENT_WORKER_COUNT}")
            print("===================================")

            consumer = _create_consumer()

            kafka_state["connected"] = True
            kafka_state["last_error"] = None
            backoff = KAFKA_RETRY_MIN_SECONDS
            print("[KAFKA] Connected - listening for incidents")

            for msg in consumer:
                try:
                    incident = dict(msg.value)

                    # Kafka message timestamp = detection/publication time.
                    if msg.timestamp is not None:
                        incident["_kafka_detected_at"] = datetime.fromtimestamp(
                            msg.timestamp / 1000
                        )

                    kafka_state["last_message_at"] = datetime.now().isoformat()

                    print("\n" + "=" * 60)
                    print("NEW INCIDENT RECEIVED FROM KAFKA")
                    print("=" * 60)
                    print(json.dumps(incident, indent=2, default=str))

                    incident_executor.submit(
                        _process_incident_in_thread, incident
                    )

                except Exception:
                    print("\nERROR reading Kafka incident")
                    traceback.print_exc()

            print("[KAFKA] Consumer stream ended - reconnecting")

        except Exception as e:
            print(f"[KAFKA] Connection problem: {type(e).__name__}: {e}")
            kafka_state["last_error"] = f"{type(e).__name__}: {e}"

        finally:
            kafka_state["connected"] = False
            if consumer is not None:
                try:
                    consumer.close()
                except Exception:
                    pass

        kafka_state["reconnect_attempts"] += 1
        print(
            f"[KAFKA] Retrying in {backoff}s "
            f"(attempt {kafka_state['reconnect_attempts']})"
        )
        time.sleep(backoff)
        backoff = min(backoff * 2, KAFKA_RETRY_MAX_SECONDS)
        

# ============================================
# STARTUP
# ============================================

def stale_task_recovery_loop():
    RECOVERY_INTERVAL = int(
        os.getenv(
            "ORCHESTRATOR_RECOVERY_INTERVAL",
            "30"
        )
    )

    while True:
        try:
            _recover_stale_tasks()
        except Exception as e:
            print(
                f"[RECOVERY] loop error: {e}"
            )

        time.sleep(RECOVERY_INTERVAL)

@app.on_event("startup")
def startup():
    threading.Thread(target=kafka_listener, daemon=True).start()
    threading.Thread(target=stale_task_recovery_loop, daemon=True).start()


# ============================================
# HEALTH CHECK
# ============================================

@app.get("/health")
def health_check():
    try:
        redis_client.ping()
        redis_status = "connected"
    except Exception:
        redis_status = "disconnected"

    return {
        "status": "running",
        "service": "PROTEGO Orchestrator",
        "redis": redis_status,
        "kafka": kafka_state,
        "timestamp": datetime.now().isoformat(),
    }


# ============================================
# INCIDENT PROCESSING
# ============================================

def _cleanup_old_tasks_for_incident(incident_id: str):
    """
    Remove stale task metadata belonging to previous
    processing attempts for the same incident.
    """
    for key in redis_client.scan_iter("task_to_incident:*"):
        mapped_incident = redis_client.get(key)

        if mapped_incident == incident_id:
            task_id = key.split(":", 1)[1]

            redis_client.delete(f"task_status:{task_id}")
            redis_client.delete(f"task_to_incident:{task_id}")
            redis_client.delete(f"task_created_at:{task_id}")

            print(
                f"[TASK CLEANUP] Removed old task "
                f"{task_id} for incident {incident_id}"
            )
            
async def process_incident_logic(incident: dict):
    """
    Main entry point.

    Flow:
        Detection Engine
              |
        Incident
              |
        Redis Storage
              |
        ChromaDB + LLM ReAct
              |
        TaskPlan
              |
        Agents
    """
    t_process_start = time.monotonic()

    # -----------------------------------------
    # Generate Incident ID
    # -----------------------------------------
    if "incident_id" not in incident:
        incident["incident_id"] = f"INC-{uuid.uuid4().hex[:8].upper()}"

    incident_id = incident["incident_id"]
    
    # -----------------------------------------
    # Durable PostgreSQL Incident Record
    # -----------------------------------------

    detected_at = incident.get(
        "_kafka_detected_at"
    )

    _insert_incident_into_postgres(
        incident,
        detected_at=detected_at
    )
    
    # -----------------------------------------
    # Watchdog: mark incident as in-flight
    # -----------------------------------------
    inflight_key = f"orchestrator:inflight:{incident_id}"

    redis_client.set(
        inflight_key,
        "1",
    ) 
        # -----------------------------------------
    # Prevent duplicate incident processing
    # -----------------------------------------
    lock_key = f"incident_processing:{incident_id}"

    acquired = redis_client.set(
        lock_key,
        "1",
        nx=True,
        ex=300,
    )

    if not acquired:
        print(
            f"[DEDUP] Incident {incident_id} is already "
            f"being processed. Skipping duplicate."
        )
        return
    
    print("\n" + "=" * 50)
    print(f"New Incident: {incident_id}")
    print(f"Type: {incident.get('rule_description', 'Unknown')}")
    print(f"Severity: {incident.get('severity', 'Unknown')}")
    print(f"Source IP: {incident.get('source_ip', 'Unknown')}")
    print("=" * 50)

    # -----------------------------------------
    # Store Incident
    # -----------------------------------------
    redis_client.setex(
        f"incident:{incident_id}",
        86400,
        json.dumps(incident, default=str),
    )

    # -----------------------------------------
    # Run ReAct Engine
    # -----------------------------------------
    try:
        print("Running LLM ReAct reasoning loop...")

        raw_plan = run_react_loop(incident)
        print("\n========= RAW PLAN =========")
        print(json.dumps(raw_plan, indent=2))
        print("============================")

        # Validate LLM output
        task_plan = TaskPlan(**raw_plan).dict()

        print("ReAct completed successfully")

    except Exception as e:
        print(f"ReAct failed: {e}")
        traceback.print_exc()
        print("Using fallback rule-based plan")

        task_plan = create_initial_task_plan(incident)

    # -----------------------------------------
    # Ensure Incident ID
    # -----------------------------------------
    task_plan["incident_id"] = incident_id

    # -----------------------------------------
    # Safety Net: Enforce Investigation Task
    # -----------------------------------------
    # The LLM's ReAct plan sometimes omits an Investigation task even
    # when severity warrants one. Rather than trust the LLM's plan
    # shape for something this consequential, verify it here and
    # append the task ourselves if it's missing. Must run before the
    # UUID-remap step below so the appended task gets swept up in the
    # same remap pass as everything else.
    task_plan = _ensure_investigation_task(task_plan, incident)
    task_plan = _ensure_required_agent_tasks(task_plan, incident)
    
    # -----------------------------------------
# DISPLAY FINAL TASK ASSIGNMENTS
# -----------------------------------------

    print("\n")
    print("=" * 70)
    print("FINAL TASK PLAN")
    print("=" * 70)

    print(
        f"Incident: {incident_id}"
    )

    print(
        f"Severity: "
        f"{task_plan.get('severity')}"
    )

    print(
        f"Approval Required: "
        f"{task_plan.get('approval_required')}"
    )

    print(
        f"Agent Sequence: "
        f"{task_plan.get('agent_sequence')}"
    )

    print("-" * 70)

    for index, action in enumerate(
        task_plan.get("actions", []),
        start=1
    ):

        print(
            f"[TASK {index}]"
        )

        print(
            f"  Task ID    : "
            f"{action.get('task_id')}"
        )

        print(
            f"  Agent      : "
            f"{action.get('agent')}"
        )

        print(
            f"  Action     : "
            f"{action.get('action')}"
        )

        print(
            f"  Depends On : "
            f"{action.get('depends_on', [])}"
        )

        print("-" * 70)

    print("=" * 70)
    print("END FINAL TASK PLAN")
    print("=" * 70)

    # -----------------------------------------
    # Force Unique Task IDs
    # -----------------------------------------
    # The LLM (and the fallback template) can emit placeholder or
    # repeated task_id values (e.g. "unique-string-id") across
    # different incidents. Since task_status/result keys in Redis are
    # keyed only by task_id, a collision makes a brand-new task look
    # "already completed" and it never gets dispatched. Rewrite every
    # task_id here to a real UUID and remap any depends_on references
    # so dependency chains stay intact.

    id_remap = {}

    for action in task_plan.get("actions", []):
        old_id = action["task_id"]
        new_id = str(uuid.uuid4())
        id_remap[old_id] = new_id
        action["task_id"] = new_id

    for action in task_plan.get("actions", []):
        action["depends_on"] = [
            id_remap.get(dep, dep)
            for dep in action.get("depends_on", [])
        ]

    # -----------------------------------------
    # Register Tasks
    # -----------------------------------------
    for action in task_plan.get("actions", []):
        task_id = action["task_id"]

        redis_client.setex(
            f"task_created_at:{task_id}",
            86400,
            time.time(),
        )

        redis_client.setex(
            f"task_to_incident:{task_id}",
            86400,
            incident_id,
        )

        redis_client.setex(
            f"task_status:{task_id}",
            86400,
            "pending",
        )

    # -----------------------------------------
    # Store Task Plan
    # -----------------------------------------
    redis_client.setex(
        f"taskplan:{incident_id}",
        86400,
        json.dumps(task_plan, default=str),
    )

    redis_client.sadd(
        "active_taskplans",
        incident_id,
    )
    # -----------------------------------------
    # PostgreSQL: mark incident dispatched
    # -----------------------------------------

    _update_incident_status(
        incident_id,
        "dispatched"
    )
    
    print("\nTask plan stored in Redis.")

    # Verify Redis contents
    stored_plan = redis_client.get(f"taskplan:{incident_id}")

    if stored_plan:
        print("Task plan successfully written to Redis!")

        # -----------------------------------------
        # Watchdog: incident is no longer in-flight
        # -----------------------------------------
        redis_client.delete(
            f"orchestrator:inflight:{incident_id}"
        )

        print(
            f"[WATCHDOG] Cleared in-flight marker for {incident_id}"
        )

    else:
        print("ERROR: Task plan NOT found in Redis!")

    print("\nRegistered Tasks:")

    for task in task_plan.get("actions", []):
        print(
            f"Task={task['task_id']} | "
            f"Agent={task['agent']} | "
            f"Action={task['action']}"
        )
        print(
            "Status:",
            redis_client.get(f"task_status:{task['task_id']}")
        )

    t_process_elapsed = time.monotonic() - t_process_start

    print(
        f"[TIMING] incident={incident_id} "
        f"end_to_end={t_process_elapsed*1000:.0f}ms "
        f"(store -> plan ready, see react_engine [TIMING] lines above "
        f"for the breakdown)"
    )

    print(f"\nTask Plan Ready: {incident_id}")

    return {
        "message": "Incident processed successfully",
        "incident_id": incident_id,
        "task_plan": task_plan,
    }
# ============================================
# PROCESS INCIDENT API ENDPOINT
# ============================================

@app.post("/incidents/process")
async def process_incident(incident: dict):
    return await process_incident_logic(incident)    

# ============================================
# ENFORCE INVESTIGATION TASK BY SEVERITY
# ============================================

def _ensure_investigation_task(task_plan: dict, incident: dict) -> dict:
    """
    Safety net: the LLM's ReAct plan sometimes omits an Investigation
    task even when severity warrants one (>= 4, matching the fallback
    plan's own threshold). Rather than trust the LLM's plan shape for
    something this consequential, verify it here and append the task
    ourselves if missing.

    Uses composite_severity (the Detection Engine's scored/correlated
    value) with a fallback to the raw rule-level severity - this must
    match whatever create_initial_task_plan() uses below, or the two
    code paths will disagree on the same incident.
    """
    severity = float(
        incident.get("composite_severity", incident.get("severity", 0))
    )

    if severity < 4:
        return task_plan

    actions = task_plan.get("actions", [])
    has_investigation = any(
        a.get("agent") == AGENT_INVESTIGATION for a in actions
    )

    if has_investigation:
        return task_plan

    # Find the triage task to depend on, if one exists
    triage_action = next(
        (a for a in actions if a.get("agent") == AGENT_TRIAGE), None
    )
    depends_on = [triage_action["task_id"]] if triage_action else []

    print(
        f"[SAFETY NET] severity={severity} but LLM plan had no "
        f"investigation task - appending one"
    )

    actions.append({
        "task_id": str(uuid.uuid4()),
        "agent": AGENT_INVESTIGATION,
        "action": "gather_ioc_timeline",
        "depends_on": depends_on,
    })

    task_plan["actions"] = actions
    return task_plan

def _ensure_required_agent_tasks(task_plan: dict, incident: dict) -> dict:
    """
    Safety net for mandatory SOAR workflow tasks.

    The LLM decides the reasoning, but Python guarantees that
    required agents are present according to severity.

    Workflow:
        1-3  -> Triage + Notification
        4-5  -> Triage + Investigation + Notification
        6-8  -> Triage + Investigation + Response + Containment + Notification
        9-10 -> Triage + Investigation + Response + Containment + Notification
                with approval required
    """

    severity = float(
        incident.get("composite_severity", incident.get("severity", 0))
    )

    actions = task_plan.setdefault("actions", [])

    def find_agent(agent_name):
        return next(
            (a for a in actions if a.get("agent") == agent_name),
            None
        )

    # --------------------------------------------------
    # TRIAGE
    # --------------------------------------------------
    triage = find_agent(AGENT_TRIAGE)

    if not triage:
        triage = {
            "task_id": str(uuid.uuid4()),
            "agent": AGENT_TRIAGE,
            "action": "confirm_severity_blast_radius",
            "depends_on": [],
        }
        actions.insert(0, triage)

    triage_id = triage["task_id"]

    # --------------------------------------------------
    # INVESTIGATION
    # --------------------------------------------------
    if severity >= 4:
        investigation = find_agent(AGENT_INVESTIGATION)

        if not investigation:
            investigation = {
                "task_id": str(uuid.uuid4()),
                "agent": AGENT_INVESTIGATION,
                "action": "gather_ioc_timeline",
                "depends_on": [triage_id],
            }
            actions.append(investigation)

        investigation_id = investigation["task_id"]

    else:
        investigation_id = None

    # --------------------------------------------------
    # RESPONSE
    # --------------------------------------------------
    if severity >= 6:
        response = find_agent(AGENT_RESPONSE)

        if not response:
            response_dependencies = (
                [investigation_id]
                if investigation_id
                else [triage_id]
            )

            response = {
                "task_id": str(uuid.uuid4()),
                "agent": AGENT_RESPONSE,
                "action": "disable_compromised_accounts",
                "depends_on": response_dependencies,
            }
            actions.append(response)

    # --------------------------------------------------
    # CONTAINMENT
    # --------------------------------------------------
    if severity >= 6:
        containment = find_agent(AGENT_CONTAINMENT)

        if not containment:
            containment_dependencies = (
                [investigation_id]
                if investigation_id
                else [triage_id]
            )

            containment = {
                "task_id": str(uuid.uuid4()),
                "agent": AGENT_CONTAINMENT,
                "action": "block_malicious_ip",
                "depends_on": containment_dependencies,
            }
            actions.append(containment)

    # --------------------------------------------------
    # NOTIFICATION
    # --------------------------------------------------
    notification = find_agent(AGENT_NOTIFICATION)

    if not notification:
        # Notification should happen after the other planned actions.
        dependency_ids = [
            a["task_id"]
            for a in actions
            if a.get("agent") != AGENT_NOTIFICATION
        ]

        notification = {
            "task_id": str(uuid.uuid4()),
            "agent": AGENT_NOTIFICATION,
            "action": "create_case_send_alert",
            "depends_on": dependency_ids,
        }

        actions.append(notification)

    # --------------------------------------------------
    # APPROVAL
    # --------------------------------------------------
    if severity >= 9:
        task_plan["approval_required"] = True

    # Never allow the LLM to lower the actual incident severity.
    if severity >= 9:
        task_plan["severity"] = int(severity)

    # Rebuild agent sequence based on actual actions.
    sequence = []

    for agent in [
        AGENT_TRIAGE,
        AGENT_INVESTIGATION,
        AGENT_RESPONSE,
        AGENT_CONTAINMENT,
        AGENT_NOTIFICATION,
    ]:
        if any(a.get("agent") == agent for a in actions):
            sequence.append(agent)

    task_plan["agent_sequence"] = sequence
    task_plan["actions"] = actions

    return task_plan

# ============================================
# FALLBACK TASK PLAN
# ============================================

def create_initial_task_plan(incident: dict):
    severity = int(incident.get("composite_severity", incident.get("severity", 5)))
    incident_id = incident["incident_id"]

    actions = []

    # ----------------------------
    # Triage Task
    # ----------------------------
    triage_id = str(uuid.uuid4())

    actions.append({
        "task_id": triage_id,
        "agent": AGENT_TRIAGE,
        "action": "confirm_severity_blast_radius",
        "depends_on": [],
    })

    # ----------------------------
    # Investigation Task
    # ----------------------------
    if severity >= 4:
        investigation_id = str(uuid.uuid4())

        actions.append({
            "task_id": investigation_id,
            "agent": AGENT_INVESTIGATION,
            "action": "gather_ioc_timeline",
            "depends_on": [triage_id],
        })

    # ----------------------------
    # Notification Task
    # ----------------------------
    notification_id = str(uuid.uuid4())

    actions.append({
        "task_id": notification_id,
        "agent": AGENT_NOTIFICATION,
        "action": "create_case_send_alert",
        "depends_on": [actions[-1]["task_id"]],
    })

    plan = TaskPlan(
        incident_id=incident_id,
        agent_sequence=[AGENT_TRIAGE, AGENT_INVESTIGATION, AGENT_NOTIFICATION],
        actions=actions,
        approval_required=(severity >= 9),
        severity=severity,
        reasoning_summary="Fallback rule-based plan",
    )

    return plan.dict()


# ============================================
# CHECK WHETHER TASK PLAN IS FINISHED
# ============================================

def _plan_is_finished(plan: dict) -> bool:
    """
    Return True only when every task has reached
    a terminal state.

    Terminal states:
        completed
        failed
    """

    actions = plan.get("actions", [])

    if not actions:
        return False

    for action in actions:

        task_id = action.get("task_id")

        if not task_id:
            return False

        status = redis_client.get(
            f"task_status:{task_id}"
        )

        if not status:
            status = action.get(
                "final_status"
            )

        if status not in (
            "completed",
            "failed",
        ):
            return False

    return True

def _cleanup_finished_plan(incident_id: str, plan: dict):
    """
    Move a finished task plan out of the active dispatcher queue.

    IMPORTANT:
    - We DO NOT delete the incident.
    - We DO NOT delete the completed task results.
    - We DO NOT lose the task plan.
    - We archive the complete plan for audit/history.
    - We remove ONLY the active taskplan:<incident_id> key so
      get_agent_tasks() stops scanning completed work.

    Archived plan:
        taskplan_archive:<incident_id>

    Active dispatcher plan:
        taskplan:<incident_id>
    """

    archive_key = f"taskplan_archive:{incident_id}"

    try:
        # --------------------------------------------------
        # 1. Read the latest task statuses and put them
        #    directly into the archived plan.
        # --------------------------------------------------

        archived_plan = json.loads(
            json.dumps(plan, default=str)
        )

        for action in archived_plan.get("actions", []):
            task_id = action.get("task_id")

            if not task_id:
                continue

            status = redis_client.get(
                f"task_status:{task_id}"
            )

            action["final_status"] = status

            result_data = redis_client.get(
                f"result:{task_id}"
            )

            if result_data:
                try:
                    action["result"] = json.loads(result_data)
                except Exception:
                    action["result"] = result_data

        # --------------------------------------------------
        # 2. Mark the plan as archived.
        # --------------------------------------------------

        archived_plan["plan_status"] = "completed"

        archived_plan["archived_at"] = datetime.now().isoformat()

        # --------------------------------------------------
        # 3. Save the complete plan for 7 days.
        # --------------------------------------------------

        redis_client.setex(
            archive_key,
            7 * 86400,
            json.dumps(
                archived_plan,
                default=str
            )
        )
        
                # --------------------------------------------------
        # 4. Mark incident CLOSED in PostgreSQL.
        #
        # PostgreSQL is the durable source of truth for
        # completed incident history.
        #
        # Closed incidents are NOT published to Kafka.
        # The Learning Agent will later read closed
        # incidents from PostgreSQL and store them in
        # ChromaDB.
        #
        # The incident itself is NOT deleted.
        # --------------------------------------------------

        closed_updated = _update_incident_status(
            incident_id,
            "closed"
        )

        if not closed_updated:
            print(
                f"[CLOSE] WARNING: PostgreSQL closure "
                f"failed for incident={incident_id}"
            )
        else:
            print(
                f"[CLOSE] Incident permanently marked "
                f"CLOSED in PostgreSQL: {incident_id}"
            )
                
        # --------------------------------------------------
        # 4. Remove ONLY the active dispatcher key.
        #
        # This is the important distinction:
        #
        # taskplan:<id>
        #       = active queue
        #
        # taskplan_archive:<id>
        #       = historical record
        # --------------------------------------------------

        redis_client.delete(
            f"taskplan:{incident_id}"
        )

        # --------------------------------------------------
        # 5. Remove incident from active task-plan set.
        # --------------------------------------------------

        redis_client.srem(
            "active_taskplans",
            incident_id
        )

        print(
            f"[CLEANUP] Finished plan moved out of active queue "
            f"incident={incident_id} "
            f"archive={archive_key}"
        )

    except Exception as e:
        print(
            f"[CLEANUP] Failed for incident={incident_id}: {e}"
        )


def _recover_stale_tasks():
    """
    Recover tasks that have been stuck in RUNNING state.

    This protects the workflow if an agent crashes,
    disconnects, or receives a task but never submits
    a result.

    Recovery runs in the background and is NOT part
    of the agent polling request.
    """

    STALE_TASK_TIMEOUT = int(
        os.getenv(
            "ORCHESTRATOR_STALE_TASK_TIMEOUT",
            "600"
        )
    )

    now = time.time()

    # --------------------------------------------------
    # 1. Find task status keys
    # --------------------------------------------------

    status_keys = list(
        redis_client.scan_iter(
            match="task_status:*",
            count=500
        )
    )

    if not status_keys:
        return

    # --------------------------------------------------
    # 2. Read all statuses in ONE Redis request
    # --------------------------------------------------

    statuses = redis_client.mget(
        status_keys
    )

    running_task_ids = [
        key.split(
            "task_status:",
            1
        )[1]
        for key, status in zip(
            status_keys,
            statuses
        )
        if status == "running"
    ]

    if not running_task_ids:
        return

    # --------------------------------------------------
    # 3. Read claim timestamps in ONE Redis request
    # --------------------------------------------------

    claimed_keys = [
        f"task_claimed_at:{task_id}"
        for task_id in running_task_ids
    ]

    claimed_values = redis_client.mget(
        claimed_keys
    )

    # --------------------------------------------------
    # 4. Reset genuinely stale tasks
    # --------------------------------------------------

    for task_id, claimed_at_raw in zip(
        running_task_ids,
        claimed_values
    ):

        if not claimed_at_raw:
            continue

        try:
            claimed_at = float(
                claimed_at_raw
            )
        except Exception:
            continue

        age = now - claimed_at

        if age < STALE_TASK_TIMEOUT:
            continue

        redis_client.setex(
            f"task_status:{task_id}",
            86400,
            "pending"
        )

        redis_client.delete(
            f"task_claimed_at:{task_id}"
        )

        print(
            f"[RECOVERY] Reset stale task "
            f"task={task_id} "
            f"age={age:.0f}s "
            f"running->pending"
        )

@app.get("/agents/{agent_name}/tasks")
def get_agent_tasks(agent_name: str):
    """
    Return ONE ready task for the requested agent.

    Dispatcher flow:
        1. Read active task plans in batches.
        2. Identify finished plans.
        3. Archive/remove finished plans.
        4. Find tasks belonging to this agent.
        5. Read task statuses in batches using MGET.
        6. Check dependencies in batches using MGET.
        7. Atomically claim ONE pending task.
        8. Return immediately.

    Important:
    - The agent receives at most ONE task per poll.
    - MGET is only used internally by the orchestrator.
    - MGET does NOT send all plans/tasks to the agent.
    """

    request_start = time.monotonic()
    
    print(
        f"[DISPATCH] Poll received "
        f"agent={agent_name}"
    )

    # ============================================================
    # STEP 1 — FIND ACTIVE TASK PLANS
    # ============================================================

    scan_start = time.monotonic()

    try:
        plan_keys = list(
            redis_client.scan_iter(
                match="taskplan:*",
                count=1000
            )
        )

    except Exception as e:

        elapsed = time.monotonic() - request_start

        print(
            f"[DISPATCH] Redis SCAN failed "
            f"agent={agent_name} "
            f"after={elapsed:.3f}s "
            f"error={e}"
        )

        return {
            "agent": agent_name,
            "tasks": []
        }

    scan_elapsed = time.monotonic() - scan_start

    print(
        f"[TIMING] agent={agent_name} "
        f"scan={scan_elapsed:.3f}s "
        f"plans={len(plan_keys)}"
    )

    # Nothing to process.
    if not plan_keys:

        total_elapsed = time.monotonic() - request_start

        print(
            f"[DISPATCH] No task plans "
            f"agent={agent_name} "
            f"total={total_elapsed:.3f}s"
        )

        return {
            "agent": agent_name,
            "tasks": []
        }

    # ============================================================
    # STEP 2 — READ ALL PLANS WITH ONE MGET
    # ============================================================

    plan_read_start = time.monotonic()

    try:

        plan_values = redis_client.mget(plan_keys)

    except Exception as e:

        elapsed = time.monotonic() - request_start

        print(
            f"[DISPATCH] Redis MGET plans failed "
            f"agent={agent_name} "
            f"after={elapsed:.3f}s "
            f"error={e}"
        )

        return {
            "agent": agent_name,
            "tasks": []
        }

    plan_read_elapsed = time.monotonic() - plan_read_start

    print(
        f"[TIMING] agent={agent_name} "
        f"mget_plans={plan_read_elapsed:.3f}s "
        f"count={len(plan_keys)}"
    )

    # ============================================================
    # STEP 3 — PARSE PLANS
    # ============================================================

    parsed_plans = []

    for key, plan_data in zip(
        plan_keys,
        plan_values
    ):

        if not plan_data:
            continue

        try:

            plan = json.loads(plan_data)

        except Exception:

            print(
                f"[DISPATCH] Invalid task plan "
                f"key={key}"
            )

            continue

        incident_id = plan.get("incident_id")

        if not incident_id:
            continue

        actions = plan.get("actions", [])

        if not actions:
            continue

        parsed_plans.append(
            (
                key,
                incident_id,
                plan,
                actions
            )
        )

    print(
        f"[DISPATCH] Parsed "
        f"{len(parsed_plans)} active plans "
        f"for agent={agent_name}"
    )

    # ============================================================
    # STEP 4 — CHECK FINISHED PLANS IN BATCHES
    # ============================================================

    #
    # Instead of calling:
    #
    #     redis_client.get(...)
    #
    # for every action, we collect ALL task-status keys first
    # and read them with MGET.
    #

    all_status_keys = []

    for key, incident_id, plan, actions in parsed_plans:

        for action in actions:

            task_id = action.get("task_id")

            if task_id:

                all_status_keys.append(
                    f"task_status:{task_id}"
                )

    # Remove duplicates while preserving order.
    all_status_keys = list(
        dict.fromkeys(all_status_keys)
    )

    status_map = {}

    if all_status_keys:

        status_start = time.monotonic()

        try:

            all_status_values = redis_client.mget(
                all_status_keys
            )

            status_map = dict(
                zip(
                    all_status_keys,
                    all_status_values
                )
            )

        except Exception as e:

            elapsed = time.monotonic() - request_start

            print(
                f"[DISPATCH] Redis MGET statuses failed "
                f"agent={agent_name} "
                f"after={elapsed:.3f}s "
                f"error={e}"
            )

            return {
                "agent": agent_name,
                "tasks": []
            }

        status_elapsed = time.monotonic() - status_start

        print(
            f"[TIMING] agent={agent_name} "
            f"mget_statuses={status_elapsed:.3f}s "
            f"statuses={len(all_status_keys)}"
        )

        # ============================================================
    # STEP 5 — REMOVE FINISHED PLANS FROM ACTIVE SCAN
    # ============================================================

    active_plans = []
    finished_plans = []

    for key, incident_id, plan, actions in parsed_plans:

        plan_finished = True

        for action in actions:

            task_id = action.get("task_id")

            if not task_id:
                plan_finished = False
                break

            status = status_map.get(
                f"task_status:{task_id}"
            )

            # A plan is still active unless every task
            # has reached a terminal state.
            if status not in (
                "completed",
                "failed"
            ):
                plan_finished = False
                break

        if plan_finished:

            finished_plans.append(
                (
                    key,
                    incident_id,
                    plan
                )
            )

        else:

            active_plans.append(
                (
                    key,
                    incident_id,
                    plan,
                    actions
                )
            )

    # ============================================================
    # STEP 6 — ARCHIVE + CLOSE + REMOVE FINISHED PLANS
    # ============================================================

    #
    # A finished plan goes through ONE cleanup path.
    #
    # _cleanup_finished_plan() performs:
    #
    #   1. Archive the completed plan with task results
    #   2. Mark PostgreSQL incident as CLOSED
    #   3. Remove taskplan:<incident_id>
    #   4. Remove incident from active_taskplans
    #
    # Closed incidents are NOT published to Kafka.
    #
    # The Learning Agent later reads CLOSED incidents
    # from PostgreSQL and stores them in ChromaDB.
    #

    if finished_plans:

        cleanup_start = time.monotonic()

        for (
            key,
            incident_id,
            plan
        ) in finished_plans:

            try:

                _cleanup_finished_plan(
                    incident_id,
                    plan
                )

            except Exception as e:

                print(
                    f"[CLEANUP] Failed for incident="
                    f"{incident_id}: {e}"
                )

        cleanup_elapsed = (
            time.monotonic()
            - cleanup_start
        )

        print(
            f"[CLEANUP] Processed "
            f"{len(finished_plans)} finished plan(s) "
            f"for agent={agent_name} "
            f"time={cleanup_elapsed:.3f}s"
        )

    # ============================================================
    # STEP 7 — FIND CANDIDATE TASKS FOR THIS AGENT
    # ============================================================

    candidate_tasks = []

    for (
        key,
        incident_id,
        plan,
        actions
    ) in active_plans:

        for action in actions:

            if action.get("agent") != agent_name:
                continue

            task_id = action.get("task_id")

            if not task_id:
                continue

            status = status_map.get(
                f"task_status:{task_id}"
            )

            # ----------------------------------------------------
            # Recover abandoned tasks
            #
            # If a running task's Redis lease expires, its
            # task_status key disappears.
            #
            # If there is no result, the task was not completed,
            # so safely requeue it as pending.
            # ----------------------------------------------------

            if status is None:

                existing_result = redis_client.get(
                    f"result:{task_id}"
                )

                if existing_result is None:

                    redis_client.setex(
                        f"task_status:{task_id}",
                        86400,
                        "pending"
                    )

                    status = "pending"

                    print(
                        f"[RECOVERY] Requeued abandoned task "
                        f"task={task_id} "
                        f"incident={incident_id} "
                        f"agent={agent_name}"
                    )

                else:

                    print(
                        f"[DISPATCH] Task has result but no "
                        f"status; skipping "
                        f"task={task_id}"
                    )

                    continue

            if status != "pending":
                continue

            candidate_tasks.append(
                (
                    key,
                    incident_id,
                    plan,
                    action
                )
            )

    print(
        f"[DISPATCH] Candidate tasks "
        f"agent={agent_name} "
        f"count={len(candidate_tasks)}"
    )

    if not candidate_tasks:

        total_elapsed = (
            time.monotonic()
            - request_start
        )

        print(
            f"[DISPATCH] No pending task "
            f"agent={agent_name} "
            f"total={total_elapsed:.3f}s"
        )

        return {
            "agent": agent_name,
            "tasks": []
        }

    # ============================================================
    # STEP 8 — CHECK CANDIDATE DEPENDENCIES
    # ============================================================

    #
    # We only check dependencies for candidate tasks belonging
    # to this agent.
    #

    dependency_ids = []

    for (
        key,
        incident_id,
        plan,
        action
    ) in candidate_tasks:

        for dep_id in action.get(
            "depends_on",
            []
        ):

            if dep_id:

                dependency_ids.append(dep_id)

    dependency_ids = list(
        dict.fromkeys(dependency_ids)
    )

    dependency_status_map = {}

    if dependency_ids:

        dependency_keys = [
            f"task_status:{dep_id}"
            for dep_id in dependency_ids
        ]

        dependency_start = time.monotonic()

        try:

            dependency_values = redis_client.mget(
                dependency_keys
            )

            dependency_status_map = dict(
                zip(
                    dependency_ids,
                    dependency_values
                )
            )

        except Exception as e:

            elapsed = time.monotonic() - request_start

            print(
                f"[DISPATCH] Dependency MGET failed "
                f"agent={agent_name} "
                f"after={elapsed:.3f}s "
                f"error={e}"
            )

            return {
                "agent": agent_name,
                "tasks": []
            }

        dependency_elapsed = (
            time.monotonic()
            - dependency_start
        )

        print(
            f"[TIMING] agent={agent_name} "
            f"mget_dependencies="
            f"{dependency_elapsed:.3f}s "
            f"count={len(dependency_ids)}"
        )

    # ============================================================
    # STEP 9 — TRY TO CLAIM ONE TASK
    # ============================================================

    #
    # This Lua script performs:
    #
    #     if status == pending
    #         change it to running
    #         return success
    #     otherwise
    #         return failure
    #
    # The important part is that Redis performs this atomically.
    #

    claim_script = """
    if redis.call('GET', KEYS[1]) == 'pending' then
        redis.call('SET', KEYS[1], 'running', 'EX', ARGV[1])
        return 1
    end
    return 0
    """

    for (
        key,
        incident_id,
        plan,
        action
    ) in candidate_tasks:

        task_id = action["task_id"]

        # --------------------------------------------------------
        # Check dependencies
        # --------------------------------------------------------

        dependencies = action.get(
            "depends_on",
            []
        )

        dependencies_ready = True

        for dep_id in dependencies:

            dep_status = dependency_status_map.get(
                dep_id
            )

            # ----------------------------------------------------
            # Dependency policy
            #
            # Normal tasks require dependencies to complete.
            #
            # Notification can run when dependencies are either
            # completed OR failed, because notification needs to
            # report the final outcome of the incident.
            # ----------------------------------------------------

            if agent_name == "notification":

                if dep_status not in (
                    "completed",
                    "failed"
                ):

                    dependencies_ready = False

                    print(
                        f"[DISPATCH] Notification waiting "
                        f"task={task_id} "
                        f"dependency={dep_id} "
                        f"status={dep_status}"
                    )

                    break

            else:

                if dep_status != "completed":

                    dependencies_ready = False

                    print(
                        f"[DISPATCH] Task not ready "
                        f"task={task_id} "
                        f"dependency={dep_id} "
                        f"status={dep_status}"
                    )

                    break

        # --------------------------------------------------------
        # If dependencies are not ready, try the next action.
        # --------------------------------------------------------

        if not dependencies_ready:
            continue

        # --------------------------------------------------------
        # Atomically claim the task
        # --------------------------------------------------------

        try:

            claimed = redis_client.eval(
                claim_script,
                1,
                f"task_status:{task_id}",
                300
            )

        except Exception as e:

            print(
                f"[DISPATCH] Failed to claim "
                f"task={task_id} "
                f"error={e}"
            )

            continue

        if claimed != 1:

            print(
                f"[DISPATCH] Task already claimed "
                f"task={task_id}"
            )

            continue

        # Record when the agent actually received the task.
        redis_client.setex(
            f"task_claimed_at:{task_id}",
            86400,
            time.time()
        )

        # --------------------------------------------------------
        # Build final task
        # --------------------------------------------------------

        task = dict(action)

        task["incident_id"] = incident_id

        incident_data = redis_client.get(
            f"incident:{incident_id}"
        )

        if incident_data:
            task["incident_context"] = json.loads(
                incident_data
            )
        else:
            task["incident_context"] = {}

        # --------------------------------------------------------
        # SUCCESS
        # --------------------------------------------------------

        total_elapsed = (
            time.monotonic()
            - request_start
        )

        print(
            f"[DISPATCH] CLAIMED "
            f"agent={agent_name} "
            f"task={task_id} "
            f"incident={incident_id} "
            f"status=pending->running"
        )

        print(
            f"[TIMING] dispatch "
            f"agent={agent_name} "
            f"total={total_elapsed:.3f}s"
        )

        # VERY IMPORTANT:
        #
        # We RETURN immediately.
        #
        # We do NOT continue scanning the remaining
        # task plans.
        #
        return {
            "agent": agent_name,
            "tasks": [task]
        }

    # ============================================================
    # STEP 10 — NOTHING READY
    # ============================================================

    total_elapsed = (
        time.monotonic()
        - request_start
    )

    print(
        f"[DISPATCH] No ready tasks "
        f"agent={agent_name} "
        f"total={total_elapsed:.3f}s"
    )

    return {
        "agent": agent_name,
        "tasks": []
    }


# ============================================
# MEMORY ENDPOINTS
# ============================================

@app.post("/memory/check_false_positive")
def check_fp_endpoint(body: dict):
    """Triage Agent checks previous false positive patterns."""
    query = body.get("query", "")
    result = check_false_positive(query)
    return result


@app.post("/memory/store_incident")
def store_incident_endpoint(body: dict):
    """Learning Agent stores completed incident knowledge."""

    resolution_time = body.get(
        "resolution_time_minutes"
    )

    # JSON null becomes Python None.
    # ChromaDB metadata cannot safely store None,
    # so normalize it to 0.
    if resolution_time is None:
        resolution_time = 0

    result = store_incident(
        incident_id=body.get("incident_id"),
        behavioral_timeline=body.get(
            "behavioral_timeline",
            ""
        ),
        outcome=body.get(
            "outcome",
            "UNKNOWN"
        ),
        resolution_time_minutes=resolution_time,
        false_positive=body.get(
            "false_positive",
            False
        ),
        notes=body.get(
            "notes",
            ""
        ),
    )

    return {
        "success": result
    }

@app.post("/memory/mark_false_positive")
def mark_false_positive_endpoint(body: dict):
    """Analyst marks an incident as false positive."""
    result = store_false_positive(
        incident_id=body.get("incident_id"),
        behavioral_pattern=body.get("behavioral_pattern", ""),
        reason=body.get("reason", ""),
    )
    return {"success": result}


@app.get("/memory/stats")
def memory_stats():
    """Returns ChromaDB statistics."""
    return get_memory_stats()


def publish_closed_incident(
    incident_id: str,
    plan: dict
):
    """
    Publish a fully completed incident to the
    incidents_closed Kafka topic.

    The Learning Agent consumes this topic and
    stores the historical incident in ChromaDB.
    """

    # --------------------------------------------------
    # Retrieve original incident.
    # --------------------------------------------------

    incident_data = redis_client.get(
        f"incident:{incident_id}"
    )

    if not incident_data:
        print(
            f"[MEMORY] Cannot publish closed incident "
            f"{incident_id}: incident data missing"
        )
        return False

    try:
        incident = json.loads(
            incident_data
        )
    except Exception:
        incident = {
            "raw_incident": incident_data
        }


# ============================================
# AGENT RESULT SUBMISSION
# ============================================

@app.post("/orchestrator/results")
def receive_result(result: dict):
    """
    Agents submit completed task results here.

    The result is:
    1. Validated
    2. Stored temporarily in Redis
    3. Task status updated in Redis
    4. Persisted permanently into PostgreSQL agent_actions
    """

    try:
        validated = AgentResult(**result)

    except ValidationError as e:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid result schema: {e}",
        )

    print("\n========================================")
    print("RESULT RECEIVED")
    print("========================================")
    print(f"Agent : {validated.agent_name}")
    print(f"Task  : {validated.task_id}")
    print(f"Success: {validated.success}")

    # --------------------------------------------------
    # 1. Store result in Redis
    # --------------------------------------------------

    redis_client.setex(
        f"result:{validated.task_id}",
        86400,
        validated.json(),
    )

    # --------------------------------------------------
    # 2. Update task status in Redis
    # --------------------------------------------------

    task_status = (
        "completed"
        if validated.success
        else "failed"
    )

    redis_client.setex(
        f"task_status:{validated.task_id}",
        86400,
        task_status,
    )

    # --------------------------------------------------
    # 3. Find incident_id and action from active plan
    # --------------------------------------------------

    incident_id = None
    action_name = None

    try:

        active_incidents = redis_client.smembers(
            "active_taskplans"
        )

        for active_incident_id in active_incidents:

            plan_data = redis_client.get(
                f"taskplan:{active_incident_id}"
            )

            if not plan_data:
                continue

            plan = json.loads(plan_data)

            for action in plan.get("actions", []):

                if action.get("task_id") == validated.task_id:

                    incident_id = active_incident_id

                    action_name = action.get(
                        "action",
                        "unknown"
                    )

                    break

            if incident_id:
                break

    except Exception as e:

        print(
            f"[RESULT] Could not resolve incident "
            f"for task {validated.task_id}: {e}"
        )

    # --------------------------------------------------
    # 4. Persist result into PostgreSQL agent_actions
    # --------------------------------------------------

    if incident_id:

        try:

            conn = _get_postgres_connection()

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO agent_actions (
                    incident_id,
                    agent_name,
                    action,
                    success,
                    output,
                    error_message,
                    executed_at
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    NOW()
                )
                """,
                (
                    incident_id,
                    validated.agent_name,
                    action_name,
                    validated.success,
                    json.dumps(validated.output),
                    validated.error_message,
                )
            )

            conn.commit()

            cursor.close()
            conn.close()

            print(
                f"[RESULT] Persisted agent action "
                f"incident={incident_id} "
                f"task={validated.task_id}"
            )

        except Exception as e:

            print(
                f"[RESULT] PostgreSQL persistence failed "
                f"for task={validated.task_id}: {e}"
            )

            # IMPORTANT:
            # PostgreSQL failure must NOT prevent
            # Redis-based task processing.

    else:

        print(
            f"[RESULT] WARNING: Could not determine "
            f"incident_id for task={validated.task_id}. "
            f"Redis result/status were still stored."
        )

    # --------------------------------------------------
    # 5. Return response to agent
    # --------------------------------------------------

    return {
        "message": "Result received",
        "task_id": validated.task_id,
        "incident_id": incident_id,
        "status": task_status,
    }

# ============================================
# INCIDENT CONTEXT
# ============================================

@app.get("/incidents/{incident_id}/context")
def get_incident_context(incident_id: str):
    """Agents retrieve full incident details."""
    data = redis_client.get(f"incident:{incident_id}")

    if not data:
        raise HTTPException(status_code=404, detail="Incident not found")

    return json.loads(data)
# ============================================
# INCIDENT APPROVAL
# ============================================

@app.post("/incidents/{incident_id}/approve")
def approve_incident(incident_id: str):
    """
    Human analyst approves an incident.

    The approval is stored in Redis so that
    Response/Containment agents can check it
    before performing sensitive actions.
    """

    # Make sure the incident exists
    if not redis_client.exists(f"incident:{incident_id}"):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    # Store approval for 1 hour
    redis_client.setex(
        f"approval:{incident_id}",
        3600,
        "approved",
    )

    print(f"[APPROVAL] Incident {incident_id} approved by analyst")

    return {
        "incident_id": incident_id,
        "approved": True,
        "message": "Incident approved successfully",
    }

# ============================================
# TASK PLAN RETRIEVAL
# ============================================


@app.get("/incidents/{incident_id}/plan")
def get_task_plan(incident_id: str):
    """
    Return the task plan for an incident.

    Active incidents:
        taskplan:<incident_id>

    Completed incidents:
        taskplan_archive:<incident_id>

    This allows the dashboard/UI to continue displaying the
    task plan even after the incident leaves the active queue.
    """

    # --------------------------------------------------
    # First check active plan.
    # --------------------------------------------------

    data = redis_client.get(
        f"taskplan:{incident_id}"
    )

    if data:
        plan = json.loads(data)

        plan["plan_status"] = "active"

        return plan

    # --------------------------------------------------
    # If no active plan exists, check archived plan.
    # --------------------------------------------------

    data = redis_client.get(
        f"taskplan_archive:{incident_id}"
    )

    if data:
        plan = json.loads(data)

        plan["plan_status"] = "archived"

        return plan

    # --------------------------------------------------
    # Neither active nor archived.
    # --------------------------------------------------

    raise HTTPException(
        status_code=404,
        detail="Task plan not found"
    )

# ============================================
# INCIDENT RESULTS
# ============================================


@app.get("/incidents/{incident_id}/results")
def get_all_results(incident_id: str):
    """
    Return all agent results for an incident.

    Looks at both:
        taskplan:<incident_id>
        taskplan_archive:<incident_id>
    """

    # --------------------------------------------------
    # Try active plan first.
    # --------------------------------------------------

    plan_data = redis_client.get(
        f"taskplan:{incident_id}"
    )

    # --------------------------------------------------
    # If the active plan is gone, use the archive.
    # --------------------------------------------------

    if not plan_data:
        plan_data = redis_client.get(
            f"taskplan_archive:{incident_id}"
        )

    if not plan_data:
        raise HTTPException(
            status_code=404,
            detail="Task plan not found"
        )

    plan = json.loads(plan_data)

    results = {}

    for action in plan.get("actions", []):
        task_id = action.get("task_id")

        if not task_id:
            continue

        result_data = redis_client.get(
            f"result:{task_id}"
        )

        if result_data:
            try:
                results[task_id] = json.loads(
                    result_data
                )
            except Exception:
                results[task_id] = result_data

        # If result was already incorporated into the
        # archived plan, expose it as well.
        elif action.get("result"):
            results[task_id] = action["result"]

    return results

# ============================================
# SERVER START
# ============================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "orchestrator.main:app",
        host=os.getenv("ORCHESTRATOR_HOST", "0.0.0.0"),
        port=int(os.getenv("ORCHESTRATOR_PORT", 8000)),
        reload=True,
    )
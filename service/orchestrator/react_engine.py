# orchestrator/react_engine.py

import time
from langchain_ollama import ChatOllama
from pydantic import ValidationError
import redis
import json
import os
from dotenv import load_dotenv
from datetime import datetime
from typing import TypedDict, Optional, Any

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.redis import RedisSaver

from shared.constants import (
    AGENT_TRIAGE, AGENT_INVESTIGATION, AGENT_RESPONSE,
    AGENT_CONTAINMENT, AGENT_NOTIFICATION, REDIS_AGENT_HEARTBEAT
)
from shared.models import TaskPlan

load_dotenv()

# Redis client
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "100.71.186.0"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=10,
    retry_on_timeout=True,
    health_check_interval=30,
)
# ============================================================
# CHECKPOINT MANAGER
# ============================================================

class CheckpointManager:
    """
    Persists ReAct execution state in Redis so the orchestrator
    can resume an interrupted investigation after a restart.
    """

    def __init__(self):
        self.redis = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=int(os.getenv("REDIS_DB", "0")),
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=10,
            retry_on_timeout=True,
            health_check_interval=30,
        )

        self.key_prefix = "checkpoint:"

    def _key(self, incident_id: str) -> str:
        return f"{self.key_prefix}{incident_id}"

    def save(
        self,
        incident_id: str,
        state: dict,
    ):
        checkpoint = {
            "incident_id": incident_id,
            "saved_at": datetime.utcnow().isoformat(),
            "state": state,
        }

        self.redis.set(
            self._key(incident_id),
            json.dumps(checkpoint),
        )

        print(
            f"[CHECKPOINT] Saved checkpoint for {incident_id}"
        )

    def load(self, incident_id: str):
        data = self.redis.get(self._key(incident_id))

        if not data:
            print(
                f"[CHECKPOINT] No checkpoint found for {incident_id}"
            )
            return None

        checkpoint = json.loads(data)

        print(
            f"[CHECKPOINT] Loaded checkpoint for {incident_id}"
        )

        return checkpoint

    def delete(self, incident_id: str):
        self.redis.delete(self._key(incident_id))

        print(
            f"[CHECKPOINT] Deleted checkpoint for {incident_id}"
        )
checkpoint_manager = CheckpointManager()

# ============================================================
# LANGGRAPH REDIS CHECKPOINTER
# ============================================================
REDIS_HOST = os.getenv(
    "REDIS_HOST",
    "100.71.186.0"
)

REDIS_PORT = os.getenv(
    "REDIS_PORT",
    "6379"
)

REDIS_DB = os.getenv(
    "REDIS_DB",
    "0"
)

REDIS_URL = (
    f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
)

checkpointer_context = RedisSaver.from_conn_string(
    REDIS_URL
)

checkpointer = checkpointer_context.__enter__()

try:
    checkpointer.setup()
    print("[LANGGRAPH] Redis checkpointer initialized")
except Exception as e:
    print(f"[LANGGRAPH] Redis checkpointer setup warning: {e}")

# ============================================
# LLM CLIENT
# ============================================
LLM_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "60"))

llm = ChatOllama(
    model=os.getenv("OLLAMA_MODEL", "qwen2.5:7b"),
    base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
    temperature=0,
    timeout=LLM_TIMEOUT_SECONDS,
)

# Structured-output wrapper: constrains the model to emit a TaskPlan
# directly instead of free text we then regex-hunt through. Falls back
# to plain invoke() + extract_json_from_output() below if the
# installed Ollama/Qwen build doesn't support this reliably.
structured_llm = llm.with_structured_output(TaskPlan)

# ============================================
# WHY THE TOOL-CALLING REACT LOOP WAS REMOVED
# ============================================
# The previous version bound 4 @tool functions to a create_react_agent
# loop: check_approval_required, check_agent_availability,
# retrieve_past_incidents, get_false_positive_history.
#
# Every one of these turned out to be fully precomputable in plain
# Python before the LLM is ever called:
#   - retrieve_past_incidents / get_false_positive_history duplicated
#     the ChromaDB retrieval run_react_loop() already does and already
#     injects into the prompt as HISTORICAL CONTEXT FROM MEMORY.
#   - check_agent_availability is 5 cheap Redis GETs - no reason to
#     let the model spend up to 5 separate inference turns discovering
#     that itself, one tool call at a time.
#   - check_approval_required's rules are already spelled out verbatim
#     in SYSTEM_PROMPT ("severity >= 9 ALWAYS requires approval" etc).
#
# None of the 4 tools needed a live decision about *whether* to call
# them - so there's nothing ReAct's multi-turn Thought/Action/
# Observation loop was buying, only cost: each tool call is a full
# extra forward pass through a 14B model. Precomputing everything and
# using a single structured-output call turns "N inference passes" per
# incident into 1 (or 0, for the fast path below).

# ============================================
# LOW-SEVERITY FAST PATH
# ============================================
# Per SYSTEM_PROMPT's own severity thresholds, 1-3 is "close as noise,
# no agents needed except notification" - there is no reasoning task
# here worth spending a 14B inference call on. Skip ChromaDB retrieval
# AND the LLM entirely for these and go straight to a deterministic
# plan. This is normally your highest-volume incident tier, so it's
# also where the biggest aggregate MTTD win is.
FAST_PATH_MAX_SEVERITY = int(os.getenv("FAST_PATH_MAX_SEVERITY", "3"))


def _is_fast_path_eligible(incident: dict) -> bool:
    severity = int(incident.get("composite_severity", incident.get("severity", 5)))
    kill_chain_stages = incident.get("kill_chain_stages") or []
    is_multi_stage = incident.get("is_multi_stage", False)

    return (
        severity <= FAST_PATH_MAX_SEVERITY
        and len(kill_chain_stages) <= 1
        and not is_multi_stage
    )


# ============================================
# PRECOMPUTED AGENT AVAILABILITY
# ============================================

_ALL_AGENTS = [
    AGENT_TRIAGE,
    AGENT_INVESTIGATION,
    AGENT_RESPONSE,
    AGENT_CONTAINMENT,
    AGENT_NOTIFICATION,
]


def get_agent_status_block() -> str:
    """
    5 Redis GETs, done once per incident instead of leaving the model
    to discover this one tool call at a time. Returned as plain text
    for the prompt.
    """
    lines = []
    for name in _ALL_AGENTS:
        heartbeat_key = REDIS_AGENT_HEARTBEAT.format(name=name)
        alive = bool(redis_client.get(heartbeat_key))
        lines.append(f"- {name}: {'ALIVE' if alive else 'DEAD - do not dispatch to this agent'}")
    return "\n".join(lines)


# ============================================
# SYSTEM PROMPT
# ============================================

SYSTEM_PROMPT = f"""You are PROTEGO, an autonomous cybersecurity incident response orchestrator.

Your job is to analyze security incidents and produce a TaskPlan JSON specifying which specialist agents should respond.

AVAILABLE AGENTS (use these EXACT names, nothing else):
- {AGENT_TRIAGE}: Confirms severity, estimates blast radius, checks false positive probability. ALWAYS runs first.
- {AGENT_INVESTIGATION}: Queries threat intelligence (MISP + VirusTotal), builds attack timeline, detects lateral movement. Runs for severity >= 4.
- {AGENT_RESPONSE}: Blocks IPs, isolates hosts, disables compromised accounts. Runs for severity >= 6.
- {AGENT_CONTAINMENT}: Blocks malicious IP across ALL VMs, segments network. Runs in PARALLEL with {AGENT_RESPONSE} for severity >= 6.
- {AGENT_NOTIFICATION}: Creates TheHive case, sends Slack notification, generates reports. ALWAYS runs last.

HARD RULES - NEVER VIOLATE THESE:
1. NEVER block private IP ranges (10.x.x.x, 192.168.x.x, 172.16.x.x)
2. NEVER disable accounts without TI confidence score > 0.5
3. Admin account actions ALWAYS require human approval
4. Severity >= 9 ALWAYS requires Slack approval before destructive actions
5. NEVER dispatch to a dead agent. Agent status for this decision is given below - it will not change during your reasoning, so do not ask for it again.

SEVERITY THRESHOLDS:
- 1-3: Close as noise, no agents needed except notification
- 4-5: Monitor only (triage + notification)
- 6-8: Auto respond (all agents, no approval needed)
- 9-10: Human approval required before response/containment

Do NOT lower the severity merely because:
- asset criticality is low
- historical incidents had lower severity
- similar incidents were less severe

Only change the severity when there is explicit evidence in the current
incident that the original severity is incorrect.

For severity >= 9:
- "approval_required" MUST be true.
- "severity" MUST remain >= 9 unless explicit evidence proves otherwise.
- Never return "approval_required": false for severity >= 9.

You will be given the current incident, historical context from memory
(already retrieved for you), and current agent availability (already
checked for you). Use all of this to produce ONE TaskPlan JSON in
this exact structure - no extra text, no markdown fences, no
explanation outside the JSON:
{{
  "incident_id": "...",
  "agent_sequence": ["{AGENT_TRIAGE}", "{AGENT_NOTIFICATION}"],
  "actions": [
    {{"task_id": "unique-string-id", "agent": "{AGENT_TRIAGE}", "action": "confirm_severity_blast_radius", "depends_on": []}}
  ],
  "approval_required": true/false,
  "severity": 1-10,
  "reasoning_summary": "brief explanation of your decisions, including any false positive concerns"
}}
"""

# ============================================================
# LANGGRAPH STATE
# ============================================================

class IncidentState(TypedDict, total=False):
    incident_id: str
    incident: dict

    chromadb_context: str
    agent_status_block: str

    task_plan: dict

    stage: str
    error: str

# ============================================
# BUILD CHROMADB QUERY FROM INCIDENT
# ============================================

def build_chromadb_query(incident: dict) -> str:
    """
    Build a natural language query from incident data for ChromaDB
    similarity search - behavioral RAG, matches HOW attacker behaved.
    """
    parts = []

    rule_desc = incident.get("rule_description", "")
    if rule_desc:
        parts.append(rule_desc)

    geo = incident.get("geo_country", "")
    if geo:
        parts.append(f"from {geo}")

    criticality = incident.get("asset_criticality", "")
    if criticality:
        parts.append(f"targeting {criticality} criticality asset")

    username = incident.get("username", "")
    dept = incident.get("user_department", "")
    if username or dept:
        parts.append(f"affecting user {'admin' if 'admin' in str(username).lower() else 'standard'} account")

    tactic = incident.get("mitre_tactic", "")
    technique = incident.get("mitre_technique", "")
    if tactic or technique:
        parts.append(f"MITRE {tactic} {technique}")

    if incident.get("is_multi_stage"):
        parts.append("multi-stage attack progressing through kill chain")

    return " ".join(parts)

# ============================================================
# LANGGRAPH NODE 1 — PREPARE INCIDENT
# ============================================================

def prepare_incident_node(state: IncidentState) -> IncidentState:
    """
    Prepare incident context before LLM reasoning.

    Performs:
      - ChromaDB historical-context retrieval
      - false-positive pattern detection
      - agent availability precomputation

    Fast-path incidents skip RAG and agent discovery entirely.
    """

    incident = state["incident"]
    incident_id = state["incident_id"]

    print(
        f"[LANGGRAPH] prepare_incident_node "
        f"incident={incident_id}"
    )

    # --------------------------------------------------------
    # Fast path
    # --------------------------------------------------------
    if _is_fast_path_eligible(incident):
        print(
            f"[LANGGRAPH] Fast-path incident {incident_id} "
            f"- skipping RAG"
        )

        return {
            "stage": "prepared_fast_path",
        }

    # --------------------------------------------------------
    # RAG retrieval
    # --------------------------------------------------------
    from orchestrator.memory import (
        retrieve_context,
        format_context_for_llm,
    )

    t_rag_start = time.monotonic()

    chromadb_query = build_chromadb_query(incident)

    print(
        f"\nChromaDB query: "
        f"{chromadb_query[:100]}..."
    )

    context = retrieve_context(
        chromadb_query,
        n_results=2,
    )

    similar_incidents = context["similar_incidents"]
    fp_check = context["fp_check"]

    chromadb_context = format_context_for_llm(
        similar_incidents
    )

    if fp_check.get("is_false_positive_pattern"):
        chromadb_context += (
            f"\nFALSE POSITIVE WARNING: "
            f"This incident pattern matches a known "
            f"false positive "
            f"(similarity: "
            f"{fp_check['similarity']:.0%}). "
            f"Reason: "
            f"{fp_check.get('reason', 'Not specified')}. "
            f"Consider reducing severity by 2 and "
            f"routing to monitoring only.\n"
        )

        print(
            "FALSE POSITIVE WARNING added "
            "to LLM context"
        )

    t_rag_elapsed = (
        time.monotonic() - t_rag_start
    )

    print(
        f"[TIMING] rag_retrieval="
        f"{t_rag_elapsed*1000:.0f}ms "
        f"(found "
        f"{len(similar_incidents)} "
        f"similar incidents)"
    )

    # --------------------------------------------------------
    # Agent availability
    # --------------------------------------------------------
    agent_status_block = get_agent_status_block()

    return {
        "chromadb_context": chromadb_context,
        "agent_status_block": agent_status_block,
        "stage": "prepared",
    }
    
# ============================================================
# LANGGRAPH FAST-PATH NODE
# ============================================================

def fast_path_node(state: IncidentState) -> IncidentState:
    """
    Build a deterministic TaskPlan for low-severity incidents.

    Fast-path incidents intentionally skip:
      - ChromaDB retrieval
      - agent availability discovery
      - LLM reasoning
    """

    incident = state["incident"]
    incident_id = state["incident_id"]

    print(
        f"[LANGGRAPH] fast_path_node "
        f"incident={incident_id}"
    )

    task_plan = build_fast_path_plan(incident)

    return {
        "task_plan": task_plan,
        "stage": "completed",
    }

# ============================================================
# LANGGRAPH ROUTING
# ============================================================

def route_after_prepare(state: IncidentState) -> str:
    """
    Decide whether the incident should use the deterministic
    fast path or continue through LLM reasoning.
    """

    if state.get("stage") == "prepared_fast_path":
        print(
            "[LANGGRAPH] Routing to fast path"
        )
        return "fast_path"

    print(
        "[LANGGRAPH] Routing to LLM reasoning"
    )
    return "llm_reasoning"

# ============================================================
# LANGGRAPH NODE 2 — LLM REASONING
# ============================================================

def llm_reasoning_node(state: IncidentState) -> IncidentState:
    """
    Generate a TaskPlan using the prepared incident state.

    Consumes:
      - incident
      - chromadb_context
      - agent_status_block

    Produces:
      - task_plan
      - stage
    """

    incident = state["incident"]
    incident_id = state["incident_id"]

    print(
        f"[LANGGRAPH] llm_reasoning_node "
        f"incident={incident_id}"
    )

    incident_text = json.dumps(
        incident,
        indent=2,
        default=str,
    )

    chromadb_context = state.get(
        "chromadb_context",
        "",
    )

    agent_status_block = state.get(
        "agent_status_block",
        "",
    )

    full_input = f"""CURRENT INCIDENT:
{incident_text}

HISTORICAL CONTEXT FROM MEMORY:
{chromadb_context}

CURRENT AGENT AVAILABILITY:
{agent_status_block}

Based on the current incident, historical context, and agent availability above, produce a TaskPlan JSON for this incident.
"""

    # --------------------------------------------------------
    # Single structured LLM call
    # --------------------------------------------------------

    t_llm_start = time.monotonic()
    task_plan_dict = None

    try:
        print("\nInvoking LLM (structured output)...")

        structured_result = structured_llm.invoke(
            [
                ("system", SYSTEM_PROMPT),
                ("user", full_input),
            ]
        )

        # with_structured_output(TaskPlan) may return either
        # a TaskPlan object or a dict depending on version.
        task_plan_dict = (
            structured_result.dict()
            if hasattr(structured_result, "dict")
            else dict(structured_result)
        )

        print(
            "Structured output parsed successfully."
        )

    except Exception as e:
        print(
            f"Structured output failed: {e}"
        )
        print(
            "Falling back to plain invoke + "
            "text extraction..."
        )

        try:
            response = llm.invoke(
                [
                    ("system", SYSTEM_PROMPT),
                    ("user", full_input),
                ]
            )

            output = response.content

            print(
                f"\nLLM Output:\n{output}"
            )

            task_plan_dict = extract_json_from_output(
                output,
                incident,
            )

        except Exception as e2:
            print(
                f"Plain invoke also failed: {e2}"
            )
            print(
                "Using fallback rule-based plan"
            )

            task_plan_dict = (
                build_fallback_plan_dict(
                    incident
                )
            )

    t_llm_elapsed = (
        time.monotonic() - t_llm_start
    )

    print(
        f"[TIMING] llm_call="
        f"{t_llm_elapsed*1000:.0f}ms"
    )

    # --------------------------------------------------------
    # Return state to LangGraph
    # --------------------------------------------------------

    return {
        "task_plan": task_plan_dict,
        "stage": "llm_completed",
    }

# ============================================================
# LANGGRAPH NODE 3 — VALIDATE / FINALIZE TASK PLAN
# ============================================================

def validate_task_plan_node(state: IncidentState) -> IncidentState:
    """
    Validate the TaskPlan produced by the LLM.

    If validation fails, generate the existing deterministic
    fallback plan.
    """

    incident = state["incident"]
    incident_id = state["incident_id"]
    task_plan_dict = state.get("task_plan")

    print(
        f"[LANGGRAPH] validate_task_plan_node "
        f"incident={incident_id}"
    )

    # --------------------------------------------------------
    # Validate LLM output against TaskPlan schema
    # --------------------------------------------------------

    try:
        validated = TaskPlan(**task_plan_dict)
        result_dict = validated.dict()

        print(
            "[LANGGRAPH] TaskPlan schema validation "
            "successful."
        )

    except (ValidationError, TypeError, ValueError) as e:
        print(
            f"[LANGGRAPH] TaskPlan failed schema "
            f"validation: {e}"
        )
        print(
            "[LANGGRAPH] Using fallback rule-based plan."
        )

        fallback = build_fallback_plan_dict(
            incident
        )

        result_dict = TaskPlan(
            **fallback
        ).dict()

    # --------------------------------------------------------
    # Final information
    # --------------------------------------------------------

    print("\nTaskPlan produced:")
    print(
        f"  Actions: "
        f"{len(result_dict.get('actions', []))}"
    )
    print(
        f"  Approval required: "
        f"{result_dict.get('approval_required', False)}"
    )

    return {
        "task_plan": result_dict,
        "stage": "completed",
    }
    
# ============================================================
# BUILD LANGGRAPH
# ============================================================

def build_incident_graph():
    """
    Build and compile the PROTEGO incident-processing graph.

    Flow:

        START
          ↓
        prepare
          ↓
       routing
        ↙   ↘
    fast    LLM
     ↓       ↓
     │    validate
     │       ↓
     └───────┘
          ↓
         END

    RedisSaver provides persistent LangGraph checkpointing.
    """

    workflow = StateGraph(IncidentState)

    # --------------------------------------------------------
    # Register nodes
    # --------------------------------------------------------

    workflow.add_node(
        "prepare",
        prepare_incident_node,
    )

    workflow.add_node(
        "fast_path",
        fast_path_node,
    )

    workflow.add_node(
        "llm_reasoning",
        llm_reasoning_node,
    )

    workflow.add_node(
        "validate",
        validate_task_plan_node,
    )

    # --------------------------------------------------------
    # Entry point
    # --------------------------------------------------------

    workflow.add_edge(
        START,
        "prepare",
    )

    # --------------------------------------------------------
    # Conditional routing after preparation
    # --------------------------------------------------------

    workflow.add_conditional_edges(
        "prepare",
        route_after_prepare,
        {
            "fast_path": "fast_path",
            "llm_reasoning": "llm_reasoning",
        },
    )

    # --------------------------------------------------------
    # Fast path goes directly to END
    # --------------------------------------------------------

    workflow.add_edge(
        "fast_path",
        END,
    )

    # --------------------------------------------------------
    # Normal path
    # --------------------------------------------------------

    workflow.add_edge(
        "llm_reasoning",
        "validate",
    )

    workflow.add_edge(
        "validate",
        END,
    )

    # --------------------------------------------------------
    # Compile with persistent Redis checkpointing
    # --------------------------------------------------------

    compiled_graph = workflow.compile(
        checkpointer=checkpointer
    )

    print(
        "[LANGGRAPH] Incident graph compiled successfully"
    )

    return compiled_graph


incident_graph = build_incident_graph()

# ============================================================
# LANGGRAPH INCIDENT RUNNER
# ============================================================

def run_react_loop(incident: dict) -> dict:
    """
    Run the incident through the LangGraph pipeline.

    The incident_id is used as the LangGraph thread_id so that
    RedisSaver can persist and reload the graph state.
    """

    incident_id = incident.get("incident_id")

    if not incident_id:
        raise ValueError(
            "Incident must contain incident_id"
        )

    print(
        f"\n[LANGGRAPH] Starting incident "
        f"processing: {incident_id}"
    )

    initial_state: IncidentState = {
        "incident_id": incident_id,
        "incident": incident,
        "stage": "started",
    }

    config = {
        "configurable": {
            "thread_id": incident_id
        }
    }

    result = incident_graph.invoke(
        initial_state,
        config=config,
    )

    task_plan = result.get("task_plan")

    if not task_plan:
        raise RuntimeError(
            f"LangGraph completed without TaskPlan "
            f"for incident {incident_id}"
        )

    print(
        f"[LANGGRAPH] Incident processing completed: "
        f"{incident_id}"
    )

    return task_plan
    
def resume_checkpoint(incident_id: str) -> dict:
    """
    Resume an incident from the latest LangGraph Redis checkpoint.

    The incident_id is used as the LangGraph thread_id.
    """

    if not incident_id:
        raise ValueError("incident_id is required")

    config = {
        "configurable": {
            "thread_id": incident_id
        }
    }

    print(f"[LANGGRAPH] Checking checkpoint for incident={incident_id}")

    # Retrieve the latest LangGraph state for this incident.
    state_snapshot = incident_graph.get_state(config)

    if state_snapshot is None or not state_snapshot.values:
        raise ValueError(
            f"No LangGraph checkpoint found for incident {incident_id}"
        )

    state = state_snapshot.values

    print(
        f"[LANGGRAPH] Checkpoint found: "
        f"incident={incident_id}, "
        f"stage={state.get('stage')}"
    )

    # If the graph already completed, return the existing TaskPlan.
    task_plan = state.get("task_plan")

    if task_plan and state.get("stage") == "completed":
        print(
            f"[LANGGRAPH] Incident {incident_id} already completed. "
            f"Returning existing TaskPlan."
        )
        return task_plan

    # Otherwise resume the graph from its saved checkpoint.
    print(
        f"[LANGGRAPH] Resuming graph execution for "
        f"incident={incident_id}"
    )

    resumed_state = incident_graph.invoke(
        None,
        config=config,
    )

    resumed_task_plan = resumed_state.get("task_plan")

    if not resumed_task_plan:
        raise RuntimeError(
            f"LangGraph resumed for {incident_id}, "
            f"but no TaskPlan was produced"
        )

    print(
        f"[LANGGRAPH] Resume completed successfully: "
        f"incident={incident_id}"
    )

    return resumed_task_plan

def extract_json_from_output(output: str, incident: dict) -> dict:
    """
    Extract TaskPlan JSON from LLM output. Only reached if structured
    output failed and we fell back to a plain text invoke - kept as a
    safety net, not the primary path anymore.
    """
    import re

    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', output, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    json_match = re.search(r'\{[^{}]*"actions"[^{}]*\[.*?\]\s*\}', output, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    try:
        return json.loads(output.strip())
    except json.JSONDecodeError:
        pass

    print("Could not parse JSON from LLM output. Using fallback plan.")
    return build_fallback_plan_dict(incident)


def build_fast_path_plan(incident: dict) -> dict:
    """
    Deterministic plan for low-severity, single-stage incidents.
    Mirrors build_fallback_plan_dict's shape but is reached by design
    (not by failure) - kept separate so the reasoning_summary and any
    future fast-path-specific logic don't get conflated with the
    LLM-failure fallback path.
    """
    severity = int(incident.get("composite_severity", incident.get("severity", 5)))
    incident_id = incident.get("incident_id", "UNKNOWN")

    return {
        "incident_id": incident_id,
        "agent_sequence": [AGENT_TRIAGE, AGENT_NOTIFICATION],
        "actions": [
            {
                "task_id": "fastpath-1",
                "agent": AGENT_TRIAGE,
                "action": "confirm_severity_blast_radius",
                "depends_on": []
            },
            {
                "task_id": "fastpath-2",
                "agent": AGENT_NOTIFICATION,
                "action": "create_case_send_alert",
                "depends_on": ["fastpath-1"]
            }
        ],
        "approval_required": False,
        "severity": severity,
        "reasoning_summary": (
            f"Fast path: severity {severity} (<= {FAST_PATH_MAX_SEVERITY}), single-stage. "
            f"Routed directly to triage + notification without LLM reasoning to minimize MTTD."
        ),
    }


def build_fallback_plan_dict(incident: dict) -> dict:
    """
    Rule-based fallback when the LLM fails or produces invalid output
    (as opposed to build_fast_path_plan, which is reached by design).
    Always produces a dict shaped exactly like shared.models.TaskPlan.
    """
    severity = int(incident.get("composite_severity", incident.get("severity", 5)))
    incident_id = incident.get("incident_id", "UNKNOWN")

    agent_sequence = [AGENT_TRIAGE, AGENT_NOTIFICATION]
    actions = [
        {
            "task_id": "fallback-1",
            "agent": AGENT_TRIAGE,
            "action": "confirm_severity_blast_radius",
            "depends_on": []
        },
        {
            "task_id": "fallback-2",
            "agent": AGENT_NOTIFICATION,
            "action": "create_case_send_alert",
            "depends_on": ["fallback-1"]
        }
    ]

    return {
        "incident_id": incident_id,
        "agent_sequence": agent_sequence,
        "actions": actions,
        "approval_required": severity >= 9,
        "severity": severity,
        "reasoning_summary": "Fallback rule-based plan (LLM parsing or validation failed)."
    }

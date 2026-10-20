import redis
import os
import json
from datetime import datetime

REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# Key naming conventions
# agent heartbeat:   agent:{name}:heartbeat          TTL 30s
# agent task queue:  agent:{name}:pending_tasks       no TTL
# incident context:  incident:{id}:context            TTL 3600s
# dedup fingerprint: dedup:{sha256}                   TTL 60s
# geo cache:         geo:{ip}                         TTL 3600s
# ldap cache:        ldap:{username}                  TTL 300s

HEARTBEAT_TTL = 30       # seconds — agent declared dead if missed
INCIDENT_CTX_TTL = 3600  # 1 hour context window
GEO_CACHE_TTL = 3600     # 1 hour geo cache
LDAP_CACHE_TTL = 300     # 5 minute LDAP cache
DEDUP_TTL = 60           # 60 second dedup window

def publish_heartbeat(agent_name: str):
    """Agent calls this every 10 seconds to signal it is alive"""
    key = f"agent:{agent_name}:heartbeat"
    value = json.dumps({
        "agent": agent_name,
        "timestamp": datetime.utcnow().isoformat(),
        "status": "alive"
    })
    r.set(key, value, ex=HEARTBEAT_TTL)

def get_agent_status(agent_name: str) -> str:
    """Returns 'alive' or 'dead'"""
    key = f"agent:{agent_name}:heartbeat"
    if r.exists(key):
        return "alive"
    return "dead"

def get_all_agent_statuses() -> dict:
    """Returns status of all known agents"""
    agents = [
        "triage",
        "investigation", 
        "response",
        "containment",
        "notification",
        "learning"
    ]
    return {agent: get_agent_status(agent) for agent in agents}

def queue_task(agent_name: str, task: dict):
    """Orchestrator calls this to queue a task for an agent"""
    key = f"agent:{agent_name}:pending_tasks"
    r.rpush(key, json.dumps(task))

def get_next_task(agent_name: str) -> dict | None:
    """Agent calls this to get its next task"""
    key = f"agent:{agent_name}:pending_tasks"
    task = r.lpop(key)
    if task:
        return json.loads(task)
    return None

def get_pending_tasks(agent_name: str) -> list:
    """Get all pending tasks for an agent"""
    key = f"agent:{agent_name}:pending_tasks"
    tasks = r.lrange(key, 0, -1)
    return [json.loads(t) for t in tasks]

def clear_agent_tasks(agent_name: str):
    """Self-healing watchdog calls this before requeuing"""
    key = f"agent:{agent_name}:pending_tasks"
    r.delete(key)

def set_incident_context(incident_id: str, context: dict):
    """Store full incident context for LLM reasoning"""
    key = f"incident:{incident_id}:context"
    r.set(key, json.dumps(context, default=str), ex=INCIDENT_CTX_TTL)

def get_incident_context(incident_id: str) -> dict | None:
    """Retrieve incident context"""
    key = f"incident:{incident_id}:context"
    data = r.get(key)
    if data:
        return json.loads(data)
    return None
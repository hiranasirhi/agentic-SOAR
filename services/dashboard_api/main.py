# dashboard_api/main.py
# Serves data for the Agent Health Grid + MTTD/MTTR Charts panels.
# ASSUMPTION: adjust the metrics table/column names in get_mttd_mttr()
# to match your actual Postgres metrics table from Module 1.

import json
import os
from datetime import datetime, timedelta

import psycopg2
import redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import sys
sys.path.append('/app')

from shared.constants import REDIS_AGENT_HEARTBEAT

load_dotenv()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
POSTGRES_DSN = os.getenv("POSTGRES_DSN", "dbname=protego user=protego password=protego host=localhost port=5432")

ALL_AGENTS = ["triage", "investigation", "response", "containment", "notification", "learning"]

app = FastAPI(title="PROTEGO Dashboard API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before deployment
    allow_methods=["*"],
    allow_headers=["*"],
)

redis_client = redis.Redis(
    host=REDIS_HOST, port=REDIS_PORT, decode_responses=True,
    socket_connect_timeout=5, socket_timeout=5, retry_on_timeout=True,
)


@app.get("/api/health/agents")
def get_agent_health():
    results = []
    for agent in ALL_AGENTS:
        heartbeat_key = REDIS_AGENT_HEARTBEAT.format(name=agent)
        ttl = redis_client.ttl(heartbeat_key)
        alive = ttl is not None and ttl > 0
        results.append({
            "agent": agent,
            "alive": alive,
            "ttl_remaining_seconds": ttl if alive else None,
        })
    return {"agents": results, "checked_at": datetime.now().isoformat()}


@app.get("/api/metrics/mttd_mttr")
def get_mttd_mttr(days: int = 7):
    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT m.incident_id, m.recorded_at, m.mttd_seconds, m.mttr_seconds,
                       m.false_positive, i.severity
                FROM metrics m
                LEFT JOIN incidents i ON i.incident_id = m.incident_id
                WHERE m.recorded_at >= %s
                ORDER BY m.recorded_at ASC
            """, (datetime.now() - timedelta(days=days),))
            rows = cur.fetchall()
    finally:
        conn.close()

    data = [
        {
            "incident_id": r[0],
            "timestamp": r[1].isoformat() if r[1] else None,
            "mttd_seconds": r[2],
            "mttr_seconds": r[3],
            "false_positive": r[4],
            "severity": r[5],
        }
        for r in rows
    ]

    mttd_values = [d["mttd_seconds"] for d in data if d["mttd_seconds"] is not None]
    mttr_values = [d["mttr_seconds"] for d in data if d["mttr_seconds"] is not None]

    avg_mttd = sum(mttd_values) / len(mttd_values) if mttd_values else 0
    avg_mttr = sum(mttr_values) / len(mttr_values) if mttr_values else 0

    return {"incidents": data, "avg_mttd_seconds": avg_mttd, "avg_mttr_seconds": avg_mttr}


@app.get("/health")
def health_check():
    return {"status": "running"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("DASHBOARD_API_PORT", 8001)), reload=True)
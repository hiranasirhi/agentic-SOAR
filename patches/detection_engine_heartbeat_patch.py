"""
Patch for detection_engine.py (your existing service).

This is the LAST hop the heartbeat needs to make. Instead of running rule
matching / Isolation Forest / MITRE kill-chain correlation / severity
scoring (all meaningless on a synthetic marker) and instead of producing
to `incidents` (which would create a fake Incident object and wake up the
Orchestrator on the other host), redirect straight to a dedicated
`pipeline-heartbeat-ack` topic that only pipeline-monitor listens to.
"""

def is_pipeline_heartbeat(event: dict) -> bool:
    return event.get("event_type") == "pipeline_heartbeat"


def handle_heartbeat_ack(event: dict, producer) -> None:
    producer.send("pipeline-heartbeat-ack", event)
    print(f"[DETECTION-ENGINE] heartbeat {event.get('heartbeat_id')} acked")


# --- integration point ---
#
# for message in consumer:  # consuming enriched-events
#     event = json.loads(message.value)
#
#     if is_pipeline_heartbeat(event):
#         handle_heartbeat_ack(event, producer)
#         continue   # <-- do NOT run detection logic, do NOT touch `incidents` topic
#
#     # ... existing rule matching / anomaly detection / correlation / scoring / produce to incidents ...
#
# NOTE: `pipeline-heartbeat-ack` is a NEW Kafka topic — create it alongside
# your existing five (raw-alerts, normalized-events, enriched-events,
# incidents, failed-events), e.g.:
#   kafka-topics.sh --create --topic pipeline-heartbeat-ack \
#       --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1

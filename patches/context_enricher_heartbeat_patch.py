"""
Patch for context_enricher.py (your existing service).

Same principle as the Normalizer patch: heartbeat markers should skip
GeoIP / asset-criticality / user-identity / MITRE enrichment entirely
(there's no IP, asset, or user to enrich) and just move to the next topic.
"""

def is_pipeline_heartbeat(event: dict) -> bool:
    return event.get("event_type") == "pipeline_heartbeat"


def handle_heartbeat_passthrough(event: dict, producer) -> None:
    producer.send("enriched-events", event)
    print(f"[ENRICHER] heartbeat {event.get('heartbeat_id')} passed through")


# --- integration point ---
#
# for message in consumer:  # consuming normalized-events
#     event = json.loads(message.value)
#
#     if is_pipeline_heartbeat(event):
#         handle_heartbeat_passthrough(event, producer)
#         continue
#
#     # ... existing GeoIP / asset / user / MITRE enrichment / produce ...

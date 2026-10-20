"""
Patch for normalizer.py (your existing service).

Add this check at the TOP of whatever function currently consumes each
message from `raw-alerts`, BEFORE format-detection / schema validation /
dedup hashing runs. Heartbeat markers should never touch the
IncidentEvent Pydantic model or the Redis dedup fingerprint window —
they're not real events.

Drop this in wherever your consume loop currently does:
    for message in consumer:
        raw = json.loads(message.value)
        <-- ADD THE CHECK HERE, before parser dispatch -->
"""

def is_pipeline_heartbeat(raw_event: dict) -> bool:
    return raw_event.get("event_type") == "pipeline_heartbeat"


def handle_heartbeat_passthrough(raw_event: dict, producer) -> None:
    """Forward the marker one hop down the chain, untouched, and return
    immediately — skip parser/validation/dedup entirely for this message."""
    producer.send("normalized-events", raw_event)
    print(f"[NORMALIZER] heartbeat {raw_event.get('heartbeat_id')} passed through")


# --- integration point in your existing consume loop ---
#
# for message in consumer:
#     raw = json.loads(message.value)
#
#     if is_pipeline_heartbeat(raw):
#         handle_heartbeat_passthrough(raw, producer)
#         continue   # <-- skip everything else for this message
#
#     # ... existing format detection / IncidentEvent validation / dedup / produce ...

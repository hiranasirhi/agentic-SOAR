"""
pipeline-monitor
================
Combines two long-running checks from proposal Sec 7.2.2 into one service:

  1. Consumer lag monitor  — every CHECK_INTERVAL seconds, for each
     (topic, consumer_group) pair, compares committed offset vs high-watermark
     offset per partition. Alerts to Slack if summed lag > LAG_THRESHOLD.

  2. Pipeline heartbeat checker — every CHECK_INTERVAL seconds, publishes a
     synthetic marker message and waits up to HEARTBEAT_SLA_SECONDS for it to
     reappear on the far side of the pipeline. Alerts to Slack on SLA breach
     or on the marker never returning at all.

     IMPORTANT DESIGN NOTE (read before wiring this up):
     The heartbeat marker is tagged {"event_type": "pipeline_heartbeat"} and
     injected into `raw-alerts`. It is NOT expected to become a real Incident —
     doing that would pollute the incidents table, trigger real agent actions,
     and require coordinating a skip-path through the Orchestrator on the
     other host. Instead, Normalizer and Detection Engine (both of which run
     on THIS host, alongside this monitor) are given a small patch (see
     ../patches/normalizer_heartbeat_patch.py and
     ../patches/detection_engine_heartbeat_patch.py) that recognizes this
     event_type and short-circuits it straight to a dedicated topic,
     `pipeline-heartbeat-ack`, instead of running full validation/detection.
     This proves liveness of raw-alerts -> normalized-events -> enriched-events
     -> detection-engine-passthrough, i.e. the entire ingestion pipeline this
     host owns, without touching the Orchestrator or agents at all.
"""

import json
import os
import time
import uuid
import threading
from datetime import datetime, timezone

sys.stdout.reconfigure(line_buffering=True)

import requests
from kafka import KafkaAdminClient, KafkaConsumer, KafkaProducer
from kafka.structs import TopicPartition

KAFKA_BROKER = os.environ["KAFKA_BROKER"]
SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "60"))
LAG_THRESHOLD = int(os.environ.get("LAG_THRESHOLD", "100"))
HEARTBEAT_SLA_SECONDS = int(os.environ.get("HEARTBEAT_SLA_SECONDS", "30"))
HEARTBEAT_SOURCE_TOPIC = os.environ.get("HEARTBEAT_SOURCE_TOPIC", "raw-alerts")
HEARTBEAT_ACK_TOPIC = os.environ.get("HEARTBEAT_ACK_TOPIC", "pipeline-heartbeat-ack")

# Comma-separated "topic:group" pairs, e.g.
#   "raw-alerts:normalizer-group,normalized-events:enricher-group,enriched-events:detection-engine-group,incidents:notification-group,incidents:learning-group,failed-events:dlq-monitor-group"
TOPIC_GROUP_PAIRS = [
    tuple(pair.split(":")) for pair in os.environ["TOPIC_GROUP_PAIRS"].split(",") if pair
]

_last_slack_alert = {}
SLACK_DEDUPE_SECONDS = int(os.environ.get("SLACK_DEDUPE_SECONDS", "300"))


def alert_slack(key: str, message: str):
    """De-duped Slack alert — same alert `key` won't re-fire within SLACK_DEDUPE_SECONDS."""
    now = time.time()
    if now - _last_slack_alert.get(key, 0) < SLACK_DEDUPE_SECONDS:
        return
    _last_slack_alert[key] = now
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": message}, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"[PIPELINE-MONITOR] Slack post failed: {e}")


def resolve_ok(key: str):
    _last_slack_alert.pop(key, None)


# ---------------------------------------------------------------------------
# 1. Consumer lag monitor
# ---------------------------------------------------------------------------

def check_lag():
    admin = KafkaAdminClient(bootstrap_servers=KAFKA_BROKER)
    consumer = KafkaConsumer(bootstrap_servers=KAFKA_BROKER)
    try:
        for topic, group in TOPIC_GROUP_PAIRS:
            try:
                partitions = consumer.partitions_for_topic(topic)
                if not partitions:
                    print(f"[LAG] topic={topic} has no partitions (does it exist yet?)")
                    continue

                tps = [TopicPartition(topic, p) for p in partitions]
                end_offsets = consumer.end_offsets(tps)

                committed = admin.list_consumer_group_offsets(group, partitions=tps)

                total_lag = 0
                for tp in tps:
                    end = end_offsets.get(tp, 0)
                    meta = committed.get(tp)
                    committed_offset = meta.offset if meta and meta.offset >= 0 else 0
                    total_lag += max(0, end - committed_offset)

                key = f"lag:{topic}:{group}"
                if total_lag > LAG_THRESHOLD:
                    alert_slack(
                        key,
                        f":warning: *Consumer lag* — topic=`{topic}` group=`{group}` "
                        f"lag=`{total_lag}` (threshold `{LAG_THRESHOLD}`)",
                    )
                else:
                    resolve_ok(key)
                    print(f"[LAG] topic={topic} group={group} lag={total_lag} OK")

            except Exception as e:
                print(f"[LAG] error checking topic={topic} group={group}: {e}")
    finally:
        consumer.close()
        admin.close()


# ---------------------------------------------------------------------------
# 2. Pipeline heartbeat checker
# ---------------------------------------------------------------------------

def heartbeat_check():
    marker_id = str(uuid.uuid4())
    sent_at = time.time()

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    try:
        producer.send(
            HEARTBEAT_SOURCE_TOPIC,
            {
                "event_type": "pipeline_heartbeat",
                "heartbeat_id": marker_id,
                "sent_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        producer.flush(timeout=5)
    finally:
        producer.close()

    consumer = KafkaConsumer(
        HEARTBEAT_ACK_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        auto_offset_reset="latest",
        consumer_timeout_ms=HEARTBEAT_SLA_SECONDS * 1000,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        group_id=None,  # ephemeral — we want to see new messages from "now", not resume a group
    )

    found = False
    try:
        deadline = sent_at + HEARTBEAT_SLA_SECONDS
        for msg in consumer:
            if msg.value.get("heartbeat_id") == marker_id:
                found = True
                break
            if time.time() > deadline:
                break
    finally:
        consumer.close()

    elapsed = time.time() - sent_at
    key = "heartbeat"

    if not found:
        alert_slack(
            key,
            f":rotating_light: *Pipeline heartbeat SLA breach* — marker `{marker_id[:8]}` "
            f"did not return within {HEARTBEAT_SLA_SECONDS}s (waited {elapsed:.1f}s). "
            f"Ingestion pipeline (raw-alerts -> normalized-events -> enriched-events -> "
            f"{HEARTBEAT_ACK_TOPIC}) may be stalled.",
        )
        print(f"[HEARTBEAT] marker {marker_id} NOT confirmed after {elapsed:.1f}s")
    else:
        resolve_ok(key)
        print(f"[HEARTBEAT] marker {marker_id} confirmed in {elapsed:.1f}s")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main_loop():
    while True:
        try:
            check_lag()
        except Exception as e:
            print(f"[PIPELINE-MONITOR] lag check crashed: {e}")

        try:
            heartbeat_check()
        except Exception as e:
            print(f"[PIPELINE-MONITOR] heartbeat check crashed: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    print(
        f"[PIPELINE-MONITOR] starting — interval={CHECK_INTERVAL}s "
        f"lag_threshold={LAG_THRESHOLD} heartbeat_sla={HEARTBEAT_SLA_SECONDS}s"
    )
    main_loop()

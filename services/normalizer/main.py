import json
import hashlib
import os
import time
import sys
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.path.insert(0, '/app')

from dotenv import load_dotenv
load_dotenv()

KAFKA_SERVERS = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:29092')
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
DEDUP_WINDOW = 3600

HEARTBEAT_ACK_TOPIC = os.getenv('HEARTBEAT_ACK_TOPIC', 'pipeline-heartbeat-ack')


print(f"Starting normalizer...")
print(f"Kafka servers: {KAFKA_SERVERS}")
print(f"Redis host: {REDIS_HOST}:{REDIS_PORT}")

# Wait for Kafka to be ready with retry logic
def wait_for_kafka(servers, max_retries=10, delay=5):
    from kafka import KafkaConsumer
    
    for attempt in range(max_retries):
        try:
            print(f"Attempting Kafka connection {attempt + 1}/{max_retries}...")
            test_consumer = KafkaConsumer(
                bootstrap_servers=servers,
                consumer_timeout_ms=5000
            )
            test_consumer.close()
            print("Kafka connection successful")
            return True
        except Exception as e:
            print(f"Kafka not ready: {e}")
            if attempt < max_retries - 1:
                print(f"Waiting {delay} seconds before retry...")
                time.sleep(delay)
    return False

# Wait for Redis to be ready
def wait_for_redis(host, port, max_retries=10, delay=5):
    import redis
    for attempt in range(max_retries):
        try:
            print(f"Attempting Redis connection {attempt + 1}/{max_retries}...")
            r = redis.Redis(host=host, port=port, decode_responses=True)
            r.ping()
            print("Redis connection successful")
            return True
        except Exception as e:
            print(f"Redis not ready: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
    return False

# Wait for both services
if not wait_for_kafka(KAFKA_SERVERS):
    print("ERROR: Could not connect to Kafka after all retries. Exiting.")
    sys.exit(1)

if not wait_for_redis(REDIS_HOST, REDIS_PORT):
    print("ERROR: Could not connect to Redis after all retries. Exiting.")
    sys.exit(1)

# Now import and initialize everything
from kafka import KafkaConsumer, KafkaProducer
import redis

def safe_json_deserializer(message):
    try:
        if not message:
            return None

        return json.loads(message.decode("utf-8"))

    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"Invalid Kafka message dropped: {e}")
        return None


consumer = KafkaConsumer(
    'raw-alerts',
    bootstrap_servers=KAFKA_SERVERS,
    value_deserializer=safe_json_deserializer,
    group_id='normalizer-group',
    auto_offset_reset='earliest',
    enable_auto_commit=True
)

producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVERS,
    value_serializer=lambda m: json.dumps(m, default=str).encode('utf-8')
)

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

print("Normalizer fully started — listening on raw-alerts topic")
    
def detect_source(raw_event):
    if 'rule' in raw_event and 'agent' in raw_event:
        return 'wazuh'
    elif raw_event.get('event_type') == 'alert':   # was: 'event_type' in raw_event
        return 'suricata'
    else:
        return 'unknown'

def detect_source(raw_event):
    if 'rule' in raw_event and 'agent' in raw_event:
        return 'wazuh'
    elif 'event_type' in raw_event:
        return 'suricata'
    else:
        return 'unknown'

def parse_wazuh(raw_event):
    data = raw_event.get("data", {})
    agent = raw_event.get("agent", {})

    # Network events have src_ip/dest_ip.
    # Host-based events (sudo, PAM, etc.) use the agent IP.
    source_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or agent.get("ip")
    )

    destination_ip = (
        data.get("dstip")
        or data.get("dest_ip")
    )

    username = (
        data.get("srcuser")
        or data.get("dstuser")
        or data.get("user")
    )

    source_port = data.get("src_port") or data.get("srcport")
    destination_port = data.get("dest_port") or data.get("dstport")

    return {
        "event_id": str(raw_event.get("id", f"evt-{time.time()}")),
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": int(source_port) if source_port else None,
        "destination_port": int(destination_port) if destination_port else None,
        "protocol": data.get("proto"),
        "rule_id": str(raw_event.get("rule", {}).get("id", "")),
        "rule_description": raw_event.get("rule", {}).get("description", ""),
        "severity": min(int(raw_event.get("rule", {}).get("level", 1)), 10),
        "hostname": agent.get("name"),
        "username": username,
        "event_source": "wazuh",
        "asset_criticality": "medium",
        "raw_log": raw_event
    }

def parse_suricata(raw_event):
    alert = raw_event.get("alert")
    if not alert:
        return None   # flow/stats/dns/http/etc — not an alert, let normalize() route it to failed-events

    # Suricata alert.severity: 1=high, 2=medium, 3=low (inverted vs Wazuh's 0-15 scale)
    suricata_sev_map = {1: 8, 2: 5, 3: 2}
    severity = suricata_sev_map.get(alert.get("severity"), 3)

    return {
        "event_id": str(raw_event.get("flow_id", f"evt-{time.time()}")),
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": raw_event.get("src_ip"),
        "destination_ip": raw_event.get("dest_ip"),
        "source_port": raw_event.get("src_port"),
        "destination_port": raw_event.get("dest_port"),
        "protocol": raw_event.get("proto"),
        "rule_id": str(alert.get("signature_id", "")),
        "rule_description": alert.get("signature", ""),
        "severity": severity,
        "event_source": "suricata",
        "asset_criticality": "medium",
        "raw_log": raw_event
    }
# ============================================
# Linux / Low-Value Event Filtering
# ============================================

IGNORED_WAZUH_RULE_IDS = {
    # PAM session opened
    "5501",
    "5502",
    "5503",
    "52002",
    "40704",
    "503",
    # Add other known noisy Linux rule IDs here
    # "5502",
    # "5503",
}

IGNORED_WAZUH_DESCRIPTIONS = {
    "PAM: Login session opened.",
    "PAM: Login session closed.",
    "PAM: User login failed.",
    "Apparmor DENIED",
    "Wazuh agent started.",
    "Systemd: Service exited due to a failure.",
}

def is_noise_event(raw_event):
    """
    Returns True if the event is a known low-value/noise event
    that should not enter the normalized-events pipeline.
    """

    source = detect_source(raw_event)

    # Only apply these rules to Wazuh
    if source != "wazuh":
        return False

    rule = raw_event.get("rule", {})

    rule_id = str(rule.get("id", ""))
    description = str(rule.get("description", ""))

    # Ignore explicitly configured noisy rule IDs
    if rule_id in IGNORED_WAZUH_RULE_IDS:
        return True

    # Ignore explicitly configured noisy descriptions
    if description in IGNORED_WAZUH_DESCRIPTIONS:
        return True

    return False


# ============================================
# Event-ID Based Deduplication
# ============================================

def deduplicate(event_id):
    """
    Deduplicate using the ORIGINAL event ID generated by Wazuh.

    The same Wazuh event keeps the same ID even if it is
    re-read by the poller.
    """

    if not event_id:
        return False

    key = f"seen_event:{event_id}"

    # Atomic Redis operation:
    # NX = only create if key does not already exist
    is_new = r.set(
        key,
        "1",
        ex=DEDUP_WINDOW,
        nx=True
    )

    if is_new:
        return False   # New event

    return True        # Duplicate event

def normalize(raw_event):
    source = detect_source(raw_event)
    if source == 'wazuh':
        return parse_wazuh(raw_event)
    elif source == 'suricata':
        return parse_suricata(raw_event)
    return None

for message in consumer:
    raw_event = message.value
    try:
        # STEP 0 — pipeline liveness marker, never a security event
        if raw_event.get('event_type') == 'pipeline_heartbeat':
            producer.send(HEARTBEAT_ACK_TOPIC, raw_event)
            continue

        # ============================================
        # STEP 1 — Detect and drop known noise
        # ============================================

        if is_noise_event(raw_event):

            rule = raw_event.get("rule", {})

            print(
                f"Noise event dropped: "
                f"rule={rule.get('id')} "
                f"desc={rule.get('description')}"
            )

            continue


        # ============================================
        # STEP 2 — Normalize event
        # ============================================

        normalized = normalize(raw_event)

        if normalized is None:

            producer.send(
                'failed-events',
                raw_event
            )

            print(
                "Unknown format sent to failed-events"
            )

            continue


        # ============================================
        # STEP 3 — Deduplicate using ORIGINAL EVENT ID
        # ============================================

        event_id = normalized.get("event_id")

        if deduplicate(normalized["event_id"]):
            print(
             f"Duplicate dropped: "
             f"event_id={normalized['event_id']}"
            )
            continue


        # ============================================
        # STEP 4 — Send only clean events downstream
        # ============================================

        producer.send(
            'normalized-events',
            normalized
        )

        print(
            f"Normalized:"
            f" event_id={normalized['event_id']}"
            f" rule={normalized['rule_id']}"
            f" desc={normalized['rule_description']}"
        )


    except Exception as e:

        print(f"Error: {e}")

        try:
            producer.send(
                'failed-events',
                raw_event
            )

        except Exception:
            pass
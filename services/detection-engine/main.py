import json
import os
import sys
import time
import hashlib


sys.stdout.reconfigure(line_buffering=True)
sys.path.insert(0, "/app")


from dotenv import load_dotenv


load_dotenv()


KAFKA_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "kafka:29092"
)


REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))


print("Starting detection-engine...")


# ---------------------------------------------------
# Wait for Kafka
# ---------------------------------------------------


def wait_for_kafka(servers, max_retries=10, delay=5):
    from kafka import KafkaConsumer

    for attempt in range(max_retries):
        try:
            print(
                f"Attempting Kafka connection "
                f"{attempt + 1}/{max_retries}..."
            )

            c = KafkaConsumer(
                bootstrap_servers=servers,
                consumer_timeout_ms=5000
            )

            c.close()

            print("Kafka connection successful")
            return True

        except Exception as e:
            print(f"Kafka not ready: {e}")

            if attempt < max_retries - 1:
                time.sleep(delay)

    return False


# ---------------------------------------------------
# Wait for Redis
# ---------------------------------------------------


def wait_for_redis(host, port, max_retries=10, delay=5):
    import redis

    for attempt in range(max_retries):
        try:
            r_test = redis.Redis(
                host=host,
                port=port,
                decode_responses=True
            )

            r_test.ping()

            print("Redis connection successful")
            return True

        except Exception as e:
            print(f"Redis not ready: {e}")

            if attempt < max_retries - 1:
                time.sleep(delay)

    return False


# ---------------------------------------------------
# Wait for dependencies
# ---------------------------------------------------


if not wait_for_kafka(KAFKA_SERVERS):
    sys.exit(1)


if not wait_for_redis(REDIS_HOST, REDIS_PORT):
    sys.exit(1)


# ---------------------------------------------------
# Imports
# ---------------------------------------------------


from kafka import KafkaConsumer, KafkaProducer
import redis
import joblib
import numpy as np


from shared.models import Incident


# ---------------------------------------------------
# Redis
# ---------------------------------------------------


r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True
)


# ---------------------------------------------------
# Kafka Consumer
# ---------------------------------------------------


consumer = KafkaConsumer(
    "enriched-events",
    bootstrap_servers=KAFKA_SERVERS,
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    group_id="detection-engine-group",
    auto_offset_reset="earliest"
)


# ---------------------------------------------------
# Kafka Producer
# ---------------------------------------------------


producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVERS,
    value_serializer=lambda m: json.dumps(
        m,
        default=str
    ).encode("utf-8")
)


# ---------------------------------------------------
# MITRE Rules
# ---------------------------------------------------


with open("/app/mitre_rules.json") as f:
    MITRE_RULES = json.load(f)


# ---------------------------------------------------
# Isolation Forest
# ---------------------------------------------------


anomaly_bundle = joblib.load(
    "/app/isolation_forest.pkl"
)


iso_model = anomaly_bundle["model"]
scaler = anomaly_bundle["scaler"]
MODEL_FEATURES = anomaly_bundle["features"]


# ---------------------------------------------------
# Configuration
# ---------------------------------------------------


CRITICALITY_ORDINAL = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3
}


CORRELATION_WINDOW = 900


# Events with the same source IP + MITRE technique
# arriving within this window are grouped together.


INCIDENT_GROUP_WINDOW = 60


# ---------------------------------------------------
# Incident Grouping
# ---------------------------------------------------


def get_incident_group_key(event: dict, mitre: dict) -> str | None:
    technique = mitre.get("technique")
    source_ip = event.get("source_ip")
    rule_id = event.get("rule_id")

    if not source_ip:
        return None

    if technique:
        return f"incident-group:{source_ip}:{technique}"

    if rule_id:
        return f"incident-group:{source_ip}:rule:{rule_id}"

    return None


def get_existing_incident(group_key: str):

    data = r.get(group_key)

    if not data:
        return None

    try:
        return json.loads(data)

    except Exception:
        return None


def create_incident_group(
    group_key: str,
    incident_id: str,
    event_id: str
):

    data = {
        "incident_id": incident_id,
        "event_ids": [event_id],
        "created_at": time.time()
    }

    r.setex(
        group_key,
        INCIDENT_GROUP_WINDOW,
        json.dumps(data)
    )

    return data


def add_event_to_incident_group(
    group_key: str,
    event_id: str
):

    data = get_existing_incident(group_key)

    if not data:
        return None

    if event_id not in data["event_ids"]:
        data["event_ids"].append(event_id)

    r.setex(
        group_key,
        INCIDENT_GROUP_WINDOW,
        json.dumps(data)
    )

    return data


# ---------------------------------------------------
# File Integrity Monitoring — path-based filtering
# ---------------------------------------------------

FIM_RULE_IDS = {"550", "553", "554"}

SENSITIVE_PATH_PATTERNS = [
    "/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/crontab",
    "/etc/cron.d/", "/etc/cron.daily/", "/etc/ssh/", "/root/.ssh/",
    "/home/", "/etc/pam.d/", "/etc/audit/", "/var/ossec/etc/",
    "/etc/systemd/system/", "/etc/security/",
]

def is_sensitive_fim_path(event: dict) -> bool:
    path = event.get("raw_log", {}).get("syscheck", {}).get("path", "") or ""
    return any(pattern in path for pattern in SENSITIVE_PATH_PATTERNS)

TRUSTED_RULE_GROUPS = {"atomic", "attack"}   # your custom detection rules

# Rules where ONE occurrence is routine; only repeats are suspicious.
# rule_id: (count, window_seconds)
THRESHOLD_RULES = {
    "5401": (3, 120),   # failed sudo
}

def is_custom_rule(rule_id: str) -> bool:
    # Wazuh reserves 100000+ for rules you wrote yourself in local_rules.xml
    return rule_id.isdigit() and int(rule_id) >= 100000

def threshold_met(event: dict) -> bool:
    rule_id = str(event.get("rule_id", ""))
    limit, window = THRESHOLD_RULES[rule_id]
    key = f"threshold:{rule_id}:{event.get('source_ip')}:{event.get('username')}"
    n = r.incr(key)
    if n == 1:
        r.expire(key, window)
    return n >= limit

NON_THREAT_RULE_GROUPS = {"sca", "config_changed", "rootcheck", "vulnerability-detector"}


# ---------------------------------------------------
# MITRE Mapping
# ---------------------------------------------------


def map_to_mitre(event: dict) -> dict:

    rule_id = str(
        event.get("rule_id", "")
    )

    if rule_id in FIM_RULE_IDS:
        if is_sensitive_fim_path(event):
            return {"technique": "T1565", "tactic": "Impact"}
        return {"technique": None, "tactic": None}

    technique = None

    # First priority: rule ID
    if rule_id in MITRE_RULES.get(
        "by_rule_id",
        {}
    ):

        technique = MITRE_RULES[
            "by_rule_id"
        ][rule_id]

    else:

        # Second priority: keyword
        desc = event.get(
            "rule_description",
            ""
        ).lower()

        for keyword, tech in MITRE_RULES.get(
            "by_keyword",
            {}
        ).items():

            if keyword in desc:
                technique = tech
                break

    if not technique:

        return {
            "technique": None,
            "tactic": None
        }

    return {
        "technique": technique,
        "tactic": MITRE_RULES[
            "tactics"
        ].get(technique)
    }


# ---------------------------------------------------
# ML Flow Features
# ---------------------------------------------------


def get_flow_proxy_features(event: dict) -> list:

    source_ip = event["source_ip"]

    freq_key = (
        f"flow:{source_ip}:count"
    )

    count = r.incr(freq_key)
    r.expire(
        freq_key,
        60
    )

    port_key = (
        f"flow:{source_ip}:ports"
    )

    if event.get("destination_port"):

        r.sadd(
            port_key,
            event["destination_port"]
        )

        r.expire(
            port_key,
            60
        )

    distinct_ports = r.scard(
        port_key
    )

    feature_map = {

        "Flow Duration":
            1000.0,

        "Total Fwd Packets":
            float(count),

        "Total Backward Packets":
            float(distinct_ports),

        "Total Length of Fwd Packets":
            float(
                event.get(
                    "severity",
                    1
                )
            ) * 100,

        "Total Length of Bwd Packets":
            0.0,

        "Flow Bytes/s":
            float(count) * 10,

        "Flow Packets/s":
            float(count),

        "Fwd Packet Length Mean":
            float(
                event.get(
                    "severity",
                    1
                )
            ) * 50,

        "Bwd Packet Length Mean":
            0.0,

        "Flow IAT Mean":
            500.0,

        "Fwd IAT Mean":
            500.0,

        "Bwd IAT Mean":
            500.0,

        "Packet Length Mean":
            float(
                event.get(
                    "severity",
                    1
                )
            ) * 40,

        "Average Packet Size":
            float(
                event.get(
                    "severity",
                    1
                )
            ) * 40,
    }

    return [
        feature_map.get(
            f,
            0.0
        )
        for f in MODEL_FEATURES
    ]

def is_network_event(event: dict) -> bool:
    """The anomaly model was trained on network flow features.
    Only trust its output for events that actually have real
    network flow data — not host-local syslog/sca/journald events
    where the features would be synthetic placeholders."""
    return (
        event.get("event_source") == "suricata"
        or event.get("destination_port") is not None
    )

# ---------------------------------------------------
# Anomaly Detection
# ---------------------------------------------------


ANOMALY_SCORE_THRESHOLD = 0.35


def score_anomaly(event: dict) -> dict:

    raw_features = get_flow_proxy_features(
        event
    )

    X = scaler.transform(
        [raw_features]
    )

    raw_score = iso_model.decision_function(
        X
    )[0]

    normalized_score = float(
        np.clip(
            (0.5 - raw_score),
            0,
            1
        )
    )

    is_anomaly = (
        normalized_score >
        ANOMALY_SCORE_THRESHOLD
    )

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": normalized_score
    }


# ---------------------------------------------------
# MITRE Kill-Chain Correlation
# ---------------------------------------------------


def correlate(event: dict, technique: str | None, tactic: str | None) -> tuple:
    if not technique:
        return None, []

    key = f"correlation:{event['source_ip']}"
    entry = json.dumps({
        "technique": technique,
        "tactic": tactic,
        "event_id": event.get("event_id"),
        "ts": str(event.get("timestamp"))
    })
    r.rpush(key, entry)
    r.expire(key, CORRELATION_WINDOW)

    entries = [json.loads(e) for e in r.lrange(key, 0, -1)]
    techniques_seen = list({e["technique"] for e in entries})
    tactics_seen = list({e["tactic"] for e in entries if e.get("tactic")})

    if len(techniques_seen) >= 2:
        correlation_id = f"corr-{event['source_ip']}-{entries[0]['ts']}"
        return correlation_id, tactics_seen

    return None, tactics_seen


MIN_INCIDENT_SEVERITY = 6   # tune against your composite_severity scale (1-10)


def is_incident_worthy(event: dict, mitre: dict, anomaly_result: dict) -> bool:
    rule_id = str(event.get("rule_id", ""))
    groups = event.get("raw_log", {}).get("rule", {}).get("groups", [])

    # File integrity: the path decides, never the rule level
    if rule_id in FIM_RULE_IDS:
        return is_sensitive_fim_path(event)

    # Network events: the ML model was trained for these
    if event.get("event_source") == "suricata":
        return (
            bool(mitre.get("technique"))
            or anomaly_result.get("is_anomaly", False)
            or event.get("severity", 1) >= MIN_INCIDENT_SEVERITY
        )

    # Frequency rules: a single hit is routine
    if rule_id in THRESHOLD_RULES:
        return threshold_met(event)

    # Rules you wrote or explicitly vouched for
    if is_custom_rule(rule_id) or any(g in TRUSTED_RULE_GROUPS for g in groups):
        return True
    if rule_id in MITRE_RULES.get("by_rule_id", {}):
        return True

    # Everything else (built-in compliance, audit, package, user-admin rules)
    return False


# ---------------------------------------------------
# Severity
# ---------------------------------------------------


def compute_severity(
    base_severity: int,
    criticality: str,
    kill_chain_stages: list,
    is_anomaly: bool,
    fp_discount: int = 0
) -> int:

    score = base_severity

    score += CRITICALITY_ORDINAL.get(
        criticality,
        0
    )

    score += min(
        len(kill_chain_stages),
        3
    )

    if is_anomaly:
        score += 1

    score -= fp_discount

    return max(
        1,
        min(
            int(score),
            10
        )
    )


# ---------------------------------------------------
# Detection Engine
# ---------------------------------------------------


print(
    "Detection Engine started — "
    "listening on enriched-events"
)


for message in consumer:

    event = message.value

    try:

        # ---------------------------------------------------
        # Ensure source_ip is always a valid string
        # ---------------------------------------------------

        source_ip = event.get(
            "source_ip"
        )

        if not source_ip:

            source_ip = (
                event.get(
                    "raw_log",
                    {}
                )
                .get(
                    "agent",
                    {}
                )
                .get(
                    "ip"
                )
            )

        if not source_ip:
            source_ip = "unknown"

        event["source_ip"] = str(
            source_ip
        )

        # ---------------------------------------------------
        # MITRE Mapping
        # ---------------------------------------------------

        mitre = map_to_mitre(
            event
        )

        print(
            "\n======================"
        )

        print(
            "Detection Engine Input"
        )

        print(
            "Rule ID:",
            event.get("rule_id")
        )

        print(
            "Description:",
            event.get(
                "rule_description"
            )
        )

        print(
            "Mapped Technique:",
            mitre.get("technique")
        )

        print(
            "Mapped Tactic:",
            mitre.get("tactic")
        )

        print(
            "Source IP:",
            event.get("source_ip")
        )

        print(
            "======================\n"
        )

        # ---------------------------------------------------
        # Anomaly Detection
        # ---------------------------------------------------

        anomaly_result = {
            "is_anomaly": False,
            "anomaly_score": None
        }

        if not mitre.get("technique") and is_network_event(event):

            anomaly_result = score_anomaly(
                event
            )

            if anomaly_result[
                "is_anomaly"
            ]:

                print(
                    f"Anomaly detected: "
                    f"{event['source_ip']} "
                    f"score="
                    f"{anomaly_result['anomaly_score']:.3f}"
                )
        
        if not is_incident_worthy(event, mitre, anomaly_result):
            print(
                f"Not incident-worthy, dropped: "
                f"event_id={event.get('event_id')} "
                f"rule={event.get('rule_id')} "
                f"desc={event.get('rule_description')}"
            )
            continue

        # ---------------------------------------------------
        # MITRE Kill-Chain Correlation
        #
        # This runs for both mapped
        # and unmapped events.
        # ---------------------------------------------------

        correlation_id, stages = correlate(event, mitre.get("technique"), mitre.get("tactic"))

        # ---------------------------------------------------
        # Incident Grouping / Deduplication
        # ---------------------------------------------------

        group_key = get_incident_group_key(
            event,
            mitre
        )

        existing_group = None

        if group_key:

            existing_group = get_existing_incident(
                group_key
            )

        # ---------------------------------------------------
        # SECOND / DUPLICATE EVENT
        # ---------------------------------------------------

        if existing_group:

            updated_group = add_event_to_incident_group(
                group_key,
                event["event_id"]
            )

            if updated_group:

                print(
                    f"Grouped event "
                    f"{event['event_id']} "
                    f"into existing incident "
                    f"{updated_group['incident_id']}"
                )

                print(
                    f"Incident "
                    f"{updated_group['incident_id']} "
                    f"now contains "
                    f"{len(updated_group['event_ids'])} "
                    f"event(s)"
                )

            # Do NOT create another Incident.
            # Do NOT send another Kafka message.

            continue

        # ---------------------------------------------------
        # FIRST EVENT — CREATE NEW INCIDENT
        # ---------------------------------------------------

        incident_id = (
            "inc-"
            + hashlib.sha256(
                (
                    event["event_id"]
                    + str(time.time())
                ).encode()
            ).hexdigest()[:12]
        )

        # ---------------------------------------------------
        # Create Redis Incident Group
        # ---------------------------------------------------



        # ---------------------------------------------------
        # Severity
        # ---------------------------------------------------

        composite = compute_severity(
            event.get("severity", 1),
            event.get("asset_criticality", "low"),
            stages,
            anomaly_result["is_anomaly"]
        )


        # ---------------------------------------------------
        # Incident Object
        # ---------------------------------------------------

        incident = Incident(
            event_id=event["event_id"],
            timestamp=event["timestamp"],

            source_ip=event["source_ip"],

            destination_ip=event.get(
                "destination_ip"
            ),

            source_port=event.get(
                "source_port"
            ),

            destination_port=event.get(
                "destination_port"
            ),

            protocol=event.get(
                "protocol"
            ),

            rule_id=event["rule_id"],

            rule_description=event[
                "rule_description"
            ],

            mitre_technique=mitre.get(
                "technique"
            ),

            mitre_tactic=mitre.get(
                "tactic"
            ),

            severity=event.get(
                "severity",
                1
            ),

            asset_criticality=event.get(
                "asset_criticality",
                "low"
            ),

            hostname=event.get(
                "hostname"
            ),

            username=event.get(
                "username"
            ),

            user_department=event.get(
                "user_department"
            ),

            geo_country=event.get(
                "geo_country"
            ),

            geo_city=event.get(
                "geo_city"
            ),

            event_source=event[
                "event_source"
            ],

            raw_log=event.get(
                "raw_log",
                {}
            ),

            tags=event.get(
                "tags",
                []
            ),

            incident_id=incident_id,

            correlation_id=correlation_id,

            kill_chain_stages=stages,

            anomaly_score=anomaly_result[
                "anomaly_score"
            ],

            is_anomaly=anomaly_result[
                "is_anomaly"
            ],

            composite_severity=composite,

            correlated_event_ids=[
                event["event_id"]
            ],

            fp_discount_applied=0,
        )

        # ---------------------------------------------------
        # Send Incident to Kafka
        # ---------------------------------------------------

        payload = json.loads(
            incident.model_dump_json()
        )

        print(
            "\n========== "
            "SENDING TO INCIDENTS TOPIC "
            "=========="
        )

        print(
            json.dumps(
                payload,
                indent=2
            )
        )

        print(
            "================================================"
        )

        producer.send(
            "incidents",
            payload
        )

        producer.flush()

        if group_key:

            create_incident_group(
                group_key,
                incident_id,
                event["event_id"]
            )

        print(
            f"Incident sent: "
            f"{incident.incident_id}"
        )

    except Exception as e:

        print(
            f"Detection error: {e}"
        )

        try:

            producer.send(
                "failed-events",
                event
            )

        except Exception:

            pass
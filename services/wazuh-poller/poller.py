import json
import time
import os
import requests
import urllib3
from kafka import KafkaProducer
from requests.auth import HTTPBasicAuth

from shared.constants import TOPIC_RAW_ALERTS, KAFKA_POLL_INTERVAL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------- Configuration ----------------

KAFKA_SERVERS = os.environ.get("KAFKA_SERVERS", "100.71.186.0:9092")

WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://100.98.120.36:9200")

WAZUH_USERNAME = os.environ["WAZUH_USERNAME"]
WAZUH_PASSWORD = os.environ["WAZUH_PASSWORD"]

LAST_TIMESTAMP_FILE = "last_poll_timestamp.txt"

# ---------------- Kafka Producer ----------------

producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVERS,
    value_serializer=lambda m: json.dumps(m).encode("utf-8")
)

# ---------------- Helper Functions ----------------

def get_last_timestamp():
    try:
        with open(LAST_TIMESTAMP_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "now-10s"


def save_timestamp(timestamp):
    with open(LAST_TIMESTAMP_FILE, "w") as f:
        f.write(timestamp)

# ---------------- Poll Wazuh Alerts ----------------

def poll_alerts():
    last_timestamp = get_last_timestamp()

    query = {
        "size": 100,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "range": {
                "@timestamp": {
                    "gte": last_timestamp
                }
            }
        }
    }

    try:
        response = requests.get(
            f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
            auth=HTTPBasicAuth(WAZUH_USERNAME, WAZUH_PASSWORD),
            json=query,
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        hits = response.json().get("hits", {}).get("hits", [])

        if hits:
            for hit in hits:
                producer.send(TOPIC_RAW_ALERTS, hit["_source"])

            producer.flush()

            save_timestamp(hits[-1]["_source"]["@timestamp"])

            print(f"Sent {len(hits)} alerts to Kafka topic '{TOPIC_RAW_ALERTS}'.")

        else:
            print("No new alerts.")

    except Exception as e:
        print(f"Poll error: {e}")

# ---------------- Main Loop ----------------

print(f"Wazuh Poller started — Kafka: {KAFKA_SERVERS}")

while True:
    poll_alerts()
    time.sleep(KAFKA_POLL_INTERVAL)

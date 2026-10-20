import json
import time
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda m: json.dumps(m).encode('utf-8')
)

# High severity + varied rule_id per event so normalizer's dedup doesn't collapse them
# This drives up the frequency/port-diversity proxy features fed to Isolation Forest
for i in range(30):
    producer.send('raw-alerts', {
        "id": f"anom-extreme-{i}",
        "rule": {"id": 90000 + i, "description": "unusual traffic pattern", "level": 10},
        "agent": {"name": "linux-victim"},
        "data": {"srcip": "192.168.1.252", "dstport": 9000 + i}
    })

producer.flush()
print("Sent 30 high-severity varied-rule events from 192.168.1.252 — check for is_anomaly: true")
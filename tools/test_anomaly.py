# tools/test_anomaly.py
import json, time
from kafka import KafkaProducer

producer = KafkaProducer(bootstrap_servers='localhost:9092',
                          value_serializer=lambda m: json.dumps(m).encode('utf-8'))

# Send 20 events fast from same IP with an unmapped rule (no keyword match)
for i in range(20):
    producer.send('raw-alerts', {
        "id": f"anom-test-{i}",
        "rule": {"id": 99999, "description": "unusual traffic pattern", "level": 3},
        "agent": {"name": "linux-victim"},
        "data": {"srcip": "192.168.1.250", "dstport": 8000 + i}
    })
producer.flush()
print("Sent burst — check detection-engine logs for anomaly flags")
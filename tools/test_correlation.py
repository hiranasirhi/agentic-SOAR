import json
import time
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda m: json.dumps(m).encode('utf-8')
)

# Three distinct MITRE tactics from the SAME source_ip, spaced a few seconds apart
sequence = [
    {"id": "corr-1", "rule": {"id": 100200, "description": "Port scanning detected", "level": 5},
     "agent": {"name": "linux-victim"}, "data": {"srcip": "192.168.1.99"}},          # T1046 Discovery
    {"id": "corr-2", "rule": {"id": 5710, "description": "SSH brute force authentication failed", "level": 8},
     "agent": {"name": "linux-victim"}, "data": {"srcip": "192.168.1.99"}},          # T1110 Credential Access
    {"id": "corr-3", "rule": {"id": 100300, "description": "Reverse shell command execution", "level": 10},
     "agent": {"name": "linux-victim"}, "data": {"srcip": "192.168.1.99"}},          # T1059 Execution
]

for s in sequence:
    producer.send('raw-alerts', s)
    producer.flush()
    print(f"Sent {s['id']} (rule {s['rule']['id']})")
    time.sleep(2)

print("Done — check incidents topic for shared correlation_id on events 2 and 3")
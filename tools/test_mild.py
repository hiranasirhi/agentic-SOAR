# tools/test_mild.py
import json
from kafka import KafkaProducer

producer = KafkaProducer(bootstrap_servers='localhost:9092',
                          value_serializer=lambda m: json.dumps(m).encode('utf-8'))

producer.send('raw-alerts', {
    "id": "mild-retest",
    "rule": {"id": 99998, "description": "unusual traffic pattern", "level": 3},
    "agent": {"name": "linux-victim"},
    "data": {"srcip": "192.168.1.253", "dstport": 5000}
})
producer.flush()
print("Mild single event sent")
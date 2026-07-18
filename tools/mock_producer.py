import json
import time
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda m: json.dumps(m).encode('utf-8')
)

fake_wazuh_alert = {
    "id": "test-alert-001",
    "rule": {
        "id": 5710,
        "description": "SSH brute force authentication failed",
        "level": 8
    },
    "agent": {
        "name": "linux-victim"
    },
    "data": {
        "srcip": "192.168.1.200",
        "srcuser": "root"
    }
}

producer.send('raw-alerts', fake_wazuh_alert)
producer.flush()
print("Fake alert sent to raw-alerts topic")
import json
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda m: json.dumps(m).encode('utf-8')
)

event = {
    "id": "test-cred",
    "rule": {
        "id": 5402,
        "description": "Credential dumping via lsass access",
        "level": 9
    },
    "agent": {"name": "win-victim"},
    "data": {"srcip": "192.168.1.30"}
}

producer.send('raw-alerts', event)
producer.flush()
print("Test event sent to raw-alerts")
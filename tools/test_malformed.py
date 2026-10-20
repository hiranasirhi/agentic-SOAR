import json
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda m: json.dumps(m).encode('utf-8')
)

# No 'rule' or 'agent' keys — normalizer's detect_source() will return 'unknown'
producer.send('raw-alerts', {"garbage": "no rule or agent fields", "random": 123})
producer.flush()
print("Malformed event sent — check failed-events topic and Postgres incidents table")
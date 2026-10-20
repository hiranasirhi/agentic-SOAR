import json

from kafka import KafkaConsumer

from writer import write_event
from config import KAFKA_BROKER, KAFKA_TOPIC

consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=KAFKA_BROKER,
    auto_offset_reset="latest",
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

print("ES Writer started...")

for message in consumer:

    event = message.value

    response = write_event(event)

    print(
      f"Stored {event['event_id']} "
    f"-> {response['_id']}"
)
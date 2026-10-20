import os
from dotenv import load_dotenv

load_dotenv()

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "100.71.186.0:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "enriched-events")

ELASTIC_HOST = os.getenv("ELASTICSEARCH_URL")
ELASTIC_USER = os.getenv("ELASTICSEARCH_USER")
ELASTIC_PASS = os.getenv("ELASTICSEARCH_PASS")

INDEX_NAME = "soar-events"
print("HOST:", ELASTIC_HOST)
print("USER:", ELASTIC_USER)
print("PASS:", ELASTIC_PASS)
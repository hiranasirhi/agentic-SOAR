import json
import os
import sys
import time
import psycopg2
from datetime import datetime

sys.path.insert(0, '/app')
sys.stdout.reconfigure(line_buffering=True)

from dotenv import load_dotenv
load_dotenv()

from kafka import KafkaConsumer

KAFKA_SERVERS = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:29092')

print("Dead Letter Queue handler starting...")

def wait_for_kafka(servers, retries=10, delay=5):
    from kafka import KafkaConsumer
    for i in range(retries):
        try:
            c = KafkaConsumer(bootstrap_servers=servers, consumer_timeout_ms=3000)
            c.close()
            print("Kafka ready")
            return True
        except Exception as e:
            print(f"Waiting for Kafka {i+1}/{retries}: {e}")
            time.sleep(delay)
    return False

def get_db():
    return psycopg2.connect(
        host=os.getenv('POSTGRES_HOST', 'postgres'),
        port=os.getenv('POSTGRES_PORT', 5432),
        dbname=os.getenv('POSTGRES_DB', 'soar_db'),
        user=os.getenv('POSTGRES_USER', 'soar_user'),
        password=os.getenv('POSTGRES_PASSWORD', 'soar_password123')
    )

wait_for_kafka(KAFKA_SERVERS)

consumer = KafkaConsumer(
    'failed-events',
    bootstrap_servers=KAFKA_SERVERS,
    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
    group_id='dlq-handler-group',
    auto_offset_reset='earliest'
)

print("DLQ handler listening on failed-events topic")

for message in consumer:
    event = message.value
    print(f"Failed event received: {json.dumps(event)[:200]}")
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO incidents (incident_id, status, raw_event, created_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (incident_id) DO NOTHING
        """, (
            f"dlq-{message.offset}-{message.partition}",
            'failed',
            json.dumps(event),
            datetime.utcnow()
        ))
        conn.commit()
        cur.close()
        conn.close()
        print(f"Failed event logged to PostgreSQL")
    except Exception as e:
        print(f"DB error logging failed event: {e}")
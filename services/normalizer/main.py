import json
import hashlib
import os
import time
import sys
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.path.insert(0, '/app')

from dotenv import load_dotenv
load_dotenv()

KAFKA_SERVERS = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:29092')
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
DEDUP_WINDOW = 60

print(f"Starting normalizer...")
print(f"Kafka servers: {KAFKA_SERVERS}")
print(f"Redis host: {REDIS_HOST}:{REDIS_PORT}")

# Wait for Kafka to be ready with retry logic
def wait_for_kafka(servers, max_retries=10, delay=5):
    from kafka import KafkaConsumer
    
    for attempt in range(max_retries):
        try:
            print(f"Attempting Kafka connection {attempt + 1}/{max_retries}...")
            test_consumer = KafkaConsumer(
                bootstrap_servers=servers,
                consumer_timeout_ms=5000
            )
            test_consumer.close()
            print("Kafka connection successful")
            return True
        except Exception as e:
            print(f"Kafka not ready: {e}")
            if attempt < max_retries - 1:
                print(f"Waiting {delay} seconds before retry...")
                time.sleep(delay)
    return False

# Wait for Redis to be ready
def wait_for_redis(host, port, max_retries=10, delay=5):
    import redis
    for attempt in range(max_retries):
        try:
            print(f"Attempting Redis connection {attempt + 1}/{max_retries}...")
            r = redis.Redis(host=host, port=port, decode_responses=True)
            r.ping()
            print("Redis connection successful")
            return True
        except Exception as e:
            print(f"Redis not ready: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
    return False

# Wait for both services
if not wait_for_kafka(KAFKA_SERVERS):
    print("ERROR: Could not connect to Kafka after all retries. Exiting.")
    sys.exit(1)

if not wait_for_redis(REDIS_HOST, REDIS_PORT):
    print("ERROR: Could not connect to Redis after all retries. Exiting.")
    sys.exit(1)

# Now import and initialize everything
from kafka import KafkaConsumer, KafkaProducer
import redis

consumer = KafkaConsumer(
    'raw-alerts',
    bootstrap_servers=KAFKA_SERVERS,
    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
    group_id='normalizer-group',
    auto_offset_reset='earliest',
    enable_auto_commit=True
)

producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVERS,
    value_serializer=lambda m: json.dumps(m, default=str).encode('utf-8')
)

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

print("Normalizer fully started — listening on raw-alerts topic")

def detect_source(raw_event):
    if 'rule' in raw_event and 'agent' in raw_event:
        return 'wazuh'
    elif 'event_type' in raw_event:
        return 'suricata'
    else:
        return 'unknown'

def parse_wazuh(raw_event):
    return {
        'event_id': str(raw_event.get('id', f'evt-{time.time()}')),
        'timestamp': datetime.utcnow().isoformat(),
        'source_ip': raw_event.get('data', {}).get('srcip', '0.0.0.0'),
        'destination_ip': raw_event.get('data', {}).get('dstip'),
        'rule_id': str(raw_event.get('rule', {}).get('id', '')),
        'rule_description': raw_event.get('rule', {}).get('description', ''),
        'severity': min(int(raw_event.get('rule', {}).get('level', 1)), 10),
        'hostname': raw_event.get('agent', {}).get('name'),
        'username': raw_event.get('data', {}).get('srcuser'),
        'event_source': 'wazuh',
        'asset_criticality': 'medium',
        'raw_log': raw_event
    }

def parse_suricata(raw_event):
    return {
        'event_id': str(raw_event.get('flow_id', f'evt-{time.time()}')),
        'timestamp': datetime.utcnow().isoformat(),
        'source_ip': raw_event.get('src_ip', '0.0.0.0'),
        'destination_ip': raw_event.get('dest_ip'),
        'source_port': raw_event.get('src_port'),
        'destination_port': raw_event.get('dest_port'),
        'protocol': raw_event.get('proto'),
        'rule_id': str(raw_event.get('alert', {}).get('signature_id', '')),
        'rule_description': raw_event.get('alert', {}).get('signature', ''),
        'severity': 5,
        'event_source': 'suricata',
        'asset_criticality': 'medium',
        'raw_log': raw_event
    }

def deduplicate(source_ip, rule_id):
    fingerprint = hashlib.sha256(f"{source_ip}:{rule_id}".encode()).hexdigest()
    key = f"dedup:{fingerprint}"
    if r.exists(key):
        return True
    r.setex(key, DEDUP_WINDOW, '1')
    return False

def normalize(raw_event):
    source = detect_source(raw_event)
    if source == 'wazuh':
        return parse_wazuh(raw_event)
    elif source == 'suricata':
        return parse_suricata(raw_event)
    return None

for message in consumer:
    raw_event = message.value
    try:
        normalized = normalize(raw_event)

        if normalized is None:
            producer.send('failed-events', raw_event)
            print(f"Unknown format sent to failed-events")
            continue

        if deduplicate(normalized['source_ip'], normalized['rule_id']):
            print(f"Duplicate dropped: {normalized['source_ip']}:{normalized['rule_id']}")
            continue

        producer.send('normalized-events', normalized)
        print(f"Normalized: {normalized['source_ip']} → {normalized['rule_description']}")

    except Exception as e:
        print(f"Error: {e}")
        try:
            producer.send('failed-events', raw_event)
        except:
            pass
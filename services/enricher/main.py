import json
import os
import requests
from datetime import datetime
from kafka import KafkaConsumer, KafkaProducer
import redis
from dotenv import load_dotenv

load_dotenv()

import sys
sys.stdout.reconfigure(line_buffering=True)

sys.path.append('/app')
from shared.models import IncidentEvent
from shared.constants import TOPIC_NORMALIZED, TOPIC_ENRICHED

consumer = KafkaConsumer(
    TOPIC_NORMALIZED,
    bootstrap_servers=os.getenv('KAFKA_BOOTSTRAP_SERVERS'),
    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
    group_id='enricher-group',
    auto_offset_reset='earliest'
)

producer = KafkaProducer(
    bootstrap_servers=os.getenv('KAFKA_BOOTSTRAP_SERVERS'),
    value_serializer=lambda m: json.dumps(m, default=str).encode('utf-8')
)

r = redis.Redis(
    host=os.getenv('REDIS_HOST'),
    port=int(os.getenv('REDIS_PORT')),
    decode_responses=True
)

# --- Load MITRE keyword map and asset inventory from file instead of hardcoding ---
with open('/app/mitre_map.json') as f:
    MITRE_KEYWORD_MAP = json.load(f)   # {"brute": "T1110", "scan": "T1046", ...}

with open('/app/assets.json') as f:
    ASSETS = json.load(f)              # {"192.168.1.10": {"criticality": ..., "hostname": ..., "department": ...}}

MITRE_TACTICS = {
    'T1110': 'Credential Access',
    'T1046': 'Discovery',
    'T1068': 'Privilege Escalation',
    'T1059': 'Execution',
    'T1059.001': 'Execution',
    'T1021': 'Lateral Movement',
    'T1041': 'Exfiltration',
    'T1003': 'Credential Access',
    'T1565': 'Impact',
    'T1053': 'Persistence',
}

def get_mitre_mapping(rule_description: str) -> dict:
    """Best-effort keyword tag from rule description.
    This is only a hint — Detection Engine re-derives the authoritative
    technique from rule_id in Phase 3, so this doesn't need to be exhaustive."""
    desc_lower = rule_description.lower()
    for keyword, technique in MITRE_KEYWORD_MAP.items():
        if keyword in desc_lower:
            return {'technique': technique, 'tactic': MITRE_TACTICS.get(technique)}
    return {}

def get_asset_info(ip: str) -> dict:
    return ASSETS.get(ip, {'criticality': 'low', 'hostname': None, 'department': None})

def get_geo(ip: str) -> dict:
    """Simple GeoIP using free API — replace with MaxMind offline later"""
    cache_key = f"geo:{ip}"
    cached = r.get(cache_key)
    if cached:
        return json.loads(cached)
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        result = {
            'geo_country': data.get('country'),
            'geo_city': data.get('city')
        }
        r.setex(cache_key, 3600, json.dumps(result))
        return result
    except:
        return {}

print("Enricher started — listening on normalized-events topic")

for message in consumer:
    event_dict = message.value
    
    try:
        mitre = get_mitre_mapping(event_dict.get('rule_description', ''))
        geo = get_geo(event_dict.get('source_ip', ''))
        asset = get_asset_info(event_dict.get('source_ip', ''))
        
        event_dict['mitre_technique'] = mitre.get('technique')
        event_dict['mitre_tactic'] = mitre.get('tactic')

        if asset.get('criticality'):
            event_dict['asset_criticality'] = asset['criticality']
        # else: keep normalizer's existing value instead of overwriting

        if not event_dict.get('hostname'):
            event_dict['hostname'] = asset.get('hostname')
        if not event_dict.get('user_department'):
            event_dict['user_department'] = asset.get('department')

        event_dict['geo_country'] = geo.get('geo_country')
        event_dict['geo_city'] = geo.get('geo_city')
        
        producer.send(TOPIC_ENRICHED, event_dict)
        print(
            f"Enriched:"
            f" rule={event_dict.get('rule_id')}"
            f" desc={event_dict.get('rule_description')}"
            f" mitre={event_dict.get('mitre_technique')}"
        )        

    except Exception as e:
        print(f"Enrichment error: {e}")
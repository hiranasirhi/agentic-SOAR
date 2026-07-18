import json
import os
import requests
from datetime import datetime
from kafka import KafkaConsumer, KafkaProducer
import redis
from dotenv import load_dotenv

load_dotenv()

import sys
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

# MITRE technique to tactic mapping
MITRE_MAP = {
    'T1110': {'technique': 'T1110', 'tactic': 'Credential Access', 'name': 'Brute Force'},
    'T1046': {'technique': 'T1046', 'tactic': 'Discovery', 'name': 'Network Service Scanning'},
    'T1059': {'technique': 'T1059', 'tactic': 'Execution', 'name': 'Command and Scripting Interpreter'},
    'T1068': {'technique': 'T1068', 'tactic': 'Privilege Escalation', 'name': 'Exploitation for Privilege Escalation'},
    'T1021': {'technique': 'T1021', 'tactic': 'Lateral Movement', 'name': 'Remote Services'},
    'T1565': {'technique': 'T1565', 'tactic': 'Impact', 'name': 'Data Manipulation'},
    'T1003': {'technique': 'T1003', 'tactic': 'Credential Access', 'name': 'OS Credential Dumping'},
    'T1041': {'technique': 'T1041', 'tactic': 'Exfiltration', 'name': 'Exfiltration Over C2 Channel'},
}

# Asset criticality mapping
ASSETS = {
    '192.168.1.10': 'critical',
    '192.168.1.20': 'high',
}

def get_mitre_mapping(rule_description: str) -> dict:
    """Match rule description to MITRE technique"""
    desc_lower = rule_description.lower()
    
    if 'brute' in desc_lower or 'authentication failed' in desc_lower:
        return MITRE_MAP['T1110']
    elif 'scan' in desc_lower or 'port' in desc_lower:
        return MITRE_MAP['T1046']
    elif 'privilege' in desc_lower or 'sudo' in desc_lower:
        return MITRE_MAP['T1068']
    elif 'shell' in desc_lower or 'command' in desc_lower:
        return MITRE_MAP['T1059']
    
    return {}

def get_asset_criticality(ip: str) -> str:
    return ASSETS.get(ip, 'low')

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
        
        event_dict['mitre_technique'] = mitre.get('technique')
        event_dict['mitre_tactic'] = mitre.get('tactic')
        event_dict['asset_criticality'] = get_asset_criticality(
            event_dict.get('source_ip', '')
        )
        event_dict['geo_country'] = geo.get('geo_country')
        event_dict['geo_city'] = geo.get('geo_city')
        
        producer.send(TOPIC_ENRICHED, event_dict)
        print(f"Enriched: {event_dict.get('source_ip')} → {mitre.get('tactic', 'Unknown tactic')}")
        
    except Exception as e:
        print(f"Enrichment error: {e}")
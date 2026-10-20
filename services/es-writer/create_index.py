from elasticsearch import Elasticsearch
from config import ELASTIC_HOST, INDEX_NAME

es = Elasticsearch(ELASTIC_HOST)

mapping = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "source_ip": {"type": "ip"},
            "destination_ip": {"type": "ip"},
            "severity": {"type": "integer"},
            "hostname": {"type": "keyword"},
            "username": {"type": "keyword"},
            "geo_country": {"type": "keyword"},
            "geo_city": {"type": "keyword"},
            "asset_criticality": {"type": "keyword"},
            "mitre_technique": {"type": "keyword"},
            "mitre_tactic": {"type": "keyword"},
            "rule_id": {"type": "keyword"},
            "event_source": {"type": "keyword"}
        }
    }
}

if not es.indices.exists(index=INDEX_NAME):
    es.indices.create(index=INDEX_NAME, body=mapping)
    print(f"{INDEX_NAME} created")
else:
    print(f"{INDEX_NAME} already exists")
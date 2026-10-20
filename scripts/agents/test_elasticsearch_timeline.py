from opensearchpy import OpenSearch
from dotenv import load_dotenv
import urllib3
import os

load_dotenv()
urllib3.disable_warnings()

client = OpenSearch(
    hosts=[{
        "host": "100.98.120.36",
        "port": 9200
    }],
    http_auth=(
        os.getenv("ELASTICSEARCH_USER"),
        os.getenv("ELASTICSEARCH_PASS")
    ),
    use_ssl=True,
    verify_certs=False
)

print("=" * 60)
print("TEST 1 - Connection")
print("=" * 60)

try:
    info = client.info()
    print("Connected!")
    print(info["cluster_name"])
except Exception as e:
    print(e)
    exit()

print("\n" + "=" * 60)
print("TEST 2 - Indices")
print("=" * 60)

indices = client.cat.indices(format="json")

for idx in indices:
    name = idx["index"]
    if "wazuh" in name or "soar" in name:
        print(name)

print("\n" + "=" * 60)
print("TEST 3 - soar-events count")
print("=" * 60)

count = client.count(index="soar-events")

print(count)

print("\n" + "=" * 60)
print("TEST 4 - Sample document")
print("=" * 60)

result = client.search(
    index="soar-events",
    body={
        "size": 1,
        "query": {
            "match_all": {}
        }
    }
)

doc = result["hits"]["hits"][0]["_source"]

print("Fields:\n")

for key, value in doc.items():
    print(f"{key}: {value}")

print("\n" + "=" * 60)
print("TEST 5 - Timeline query")
print("=" * 60)

TEST_IP = "0.0.0.0"      # Replace with any source_ip from Test 4

result = client.search(
    index="soar-events",
    body={
        "query": {
            "term": {
                "source_ip.keyword": TEST_IP
            }
        },
        "sort": [
            {
                "timestamp": {
                    "order": "asc"
                }
            }
        ],
        "size": 10
    }
)

hits = result["hits"]["hits"]

print(f"\nFound {len(hits)} events\n")

for hit in hits:
    e = hit["_source"]

    print(
        f"{e['timestamp']} | "
        f"{e['rule_description']} | "
        f"{e['severity']}"
    )

print("\nAll tests complete.")
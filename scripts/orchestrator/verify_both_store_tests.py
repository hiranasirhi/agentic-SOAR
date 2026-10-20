from orchestrator.memory import incidents_collection

for incident_id in [
    "STORE-TEST-001",
    "STORE-TEST-NULL-001"
]:
    data = incidents_collection.get(
        ids=[incident_id],
        include=["metadatas", "documents"]
    )

    print()
    print("INCIDENT:", incident_id)
    print("IDS:", data["ids"])
    print("METADATA:", data["metadatas"])
    print("DOCUMENTS:", data["documents"])

from orchestrator.memory import incidents_collection

data = incidents_collection.get(
    ids=["STORE-TEST-001"],
    include=["metadatas", "documents"]
)

print("IDS:", data["ids"])
print("METADATA:", data["metadatas"])
print("DOCUMENTS:", data["documents"])

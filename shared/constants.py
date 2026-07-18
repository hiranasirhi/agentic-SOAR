# Kafka Topics
TOPIC_RAW_ALERTS = "raw-alerts"
TOPIC_NORMALIZED = "normalized-events"
TOPIC_ENRICHED = "enriched-events"
TOPIC_INCIDENTS = "incidents"
TOPIC_FAILED = "failed-events"

# Redis Key Patterns
REDIS_AGENT_HEARTBEAT = "agent:{name}:heartbeat"
REDIS_DEDUP_PREFIX = "dedup:"
REDIS_INCIDENT_CONTEXT = "incident:{id}:context"

# Agent Names
AGENT_TRIAGE = "triage"
AGENT_INVESTIGATION = "investigation"
AGENT_RESPONSE = "response"
AGENT_CONTAINMENT = "containment"
AGENT_NOTIFICATION = "notification"
AGENT_LEARNING = "learning"

# Severity Levels
SEVERITY_LOW = range(1, 4)
SEVERITY_MEDIUM = range(4, 7)
SEVERITY_HIGH = range(7, 10)
SEVERITY_CRITICAL = 10

# Timeouts
AGENT_HEARTBEAT_TTL = 30        # seconds
AGENT_HEARTBEAT_INTERVAL = 10   # seconds
DEDUP_WINDOW = 60               # seconds
KAFKA_POLL_INTERVAL = 10        # seconds
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(255) UNIQUE NOT NULL,
    source_ip VARCHAR(50),
    mitre_technique VARCHAR(50),
    severity INTEGER,
    status VARCHAR(50) DEFAULT 'open',
    created_at TIMESTAMP DEFAULT NOW(),
    closed_at TIMESTAMP,
    raw_event JSONB
);

CREATE TABLE IF NOT EXISTS metrics (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(255) REFERENCES incidents(incident_id),
    mttd_seconds FLOAT,
    mttr_seconds FLOAT,
    false_positive BOOLEAN DEFAULT FALSE,
    agent_sequence TEXT[],
    recorded_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_actions (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(255),
    agent_name VARCHAR(100),
    action VARCHAR(255),
    success BOOLEAN,
    output JSONB,
    executed_at TIMESTAMP DEFAULT NOW()
);
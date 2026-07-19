-- Incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(255) UNIQUE NOT NULL,
    source_ip VARCHAR(50),
    destination_ip VARCHAR(50),
    mitre_technique VARCHAR(50),
    mitre_tactic VARCHAR(100),
    severity INTEGER,
    asset_criticality VARCHAR(50),
    hostname VARCHAR(255),
    username VARCHAR(255),
    event_source VARCHAR(50),
    status VARCHAR(50) DEFAULT 'open',
    false_positive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    closed_at TIMESTAMP,
    raw_event JSONB
);

-- Metrics table for MTTD and MTTR tracking
CREATE TABLE IF NOT EXISTS metrics (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(255) REFERENCES incidents(incident_id),
    attack_start_time TIMESTAMP,
    detection_time TIMESTAMP,
    response_start_time TIMESTAMP,
    response_complete_time TIMESTAMP,
    mttd_seconds FLOAT,
    mttr_seconds FLOAT,
    false_positive BOOLEAN DEFAULT FALSE,
    agent_sequence TEXT[],
    llm_reasoning TEXT,
    recorded_at TIMESTAMP DEFAULT NOW()
);

-- Agent actions table
CREATE TABLE IF NOT EXISTS agent_actions (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(255),
    agent_name VARCHAR(100),
    action VARCHAR(255),
    success BOOLEAN,
    output JSONB,
    error_message TEXT,
    executed_at TIMESTAMP DEFAULT NOW()
);

-- False positive patterns table
CREATE TABLE IF NOT EXISTS false_positive_patterns (
    id SERIAL PRIMARY KEY,
    source_ip VARCHAR(50),
    rule_id VARCHAR(50),
    mitre_technique VARCHAR(50),
    fp_count INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT NOW()
);

-- Rule tuning recommendations
CREATE TABLE IF NOT EXISTS rule_tuning (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(50),
    recommendation TEXT,
    incident_count INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Self healing events log
CREATE TABLE IF NOT EXISTS healing_events (
    id SERIAL PRIMARY KEY,
    agent_name VARCHAR(100),
    event_type VARCHAR(100),
    docker_exit_code INTEGER,
    log_summary TEXT,
    recovery_time_seconds FLOAT,
    recovered_at TIMESTAMP DEFAULT NOW()
);
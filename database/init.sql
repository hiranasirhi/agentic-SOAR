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

CREATE TABLE IF NOT EXISTS expected_state (
    id SERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL,
    check_type TEXT NOT NULL,          -- 'ufw_rule' | 'inter_vm_ping' | 'ldap_account'
    target TEXT NOT NULL,              -- VM name or username
    expected_value JSONB NOT NULL,     -- e.g. {"rule": "deny from 1.2.3.4"}
    created_at TIMESTAMP DEFAULT NOW(),
    verified_at TIMESTAMP,
    last_check_ok BOOLEAN,
    last_check_reason TEXT
);

-- Run this once against the existing PostgreSQL instance (same DB as healing_events, expected_state).
-- psql -h <postgres-host> -U <user> -d <db> -f evaluation_schema.sql

CREATE TABLE IF NOT EXISTS evaluation_runs (
    id SERIAL PRIMARY KEY,
    run_batch_id TEXT NOT NULL,          -- groups one full pass (all 12 scenarios, one mode) together
    mode TEXT NOT NULL,                  -- 'full' | 'baseline'
    scenario_id TEXT NOT NULL,           -- matches scenarios.py SCENARIOS[].id
    environment TEXT NOT NULL,           -- 'linux' | 'windows'
    expected_technique TEXT NOT NULL,    -- ground truth, e.g. 'T1110'
    attack_fired_at TIMESTAMP NOT NULL,
    incident_id TEXT,
    incident_detected_at TIMESTAMP,
    detected_technique TEXT,
    mttd_seconds FLOAT,
    response_completed_at TIMESTAMP,
    mttr_seconds FLOAT,
    outcome TEXT NOT NULL,               -- 'detected' | 'missed' | 'wrong_technique' | 'error'
    raw_result JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_eval_runs_batch ON evaluation_runs (run_batch_id);
CREATE INDEX IF NOT EXISTS idx_eval_runs_mode ON evaluation_runs (mode);

CREATE TABLE IF NOT EXISTS baseline_dispatch_log (
    id SERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL,
    technique TEXT,
    agent TEXT NOT NULL,
    action TEXT NOT NULL,
    dispatched_at TIMESTAMP DEFAULT NOW()
);

-- NOTE: healing_events already exists (created by the Watchdog component) with this shape —
-- included here ONLY as a reference so measure_self_healing.py's query makes sense.
-- Do NOT re-run this if it already exists; IF NOT EXISTS makes it a no-op either way.
CREATE TABLE IF NOT EXISTS healing_events (
    id SERIAL PRIMARY KEY,
    agent_name VARCHAR(100),
    event_type VARCHAR(100),
    docker_exit_code INTEGER,
    log_summary TEXT,
    recovery_time_seconds FLOAT,
    recovered_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS postmortems (
    id SERIAL PRIMARY KEY,
    incident_id TEXT UNIQUE NOT NULL,
    report TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
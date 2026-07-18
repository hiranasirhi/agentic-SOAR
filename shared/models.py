from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict, Any

class IncidentEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    rule_id: str
    rule_description: str
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    severity: int                          # 1-10
    asset_criticality: str                 # low / medium / high / critical
    hostname: Optional[str] = None
    username: Optional[str] = None
    user_department: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    event_source: str                      # wazuh / suricata / ufw
    raw_log: Dict[str, Any]
    tags: List[str] = []

class TaskPlan(BaseModel):
    incident_id: str
    agent_sequence: List[str]
    actions: List[Dict[str, Any]]
    approval_required: bool
    severity: int
    reasoning_summary: str

class AgentResult(BaseModel):
    task_id: str
    agent_name: str
    success: bool
    output: Dict[str, Any]
    error_message: Optional[str] = None
    timestamp: datetime
import json
import time
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda m: json.dumps(m).encode('utf-8')
)

SCENARIOS = [
    {"name": "Linux SSH Brute Force (T1110)", "event":
        {"id": "s1", "rule": {"id": 5710, "description": "SSH brute force authentication failed", "level": 8},
         "agent": {"name": "linux-victim"}, "data": {"srcip": "10.0.0.1"}}},
    {"name": "Linux Port Scanning (T1046)", "event":
        {"id": "s2", "rule": {"id": 100200, "description": "Port scanning detected", "level": 5},
         "agent": {"name": "linux-victim"}, "data": {"srcip": "10.0.0.2"}}},
    {"name": "Linux Privilege Escalation via Sudo (T1068)", "event":
        {"id": "s3", "rule": {"id": 5401, "description": "Sudo privilege escalation attempt", "level": 9},
         "agent": {"name": "linux-victim"}, "data": {"srcip": "10.0.0.3"}}},
    {"name": "Linux Reverse Shell (T1059)", "event":
        {"id": "s4", "rule": {"id": 100300, "description": "Reverse shell command execution", "level": 10},
         "agent": {"name": "linux-victim"}, "data": {"srcip": "10.0.0.4"}}},
    {"name": "Linux File Integrity Violation (T1565)", "event":
        {"id": "s5", "rule": {"id": 553, "description": "File integrity tamper detected", "level": 7},
         "agent": {"name": "linux-victim"}, "data": {"srcip": "10.0.0.5"}}},
    {"name": "Linux Lateral Movement (T1021)", "event":
        {"id": "s6", "rule": {"id": 100400, "description": "Remote lateral movement detected", "level": 8},
         "agent": {"name": "linux-victim"}, "data": {"srcip": "10.0.0.6"}}},
    {"name": "Windows RDP Brute Force (T1110)", "event":
        {"id": "s7", "rule": {"id": 5711, "description": "RDP brute force authentication failed", "level": 8},
         "agent": {"name": "win-victim"}, "data": {"srcip": "10.0.0.7"}}},
    {"name": "Windows PowerShell Abuse (T1059.001)", "event":
        {"id": "s8", "rule": {"id": 100301, "description": "Malicious powershell script execution", "level": 9},
         "agent": {"name": "win-victim"}, "data": {"srcip": "10.0.0.8"}}},
    {"name": "Windows Privilege Escalation (T1068)", "event":
        {"id": "s9", "rule": {"id": 5402, "description": "Windows privilege escalation attempt", "level": 9},
         "agent": {"name": "win-victim"}, "data": {"srcip": "10.0.0.9"}}},
    {"name": "Windows Persistence (T1053)", "event":
        {"id": "s10", "rule": {"id": 100600, "description": "Persistence via scheduled task", "level": 7},
         "agent": {"name": "win-victim"}, "data": {"srcip": "10.0.0.10"}}},
    {"name": "Windows Credential Dumping / LSASS (T1003)", "event":
        {"id": "s11", "rule": {"id": 5403, "description": "Credential dumping via lsass access", "level": 9},
         "agent": {"name": "win-victim"}, "data": {"srcip": "10.0.0.11"}}},
    {"name": "Windows Data Exfiltration (T1041)", "event":
        {"id": "s12", "rule": {"id": 100500, "description": "Suspicious outbound data exfiltration", "level": 8},
         "agent": {"name": "win-victim"}, "data": {"srcip": "10.0.0.12"}}},
]

for s in SCENARIOS:
    producer.send('raw-alerts', s['event'])
    print(f"Sent: {s['name']}")
    time.sleep(1)

producer.flush()
print("\nAll 12 scenarios sent — check incidents topic and cross-reference against expected MITRE techniques")
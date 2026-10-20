# seed_chromadb.py
# Run this ONCE before evaluation begins
# Pre-seeds ChromaDB with 25 synthetic historical incidents

from orchestrator.memory import store_incident, store_false_positive, get_memory_stats

print("="*60)
print("PROTEGO ChromaDB Pre-Seeding Script")
print("Seeding 25 synthetic historical incidents...")
print("="*60)

# ============================================
# 25 SYNTHETIC INCIDENTS
# Covering all 6 attack types
# Mix of outcomes: contained, FP, escalated
# ============================================

synthetic_incidents = [

    # ---- SSH BRUTE FORCE (T1110) ---- 5 incidents
    {
        "id": "HIST-001",
        "timeline": (
            "Attacker from Russian IP performed port scan at T+0 targeting port 22. "
            "Eight minutes later initiated SSH brute force with 47 failed attempts against admin account. "
            "Successful login achieved at T+24 minutes using valid credentials. "
            "Outcome: IP blocked via UFW, admin account disabled, host isolated. "
            "Resolution: 18 minutes. Confirmed malicious."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 18,
        "false_positive": False,
        "notes": "TI confidence 0.82. APT activity suspected."
    },
    {
        "id": "HIST-002",
        "timeline": (
            "Multiple rapid SSH login attempts from internal IP 10.0.0.45 on admin account. "
            "47 attempts in 2 minutes. Pattern consistent with automated script. "
            "Analyst review: FALSE POSITIVE. "
            "Legitimate admin running automated deployment script every Monday morning. "
            "Resolution: 3 minutes after analyst review."
        ),
        "outcome": "FALSE_POSITIVE",
        "resolution_time": 3,
        "false_positive": True,
        "notes": "Whitelist deployment script source IP to prevent recurrence."
    },
    {
        "id": "HIST-003",
        "timeline": (
            "External IP performed SSH brute force with 120 attempts over 15 minutes. "
            "No successful login achieved. "
            "Suricata detected scanning signatures in network traffic. "
            "IP blocked at firewall. Incident contained without compromise. "
            "Resolution: 5 minutes. Automated block applied."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 5,
        "false_positive": False,
        "notes": "No successful login. Preemptive block applied."
    },
    {
        "id": "HIST-004",
        "timeline": (
            "SSH brute force on service account from Chinese IP. "
            "Failed attempts followed by successful authentication at T+45 minutes. "
            "Attacker immediately ran privilege escalation commands. "
            "Multi-stage attack confirmed. Human approval requested for destructive actions. "
            "Analyst approved. All 4 systems in blast radius contained. "
            "Resolution: 14 minutes including approval wait time."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 14,
        "false_positive": False,
        "notes": "Severity 10. Required human approval. Lateral movement to 3 systems."
    },
    {
        "id": "HIST-005",
        "timeline": (
            "Low-rate SSH brute force: 1 attempt every 10 minutes over 3 hours. "
            "Evaded threshold-based detection initially. "
            "Isolation Forest anomaly detection flagged behavioral pattern. "
            "No successful login. Source IP blocked preemptively. "
            "Resolution: 8 minutes after ML detection."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 8,
        "false_positive": False,
        "notes": "Slow brute force evading rules. ML detection caught it."
    },

    # ---- PORT SCAN (T1046) ---- 4 incidents
    {
        "id": "HIST-006",
        "timeline": (
            "Network scan detected from external IP 203.0.113.5 at T+0. "
            "Suricata detected 150 port probe signatures in 60 seconds. "
            "Ports 22, 80, 443, 3306, 5432, 8080 probed. "
            "No exploitation followed. IP blocked preventively. "
            "Resolution: 3 minutes. Monitoring only response."
        ),
        "outcome": "MONITORED",
        "resolution_time": 3,
        "false_positive": False,
        "notes": "Reconnaissance only. No follow-up attack."
    },
    {
        "id": "HIST-007",
        "timeline": (
            "Port scan from security team IP during authorized penetration test. "
            "Alert fired on scanning signatures. "
            "FALSE POSITIVE: authorized pen test activity. "
            "Incident closed immediately after verification with IT team. "
            "Resolution: 2 minutes."
        ),
        "outcome": "FALSE_POSITIVE",
        "resolution_time": 2,
        "false_positive": True,
        "notes": "Add pen test schedule to exception list."
    },
    {
        "id": "HIST-008",
        "timeline": (
            "Port scan at T+0 followed by targeted brute force at T+12 minutes. "
            "Same source IP. Reconnaissance then exploitation pattern. "
            "Multi-stage kill chain: Discovery then Credential Access. "
            "Attacker used scan results to target open SSH port specifically. "
            "IP blocked across all systems. Resolution: 10 minutes."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 10,
        "false_positive": False,
        "notes": "Classic recon-to-exploit pattern. Kill chain correlated."
    },
    {
        "id": "HIST-009",
        "timeline": (
            "Slow port scan over 2 hours from rotating source IPs. "
            "Distributed scanning evading single-IP thresholds. "
            "Suricata correlated distributed scan pattern. "
            "Network segment blocked. Notified ISP about scanning infrastructure. "
            "Resolution: 20 minutes."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 20,
        "false_positive": False,
        "notes": "Distributed scan. Multiple source IPs coordinating."
    },

    # ---- PRIVILEGE ESCALATION (T1068) ---- 4 incidents
    {
        "id": "HIST-010",
        "timeline": (
            "Non-admin user john.doe executed sudo command at T+0. "
            "Attempted to access /etc/shadow file. "
            "Wazuh FIM detected unauthorized access attempt. "
            "User account suspended immediately. "
            "Investigation showed john.doe credentials had been compromised. "
            "Resolution: 7 minutes."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 7,
        "false_positive": False,
        "notes": "Compromised standard user attempting privilege escalation."
    },
    {
        "id": "HIST-011",
        "timeline": (
            "IT admin jane.smith executed sudo for legitimate system maintenance. "
            "Wazuh flagged privileged command execution. "
            "FALSE POSITIVE: authorized maintenance during scheduled window. "
            "Incident closed after verification with IT manager. "
            "Resolution: 4 minutes."
        ),
        "outcome": "FALSE_POSITIVE",
        "resolution_time": 4,
        "false_positive": True,
        "notes": "Add maintenance windows to suppression rules."
    },
    {
        "id": "HIST-012",
        "timeline": (
            "Privilege escalation via sudo NOPASSWD misconfiguration at T+0. "
            "Attacker gained root access within 30 seconds. "
            "Immediately modified /etc/crontab for persistence at T+2 minutes. "
            "Wazuh FIM detected crontab modification. "
            "Host isolated, crontab restored from backup. "
            "Resolution: 12 minutes including forensic preservation."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 12,
        "false_positive": False,
        "notes": "sudo misconfiguration exploited. Config hardened post-incident."
    },
    {
        "id": "HIST-013",
        "timeline": (
            "Privilege escalation following successful SSH brute force. "
            "Multi-stage: Credential Access then Privilege Escalation. "
            "Attacker progressed from standard user to root in 8 minutes. "
            "Severity 10 triggered. Human approval requested and received. "
            "All escalation paths blocked. Root cause: weak password policy. "
            "Resolution: 16 minutes."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 16,
        "false_positive": False,
        "notes": "Multi-stage attack. Password policy updated post-incident."
    },

    # ---- FILE INTEGRITY VIOLATION (T1565) ---- 4 incidents
    {
        "id": "HIST-014",
        "timeline": (
            "Wazuh FIM detected modification to /etc/passwd at T+0. "
            "New user account 'backdoor' added with UID 0. "
            "Attacker had already compromised system and added persistence. "
            "Backdoor account removed, system audited for other modifications. "
            "Resolution: 22 minutes including full system audit."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 22,
        "false_positive": False,
        "notes": "Persistence mechanism. Full forensic investigation required."
    },
    {
        "id": "HIST-015",
        "timeline": (
            "FIM alert on /etc/hosts file modification. "
            "FALSE POSITIVE: legitimate configuration change by sysadmin. "
            "Change was planned and documented in change management system. "
            "Incident closed after verification. "
            "Resolution: 2 minutes."
        ),
        "outcome": "FALSE_POSITIVE",
        "resolution_time": 2,
        "false_positive": True,
        "notes": "Exclude change management approved changes from FIM alerts."
    },
    {
        "id": "HIST-016",
        "timeline": (
            "FIM detected /etc/crontab modification adding reverse shell. "
            "Scheduled task to phone home every 5 minutes created. "
            "Wazuh correlated FIM alert with subsequent outbound connection. "
            "Crontab entry removed, outbound connection blocked. "
            "Source of initial compromise under investigation. "
            "Resolution: 11 minutes."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 11,
        "false_positive": False,
        "notes": "Persistence via cron. Initial compromise vector: web app."
    },
    {
        "id": "HIST-017",
        "timeline": (
            "Multiple FIM alerts across 3 systems simultaneously. "
            "Same files modified: /etc/hosts, /etc/resolv.conf. "
            "DNS hijacking attempt to redirect traffic. "
            "Lateral movement confirmed: attacker on multiple hosts. "
            "Network segmented, all affected hosts isolated. "
            "Resolution: 19 minutes for all 3 systems."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 19,
        "false_positive": False,
        "notes": "DNS hijacking. Multi-host compromise detected via correlated FIM."
    },

    # ---- REVERSE SHELL (T1059) ---- 4 incidents
    {
        "id": "HIST-018",
        "timeline": (
            "Suspicious outbound connection from python3 process to external IP on port 4444. "
            "Suricata detected reverse shell signature in network traffic. "
            "Wazuh detected python3 with -c flag spawned by web server process. "
            "Web application exploitation confirmed. "
            "Process killed, web app patched, IP blocked. "
            "Resolution: 9 minutes."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 9,
        "false_positive": False,
        "notes": "Web app RCE exploited. Python reverse shell via web server."
    },
    {
        "id": "HIST-019",
        "timeline": (
            "Outbound connection to port 1337 from developer laptop. "
            "FALSE POSITIVE: developer testing netcat for legitimate network debugging. "
            "Verified with developer and team lead. "
            "Added developer testing subnet to suppression rules. "
            "Resolution: 5 minutes."
        ),
        "outcome": "FALSE_POSITIVE",
        "resolution_time": 5,
        "false_positive": True,
        "notes": "Developer tools triggering reverse shell signatures. Add exception."
    },
    {
        "id": "HIST-020",
        "timeline": (
            "Reverse shell established after successful privilege escalation. "
            "Attacker progression: port scan → brute force → priv esc → reverse shell. "
            "Full kill chain completed. Attacker had interactive terminal access. "
            "Severity 10. Human approval obtained. "
            "Host isolated, all network paths blocked. Forensic image taken. "
            "Resolution: 21 minutes including forensic preservation."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 21,
        "false_positive": False,
        "notes": "Complete kill chain. Full forensic investigation conducted."
    },
    {
        "id": "HIST-021",
        "timeline": (
            "Netcat reverse shell from database server to attacker IP. "
            "Attacker pivoted from compromised web server to database. "
            "Lateral movement detected: web server to database server. "
            "Both systems isolated simultaneously. "
            "Database credentials rotated immediately. "
            "Resolution: 13 minutes."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 13,
        "false_positive": False,
        "notes": "Lateral movement via database access. Both hosts isolated."
    },

    # ---- LATERAL MOVEMENT (T1021) ---- 4 incidents
    {
        "id": "HIST-022",
        "timeline": (
            "Compromised admin account accessed 4 systems via SSH within 10 minutes. "
            "Starting from web server, pivoting to database, backup, and monitoring systems. "
            "Wazuh correlated login events across all 4 systems to same source account. "
            "Account disabled across all systems. All 4 systems isolated. "
            "Resolution: 16 minutes for full containment."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 16,
        "false_positive": False,
        "notes": "Widespread lateral movement. Account as pivot mechanism."
    },
    {
        "id": "HIST-023",
        "timeline": (
            "Admin accessing multiple systems for legitimate patch deployment. "
            "Wazuh detected same account accessing 6 systems in rapid succession. "
            "FALSE POSITIVE: authorized patch deployment by IT team. "
            "Verified with IT manager. Scheduled maintenance window missed from calendar. "
            "Resolution: 6 minutes."
        ),
        "outcome": "FALSE_POSITIVE",
        "resolution_time": 6,
        "false_positive": True,
        "notes": "Patch deployment looks like lateral movement. Add maintenance calendar."
    },
    {
        "id": "HIST-024",
        "timeline": (
            "Lateral movement from DMZ server to internal network. "
            "Attacker breached perimeter via web application, then pivoted inward. "
            "Internal systems accessed: file server, HR database, finance system. "
            "Severity 10. Data exfiltration risk. Human approval for isolation obtained. "
            "Network segmented at DMZ boundary. "
            "Resolution: 25 minutes. Possible data exposure under investigation."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 25,
        "false_positive": False,
        "notes": "DMZ breach. High data exposure risk. Regulatory notification required."
    },
    {
        "id": "HIST-025",
        "timeline": (
            "Service account used for lateral movement after credential theft. "
            "Service account accessed systems it does not normally access. "
            "Behavior anomaly detected by Isolation Forest. "
            "Service account disabled. Password rotated across all systems. "
            "Source of credential theft: phishing email on admin workstation. "
            "Resolution: 14 minutes."
        ),
        "outcome": "CONTAINED",
        "resolution_time": 14,
        "false_positive": False,
        "notes": "Service account abuse via phishing. Credential hygiene review needed."
    }
]

# ============================================
# SEED ALL INCIDENTS
# ============================================

print(f"\nSeeding {len(synthetic_incidents)} incidents into ChromaDB...\n")

success_count = 0
fp_count = 0

for incident in synthetic_incidents:
    result = store_incident(
        incident_id=incident["id"],
        behavioral_timeline=incident["timeline"],
        outcome=incident["outcome"],
        resolution_time_minutes=incident["resolution_time"],
        false_positive=incident["false_positive"],
        notes=incident["notes"]
    )
    
    if result:
        success_count += 1
    
    # Also store FPs in false_positives collection
    if incident["false_positive"]:
        store_false_positive(
            incident_id=incident["id"],
            behavioral_pattern=incident["timeline"],
            reason=incident["notes"]
        )
        fp_count += 1

print(f"\n{'='*60}")
print(f"Pre-seeding complete!")
print(f"Incidents stored: {success_count}/{len(synthetic_incidents)}")
print(f"False positive patterns stored: {fp_count}")
print(f"{'='*60}")

# Show final stats
from orchestrator.memory import get_memory_stats
stats = get_memory_stats()
print(f"\nFinal ChromaDB state:")
print(f"  incidents collection: {stats['incidents_count']} records")
print(f"  false_positives collection: {stats['false_positives_count']} records")
print(f"\nChromaDB is ready for evaluation!")
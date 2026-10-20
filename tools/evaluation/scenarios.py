"""
Table 10.1 — the 12 planned attack scenarios, as ground truth for the
evaluation harness and the P/R/F1 script.

`atomic_test` follows the Invoke-AtomicRedTeam convention: `Invoke-AtomicTest
<technique> -TestNumber <n>`. This assumes PowerShell (pwsh on Linux,
native on Windows) + the Invoke-AtomicRedTeam module are ALREADY INSTALLED
on both victim VMs — that's a one-time environment setup step, not part of
this deliverable. TestNumber values below are placeholders (1 = commonly the
first/simplest test for that technique) — run
`Invoke-AtomicTest <technique> -ShowDetailsBrief` on each victim first and
swap in the test numbers that actually match what you want to demonstrate
(e.g. you may want a specific test number for the RDP brute-force vs the
SSH brute-force, since T1110 appears on both platforms with different
sub-tests).
"""

SCENARIOS = [
    {
        "id": "linux_ssh_bruteforce",
        "environment": "linux",
        "technique": "T1110",
        "description": "SSH Brute Force Attack",
        "atomic_test": "Invoke-AtomicTest T1110 -TestNumber 1",
        "host_env_var": "LINUX_VICTIM_HOST",
    },
    {
        "id": "linux_port_scan",
        "environment": "linux",
        "technique": "T1046",
        "description": "Port Scanning / Reconnaissance",
        "atomic_test": "Invoke-AtomicTest T1046 -TestNumber 1",
        "host_env_var": "LINUX_VICTIM_HOST",
    },
    {
        "id": "linux_sudo_privesc",
        "environment": "linux",
        "technique": "T1068",
        "description": "Privilege Escalation via Sudo Abuse",
        "atomic_test": "Invoke-AtomicTest T1068 -TestNumber 1",
        "host_env_var": "LINUX_VICTIM_HOST",
    },
    {
        "id": "linux_reverse_shell",
        "environment": "linux",
        "technique": "T1059",
        "description": "Reverse Shell / Remote Command Execution",
        "atomic_test": "Invoke-AtomicTest T1059 -TestNumber 1",
        "host_env_var": "LINUX_VICTIM_HOST",
    },
    {
        "id": "linux_file_tampering",
        "environment": "linux",
        "technique": "T1565",
        "description": "File Integrity Violation / Critical File Tampering",
        "atomic_test": "Invoke-AtomicTest T1565 -TestNumber 1",
        "host_env_var": "LINUX_VICTIM_HOST",
    },
    {
        "id": "linux_lateral_movement",
        "environment": "linux",
        "technique": "T1021",
        "description": "Lateral Movement (Linux Remote Access)",
        "atomic_test": "Invoke-AtomicTest T1021 -TestNumber 1",
        "host_env_var": "LINUX_VICTIM_HOST",
    },
    {
        "id": "windows_rdp_bruteforce",
        "environment": "windows",
        "technique": "T1110",
        "description": "RDP Brute Force Attack",
        "atomic_test": "Invoke-AtomicTest T1110 -TestNumber 2",
        "host_env_var": "WINDOWS_VICTIM_HOST",
    },
    {
        "id": "windows_powershell_abuse",
        "environment": "windows",
        "technique": "T1059.001",
        "description": "PowerShell Abuse / Malicious Script Execution",
        "atomic_test": "Invoke-AtomicTest T1059.001 -TestNumber 1",
        "host_env_var": "WINDOWS_VICTIM_HOST",
    },
    {
        "id": "windows_privesc",
        "environment": "windows",
        "technique": "T1068",
        "description": "Windows Privilege Escalation",
        "atomic_test": "Invoke-AtomicTest T1068 -TestNumber 2",
        "host_env_var": "WINDOWS_VICTIM_HOST",
    },
    {
        "id": "windows_persistence",
        "environment": "windows",
        "technique": "T1053",
        "description": "Persistence via Scheduled Tasks / Registry Run Keys",
        "atomic_test": "Invoke-AtomicTest T1053 -TestNumber 1",
        "host_env_var": "WINDOWS_VICTIM_HOST",
    },
    {
        "id": "windows_credential_dumping",
        "environment": "windows",
        "technique": "T1003",
        "description": "Credential Dumping / LSASS Access",
        "atomic_test": "Invoke-AtomicTest T1003 -TestNumber 1",
        "host_env_var": "WINDOWS_VICTIM_HOST",
    },
    {
        "id": "windows_data_exfil",
        "environment": "windows",
        "technique": "T1041",
        "description": "Data Exfiltration / Suspicious Outbound Transfer",
        "atomic_test": "Invoke-AtomicTest T1041 -TestNumber 1",
        "host_env_var": "WINDOWS_VICTIM_HOST",
    },
]

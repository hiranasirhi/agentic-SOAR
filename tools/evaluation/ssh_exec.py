"""
Remote execution helpers for the evaluation harness — mirrors the
_ssh_run() pattern already established in your Watchdog (mod03), so the
whole project uses one consistent remote-exec convention.

Linux victim: plain SSH + pwsh -Command "<atomic_test>"
Windows victim: SSH is assumed available too (OpenSSH Server for Windows is
commonly installed on lab Windows boxes specifically to keep tooling
consistent — if you're using WinRM instead, swap run_on_windows()'s body
for pywinrm; the calling code in harness.py doesn't care which transport
is used as long as this function returns (exit_status, stdout, stderr)).
"""

import os
import paramiko

SSH_KEY_PATH = os.environ["SSH_KEY_PATH"]
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
SSH_TIMEOUT_SECONDS = int(os.environ.get("SSH_TIMEOUT_SECONDS", "30"))
SSH_USER = os.environ.get("SSH_USER", "atomicred")


def _ssh_run(host: str, user: str, command: str, timeout: int = SSH_TIMEOUT_SECONDS):
    """Run a single command on a remote host over SSH. Returns (exit_status, stdout, stderr)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, username=user, key_filename=SSH_KEY_PATH,
            port=SSH_PORT, timeout=timeout,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return exit_status, out, err
    finally:
        client.close()


def run_atomic_test(host: str, atomic_test: str, environment: str):
    """Runs `pwsh -Command "<atomic_test>"` on the target victim.
    Requires PowerShell + Invoke-AtomicRedTeam pre-installed on the victim —
    see scenarios.py docstring."""
    command = f'pwsh -NoProfile -Command "{atomic_test}"'
    exit_status, out, err = _ssh_run(host, SSH_USER, command)
    return {
        "exit_status": exit_status,
        "stdout": out[-2000:],
        "stderr": err[-2000:],
        "environment": environment,
    }

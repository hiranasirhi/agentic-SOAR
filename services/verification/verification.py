# verification/verification.py
#
# ASSUMPTIONS:
#   1. Response/Containment agents INSERT into an `expected_state`
#      Postgres table when they act (schema below). This is a
#      coordination item with whoever builds those agents (Person C) -
#      until they write to it, this service has nothing to check and
#      will just log "no records found".
#   2. VM inventory comes from VM_INVENTORY (env var, JSON).
#   3. LDAP is stubbed - fill in real ldap3 logic or leave disabled.

import json
import os
import time
import traceback
from datetime import datetime

import paramiko
import psycopg2
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
POSTGRES_DSN = os.getenv("POSTGRES_DSN", "dbname=protego user=protego password=protego host=localhost port=5432")
VERIFY_INTERVAL_SECONDS = int(os.getenv("VERIFY_INTERVAL_SECONDS", "10"))
VERIFY_LDAP = os.getenv("VERIFY_LDAP", "false").lower() == "true"
VM_INVENTORY = json.loads(os.getenv("VM_INVENTORY", "[]"))
DRIFT_ALERT_CHANNEL = "alerts:drift_detected"
# How long to keep verifying after the incident closes. Must exceed 15 min
# so the T+15 check still runs if the plan finishes early.
VERIFY_GRACE_SECONDS = int(os.getenv("VERIFY_GRACE_SECONDS", "1200"))
# After the 3 scheduled checks (T+0, T+5, T+15), re-check this often while active.
VERIFY_RECHECK_SECONDS = int(os.getenv("VERIFY_RECHECK_SECONDS", "300"))

redis_client = redis.Redis(
    host=REDIS_HOST, port=REDIS_PORT, decode_responses=True,
    socket_connect_timeout=5, socket_timeout=5, retry_on_timeout=True,
)


def _ssh_exec(vm: dict, command: str, timeout: int = 15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=vm["host"], username=vm["ssh_user"],
                        key_filename=vm.get("ssh_key_path"), timeout=timeout)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode() + stderr.read().decode()
        return exit_status == 0, output
    except Exception as e:
        return False, str(e)
    finally:
        client.close()


def _find_vm(vm_name: str):
    return next((vm for vm in VM_INVENTORY if vm["name"] == vm_name), None)

MONITOR_VM_NAME = os.getenv("MONITOR_VM_NAME", "")

def check_host_isolation(agent_id: str) -> dict:
    isolated_vm = next((vm for vm in VM_INVENTORY if vm.get("agent_id") == agent_id), None)
    if not isolated_vm:
        return {"ok": False, "reason": f"agent_id '{agent_id}' not found in VM_INVENTORY — no known IP to ping"}

    monitor_vm = _find_vm(MONITOR_VM_NAME)
    if not monitor_vm:
        return {"ok": False, "reason": f"MONITOR_VM_NAME '{MONITOR_VM_NAME}' not found in VM_INVENTORY"}

    success, output = _ssh_exec(monitor_vm, f"ping -c 2 -W 3 {isolated_vm['host']}")
    is_isolated = not success  # ping should FAIL if isolation is working
    return {"ok": is_isolated,
            "reason": "host unreachable, isolation confirmed" if is_isolated else
                      "host is STILL REACHABLE - drift detected",
            "raw_output": output}

def check_ufw_rule(vm_name: str, malicious_ip: str) -> dict:
    vm = _find_vm(vm_name)
    if not vm:
        return {"ok": False, "reason": f"VM '{vm_name}' not in VM_INVENTORY"}
    success, output = _ssh_exec(vm, "sudo ufw status")
    if not success:
        return {"ok": False, "reason": f"SSH/command failed: {output}"}
    rule_present = bool(malicious_ip) and malicious_ip in output
    return {"ok": rule_present,
            "reason": "rule present" if rule_present else "rule MISSING - drift detected",
            "raw_output": output}


def check_process_killed(vm_name: str, pid, process_name: str) -> dict:
    vm = _find_vm(vm_name)
    if not vm:
        return {"ok": False, "reason": f"VM '{vm_name}' not in VM_INVENTORY"}
    command = f"ps -p {pid}" if pid else f"pgrep -f '{process_name}'"
    success, output = _ssh_exec(vm, command)
    still_running = success  # exit 0 means the process IS still running
    return {"ok": not still_running,
            "reason": "process confirmed killed" if not still_running else
                      "process is STILL RUNNING - drift detected",
            "raw_output": output}

def check_inter_vm_ping(from_vm_name: str, target_ip: str, expect_reachable: bool) -> dict:
    vm = _find_vm(from_vm_name)
    if not vm:
        return {"ok": False, "reason": f"VM '{from_vm_name}' not in VM_INVENTORY"}
    success, output = _ssh_exec(vm, f"ping -c 2 -W 3 {target_ip}")
    matches = (success == expect_reachable)
    return {"ok": matches,
            "reason": "matches expected reachability" if matches else
                      f"expected reachable={expect_reachable}, actual={success} - drift detected",
            "raw_output": output}


def check_ldap_account_status(username: str, expected_disabled: bool) -> dict:
    if not VERIFY_LDAP:
        return {"ok": None, "reason": "LDAP verification disabled (VERIFY_LDAP=false) - not verified"}
    # TODO: real ldap3 query once AD details are known.
    return {"ok": None, "reason": "LDAP check not yet implemented - not verified"}

def fetch_active_expected_states() -> list:
    """
    Rows due for a check, for incidents that are still active.

    Active = not closed, OR closed less than VERIFY_GRACE_SECONDS ago.
    Stopping is based on closed_at only. Status 'learned' must NOT stop
    verification, because the Learning Agent can finish before T+15.

    Schedule (relative to when the action was recorded):
      check 1 -> immediately, check 2 -> T+5 min, check 3 -> T+15 min,
      then every VERIFY_RECHECK_SECONDS while the incident is active.
    """
    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT es.id, es.incident_id, es.check_type, es.target,
                       es.expected_value, es.created_at, es.check_count,
                       i.status AS incident_status
                FROM expected_state es
                JOIN incidents i ON i.incident_id = es.incident_id
                WHERE (i.closed_at IS NULL
                       OR i.closed_at > NOW() - (%(grace)s * INTERVAL '1 second'))
                  AND NOW() >= CASE
                        WHEN es.check_count = 0 THEN es.created_at
                        WHEN es.check_count = 1 THEN es.created_at + INTERVAL '5 minutes'
                        WHEN es.check_count = 2 THEN es.created_at + INTERVAL '15 minutes'
                        ELSE COALESCE(es.verified_at, es.created_at)
                             + (%(recheck)s * INTERVAL '1 second')
                      END
                ORDER BY es.created_at
            """, {"grace": VERIFY_GRACE_SECONDS, "recheck": VERIFY_RECHECK_SECONDS})
            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in rows]
    finally:
        conn.close()

def record_verification_result(expected_state_id: int, ok, reason: str):
    """
    ok: True (passed), False (drift), or None (could not verify).
    Uses the database clock (NOW()) so timestamps are comparable with
    incidents.created_at when computing MTTR.
    """
    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE expected_state
                SET verified_at       = NOW(),
                    last_check_ok     = %s,
                    last_check_reason = %s,
                    check_count       = check_count + 1,
                    first_verified_at = CASE WHEN %s IS NOT NULL
                                             THEN COALESCE(first_verified_at, NOW())
                                             ELSE first_verified_at END,
                    first_ok_at       = CASE WHEN %s IS TRUE
                                             THEN COALESCE(first_ok_at, NOW())
                                             ELSE first_ok_at END
                WHERE id = %s
            """, (ok, reason, ok, ok, expected_state_id))
            conn.commit()
    finally:
        conn.close()


def run_verification_cycle():
    try:
        expected_states = fetch_active_expected_states()
    except Exception as e:
        print(f"[VERIFICATION] Could not fetch expected_state rows: {e}")
        return

    if not expected_states:
        return  # quiet: this loop now polls every few seconds

    for row in expected_states:
        check_type = row["check_type"]
        target = row["target"]
        incident_id = row["incident_id"]

        # psycopg2 returns JSONB as a dict already; only parse if it's a string
        ev = row["expected_value"]
        expected_value = json.loads(ev) if isinstance(ev, str) else (ev or {})

        try:
            if check_type == "ufw_rule":
                result = check_ufw_rule(target, expected_value.get("malicious_ip", ""))
            elif check_type == "host_isolation":
                result = check_host_isolation(target)
            elif check_type == "account_disabled":
                result = check_ldap_account_status(target, expected_value.get("disabled", True))
            elif check_type == "process_killed":
                result = check_process_killed(target, expected_value.get("pid"),
                                              expected_value.get("process_name", ""))
            else:
                result = {"ok": None, "reason": f"Unknown check_type '{check_type}' - not verified"}
        except Exception as e:
            result = {"ok": None, "reason": f"check raised an exception: {e}"}

        # Persist the result FIRST. MTTR depends on this write.
        try:
            record_verification_result(row["id"], result["ok"], result["reason"])
        except Exception as e:
            print(f"[VERIFICATION] Could not record result for expected_state {row['id']}: {e}")

        check_no = row["check_count"] + 1
        if result["ok"] is False:
            print(f"[VERIFICATION] DRIFT DETECTED (check #{check_no}): incident={incident_id} "
                  f"check={check_type} target={target} reason={result['reason']}")
            try:
                redis_client.publish(DRIFT_ALERT_CHANNEL, json.dumps({
                    "incident_id": incident_id, "check_type": check_type, "target": target,
                    "reason": result["reason"], "detected_at": datetime.now().isoformat(),
                }))
            except Exception as e:
                print(f"[VERIFICATION] Could not publish drift alert: {e}")
        elif result["ok"] is None:
            print(f"[VERIFICATION] SKIPPED (check #{check_no}): incident={incident_id} "
                  f"check={check_type} target={target} reason={result['reason']}")
        else:
            print(f"[VERIFICATION] OK (check #{check_no}): incident={incident_id} "
                  f"check={check_type} target={target}")


def run_verification_loop():
    print(f"Idempotent Verification starting. Poll={VERIFY_INTERVAL_SECONDS}s "
          f"grace={VERIFY_GRACE_SECONDS}s VMs={len(VM_INVENTORY)}")
    if not VM_INVENTORY:
        print("[VERIFICATION] WARNING: VM_INVENTORY is empty - UFW/ping checks will fail.")

    while True:
        cycle_start = time.time()
        try:
            run_verification_cycle()
        except Exception:
            print("[VERIFICATION] Unhandled error:")
            traceback.print_exc()
        time.sleep(max(0, VERIFY_INTERVAL_SECONDS - (time.time() - cycle_start)))


if __name__ == "__main__":
    run_verification_loop()
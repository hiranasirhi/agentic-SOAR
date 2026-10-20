# agents/response_agent.py

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import paramiko
import requests
from dotenv import load_dotenv
from ldap3 import ALL, MODIFY_REPLACE, Connection, Server

from agents.base_agent import BaseAgent

from shared.constants import (
    AGENT_RESPONSE,
    REDIS_INCIDENT_CONTEXT,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)

from shared.models import (
    AgentResult,
    Incident,
    TaskPlan,
)


load_dotenv()


class ResponseAgent(BaseAgent):

    def __init__(self):

        super().__init__(AGENT_RESPONSE)

        # ========================================================
        # SSH CONFIG
        # ========================================================

        self.ssh_user = os.getenv(
            "VM_SSH_USER",
            "ubuntu"
        )

        self.ssh_key_path = os.getenv(
            "VM_SSH_KEY_PATH",
            "~/.ssh/id_rsa"
        )

        self.ssh_password = os.getenv(
            "VM_SSH_PASSWORD",
            ""
        )

        # ========================================================
        # WAZUH API
        # ========================================================
        #
        # IMPORTANT:
        # Wazuh Manager API is normally port 55000.
        #
        # 9200 = OpenSearch / Elasticsearch
        # 55000 = Wazuh Manager API
        #
        # ========================================================

        self.wazuh_url = os.getenv(
            "WAZUH_URL",
            "https://localhost:55000"
        ).rstrip("/")

        self.wazuh_user = os.getenv(
            "WAZUH_API_USER",
            "wazuh"
        )

        self.wazuh_pass = os.getenv(
            "WAZUH_API_PASS",
            "wazuh"
        )

        # ========================================================
        # ACTIVE DIRECTORY / SAMBA
        # ========================================================

        self.ad_server = os.getenv(
            "AD_SERVER",
            ""
        )

        self.ad_user = os.getenv(
            "AD_BIND_USER",
            ""
        )

        self.ad_pass = os.getenv(
            "AD_BIND_PASS",
            ""
        )

        self.ad_base_dn = os.getenv(
            "AD_BASE_DN",
            "dc=lab,dc=local"
        )

        # ========================================================
        # ORCHESTRATOR
        # ========================================================

        self.orchestrator_url = os.getenv(
            "ORCHESTRATOR_URL",
            "http://localhost:8000"
        ).rstrip("/")

        # ========================================================
        # PRIVATE IP RANGES
        # ========================================================

        self.private_ranges = [
            "10.",
            "192.168.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "127.",
            "localhost"
        ]

        print(f"[{AGENT_RESPONSE}] Initialized")
        print(
            f"[{AGENT_RESPONSE}] "
            f"Wazuh URL: {self.wazuh_url}"
        )

    # ============================================================
    # APPROVAL GATE
    # ============================================================

    def check_approval(
        self,
        task_plan: TaskPlan
    ) -> bool:

        if not task_plan.approval_required:
            return True

        incident_id = task_plan.incident_id

        print(
            f"[{AGENT_RESPONSE}] "
            f"Checking approval for incident "
            f"{incident_id} "
            f"(severity={task_plan.severity})"
        )

        max_wait = 600
        poll_interval = 15
        waited = 0

        while waited < max_wait:

            try:

                response = requests.get(
                    f"{self.orchestrator_url}"
                    f"/incidents/{incident_id}"
                    f"/approval_status",
                    timeout=10
                )

                if response.status_code != 200:

                    print(
                        f"[{AGENT_RESPONSE}] "
                        f"Approval endpoint returned "
                        f"{response.status_code}"
                    )

                    time.sleep(poll_interval)
                    waited += poll_interval
                    continue

                status = response.json().get(
                    "approval_status",
                    "pending"
                )

                if status == "approved":

                    print(
                        f"[{AGENT_RESPONSE}] "
                        f"APPROVED — proceeding"
                    )

                    return True

                if status == "rejected":

                    print(
                        f"[{AGENT_RESPONSE}] "
                        f"REJECTED — standing down"
                    )

                    return False

                print(
                    f"[{AGENT_RESPONSE}] "
                    f"Waiting for approval... "
                    f"({waited}s elapsed)"
                )

            except Exception as e:

                print(
                    f"[{AGENT_RESPONSE}] "
                    f"Approval check error: {e}"
                )

            time.sleep(poll_interval)
            waited += poll_interval

        print(
            f"[{AGENT_RESPONSE}] "
            f"Approval timeout after "
            f"{max_wait}s — standing down"
        )

        return False

    # ============================================================
    # PRIVATE IP CHECK
    # ============================================================

    def is_private_ip(
        self,
        ip: str
    ) -> bool:

        if not ip:
            return False

        for prefix in self.private_ranges:

            if ip.startswith(prefix):
                return True

        return False

    # ============================================================
    # BLOCK IP
    # ============================================================

    def block_ip(
        self,
        target_vm_ip: str,
        malicious_ip: str
    ) -> dict:

        if self.is_private_ip(malicious_ip):

            return {
                "action": "block_ip",
                "success": False,
                "error": (
                    f"REJECTED: {malicious_ip} "
                    f"is a private IP range."
                ),
                "malicious_ip": malicious_ip,
                "target_vm": target_vm_ip
            }

        print(
            f"[{AGENT_RESPONSE}] "
            f"Blocking IP {malicious_ip} "
            f"on {target_vm_ip}"
        )

        ssh = paramiko.SSHClient()

        ssh.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        try:

            key_path = os.path.expanduser(
                self.ssh_key_path
            )

            if (
                self.ssh_key_path
                and os.path.exists(key_path)
            ):

                ssh.connect(
                    target_vm_ip,
                    username=self.ssh_user,
                    key_filename=key_path,
                    timeout=10
                )

            else:

                ssh.connect(
                    target_vm_ip,
                    username=self.ssh_user,
                    password=self.ssh_password,
                    timeout=10
                )

            command = (
                f"sudo ufw deny "
                f"from {malicious_ip} "
                f"to any"
            )

            stdin, stdout, stderr = (
                ssh.exec_command(command)
            )

            exit_code = (
                stdout.channel.recv_exit_status()
            )

            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()

            print(
                f"[{AGENT_RESPONSE}] "
                f"UFW command exit code: "
                f"{exit_code}"
            )

            if output:
                print(
                    f"[{AGENT_RESPONSE}] "
                    f"UFW output: {output}"
                )

            if error:
                print(
                    f"[{AGENT_RESPONSE}] "
                    f"UFW stderr: {error}"
                )

            # ----------------------------------------------------
            # VERIFY
            # ----------------------------------------------------

            stdin, stdout, stderr = (
                ssh.exec_command(
                    "sudo ufw status numbered"
                )
            )

            ufw_status = stdout.read().decode()

            rule_applied = (
                malicious_ip in ufw_status
            )

            if rule_applied:

                print(
                    f"[{AGENT_RESPONSE}] "
                    f"UFW rule verified — "
                    f"{malicious_ip} is blocked"
                )

                return {
                    "action": "block_ip",
                    "success": True,
                    "malicious_ip": malicious_ip,
                    "target_vm": target_vm_ip,
                    "verified": True,
                    "ufw_output": output
                }

            return {
                "action": "block_ip",
                "success": False,
                "error": (
                    "UFW command ran but "
                    "rule was not found"
                ),
                "malicious_ip": malicious_ip,
                "target_vm": target_vm_ip,
                "verified": False
            }

        except Exception as e:

            print(
                f"[{AGENT_RESPONSE}] "
                f"block_ip error: {e}"
            )

            return {
                "action": "block_ip",
                "success": False,
                "error": str(e),
                "malicious_ip": malicious_ip,
                "target_vm": target_vm_ip
            }

        finally:

            ssh.close()

    # ============================================================
    # WAZUH HOST ISOLATION
    # ============================================================

    def isolate_host(
        self,
        agent_id: str,
        incident_id: str
    ) -> dict:

        print(
            f"[{AGENT_RESPONSE}] "
            f"Isolating host via Wazuh agent "
            f"{agent_id}"
        )

        try:

            # ----------------------------------------------------
            # AUTHENTICATE
            # ----------------------------------------------------

            token_response = requests.post(
                f"{self.wazuh_url}"
                f"/security/user/authenticate",
                auth=(
                    self.wazuh_user,
                    self.wazuh_pass
                ),
                verify=False,
                timeout=10
            )

            if token_response.status_code != 200:

                return {
                    "action": "isolate_host",
                    "success": False,
                    "error": (
                        "Wazuh authentication failed: "
                        f"{token_response.status_code}"
                    )
                }

            token_data = token_response.json()

            token = (
                token_data
                .get("data", {})
                .get("token")
            )

            if not token:

                return {
                    "action": "isolate_host",
                    "success": False,
                    "error": (
                        "Wazuh authentication "
                        "returned no token"
                    )
                }

            headers = {
                "Authorization": f"Bearer {token}"
            }

            # ----------------------------------------------------
            # ACTIVE RESPONSE
            # ----------------------------------------------------

            ar_response = requests.put(
                f"{self.wazuh_url}"
                f"/active-response",
                headers=headers,
                json={
                    "command": "isolation",
                    "custom": False,
                    "arguments": [
                        incident_id
                    ],
                    "alert": {
                        "data": {
                            "srcip":
                                "isolation_triggered_by_protego"
                        }
                    }
                },
                params={
                    "agents_list": agent_id
                },
                verify=False,
                timeout=15
            )

            if ar_response.status_code in (200, 201):

                print(
                    f"[{AGENT_RESPONSE}] "
                    f"Host isolation command sent "
                    f"to agent {agent_id}"
                )

                try:
                    response_data = (
                        ar_response.json()
                    )
                except Exception:
                    response_data = (
                        ar_response.text
                    )

                return {
                    "action": "isolate_host",
                    "success": True,
                    "agent_id": agent_id,
                    "wazuh_response": response_data
                }

            return {
                "action": "isolate_host",
                "success": False,
                "error": (
                    "Active Response failed: "
                    f"{ar_response.status_code}"
                ),
                "response": ar_response.text
            }

        except Exception as e:

            print(
                f"[{AGENT_RESPONSE}] "
                f"isolate_host error: {e}"
            )

            return {
                "action": "isolate_host",
                "success": False,
                "error": str(e)
            }

    # ============================================================
    # DISABLE ACCOUNT
    # ============================================================

    def disable_account(
        self,
        username: str,
        ti_confidence: Optional[float]
    ) -> dict:

        if ti_confidence is not None:

            if ti_confidence < 0.5:

                return {
                    "action": "disable_account",
                    "success": False,
                    "error": (
                        f"REJECTED: TI confidence "
                        f"{ti_confidence} below 0.5"
                    ),
                    "username": username
                }

        else:

            return {
                "action": "disable_account",
                "success": False,
                "error": (
                    "REJECTED: Null TI confidence. "
                    "Mandatory escalation required."
                ),
                "username": username
            }

        if not self.ad_server:

            return {
                "action": "disable_account",
                "success": False,
                "error": (
                    "AD_SERVER is not configured"
                ),
                "username": username
            }

        print(
            f"[{AGENT_RESPONSE}] "
            f"Disabling account: {username}"
        )

        conn = None

        try:

            server = Server(
                self.ad_server,
                get_info=ALL
            )

            conn = Connection(
                server,
                user=self.ad_user,
                password=self.ad_pass,
                auto_bind=True
            )

            conn.search(
                self.ad_base_dn,
                f"(sAMAccountName={username})",
                attributes=[
                    "userAccountControl",
                    "distinguishedName"
                ]
            )

            if not conn.entries:

                return {
                    "action": "disable_account",
                    "success": False,
                    "error": (
                        f"User {username} "
                        f"not found in AD"
                    ),
                    "username": username
                }

            user_dn = (
                conn.entries[0]
                .distinguishedName.value
            )

            current_uac = (
                conn.entries[0]
                .userAccountControl.value
            )

            new_uac = current_uac | 0x0002

            conn.modify(
                user_dn,
                {
                    "userAccountControl": [
                        (
                            MODIFY_REPLACE,
                            [new_uac]
                        )
                    ]
                }
            )

            if conn.result["result"] != 0:

                return {
                    "action": "disable_account",
                    "success": False,
                    "error": (
                        f"LDAP modify failed: "
                        f"{conn.result}"
                    ),
                    "username": username
                }

            # ----------------------------------------------------
            # VERIFY ACCOUNT DISABLED
            # ----------------------------------------------------

            conn.search(
                self.ad_base_dn,
                f"(sAMAccountName={username})",
                attributes=[
                    "userAccountControl"
                ]
            )

            if not conn.entries:

                return {
                    "action": "disable_account",
                    "success": False,
                    "error": (
                        "Account disappeared "
                        "during verification"
                    ),
                    "username": username
                }

            verified_uac = (
                conn.entries[0]
                .userAccountControl.value
            )

            is_disabled = bool(
                verified_uac & 0x0002
            )

            print(
                f"[{AGENT_RESPONSE}] "
                f"Account {username} "
                f"disabled: {is_disabled}"
            )

            return {
                "action": "disable_account",
                "success": is_disabled,
                "username": username,
                "user_dn": user_dn,
                "verified_disabled": is_disabled
            }

        except Exception as e:

            print(
                f"[{AGENT_RESPONSE}] "
                f"disable_account error: {e}"
            )

            return {
                "action": "disable_account",
                "success": False,
                "error": str(e),
                "username": username
            }

        finally:

            if conn:

                try:
                    conn.unbind()
                except Exception:
                    pass

    # ============================================================
    # KILL PROCESS
    # ============================================================

    def kill_process(
        self,
        target_vm_ip: str,
        process_info: dict
    ) -> dict:

        pid = process_info.get("pid")

        process_name = process_info.get(
            "process_name",
            ""
        )

        print(
            f"[{AGENT_RESPONSE}] "
            f"Killing process on "
            f"{target_vm_ip}: "
            f"pid={pid} "
            f"name={process_name}"
        )

        ssh = paramiko.SSHClient()

        ssh.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        try:

            key_path = os.path.expanduser(
                self.ssh_key_path
            )

            if (
                self.ssh_key_path
                and os.path.exists(key_path)
            ):

                ssh.connect(
                    target_vm_ip,
                    username=self.ssh_user,
                    key_filename=key_path,
                    timeout=10
                )

            else:

                ssh.connect(
                    target_vm_ip,
                    username=self.ssh_user,
                    password=self.ssh_password,
                    timeout=10
                )

            if pid:

                command = (
                    f"sudo kill -9 {pid}"
                )

            elif process_name:

                command = (
                    f"sudo pkill -f "
                    f"'{process_name}'"
                )

            else:

                return {
                    "action": "kill_process",
                    "success": False,
                    "error": (
                        "No PID or process name "
                        "provided"
                    )
                }

            stdin, stdout, stderr = (
                ssh.exec_command(command)
            )

            exit_code = (
                stdout.channel
                .recv_exit_status()
            )

            # ----------------------------------------------------
            # VERIFY
            # ----------------------------------------------------

            if pid:

                check_cmd = (
                    f"ps -p {pid}"
                )

            else:

                check_cmd = (
                    f"pgrep -f "
                    f"'{process_name}'"
                )

            stdin, stdout, stderr = (
                ssh.exec_command(check_cmd)
            )

            check_output = (
                stdout.read()
                .decode()
                .strip()
            )

            process_killed = (
                len(check_output) == 0
            )

            print(
                f"[{AGENT_RESPONSE}] "
                f"Process killed: "
                f"{process_killed}"
            )

            return {
                "action": "kill_process",
                "success": process_killed,
                "pid": pid,
                "process_name": process_name,
                "verified_killed": process_killed,
                "exit_code": exit_code
            }

        except Exception as e:

            print(
                f"[{AGENT_RESPONSE}] "
                f"kill_process error: {e}"
            )

            return {
                "action": "kill_process",
                "success": False,
                "error": str(e)
            }

        finally:

            ssh.close()

    # ============================================================
    # TI CONFIDENCE
    # ============================================================

    def _get_ti_confidence(
        self,
        incident_id: str
    ) -> Optional[float]:

        try:

            key = REDIS_INCIDENT_CONTEXT.format(
                id=incident_id
            )

            context_data = (
                self.redis_client.get(key)
            )

            if context_data:

                context = json.loads(
                    context_data
                )

                value = context.get(
                    "ti_confidence"
                )

                if value is not None:

                    return float(value)

        except Exception as e:

            print(
                f"[{AGENT_RESPONSE}] "
                f"TI confidence lookup error: {e}"
            )

        return None

    # ============================================================
    # CONVERT DICT -> TASK PLAN
    # ============================================================

    def _build_task_plan(
        self,
        task: dict
    ) -> TaskPlan:

        """
        Convert the dictionary received from
        BaseAgent into the Pydantic TaskPlan model.

        This fixes:

            'dict' object has no attribute 'incident_id'
        """

        # The orchestrator may send either:
        #
        # {
        #     "task_id": "...",
        #     "incident_id": "...",
        #     "action": "disable_account",
        #     ...
        # }
        #
        # or a nested task-plan dictionary.
        #
        # We support both.

        plan_data = task.get(
            "task_plan"
        )

        if not plan_data:

            plan_data = task

        incident_id = (
            plan_data.get("incident_id")
            or task.get("incident_id")
        )

        actions = (
            plan_data.get("actions")
        )

        if actions is None:

            action = task.get(
                "action"
            )

            if action:

                actions = [
                    {
                        "action": action
                    }
                ]

            else:

                actions = []

        agent_sequence = (
            plan_data.get(
                "agent_sequence",
                [AGENT_RESPONSE]
            )
        )

        approval_required = bool(
            plan_data.get(
                "approval_required",
                task.get(
                    "approval_required",
                    False
                )
            )
        )

        severity = int(
            plan_data.get(
                "severity",
                task.get(
                    "severity",
                    0
                )
            )
        )

        reasoning_summary = (
            plan_data.get(
                "reasoning_summary",
                ""
            )
        )

        return TaskPlan(
            incident_id=incident_id,
            agent_sequence=agent_sequence,
            actions=actions,
            approval_required=approval_required,
            severity=severity,
            reasoning_summary=reasoning_summary
        )

    # ============================================================
    # CONVERT DICT -> INCIDENT
    # ============================================================

    def _build_incident(
        self,
        task: dict,
        incident_context: dict
    ) -> Incident:

        """
        Convert incident context dictionary
        into the Pydantic Incident model.
        """

        # Prefer explicit incident_context.
        data = dict(
            incident_context or {}
        )

        # If context doesn't contain incident_id,
        # get it from the task.

        if not data.get("incident_id"):

            data["incident_id"] = (
                task.get("incident_id")
            )

        # Some orchestrator implementations may put
        # the actual incident under "incident".

        nested_incident = task.get(
            "incident"
        )

        if isinstance(
            nested_incident,
            dict
        ):

            merged = dict(
                nested_incident
            )

            merged.update(data)

            data = merged

        # --------------------------------------------------------
        # Make sure optional collection fields exist
        # --------------------------------------------------------

        data.setdefault(
            "kill_chain_stages",
            []
        )

        data.setdefault(
            "correlated_event_ids",
            []
        )

        data.setdefault(
            "tags",
            []
        )

        data.setdefault(
            "fp_discount_applied",
            0
        )

        data.setdefault(
            "anomaly_score",
            None
        )

        data.setdefault(
            "is_anomaly",
            False
        )

        data.setdefault(
            "correlation_id",
            None
        )

        # --------------------------------------------------------
        # raw_log must be a dictionary
        # --------------------------------------------------------

        if not isinstance(
            data.get("raw_log"),
            dict
        ):

            data["raw_log"] = {}

        # --------------------------------------------------------
        # Some data may be supplied by the task itself.
        # --------------------------------------------------------

        if task.get("source_ip"):

            data.setdefault(
                "source_ip",
                task["source_ip"]
            )

        if task.get("destination_ip"):

            data.setdefault(
                "destination_ip",
                task["destination_ip"]
            )

        if task.get("username"):

            data.setdefault(
                "username",
                task["username"]
            )

        if task.get("severity") is not None:

            data.setdefault(
                "severity",
                task["severity"]
            )

        if task.get(
            "composite_severity"
        ) is not None:

            data.setdefault(
                "composite_severity",
                task["composite_severity"]
            )

        # --------------------------------------------------------
        # Validate through Pydantic
        # --------------------------------------------------------

        return Incident.model_validate(
            data
        )

    # ============================================================
    # EXECUTE TASK
    # ============================================================

    def execute_task(
        self,
        task: dict,
        incident_context: dict
    ) -> dict:

        """
        BaseAgent-compatible execute_task().

        IMPORTANT:
        BaseAgent passes dictionaries.

        We convert those dictionaries into:

            TaskPlan
            Incident

        before using them.
        """

        task_id = task.get(
            "task_id"
        )

        if not task_id:

            task_id = (
                f"{task.get('incident_id', 'unknown')}"
                f"-{AGENT_RESPONSE}-"
                f"{uuid.uuid4().hex[:8]}"
            )

        # ========================================================
        # BUILD MODELS
        # ========================================================

        try:

            task_plan = (
                self._build_task_plan(task)
            )

        except Exception as e:

            print(
                f"[{AGENT_RESPONSE}] "
                f"TaskPlan validation failed: {e}"
            )

            return AgentResult(
                task_id=task_id,
                agent_name=AGENT_RESPONSE,
                success=False,
                output={},
                error_message=(
                    f"Invalid TaskPlan: {e}"
                ),
                timestamp=datetime.now(
                    timezone.utc
                )
            ).model_dump()

        try:

            incident = (
                self._build_incident(
                    task,
                    incident_context
                )
            )

        except Exception as e:

            print(
                f"[{AGENT_RESPONSE}] "
                f"Incident validation failed: {e}"
            )

            return AgentResult(
                task_id=task_id,
                agent_name=AGENT_RESPONSE,
                success=False,
                output={},
                error_message=(
                    f"Invalid Incident context: {e}"
                ),
                timestamp=datetime.now(
                    timezone.utc
                )
            ).model_dump()

        print(
            f"\n[{AGENT_RESPONSE}] "
            f"Task received: {task_id}"
        )

        print(
            f"[{AGENT_RESPONSE}] "
            f"Incident: {incident.incident_id} "
            f"(severity={incident.severity}, "
            f"composite={incident.composite_severity})"
        )

        # ========================================================
        # APPROVAL
        # ========================================================

        approved = self.check_approval(
            task_plan
        )

        if not approved:

            return AgentResult(
                task_id=task_id,
                agent_name=AGENT_RESPONSE,
                success=False,
                output={
                    "incident_id":
                        incident.incident_id,
                    "reason": (
                        "Action not approved "
                        "by human analyst or "
                        "approval timed out"
                    ),
                    "actions_requested":
                        task_plan.actions
                },
                error_message=(
                    "approval_denied_or_timeout"
                ),
                timestamp=datetime.now(
                    timezone.utc
                )
            ).model_dump()

        # ========================================================
        # INCIDENT DATA
        # ========================================================

        source_ip = incident.source_ip

        username = incident.username

        target_vm_ip = (
            incident.destination_ip
            or incident.source_ip
        )

        # Extra information from raw_log

        raw_log = incident.raw_log or {}

        wazuh_agent_id = (
            raw_log.get(
                "wazuh_agent_id"
            )
            or raw_log.get(
                "agent_id"
            )
            or "001"
        )

        malicious_process = (
            raw_log.get(
                "malicious_process",
                {}
            )
        )

        if not isinstance(
            malicious_process,
            dict
        ):

            malicious_process = {}

        ti_confidence = (
            self._get_ti_confidence(
                incident.incident_id
            )
        )

        # ========================================================
        # HIGH IMPACT LOGGING
        # ========================================================

        if (
            incident.composite_severity
            in SEVERITY_HIGH
            or
            incident.composite_severity
            == SEVERITY_CRITICAL
        ):

            print(
                f"[{AGENT_RESPONSE}] "
                f"High-impact incident "
                f"(composite_severity="
                f"{incident.composite_severity})"
            )

        # ========================================================
        # EXECUTE ACTIONS
        # ========================================================

        actions_taken = []

        overall_success = True

        errors = []

        for action_item in task_plan.actions:

            if not isinstance(
                action_item,
                dict
            ):

                result = {
                    "action": "unknown",
                    "success": False,
                    "error": (
                        "Action item is not a dictionary"
                    )
                }

            else:

                action_type = (
                    action_item.get("action")
                    or action_item.get("type")
                    or ""
                )

                print(
                    f"[{AGENT_RESPONSE}] "
                    f"Executing action: "
                    f"{action_type}"
                )

                # ------------------------------------------------
                # BLOCK IP
                # ------------------------------------------------

                if (
                    action_type == "block_ip"
                    and source_ip
                    and target_vm_ip
                ):

                    result = self.block_ip(
                        target_vm_ip,
                        source_ip
                    )

                # ------------------------------------------------
                # ISOLATE HOST
                # ------------------------------------------------

                elif (
                    action_type
                    == "isolate_host"
                ):

                    result = self.isolate_host(
                        wazuh_agent_id,
                        incident.incident_id
                    )

                # ------------------------------------------------
                # DISABLE ACCOUNT
                # ------------------------------------------------

                elif (
                    action_type
                    == "disable_account"
                    and username
                ):

                    result = self.disable_account(
                        username,
                        ti_confidence
                    )

                # ------------------------------------------------
                # KILL PROCESS
                # ------------------------------------------------

                elif (
                    action_type
                    == "kill_process"
                    and malicious_process
                    and target_vm_ip
                ):

                    result = self.kill_process(
                        target_vm_ip,
                        malicious_process
                    )

                # ------------------------------------------------
                # UNKNOWN ACTION
                # ------------------------------------------------

                else:

                    result = {
                        "action":
                            action_type
                            or "unknown",
                        "success": False,
                        "error": (
                            "Unrecognized or "
                            "unsupported action "
                            "for this incident context"
                        )
                    }

            actions_taken.append(
                result
            )

            if not result.get(
                "success",
                False
            ):

                overall_success = False

                if result.get("error"):

                    errors.append(
                        f"{result.get('action')}: "
                        f"{result['error']}"
                    )

        # ========================================================
        # FINAL RESULT
        # ========================================================

        print(
            f"[{AGENT_RESPONSE}] "
            f"Actions completed: "
            f"{len(actions_taken)}"
        )

        print(
            f"[{AGENT_RESPONSE}] "
            f"Overall success: "
            f"{overall_success}"
        )

        agent_result = AgentResult(
            task_id=task_id,
            agent_name=AGENT_RESPONSE,
            success=overall_success,
            output={
                "incident_id":
                    incident.incident_id,
                "actions_taken":
                    actions_taken,
                "actions_count":
                    len(actions_taken)
            },
            error_message=(
                "; ".join(errors)
                if errors
                else None
            ),
            timestamp=datetime.now(
                timezone.utc
            )
        )

        return agent_result.model_dump()

    # ============================================================
    # MAIN
    # ============================================================


if __name__ == "__main__":

    agent = ResponseAgent()
    agent.run()
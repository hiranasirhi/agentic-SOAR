# agents/containment_agent.py

from agents.base_agent import BaseAgent

import paramiko
import json
import os
import requests
import time

from datetime import datetime

from dotenv import load_dotenv

from shared.models import AgentResult
from shared.constants import AGENT_CONTAINMENT


load_dotenv()


class ContainmentAgent(BaseAgent):

    def __init__(self):
        # Must match constants.py
        # AGENT_CONTAINMENT = "containment"
        super().__init__(AGENT_CONTAINMENT)

        self.ssh_user = os.getenv(
            "VM_SSH_USER",
            "ubuntu"
        )

        self.ssh_password = os.getenv(
            "VM_SSH_PASSWORD",
            ""
        )

        self.ssh_key_path = os.getenv(
            "VM_SSH_KEY_PATH",
            "~/.ssh/id_rsa"
        )

        # Load VMs
        self.lab_vms = self._load_vm_registry()

        # Private IP ranges
        self.private_ranges = [
            "10.",
            "192.168.",
            "172.16.",
            "127.",
            "localhost"
        ]

        print("[containment] Initialized")
        print(
            f"[containment] Lab VMs registered: "
            f"{len(self.lab_vms)}"
        )

    # ============================================================
    # LOAD VM REGISTRY
    # ============================================================

    def _load_vm_registry(self) -> list:
        """
        Load list of VMs from environment or assets.json.
        """

        vms_env = os.getenv(
            "LAB_VM_IPS",
            ""
        )

        if vms_env:

            return [
                {
                    "ip": ip.strip(),
                    "name": f"vm-{i}"
                }
                for i, ip in enumerate(
                    vms_env.split(","),
                    start=1
                )
                if ip.strip()
            ]

        try:

            with open("assets.json", "r") as f:
                assets = json.load(f)

            return [
                {
                    "ip": ip,
                    "name": details.get(
                        "name",
                        ip
                    )
                }
                for ip, details in assets.items()
                if details.get("type") == "vm"
            ]

        except Exception:

            print(
                "[containment] WARNING: "
                "No VM registry found. "
                "Set LAB_VM_IPS in .env"
            )

            return []

    # ============================================================
    # PRIVATE IP CHECK
    # ============================================================

    def is_private_ip(self, ip: str) -> bool:

        for prefix in self.private_ranges:

            if ip.startswith(prefix):
                return True

        return False

    # ============================================================
    # CHECK APPROVAL
    # ============================================================

    def check_approval(
        self,
        incident_id: str,
        task: dict
    ) -> bool:
        """
        Uses approval_required from TaskPlan schema.
        """

        # TaskPlan schema uses approval_required
        requires_approval = task.get(
            "approval_required",
            False
        )

        if not requires_approval:
            return True

        print(
            f"[containment] Waiting for approval "
            f"for incident {incident_id}"
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

                status = response.json().get(
                    "approval_status",
                    "pending"
                )

                if status == "approved":
                    return True

                if status == "rejected":
                    return False

            except Exception:
                pass

            time.sleep(poll_interval)
            waited += poll_interval

        return False

    # ============================================================
    # BLOCK IP ON ONE VM
    # ============================================================

    def _block_ip_on_vm(
        self,
        vm_ip: str,
        vm_name: str,
        malicious_ip: str
    ) -> dict:
        """
        Apply UFW deny rule on one VM.
        """

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
                    vm_ip,
                    username=self.ssh_user,
                    key_filename=key_path,
                    timeout=10
                )

            else:

                ssh.connect(
                    vm_ip,
                    username=self.ssh_user,
                    password=self.ssh_password,
                    timeout=10
                )

            # Apply UFW rule
            cmd = (
                f"sudo ufw deny "
                f"from {malicious_ip} to any"
            )

            stdin, stdout, stderr = (
                ssh.exec_command(cmd)
            )

            stdout.channel.recv_exit_status()

            # Verify
            stdin, stdout, stderr = (
                ssh.exec_command("sudo ufw status")
            )

            ufw_status = stdout.read().decode()

            rule_applied = (
                malicious_ip in ufw_status
            )

            print(
                f"[containment] "
                f"{vm_name} ({vm_ip}): "
                f"{'BLOCKED' if rule_applied else 'FAILED'}"
            )

            return {
                "vm": vm_name,
                "vm_ip": vm_ip,
                "success": rule_applied,
                "verified": rule_applied
            }

        except Exception as e:

            print(
                f"[containment] "
                f"Error on {vm_name}: {e}"
            )

            return {
                "vm": vm_name,
                "vm_ip": vm_ip,
                "success": False,
                "error": str(e)
            }

        finally:

            ssh.close()

    # ============================================================
    # BLOCK IP ON ALL VMs
    # ============================================================

    def block_ip_all_vms(
        self,
        malicious_ip: str
    ) -> dict:
        """
        Apply UFW deny rule across all registered VMs.
        """

        if self.is_private_ip(malicious_ip):

            return {
                "action": "block_ip_all_vms",
                "success": False,
                "error": (
                    f"REJECTED: {malicious_ip} "
                    f"is private IP range"
                )
            }

        if not self.lab_vms:

            return {
                "action": "block_ip_all_vms",
                "success": False,
                "error": (
                    "No VMs registered in registry"
                )
            }

        print(
            f"[containment] Blocking "
            f"{malicious_ip} across "
            f"{len(self.lab_vms)} VMs"
        )

        vm_results = []
        success_count = 0

        for vm in self.lab_vms:

            result = self._block_ip_on_vm(
                vm["ip"],
                vm["name"],
                malicious_ip
            )

            vm_results.append(result)

            if result["success"]:
                success_count += 1

        overall_success = (
            success_count == len(self.lab_vms)
        )

        return {
            "action": "block_ip_all_vms",
            "success": overall_success,
            "malicious_ip": malicious_ip,
            "vms_blocked": success_count,
            "vms_total": len(self.lab_vms),
            "vm_results": vm_results
        }

    # ============================================================
    # VERIFY CONTAINMENT
    # ============================================================

    def verify_containment(
        self,
        malicious_ip: str
    ) -> dict:
        """
        Verify containment on all VMs.
        """

        print(
            f"[containment] Verifying "
            f"containment for {malicious_ip}"
        )

        verification_results = []
        all_verified = True

        for vm in self.lab_vms:

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
                        vm["ip"],
                        username=self.ssh_user,
                        key_filename=key_path,
                        timeout=10
                    )

                else:

                    ssh.connect(
                        vm["ip"],
                        username=self.ssh_user,
                        password=self.ssh_password,
                        timeout=10
                    )

                stdin, stdout, stderr = (
                    ssh.exec_command(
                        "sudo ufw status"
                    )
                )

                status = stdout.read().decode()

                rule_present = (
                    malicious_ip in status
                )

                verification_results.append({
                    "vm": vm["name"],
                    "vm_ip": vm["ip"],
                    "rule_present": rule_present
                })

                if not rule_present:

                    all_verified = False

                    print(
                        f"[containment] "
                        f"DRIFT DETECTED on "
                        f"{vm['name']}"
                    )

            except Exception as e:

                all_verified = False

                verification_results.append({
                    "vm": vm["name"],
                    "vm_ip": vm["ip"],
                    "rule_present": False,
                    "error": str(e)
                })

            finally:

                ssh.close()

        return {
            "action": "verify_containment",
            "success": all_verified,
            "all_verified": all_verified,
            "malicious_ip": malicious_ip,
            "vm_verifications": verification_results
        }

    # ============================================================
    # EXECUTE TASK
    # ============================================================

    def execute_task(
        self,
        task: dict,
        incident_context: dict
    ) -> dict:
        """
        Execute containment task.

        Output follows AgentResult schema:

        task_id
        agent_name
        success
        output
        error_message
        timestamp
        """

        task_id = task.get(
            "task_id",
            "UNKNOWN"
        )

        incident_id = task.get(
            "incident_id",
            "UNKNOWN"
        )

        source_ip = incident_context.get(
            "source_ip"
        )

        print(
            f"\n[containment] "
            f"Starting containment for "
            f"{incident_id}"
        )

        # --------------------------------------------------------
        # APPROVAL
        # --------------------------------------------------------

        approved = self.check_approval(
            incident_id,
            task
        )

        if not approved:

            result = AgentResult(
                task_id=task_id,
                agent_name=AGENT_CONTAINMENT,
                success=False,
                output={
                    "incident_id": incident_id,
                    "reason": (
                        "Containment not approved "
                        "or approval timed out"
                    )
                },
                error_message=(
                    "Containment approval denied "
                    "or timed out"
                ),
                timestamp=datetime.utcnow()
            )

            return result.dict()

        # --------------------------------------------------------
        # SOURCE IP
        # --------------------------------------------------------

        if not source_ip:

            result = AgentResult(
                task_id=task_id,
                agent_name=AGENT_CONTAINMENT,
                success=False,
                output={
                    "incident_id": incident_id,
                    "reason": (
                        "No source_ip found "
                        "in incident context"
                    )
                },
                error_message="Missing source_ip",
                timestamp=datetime.utcnow()
            )

            return result.dict()

        results = []

        # --------------------------------------------------------
        # BLOCK IP
        # --------------------------------------------------------

        block_result = self.block_ip_all_vms(
            source_ip
        )

        results.append(block_result)

        # --------------------------------------------------------
        # VERIFY
        # --------------------------------------------------------

        if block_result["success"]:

            verify_result = (
                self.verify_containment(
                    source_ip
                )
            )

            results.append(verify_result)

            # ----------------------------------------------------
            # RE-APPLY IF DRIFT DETECTED
            # ----------------------------------------------------

            if not verify_result["all_verified"]:

                print(
                    "[containment] "
                    "Drift detected — "
                    "re-applying rules"
                )

                reapply_result = (
                    self.block_ip_all_vms(
                        source_ip
                    )
                )

                results.append(
                    reapply_result
                )

        # --------------------------------------------------------
        # OVERALL SUCCESS
        # --------------------------------------------------------

        overall_success = all(
            result.get(
                "success",
                result.get(
                    "all_verified",
                    False
                )
            )
            for result in results
        )

        # --------------------------------------------------------
        # AGENT RESULT
        # --------------------------------------------------------

        agent_result = AgentResult(
            task_id=task_id,
            agent_name=AGENT_CONTAINMENT,
            success=overall_success,
            output={
                "incident_id": incident_id,
                "source_ip": source_ip,
                "containment_results": results
            },
            error_message=(
                None
                if overall_success
                else "Containment operation failed"
            ),
            timestamp=datetime.utcnow()
        )

        return agent_result.model_dump()


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    agent = ContainmentAgent()
    agent.run()
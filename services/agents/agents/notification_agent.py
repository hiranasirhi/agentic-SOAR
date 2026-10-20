from agents.base_agent import BaseAgent

import requests
import json
import os

from datetime import datetime
from typing import Dict, Any

from langchain_ollama import OllamaLLM
from dotenv import load_dotenv

from shared.constants import AGENT_NOTIFICATION

load_dotenv()


class NotificationAgent(BaseAgent):

    def __init__(self):
        super().__init__(AGENT_NOTIFICATION)

        # ============================================================
        # TheHive Configuration
        # ============================================================

        self.thehive_url = os.getenv("THEHIVE_URL", "").rstrip("/")
        self.thehive_api_key = os.getenv("THEHIVE_API_KEY", "")

        # ============================================================
        # Slack Configuration
        # ============================================================

        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        self.slack_approval_channel = os.getenv(
            "SLACK_APPROVAL_WEBHOOK",
            ""
        )

        # ============================================================
        # LLM Configuration
        # ============================================================

        self.llm = OllamaLLM(
        model=os.getenv(
        "OLLAMA_MODEL",
        "qwen2.5:14b"
    ),
    base_url=os.getenv(
        "OLLAMA_URL",
        "http://localhost:11434"
    ),
    temperature=0
    )

        print(
            f"[{AGENT_NOTIFICATION}] TheHive: "
            f"{'configured' if self.thehive_url and self.thehive_api_key else 'NOT configured'}"
        )

        print(
            f"[{AGENT_NOTIFICATION}] Slack: "
            f"{'configured' if self.slack_webhook else 'NOT configured'}"
        )

    # ================================================================
    # HELPER METHODS
    # ================================================================

    @staticmethod
    def _get_value(data: Any, key: str, default=None):
        """
        Safely retrieve a value from either a dictionary
        or a Pydantic model.
        """

        if data is None:
            return default

        if isinstance(data, dict):
            return data.get(key, default)

        return getattr(data, key, default)

    @staticmethod
    def _normalize_result(result: Any) -> Dict[str, Any]:
        """
        Convert an AgentResult/Pydantic object/dict into a dictionary.
        """

        if result is None:
            return {}

        if isinstance(result, dict):
            return result

        if hasattr(result, "model_dump"):
            return result.model_dump()

        if hasattr(result, "dict"):
            return result.dict()

        return {
            "agent_name": getattr(result, "agent_name", "unknown"),
            "success": getattr(result, "success", False),
            "output": getattr(result, "output", {}),
            "error_message": getattr(
                result,
                "error_message",
                None
            ),
            "timestamp": getattr(
                result,
                "timestamp",
                None
            )
        }

    # ================================================================
    # GET ALL AGENT RESULTS
    # ================================================================

    def get_all_results(self, incident_id: str) -> Dict[str, Any]:
        """
        Fetch all AgentResult objects associated with an incident.

        Expected endpoint:

            GET /incidents/{incident_id}/results
        """

        if not incident_id:
            print(
                f"[{AGENT_NOTIFICATION}] "
                f"No incident_id supplied"
            )
            return {}

        try:
            response = requests.get(
                f"{self.orchestrator_url}/incidents/{incident_id}/results",
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

            # --------------------------------------------------------
            # If orchestrator returns:
            #
            # {
            #     "task_id": {...},
            #     "task_id": {...}
            # }
            # --------------------------------------------------------

            if isinstance(data, dict):
                return {
                    str(task_id): self._normalize_result(result)
                    for task_id, result in data.items()
                }

            # --------------------------------------------------------
            # If orchestrator returns:
            #
            # [
            #     {...},
            #     {...}
            # ]
            # --------------------------------------------------------

            if isinstance(data, list):
                results = {}

                for index, result in enumerate(data):

                    normalized = self._normalize_result(result)

                    task_id = normalized.get(
                        "task_id",
                        f"result-{index}"
                    )

                    results[str(task_id)] = normalized

                return results

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"Unexpected results format"
            )

            return {}

        except requests.RequestException as e:

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"Error getting agent results: {e}"
            )

            return {}

        except Exception as e:

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"Unexpected error getting results: {e}"
            )

            return {}

    # ================================================================
    # THEHIVE CASE CREATION
    # ================================================================

    def create_thehive_case(
        self,
        incident: Dict[str, Any],
        all_results: Dict[str, Any]
    ) -> Dict[str, Any]:

        """
        Create a TheHive case using the Incident schema.
        """

        if not self.thehive_url or not self.thehive_api_key:

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"TheHive not configured — skipping"
            )

            return {
                "success": False,
                "error": "TheHive not configured"
            }

        print(
            f"[{AGENT_NOTIFICATION}] "
            f"Creating TheHive case"
        )

        try:

            headers = {
                "Authorization": (
                    f"Bearer {self.thehive_api_key}"
                ),
                "Content-Type": "application/json"
            }

            description = self._build_case_description(
                incident,
                all_results
            )

            severity = self._get_value(
                incident,
                "composite_severity",
                self._get_value(
                    incident,
                    "severity",
                    5
                )
            )

            severity = int(severity or 5)

            mitre_technique = self._get_value(
                incident,
                "mitre_technique"
            )

            event_source = self._get_value(
                incident,
                "event_source",
                "unknown"
            )

            incident_id = self._get_value(
                incident,
                "incident_id",
                ""
            )

            tags = [
                "PROTEGO-automated",
                event_source,
                f"severity-{severity}"
            ]

            if mitre_technique:
                tags.append(str(mitre_technique))

            kill_chain_stages = self._get_value(
                incident,
                "kill_chain_stages",
                []
            )

            if kill_chain_stages:
                tags.extend(
                    [
                        f"kill-chain-{stage}"
                        for stage in kill_chain_stages
                    ]
                )

            case_data = {
                "title": (
                    f"PROTEGO: "
                    f"{self._get_value(incident, 'rule_description', 'Security Incident')} "
                    f"— "
                    f"{self._get_value(incident, 'source_ip', 'Unknown IP')}"
                ),

                "description": description,

                "severity": self._map_severity(severity),

                "tags": tags,

                "tlp": 2,

                "status": "New",

                "source": "PROTEGO",

                "sourceRef": incident_id
            }

            response = requests.post(
                f"{self.thehive_url}/api/v1/case",
                headers=headers,
                json=case_data,
                timeout=15
            )

            if response.status_code in (200, 201):

                case = response.json()

                case_id = case.get(
                    "_id",
                    ""
                )

                case_number = case.get(
                    "caseId",
                    ""
                )

                print(
                    f"[{AGENT_NOTIFICATION}] "
                    f"TheHive case created: #{case_number}"
                )

                return {
                    "success": True,
                    "case_id": case_id,
                    "case_number": case_number,
                    "case_url": (
                        f"{self.thehive_url}/cases/{case_id}"
                        if case_id
                        else ""
                    )
                }

            return {
                "success": False,
                "error": (
                    f"HTTP {response.status_code}: "
                    f"{response.text[:500]}"
                )
            }

        except requests.RequestException as e:

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"TheHive request error: {e}"
            )

            return {
                "success": False,
                "error": str(e)
            }

        except Exception as e:

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"TheHive error: {e}"
            )

            return {
                "success": False,
                "error": str(e)
            }

    # ================================================================
    # BUILD THEHIVE DESCRIPTION
    # ================================================================

    def _build_case_description(
        self,
        incident: Dict[str, Any],
        all_results: Dict[str, Any]
    ) -> str:

        incident_id = self._get_value(
            incident,
            "incident_id",
            "N/A"
        )

        correlation_id = self._get_value(
            incident,
            "correlation_id",
            "N/A"
        )

        severity = self._get_value(
            incident,
            "composite_severity",
            self._get_value(
                incident,
                "severity",
                "N/A"
            )
        )

        lines = [
            "## PROTEGO Incident Details",
            "",
            f"- **Incident ID:** {incident_id}",
            f"- **Correlation ID:** {correlation_id}",
            f"- **Rule:** {self._get_value(incident, 'rule_description', 'N/A')}",
            f"- **Rule ID:** {self._get_value(incident, 'rule_id', 'N/A')}",
            f"- **Source IP:** {self._get_value(incident, 'source_ip', 'N/A')}",
            f"- **Destination IP:** {self._get_value(incident, 'destination_ip', 'N/A')}",
            f"- **Source Port:** {self._get_value(incident, 'source_port', 'N/A')}",
            f"- **Destination Port:** {self._get_value(incident, 'destination_port', 'N/A')}",
            f"- **Protocol:** {self._get_value(incident, 'protocol', 'N/A')}",
            f"- **Severity:** {severity}/10",
            f"- **Asset Criticality:** {self._get_value(incident, 'asset_criticality', 'N/A')}",
            f"- **Hostname:** {self._get_value(incident, 'hostname', 'N/A')}",
            f"- **Username:** {self._get_value(incident, 'username', 'N/A')}",
            f"- **Department:** {self._get_value(incident, 'user_department', 'N/A')}",
            f"- **Country:** {self._get_value(incident, 'geo_country', 'N/A')}",
            f"- **City:** {self._get_value(incident, 'geo_city', 'N/A')}",
            f"- **Event Source:** {self._get_value(incident, 'event_source', 'N/A')}",
            f"- **MITRE Technique:** {self._get_value(incident, 'mitre_technique', 'N/A')}",
            f"- **MITRE Tactic:** {self._get_value(incident, 'mitre_tactic', 'N/A')}",
            f"- **Kill Chain Stages:** {self._get_value(incident, 'kill_chain_stages', [])}",
            f"- **Anomaly Score:** {self._get_value(incident, 'anomaly_score', 'N/A')}",
            f"- **Is Anomaly:** {self._get_value(incident, 'is_anomaly', False)}",
            f"- **FP Discount Applied:** {self._get_value(incident, 'fp_discount_applied', 0)}",
            "",
            "## Agent Actions Taken"
        ]

        if not all_results:

            lines.append(
                "- No agent results available."
            )

        else:

            for task_id, raw_result in all_results.items():

                result = self._normalize_result(
                    raw_result
                )

                agent_name = result.get(
                    "agent_name",
                    "unknown"
                )

                success = result.get(
                    "success",
                    False
                )

                output = result.get(
                    "output",
                    {}
                )

                if not isinstance(output, dict):
                    output = {
                        "result": output
                    }

                status = (
                    "SUCCESS"
                    if success
                    else "FAILED"
                )

                lines.append(
                    f"- **{agent_name}** "
                    f"(Task: {task_id}): {status}"
                )

                if result.get("error_message"):
                    lines.append(
                        f"  - Error: "
                        f"{result.get('error_message')}"
                    )

                # ----------------------------------------------------
                # Investigation agent
                # constants.py uses "investigation"
                # ----------------------------------------------------

                if agent_name == "investigation":

                    ti_confidence = output.get(
                        "ti_confidence",
                        "N/A"
                    )

                    ioc_reputation = output.get(
                        "ioc_reputation",
                        {}
                    )

                    if not isinstance(
                        ioc_reputation,
                        dict
                    ):
                        ioc_reputation = {}

                    verdict = ioc_reputation.get(
                        "overall_verdict",
                        "N/A"
                    )

                    lines.append(
                        f"  - TI Confidence: "
                        f"{ti_confidence}"
                    )

                    lines.append(
                        f"  - IOC Verdict: "
                        f"{verdict}"
                    )

                    lines.append(
                        f"  - Lateral Movement: "
                        f"{output.get('lateral_movement_detected', False)}"
                    )

                # ----------------------------------------------------
                # Triage agent
                # constants.py uses "triage"
                # ----------------------------------------------------

                elif agent_name == "triage":

                    lines.append(
                        f"  - Confirmed Severity: "
                        f"{output.get('confirmed_severity', 'N/A')}"
                    )

                    lines.append(
                        f"  - Escalation: "
                        f"{output.get('escalation_decision', 'N/A')}"
                    )

                # ----------------------------------------------------
                # Response agent
                # ----------------------------------------------------

                elif agent_name == "response":

                    lines.append(
                        f"  - Response Action: "
                        f"{output.get('action', output.get('response_action', 'N/A'))}"
                    )

                # ----------------------------------------------------
                # Containment agent
                # ----------------------------------------------------

                elif agent_name == "containment":

                    lines.append(
                        f"  - Containment Action: "
                        f"{output.get('action', output.get('containment_action', 'N/A'))}"
                    )

        return "\n".join(lines)

    # ================================================================
    # SEVERITY MAPPING
    # ================================================================

    @staticmethod
    def _map_severity(severity: int) -> int:
        """
        Map PROTEGO severity (1-10)
        to TheHive severity (1-3).

        1-3  -> Low
        4-6  -> Medium
        7-10 -> High
        """

        severity = max(
            1,
            min(
                int(severity),
                10
            )
        )

        if severity >= 7:
            return 3

        if severity >= 4:
            return 2

        return 1

    # ================================================================
    # SLACK NOTIFICATION
    # ================================================================

    def send_slack_alert(
        self,
        incident: Dict[str, Any],
        all_results: Dict[str, Any],
        thehive_result: Dict[str, Any]
    ) -> Dict[str, Any]:

        if not self.slack_webhook:

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"Slack not configured — skipping"
            )

            return {
                "success": False,
                "error": "Slack not configured"
            }

        severity = int(
            self._get_value(
                incident,
                "composite_severity",
                self._get_value(
                    incident,
                    "severity",
                    5
                )
            )
        )

        if severity >= 9:
            emoji = "🚨"
        elif severity >= 7:
            emoji = "⚠️"
        elif severity >= 4:
            emoji = "🔍"
        else:
            emoji = "ℹ️"

        ti_confidence = "N/A"
        verdict = "N/A"

        actions_summary = []

        for task_id, raw_result in all_results.items():

            result = self._normalize_result(
                raw_result
            )

            agent_name = result.get(
                "agent_name",
                "unknown"
            )

            success = result.get(
                "success",
                False
            )

            output = result.get(
                "output",
                {}
            )

            if not isinstance(output, dict):
                output = {}

            if agent_name == "investigation":

                ti_confidence = output.get(
                    "ti_confidence",
                    "N/A"
                )

                ioc_reputation = output.get(
                    "ioc_reputation",
                    {}
                )

                if isinstance(
                    ioc_reputation,
                    dict
                ):

                    verdict = ioc_reputation.get(
                        "overall_verdict",
                        "N/A"
                    )

            status = "SUCCESS" if success else "FAILED"

            actions_summary.append(
                f"• {agent_name}: {status}"
            )

        case_link = thehive_result.get(
            "case_url",
            "N/A"
        )

        message = {
            "text": (
                f"{emoji} *PROTEGO Security Incident*\n"
                f"*Incident ID*: "
                f"{self._get_value(incident, 'incident_id', 'N/A')}\n"
                f"*Type*: "
                f"{self._get_value(incident, 'rule_description', 'N/A')}\n"
                f"*Severity*: {severity}/10\n"
                f"*Source IP*: "
                f"{self._get_value(incident, 'source_ip', 'N/A')}\n"
                f"*MITRE*: "
                f"{self._get_value(incident, 'mitre_technique', 'N/A')}\n"
                f"*TI Confidence*: {ti_confidence}\n"
                f"*Verdict*: {verdict}\n"
                f"*Agent Actions*:\n"
                f"{chr(10).join(actions_summary)}\n"
                f"*TheHive Case*: {case_link}"
            )
        }

        try:

            response = requests.post(
                self.slack_webhook,
                json=message,
                timeout=10
            )

            success = response.status_code == 200

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"Slack alert sent: {success}"
            )

            return {
                "success": success,
                "status_code": response.status_code
            }

        except requests.RequestException as e:

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"Slack error: {e}"
            )

            return {
                "success": False,
                "error": str(e)
            }

    # ================================================================
    # LLM REPORT GENERATION
    # ================================================================

    def generate_analyst_report(
        self,
        incident: Dict[str, Any],
        all_results: Dict[str, Any]
    ) -> str:

        prompt = f"""
You are a cybersecurity analyst working for the PROTEGO
agentic SOAR platform.

Write a concise and factual technical incident report.

Incident:
{json.dumps(incident, indent=2, default=str)}

Agent Results:
{json.dumps(all_results, indent=2, default=str)}

Include:

1. Executive Summary
2. Attack Timeline
3. Indicators of Compromise
4. Agent Actions Taken
5. Risk Assessment
6. Recommendations

Do not invent evidence.
Only use information present in the incident
and agent results.
"""

        try:

            report = self.llm.invoke(
                prompt
            )

            return str(report)

        except Exception as e:

            print(
                f"[{AGENT_NOTIFICATION}] "
                f"LLM report generation failed: {e}"
            )

            return (
                f"Report generation failed: {str(e)}"
            )

    # ================================================================
    # EXECUTE TASK
    # ================================================================

    def execute_task(
        self,
        task: Dict[str, Any],
        incident_context: Dict[str, Any]
    ) -> Dict[str, Any]:

        task_id = task.get(
            "task_id",
            "UNKNOWN"
        )

        incident_id = task.get(
            "incident_id",
            incident_context.get(
                "incident_id",
                "UNKNOWN"
            )
        )

        print(
            f"\n[{AGENT_NOTIFICATION}] "
            f"Processing incident {incident_id}"
        )

        # ------------------------------------------------------------
        # Get all agent results
        # ------------------------------------------------------------

        all_results = self.get_all_results(
            incident_id
        )

        print(
            f"[{AGENT_NOTIFICATION}] "
            f"Got {len(all_results)} agent results"
        )

        # ------------------------------------------------------------
        # Create TheHive case
        # ------------------------------------------------------------

        thehive_result = self.create_thehive_case(
            incident_context,
            all_results
        )

        # ------------------------------------------------------------
        # Send Slack alert
        # ------------------------------------------------------------

        slack_result = self.send_slack_alert(
            incident_context,
            all_results,
            thehive_result
        )

        # ------------------------------------------------------------
        # Generate analyst report
        # ------------------------------------------------------------

        print(
            f"[{AGENT_NOTIFICATION}] "
            f"Generating analyst report..."
        )

        report = self.generate_analyst_report(
            incident_context,
            all_results
        )

        report_success = bool(
            report
            and not report.startswith(
                "Report generation failed:"
            )
        )

        # ------------------------------------------------------------
        # Overall result
        #
        # Notification succeeds if at least one notification
        # mechanism succeeds or the report is generated.
        # ------------------------------------------------------------

        overall_success = (
            thehive_result.get("success", False)
            or slack_result.get("success", False)
            or report_success
        )

        output = {
            "thehive": thehive_result,
            "slack": slack_result,
            "report_generated": report_success,
            "report_preview": report[:500] if report else "",
            "agent_results_count": len(all_results)
        }

        error_message = None

        if not overall_success:

            error_message = (
                "All notification/report operations failed"
            )

        # ------------------------------------------------------------
        # IMPORTANT:
        #
        # This structure matches AgentResult:
        #
        # task_id
        # agent_name
        # success
        # output
        # error_message
        # timestamp
        # ------------------------------------------------------------

        return {
            "task_id": task_id,
            "agent_name": AGENT_NOTIFICATION,
            "success": overall_success,
            "output": output,
            "error_message": error_message,
            "timestamp": datetime.utcnow().isoformat()
        }


# ====================================================================
# MAIN
# ====================================================================

if __name__ == "__main__":

    agent = NotificationAgent()

    agent.run()
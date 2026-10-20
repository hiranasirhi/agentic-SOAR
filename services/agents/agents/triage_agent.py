# agents/triage_agent.py

from agents.base_agent import BaseAgent
from shared.constants import AGENT_TRIAGE
import requests
import os

class TriageAgent(BaseAgent):

    def __init__(self):
        super().__init__(AGENT_TRIAGE)
        self.orchestrator_url = os.getenv("ORCHESTRATOR_URL", "100.82.97.75:8000")

    # ============================================
    # SEVERITY CONFIRMATION
    # ============================================

    def confirm_severity(self, incident: dict) -> float:
        """
        Recalculate severity using full contextual information.

        Formula:
        base_score
        + asset_criticality_modifier
        + user_privilege_modifier
        + multi_stage_bonus
        - false_positive_discount
        Capped at 10
        """
        base_score = float(incident.get("severity", 5))

        asset = str(incident.get("asset_criticality") or "low").lower()
        asset_modifier = {
            "critical": 2,
            "high": 1,
            "medium": 0,
            "low": 0
        }.get(asset, 0)

        username = str(incident.get("username", "")).lower()
        user_dept = str(incident.get("user_department", "")).lower()
        user_modifier = 2 if any(word in username + user_dept for word in ["admin", "root", "sudo"]) else 0

        multi_stage_bonus = 1 if incident.get("is_multi_stage", False) else 0

        fp_discount = self._check_false_positive_discount(incident)

        final_score = base_score + asset_modifier + user_modifier + multi_stage_bonus - fp_discount
        final_score = min(10, max(1, final_score))

        print(f"[{AGENT_TRIAGE}] Severity calculation:")
        print(f"  Base: {base_score}")
        print(f"  + Asset modifier: {asset_modifier} ({asset})")
        print(f"  + User modifier: {user_modifier}")
        print(f"  + Multi-stage: {multi_stage_bonus}")
        print(f"  - FP discount: {fp_discount}")
        print(f"  = Final: {final_score}")

        return round(final_score, 1)

    def _check_false_positive_discount(self, incident: dict) -> float:
        """
        Check ChromaDB false_positives collection via the Orchestrator.
        If similar pattern was FP before -> apply -2 discount.
        """
        try:
            query = (
                f"{incident.get('rule_description', '')} "
                f"from {incident.get('geo_country', 'unknown')} "
                f"targeting {incident.get('asset_criticality', 'unknown')} asset"
            )

            response = requests.post(
                f"{self.orchestrator_url}/memory/check_false_positive",
                json={"query": query},
                timeout=20
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("is_false_positive_pattern"):
                    print(f"[{AGENT_TRIAGE}] False positive pattern detected! Applying -2 discount")
                    return 2

        except Exception as e:
            print(f"[{AGENT_TRIAGE}] FP check unavailable: {e}")

        return 0

    # ============================================
    # BLAST RADIUS ESTIMATION
    # ============================================

    def estimate_blast_radius(self, incident: dict) -> dict:
        asset_criticality = str(incident.get("asset_criticality") or "low").lower()
        is_multi_stage = incident.get("is_multi_stage", False)
        mitre_tactic = str(incident.get("mitre_tactic") or "").lower()

        if "lateral" in mitre_tactic or is_multi_stage:
            return {
                "level": "HIGH",
                "affected_systems_count": 4,
                "description": "Multi-stage attack detected — attacker may have already moved laterally to other systems"
            }
        elif asset_criticality in ["critical", "high"]:
            return {
                "level": "MEDIUM",
                "affected_systems_count": 2,
                "description": f"High-value {asset_criticality} asset targeted — adjacent systems at risk"
            }
        else:
            return {
                "level": "LOW",
                "affected_systems_count": 1,
                "description": "Low criticality asset — blast radius contained to single system"
            }

    # ============================================
    # ESCALATION DECISION
    # ============================================

    def make_escalation_decision(self, confirmed_severity: float) -> str:
        if confirmed_severity <= 3:
            return "close_as_noise"
        elif confirmed_severity <= 5:
            return "monitor_only"
        elif confirmed_severity <= 8:
            return "auto_respond"
        else:
            return "human_approval_required"

    # ============================================
    # EXECUTE TASK — Called by BaseAgent
    # ============================================

    def execute_task(self, task: dict, incident_context: dict) -> dict:
        """
        Main Triage Agent logic. Called by BaseAgent when a task is received.

        Returns only task_id, success, output - BaseAgent.submit_result()
        fills in agent_name and timestamp automatically, then validates the
        full dict against shared.models.AgentResult before sending it on.
        """
        incident_id = task.get("incident_id", "UNKNOWN")

        print(f"\n[{AGENT_TRIAGE}] Processing incident {incident_id}")
        print(f"[{AGENT_TRIAGE}] Type: {incident_context.get('rule_description', 'Unknown')}")

        confirmed_severity = self.confirm_severity(incident_context)
        blast_radius = self.estimate_blast_radius(incident_context)

        fp_discount = self._check_false_positive_discount(incident_context)
        fp_probability = 0.34 if fp_discount > 0 else 0.05

        escalation = self.make_escalation_decision(confirmed_severity)

        print(f"[{AGENT_TRIAGE}] Results:")
        print(f"  Confirmed Severity: {confirmed_severity}")
        print(f"  FP Probability: {fp_probability}")
        print(f"  Blast Radius: {blast_radius['level']} ({blast_radius['affected_systems_count']} systems)")
        print(f"  Escalation: {escalation}")

        return {
            "task_id": task.get("task_id"),
            "success": True,
            "output": {
                "confirmed_severity": confirmed_severity,
                "false_positive_probability": fp_probability,
                "blast_radius": blast_radius["level"],
                "affected_systems_count": blast_radius["affected_systems_count"],
                "blast_radius_description": blast_radius["description"],
                "escalation_decision": escalation,
                "reasoning": (
                    f"Severity confirmed at {confirmed_severity} "
                    f"(base: {incident_context.get('severity')}, "
                    f"asset: {incident_context.get('asset_criticality')}, "
                    f"multi-stage: {incident_context.get('is_multi_stage')}). "
                    f"Blast radius {blast_radius['level']}. "
                    f"Decision: {escalation}."
                )
            }
        }


# Run triage agent
if __name__ == "__main__":
    agent = TriageAgent()
    agent.run()
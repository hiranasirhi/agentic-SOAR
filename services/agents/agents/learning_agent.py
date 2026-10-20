# agents/learning_agent.py

import json
import os
import time
import threading

import psycopg2
import psycopg2.extras
import redis
import requests

from datetime import datetime, timezone

from langchain_community.llms import Ollama
from dotenv import load_dotenv

from shared.constants import (
    AGENT_LEARNING,
    REDIS_AGENT_HEARTBEAT,
    AGENT_HEARTBEAT_INTERVAL,
    AGENT_HEARTBEAT_TTL,
)

from agents.rule_tuning import on_incident_closed_as_false_positive


load_dotenv()

VERIFICATION_WAIT_TIMEOUT = int(
    os.getenv("VERIFICATION_WAIT_TIMEOUT_SECONDS", "300")
)
VERIFICATION_POLL_INTERVAL = int(
    os.getenv("VERIFICATION_POLL_INTERVAL_SECONDS", "10")
)

# Sentinel used in ChromaDB metadata for "MTTR not applicable" (no
# expected_state rows, or none ever verified OK). ChromaDB metadata
# cannot hold a bare null, so 0 was previously used by mistake - 0
# reads as "resolved instantly", which is wrong for a failed/никогда
# verified action. -1 is unambiguous and easy to filter out in any
# downstream MTTR aggregation (WHERE resolution_time_minutes >= 0).
MTTR_NOT_APPLICABLE = -1


class LearningAgent:
    """
    Learning Agent - reads directly from Postgres instead of polling
    the Orchestrator over HTTP. Not part of any TaskPlan; runs its
    own 30-second sweep. See class docstring in prior version for
    full schema notes - unchanged here except where noted below.
    """

    def __init__(self):

        self.agent_name = AGENT_LEARNING

        self.orchestrator_url = os.getenv(
            "ORCHESTRATOR_URL",
            "http://localhost:8000"
        )

        self.redis_client = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            decode_responses=True
        )

        self.postgres_dsn = os.getenv("POSTGRES_DSN")

        if not self.postgres_dsn:
            self.postgres_dsn = (
                f"dbname={os.getenv('POSTGRES_DB', 'soar_db')} "
                f"user={os.getenv('POSTGRES_USER', 'soar_user')} "
                f"password={os.getenv('POSTGRES_PASSWORD', '')} "
                f"host={os.getenv('POSTGRES_HOST', 'localhost')} "
                f"port={os.getenv('POSTGRES_PORT', '5432')}"
            )

        self.llm = Ollama(
            model=os.getenv("OLLAMA_MODEL", "qwen2.5:14b"),
            base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
            temperature=0
        )

        self.running = False

        print(
            "[learning] Initialized — reading closed incidents "
            "directly from Postgres (status='closed' AND "
            "learned_at IS NULL)"
        )

    # ============================================================
    # HEARTBEAT
    # ============================================================

    def _publish_heartbeat(self):

        heartbeat_key = REDIS_AGENT_HEARTBEAT.format(
            name=self.agent_name
        )

        while self.running:
            try:
                self.redis_client.setex(
                    heartbeat_key,
                    AGENT_HEARTBEAT_TTL,
                    "alive"
                )
            except Exception as e:
                print(f"[learning] Heartbeat error: {e}")

            time.sleep(AGENT_HEARTBEAT_INTERVAL)

    # ============================================================
    # POSTGRES HELPERS
    # ============================================================

    def _pg_connect(self):
        return psycopg2.connect(self.postgres_dsn)

    def get_closed_unlearned_incidents(self) -> list:
        conn = self._pg_connect()
        try:
            with conn.cursor(
                cursor_factory=psycopg2.extras.RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM incidents
                    WHERE status = 'closed'
                      AND learned_at IS NULL
                    """
                )
                return cur.fetchall()
        finally:
            conn.close()

    def get_agent_actions(self, incident_id: str) -> list:
        conn = self._pg_connect()
        try:
            with conn.cursor(
                cursor_factory=psycopg2.extras.RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    SELECT agent_name, action, success, output,
                           error_message, executed_at
                    FROM agent_actions
                    WHERE incident_id = %s
                    ORDER BY executed_at
                    """,
                    (incident_id,)
                )
                return cur.fetchall()
        finally:
            conn.close()

    def wait_for_first_verification(self, incident_id: str):
        """Unchanged from prior version - see original docstring."""

        conn = self._pg_connect()
        try:
            with conn.cursor(
                cursor_factory=psycopg2.extras.RealDictCursor
            ) as cur:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM expected_state "
                    "WHERE incident_id = %s",
                    (incident_id,)
                )
                if cur.fetchone()["n"] == 0:
                    return None, None
        finally:
            conn.close()

        waited = 0

        while waited < VERIFICATION_WAIT_TIMEOUT:

            conn = self._pg_connect()
            try:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cur:
                    cur.execute(
                        """
                        SELECT MIN(first_ok_at) AS first_ok_at
                        FROM expected_state
                        WHERE incident_id = %s AND first_ok_at IS NOT NULL
                        """,
                        (incident_id,)
                    )
                    row = cur.fetchone()
                    if row and row["first_ok_at"]:
                        return row["first_ok_at"], True
            finally:
                conn.close()

            time.sleep(VERIFICATION_POLL_INTERVAL)
            waited += VERIFICATION_POLL_INTERVAL

        conn = self._pg_connect()
        try:
            with conn.cursor(
                cursor_factory=psycopg2.extras.RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    SELECT MIN(first_verified_at) AS first_verified_at
                    FROM expected_state
                    WHERE incident_id = %s
                      AND first_verified_at IS NOT NULL
                    """,
                    (incident_id,)
                )
                row = cur.fetchone()
                if row and row["first_verified_at"]:
                    return row["first_verified_at"], False
        finally:
            conn.close()

        return None, None

    def _mark_learned(self, incident_id: str, false_positive: bool):
        conn = self._pg_connect()
        try:
            with conn, conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE incidents
                    SET status = 'learned',
                        learned_at = NOW(),
                        false_positive = %s
                    WHERE incident_id = %s
                    """,
                    (false_positive, incident_id)
                )
        finally:
            conn.close()

    # ============================================================
    # PERSIST POSTMORTEM (NEW)
    # ============================================================

    def _persist_postmortem(self, incident_id: str, report: str):
        """
        Writes the post-mortem into Postgres so it survives beyond
        Redis's TTL and is queryable independently of the incident
        row. Redis cache (below, unchanged) stays as a fast-access
        copy for the Dashboard.
        """
        try:
            conn = self._pg_connect()
            try:
                with conn, conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO postmortems (incident_id, report)
                        VALUES (%s, %s)
                        ON CONFLICT (incident_id) DO UPDATE SET
                            report = EXCLUDED.report,
                            created_at = NOW()
                        """,
                        (incident_id, report)
                    )
                print(f"[learning] Postmortem persisted to Postgres for {incident_id}")
            finally:
                conn.close()
        except Exception as e:
            print(f"[learning] Could not persist postmortem to Postgres: {e}")

    # ============================================================
    # PERSIST RULE RECOMMENDATIONS (NEW)
    # ============================================================

    def _persist_rule_recommendations(self, incident: dict, recommendations: list):
        """
        generate_rule_recommendations() previously only wrote to
        Redis (30-day TTL). Per the proposal, rule-tuning recs should
        surface fallback-plan usage and high-FP-probability cases for
        analyst review regardless of whether the incident was
        ultimately confirmed as a false positive - update_rule_tuning()
        only covers the FP-confirmed case, so this covers the rest.
        """
        if not recommendations:
            return

        try:
            conn = self._pg_connect()
            try:
                with conn, conn.cursor() as cur:
                    for rec in recommendations:
                        rule_id = (
                            rec.get("rule_id")
                            or incident.get("mitre_technique")
                            or incident.get("incident_id")
                        )
                        cur.execute(
                            """
                            INSERT INTO rule_tuning
                                (rule_id, recommendation, incident_count)
                            VALUES (%s, %s, 1)
                            """,
                            (rule_id, rec.get("message", ""))
                        )
                print(
                    f"[learning] {len(recommendations)} recommendation(s) "
                    f"persisted to Postgres rule_tuning"
                )
            finally:
                conn.close()
        except Exception as e:
            print(f"[learning] Could not persist recommendations to Postgres: {e}")

    # ============================================================
    # ENRICH INCIDENT WITH raw_event FALLBACK FIELDS
    # ============================================================

    def _enrich_incident(self, incident: dict) -> dict:
        raw_event = incident.get("raw_event") or {}
        return {**raw_event, **incident}

    # ============================================================
    # BUILD BEHAVIORAL TIMELINE (rewritten - full narrative)
    # ============================================================

    def build_behavioral_timeline(
        self,
        incident: dict,
        agent_actions: list
    ) -> str:
        """
        Rewritten to produce a narrative closer in style to
        seed_chromadb.py's synthetic incidents, rather than
        concatenated field values. MITRE technique/tactic are named
        explicitly, since build_chromadb_query() in react_engine.py
        builds future search queries around those exact terms - a
        document that never mentions them will retrieve poorly even
        for a genuinely similar future incident.
        """

        parts = []

        rule_desc = incident.get("rule_description", "an unspecified alert")
        source_ip = incident.get("source_ip", "an unknown source IP")
        asset = incident.get("asset_criticality", "unknown")
        hostname = incident.get("hostname", "an unspecified host")
        username = incident.get("username")
        mitre_technique = incident.get("mitre_technique", "")
        mitre_tactic = incident.get("mitre_tactic", "")

        mitre_clause = ""
        if mitre_technique or mitre_tactic:
            mitre_clause = (
                f" (MITRE technique {mitre_technique or 'unknown'}, "
                f"tactic {mitre_tactic or 'unknown'})"
            )

        opening = (
            f"Source IP {source_ip} triggered '{rule_desc}'{mitre_clause} "
            f"on host {hostname}, a {asset} criticality asset."
        )
        if username:
            opening += f" Associated user account: {username}."

        parts.append(opening)

        for row in agent_actions:

            agent_name = row.get("agent_name", "")
            output = row.get("output") or {}
            success = row.get("success", False)
            error_message = row.get("error_message")

            if agent_name == "triage":
                confirmed_sev = output.get("confirmed_severity", "unknown")
                escalation = output.get("escalation_decision", "unknown")
                fp_prob = output.get("false_positive_probability")
                sentence = (
                    f"Triage confirmed severity {confirmed_sev} and "
                    f"escalated with decision '{escalation}'."
                )
                if fp_prob is not None:
                    sentence += f" False-positive probability estimated at {fp_prob:.0%}."
                parts.append(sentence)

            elif agent_name == "investigation":
                timeline = output.get("threat_timeline", [])
                ti_confidence = output.get("ti_confidence", 0)
                verdict = output.get("ioc_reputation", {}).get("overall_verdict", "")

                sentence = f"Investigation returned a threat-intelligence confidence of {ti_confidence}"
                if verdict:
                    sentence += f", verdict: {verdict}"
                sentence += "."
                if timeline:
                    sentence += (
                        f" Reconstructed timeline spans {len(timeline)} event(s), "
                        f"from {timeline[0].get('timestamp', 'T+0')} to "
                        f"'{timeline[-1].get('event_type', 'an unspecified event')}'."
                    )
                if output.get("lateral_movement_detected", False):
                    affected = output.get("affected_assets", [])
                    sentence += (
                        f" Lateral movement was detected, affecting "
                        f"{len(affected)} additional system(s)."
                    )
                parts.append(sentence)

            elif agent_name in ("response", "containment"):
                actions = output.get("actions_taken", [])
                containment_results = output.get("containment_results", [])
                action_desc = ", ".join(
                    a.get("action", "unknown") for a in actions if isinstance(a, dict)
                ) or ("network containment" if containment_results else "an action")

                if success:
                    parts.append(
                        f"{agent_name.capitalize()} successfully executed {action_desc}."
                    )
                else:
                    # This is the gap the thin version had - WHY it failed,
                    # not just that it did.
                    reason = (
                        error_message
                        or output.get("failure_reason")
                        or "no failure reason was recorded"
                    )
                    parts.append(
                        f"{agent_name.capitalize()} attempted {action_desc} but FAILED. "
                        f"Reason: {reason}."
                    )

            elif agent_name == "notification":
                case_id = output.get("thehive_case_id")
                if case_id:
                    parts.append(f"A TheHive case ({case_id}) was created and the SOC team notified.")

        return " ".join(parts)

    # ============================================================
    # DETERMINE OUTCOME (rewritten - distinguishes failed response)
    # ============================================================

    def determine_outcome(self, agent_actions: list) -> str:

        response_rows = [
            row for row in agent_actions
            if row.get("agent_name") in ("response", "containment")
        ]

        if any(row.get("success", False) for row in response_rows):
            return "CONTAINED"

        if response_rows:
            # An action was attempted but none succeeded - distinct
            # from "nothing was attempted at all". Previously this
            # fell through to INVESTIGATED_NO_ACTION, which misrepresents
            # what actually happened (e.g. your containment-failed example).
            return "RESPONSE_FAILED"

        if agent_actions:
            return "INVESTIGATED_NO_ACTION"

        return "UNKNOWN"

    def determine_false_positive(self, agent_actions: list) -> bool:
        return any(
            row.get("agent_name") == "triage"
            and (row.get("output") or {}).get(
                "false_positive_probability", 0
            ) > 0.7
            for row in agent_actions
        )

    # ============================================================
    # COMPUTE RESOLUTION TIME
    # ============================================================

    def compute_resolution_minutes(self, created_at, first_ok_at) -> int:
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if first_ok_at.tzinfo is None:
            first_ok_at = first_ok_at.replace(tzinfo=timezone.utc)

        return max(
            0,
            int((first_ok_at - created_at).total_seconds() / 60)
        )

    # ============================================================
    # STORE INCIDENT IN CHROMADB
    # ============================================================

    def store_in_chromadb(
        self,
        incident_id: str,
        behavioral_timeline: str,
        outcome: str,
        resolution_minutes,
        false_positive: bool
    ) -> bool:

        try:
            response = requests.post(
                f"{self.orchestrator_url}/memory/store_incident",
                json={
                    "incident_id": incident_id,
                    "behavioral_timeline": behavioral_timeline,
                    "outcome": outcome,
                    "resolution_time_minutes": resolution_minutes,
                    "false_positive": false_positive
                },
                timeout=15
            )
            response.raise_for_status()
            success = response.json().get("success", False)

            print(
                f"[learning] Stored in ChromaDB: {success} "
                f"(false_positive={false_positive}, "
                f"resolution_minutes={resolution_minutes})"
            )
            return success

        except Exception as e:
            print(f"[learning] ChromaDB store error: {e}")
            return False

    # ============================================================
    # RULE TUNING (false-positive-specific, Postgres-backed)
    # ============================================================

    def update_rule_tuning(self, incident: dict, false_positive: bool):

        if not false_positive:
            return

        raw_event = incident.get("raw_event") or {}
        rule_tuning_incident = {
            **incident,
            "rule_id": raw_event.get("rule_id"),
        }

        try:
            conn = self._pg_connect()
            try:
                on_incident_closed_as_false_positive(
                    conn, rule_tuning_incident
                )
            finally:
                conn.close()
        except Exception as e:
            print(f"[learning] Rule-tuning update failed: {e}")

    # ============================================================
    # GENERATE POSTMORTEM
    # ============================================================

    def generate_postmortem(self, incident: dict, agent_actions: list) -> str:

        prompt = f"""
Generate a brief post-mortem report for this security incident.

Incident:
{json.dumps(incident, indent=2, default=str)}

Agent actions:
{json.dumps(agent_actions, indent=2, default=str)}

Include:
1. What happened (2-3 sentences)
2. What worked well
3. What could be improved
4. Recommendations to prevent recurrence

Keep it under 300 words.
"""

        try:
            return self.llm.invoke(prompt)
        except Exception as e:
            print(f"[learning] Post-mortem generation raised: {e}")
            return f"Post-mortem generation failed: {e}"

    # ============================================================
    # GENERATE RULE RECOMMENDATIONS
    # ============================================================

    def generate_rule_recommendations(
        self,
        incident: dict,
        agent_actions: list
    ) -> list:

        recommendations = []
        incident_id = incident.get("incident_id")

        plan_data = self.redis_client.get(f"taskplan:{incident_id}")

        if plan_data:
            try:
                plan = json.loads(plan_data)
                reasoning = plan.get("reasoning_summary", "")

                if "Fallback" in reasoning or "SAFETY NET" in reasoning:
                    recommendations.append({
                        "type": "llm_reliability",
                        "message": (
                            "Fallback plan or safety-net enforcement "
                            "was used — LLM may need prompt refinement"
                        ),
                        "incident_id": incident_id
                    })
            except json.JSONDecodeError:
                print("[learning] Invalid task plan JSON")

        for row in agent_actions:

            if row.get("agent_name") != "triage":
                continue

            fp_prob = (row.get("output") or {}).get(
                "false_positive_probability", 0
            )

            if fp_prob > 0.5:
                recommendations.append({
                    "type": "false_positive_risk",
                    "message": (
                        f"High FP probability ({fp_prob}) detected. "
                        f"Consider tuning rule "
                        f"{incident.get('mitre_technique')}"
                    ),
                    "rule_id": incident.get("mitre_technique")
                })

        return recommendations

    # ============================================================
    # PROCESS CLOSED INCIDENT
    # ============================================================

    def process_closed_incident(self, incident: dict) -> bool:

        incident_id = incident["incident_id"]

        print(f"\n[learning] Processing closed incident: {incident_id}")

        enriched_incident = self._enrich_incident(incident)
        agent_actions = self.get_agent_actions(incident_id)

        behavioral_timeline = self.build_behavioral_timeline(
            enriched_incident, agent_actions
        )
        print(f"[learning] Timeline: {behavioral_timeline[:150]}...")

        outcome = self.determine_outcome(agent_actions)
        false_positive = self.determine_false_positive(agent_actions)

        self.update_rule_tuning(incident, false_positive)

        first_ts, was_ok = self.wait_for_first_verification(incident_id)

        if first_ts is None:
            resolution_minutes = None
            print(
                f"[learning] No verification result for {incident_id} - "
                f"MTTR stored as not applicable"
            )
        else:
            resolution_minutes = self.compute_resolution_minutes(
                incident["created_at"], first_ts
            )
            print(
                f"[learning] MTTR={resolution_minutes}min "
                f"(first_{'ok' if was_ok else 'verified'}_at={first_ts})"
            )

        # FIX: -1 sentinel instead of 0. ChromaDB metadata can't hold
        # null, but 0 misleadingly reads as "resolved instantly".
        resolution_minutes_for_storage = (
            MTTR_NOT_APPLICABLE if resolution_minutes is None else resolution_minutes
        )

        stored = self.store_in_chromadb(
            incident_id,
            behavioral_timeline,
            outcome,
            resolution_minutes_for_storage,
            false_positive
        )

        if not stored:
            print(
                f"[learning] ChromaDB storage FAILED for {incident_id} - "
                f"incident remains CLOSED (not marked learned) and will "
                f"be retried on the next polling cycle"
            )
            return False

        print("[learning] Generating post-mortem report...")
        postmortem = self.generate_postmortem(enriched_incident, agent_actions)

        self.redis_client.setex(
            f"postmortem:{incident_id}", 86400 * 7, postmortem
        )
        # FIX: also persist durably to Postgres, not just a 7-day Redis cache.
        self._persist_postmortem(incident_id, postmortem)

        recommendations = self.generate_rule_recommendations(
            enriched_incident, agent_actions
        )

        if recommendations:
            self.redis_client.setex(
                f"recommendations:{incident_id}",
                86400 * 30,
                json.dumps(recommendations)
            )
            print(f"[learning] {len(recommendations)} recommendations cached in Redis")

        # FIX: persist to Postgres rule_tuning regardless of false_positive
        # status - previously only update_rule_tuning() (FP-only) wrote here.
        self._persist_rule_recommendations(enriched_incident, recommendations)

        self._mark_learned(incident_id, false_positive)

        print(f"[learning] Learning complete for {incident_id}")

        return True

    # ============================================================
    # RUN
    # ============================================================

    def run(self):

        self.running = True

        threading.Thread(
            target=self._publish_heartbeat,
            daemon=True,
            name="learning-heartbeat"
        ).start()

        print("[learning] Started — polling Postgres for closed incidents")

        while self.running:

            try:
                for incident in self.get_closed_unlearned_incidents():
                    self.process_closed_incident(incident)

            except KeyboardInterrupt:
                print("\n[learning] Stopping...")
                self.running = False
                break

            except Exception as e:
                print(f"[learning] Error: {e}")

            time.sleep(30)

        print("[learning] Stopped")


if __name__ == "__main__":
    agent = LearningAgent()
    agent.run()
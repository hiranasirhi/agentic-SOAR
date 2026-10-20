"""
rule_tuning.py

Implements the piece of the Learning Agent's scope that the audit script
(audit/audit_rule_tuning.py) checks for. Two responsibilities:

  1. record_false_positive() — call this whenever an incident is closed
     and marked as a false positive. Upserts an aggregate count into
     false_positive_patterns (grouped by rule_id, across all source IPs —
     the existing table is keyed more granularly by source_ip too, which
     this preserves, but recommendation logic below reasons at the rule_id
     level since that's what an analyst would actually go tune).

  2. maybe_generate_recommendation() — call this right after step 1. Checks
     whether the rule has crossed FP_THRESHOLD false positives, and if so,
     writes ONE new row to rule_tuning with a generated recommendation.
     Includes duplicate-suppression: won't write a second recommendation
     for the same rule within RECOMMENDATION_COOLDOWN_DAYS, so closing 10
     false positives in a row doesn't spam 10 near-identical rows.

Where this plugs in: Learning Agent's existing incident-closure handler
(wherever it currently does "Records MTTD/MTTR in Postgres, writes
embedding to ChromaDB, updates false positive records" per the proposal) —
see INTEGRATION.md in this folder for the exact call site.
"""

import os
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras

FP_THRESHOLD = int(os.environ.get("RULE_TUNING_FP_THRESHOLD", "3"))
RECOMMENDATION_COOLDOWN_DAYS = int(os.environ.get("RULE_TUNING_COOLDOWN_DAYS", "7"))


def record_false_positive(conn, incident: dict) -> None:
    """incident must have: source_ip, mitre_technique. rule_id is derived
    from mitre_technique if the incident doesn't carry a separate rule_id
    field — adjust the `rule_id = incident.get(...)` line below if your
    Detection Engine's rule IDs are a distinct value from the technique
    (e.g. 'RULE-104' rather than 'T1046')."""
    rule_id = incident.get("rule_id") or incident["mitre_technique"]
    source_ip = incident.get("source_ip")
    mitre_technique = incident["mitre_technique"]

    with conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, fp_count FROM false_positive_patterns
            WHERE rule_id = %s AND source_ip = %s
            """,
            (rule_id, source_ip),
        )
        row = cur.fetchone()

        if row:
            cur.execute(
                "UPDATE false_positive_patterns SET fp_count = fp_count + 1, last_seen = NOW() WHERE id = %s",
                (row[0],),
            )
        else:
            cur.execute(
                """
                INSERT INTO false_positive_patterns (source_ip, rule_id, mitre_technique, fp_count, last_seen)
                VALUES (%s, %s, %s, 1, NOW())
                """,
                (source_ip, rule_id, mitre_technique),
            )


def _total_fp_count_for_rule(conn, rule_id: str) -> int:
    """Aggregates across all source_ips for this rule — a rule firing
    false positives from 3 different IPs is just as much a tuning signal
    as 3 false positives from one IP."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COALESCE(SUM(fp_count), 0) FROM false_positive_patterns WHERE rule_id = %s",
            (rule_id,),
        )
        return cur.fetchone()[0]


def _recent_recommendation_exists(conn, rule_id: str) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECOMMENDATION_COOLDOWN_DAYS)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM rule_tuning WHERE rule_id = %s AND created_at >= %s LIMIT 1",
            (rule_id, cutoff),
        )
        return cur.fetchone() is not None


def _build_recommendation_text(rule_id: str, mitre_technique: str, fp_count: int) -> str:
    """Simple, deterministic template — not LLM-generated. This is
    intentional: rule-tuning recommendations are a data-driven signal for
    a human analyst to act on, not something that benefits from
    non-deterministic phrasing, and it keeps this function testable
    without an LLM call in the loop."""
    return (
        f"Rule {rule_id} (technique {mitre_technique}) has produced {fp_count} false "
        f"positives. Consider raising the detection threshold, adding an allowlist "
        f"entry for the recurring source(s), or reviewing the rule's match logic "
        f"for over-broad conditions."
    )


def maybe_generate_recommendation(conn, incident: dict) -> bool:
    """Returns True if a new recommendation row was written, False otherwise
    (threshold not met, or suppressed by cooldown)."""
    rule_id = incident.get("rule_id") or incident["mitre_technique"]
    mitre_technique = incident["mitre_technique"]

    fp_count = _total_fp_count_for_rule(conn, rule_id)
    if fp_count < FP_THRESHOLD:
        return False

    if _recent_recommendation_exists(conn, rule_id):
        return False

    recommendation = _build_recommendation_text(rule_id, mitre_technique, fp_count)

    with conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO rule_tuning (rule_id, recommendation, incident_count, created_at)
            VALUES (%s, %s, %s, NOW())
            """,
            (rule_id, recommendation, fp_count),
        )

    return True


def on_incident_closed_as_false_positive(conn, incident: dict) -> None:
    """The single entry point Learning Agent's closure handler should call.
    Wraps both steps above — see INTEGRATION.md for the exact call site."""
    record_false_positive(conn, incident)
    wrote = maybe_generate_recommendation(conn, incident)
    if wrote:
        print(f"[RULE-TUNING] new recommendation written for rule_id={incident.get('rule_id') or incident['mitre_technique']}")

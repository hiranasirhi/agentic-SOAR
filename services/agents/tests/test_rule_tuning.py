"""
test_rule_tuning.py

Run this BEFORE integrating into the real Learning Agent, to confirm the
logic actually behaves as intended against your real Postgres instance.
Simulates 3 false-positive closures for the same synthetic rule and
confirms a recommendation gets written on the 3rd (matching
FP_THRESHOLD's default of 3), then confirms a 4th closure does NOT write
a duplicate (cooldown suppression).

This inserts and cleans up its own test rows — safe to run against your
real database, but read the cleanup section before running if you want
to keep the test data around to inspect manually.

Usage:
    python test_rule_tuning.py
"""

import os
import psycopg2

from rule_tuning import on_incident_closed_as_false_positive

PG_DSN = os.environ["POSTGRES_DSN"]
TEST_RULE_ID = "TEST-RULE-9999"
TEST_TECHNIQUE = "T9999"


def cleanup(conn):
    with conn, conn.cursor() as cur:
        cur.execute("DELETE FROM false_positive_patterns WHERE rule_id = %s", (TEST_RULE_ID,))
        cur.execute("DELETE FROM rule_tuning WHERE rule_id = %s", (TEST_RULE_ID,))


def count_recommendations(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM rule_tuning WHERE rule_id = %s", (TEST_RULE_ID,))
        return cur.fetchone()[0]


def main():
    conn = psycopg2.connect(PG_DSN)
    cleanup(conn)  # start clean in case a previous run left rows behind

    fake_incident = {
        "rule_id": TEST_RULE_ID,
        "mitre_technique": TEST_TECHNIQUE,
        "source_ip": "10.0.0.99",
    }

    print("Closing false positive #1...")
    on_incident_closed_as_false_positive(conn, fake_incident)
    assert count_recommendations(conn) == 0, "should NOT recommend yet (below threshold)"
    print("  OK — no recommendation yet (correct, below threshold)")

    print("Closing false positive #2...")
    on_incident_closed_as_false_positive(conn, fake_incident)
    assert count_recommendations(conn) == 0, "should NOT recommend yet (still below threshold)"
    print("  OK — still no recommendation (correct)")

    print("Closing false positive #3...")
    on_incident_closed_as_false_positive(conn, fake_incident)
    assert count_recommendations(conn) == 1, "SHOULD have written a recommendation at threshold"
    print("  OK — recommendation written at threshold")

    print("Closing false positive #4 (testing cooldown suppression)...")
    on_incident_closed_as_false_positive(conn, fake_incident)
    assert count_recommendations(conn) == 1, "should NOT write a 2nd recommendation within cooldown"
    print("  OK — cooldown correctly suppressed duplicate")

    print("\nAll checks passed.")

    cleanup(conn)
    print("Test rows cleaned up.")
    conn.close()


if __name__ == "__main__":
    main()

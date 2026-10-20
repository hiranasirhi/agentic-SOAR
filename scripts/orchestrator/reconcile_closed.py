import json
import redis
import psycopg2

redis_client = redis.Redis(
    host="100.71.186.0",
    port=6379,
    decode_responses=True
)

conn = psycopg2.connect(
    host="100.71.186.0",
    port=5432,
    dbname="soar_db",
    user="soar_user",
    password="soar_password123"
)

cur = conn.cursor()

archive_keys = sorted(
    redis_client.keys("taskplan_archive:*")
)

print("ARCHIVED PLANS FOUND:", len(archive_keys))
print()

closed = 0
skipped = 0
missing = 0

for key in archive_keys:

    incident_id = key.split(":", 1)[1]

    data = redis_client.get(key)

    if not data:
        print(f"SKIP {incident_id}: archive data missing")
        skipped += 1
        continue

    plan = json.loads(data)

    actions = plan.get("actions", [])

    statuses = []

    for action in actions:
        status = action.get("final_status")

        if status is None:
            task_id = action.get("task_id")

            if task_id:
                status = redis_client.get(
                    f"task_status:{task_id}"
                )

        statuses.append(status)

    all_terminal = (
        len(actions) > 0
        and all(
            status in ("completed", "failed")
            for status in statuses
        )
    )

    if not all_terminal:
        print(
            f"SKIP {incident_id}: "
            f"non-terminal statuses={statuses}"
        )
        skipped += 1
        continue

    cur.execute(
        """
        UPDATE incidents
        SET
            status = 'closed',
            closed_at = COALESCE(closed_at, NOW())
        WHERE incident_id = %s
          AND status IN ('open', 'dispatched')
        RETURNING incident_id, status, closed_at
        """,
        (incident_id,)
    )

    row = cur.fetchone()

    if row:
        conn.commit()

        print(
            f"CLOSED {row[0]} | "
            f"status={row[1]} | "
            f"closed_at={row[2]}"
        )

        closed += 1

    else:

        cur.execute(
            """
            SELECT incident_id, status, closed_at
            FROM incidents
            WHERE incident_id = %s
            """,
            (incident_id,)
        )

        existing = cur.fetchone()

        if existing:
            print(
                f"UNCHANGED {incident_id} | "
                f"already status={existing[1]}"
            )
        else:
            print(
                f"MISSING {incident_id}: "
                f"no PostgreSQL incident record"
            )
            missing += 1

cur.close()
conn.close()

print()
print("================================")
print("RECONCILIATION COMPLETE")
print("================================")
print("CLOSED   =", closed)
print("SKIPPED  =", skipped)
print("MISSING  =", missing)

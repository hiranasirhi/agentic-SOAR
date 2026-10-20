import redis
import psycopg2
import json

r = redis.Redis(
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

cur.execute("""
    SELECT incident_id, agent_name, action
    FROM agent_actions
""")

pg_rows = cur.fetchall()

pg_set = set(
    (str(row[0]), str(row[1]), str(row[2]))
    for row in pg_rows
)

plans = sorted(r.keys("taskplan_archive:*"))

missing_pg = []
missing_redis = []
total_actions = 0

for key in plans:

    incident_id = key.split(":", 1)[1]

    plan_raw = r.get(key)

    if not plan_raw:
        continue

    plan = json.loads(plan_raw)

    for action in plan.get("actions", []):

        total_actions += 1

        task_id = action.get("task_id")
        agent = action.get("agent")
        action_name = action.get("action")

        result_raw = r.get("result:" + task_id)

        if not result_raw:
            missing_redis.append({
                "incident": incident_id,
                "task_id": task_id,
                "agent": agent,
                "action": action_name
            })
            continue

        result = json.loads(result_raw)

        pg_key = (
            incident_id,
            result.get("agent_name", agent),
            action_name
        )

        if pg_key not in pg_set:

            missing_pg.append({
                "incident": incident_id,
                "task_id": task_id,
                "agent": result.get("agent_name", agent),
                "action": action_name,
                "success": result.get("success")
            })

print("ARCHIVED INCIDENTS =", len(plans))
print("ARCHIVED ACTIONS =", total_actions)
print("MISSING REDIS RESULTS =", len(missing_redis))
print("MISSING FROM POSTGRES =", len(missing_pg))
print()

if missing_redis:
    print("MISSING REDIS:")
    for x in missing_redis:
        print(x)

if missing_pg:
    print("MISSING FROM POSTGRES:")
    for x in missing_pg:
        print(
            x["incident"],
            "| task=", x["task_id"],
            "| agent=", x["agent"],
            "| action=", x["action"],
            "| success=", x["success"]
        )

cur.close()
conn.close()

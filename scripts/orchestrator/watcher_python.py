import redis, time, json

r = redis.Redis(host="100.71.186.0", port=6379, decode_responses=True)

seen = set()
while True:
    for key in r.keys("taskplan:*"):
        
        if key not in seen:
            seen.add(key)
            plan = json.loads(r.get(key))
            print(f"\n=== NEW TASKPLAN: {key} ===")
            print(f"incident_id: {plan.get('incident_id')}")
            for action in plan.get("actions", []):
                print(f"  task_id={action['task_id']} agent={action['agent']} action={action['action']}")
    time.sleep(1)
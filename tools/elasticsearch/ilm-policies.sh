#!/bin/sh
set -e

# ES_URL is https://100.98.120.36:9200 (Person B's Tailscale IP, confirmed).
# -k because this is almost certainly a self-signed cert on a lab ES node —
# if Person B set up a real CA-signed cert, drop -k and pass --cacert instead.
# If ES has security enabled (auth), also add: -u "$ES_USER:$ES_PASSWORD"

if [ -z "$ES_URL" ]; then
  echo "[ES-INIT] ES_URL not set — aborting" >&2
  exit 1
fi

echo "[ES-INIT] applying ILM policy: wazuh-alerts-policy (delete after 3 days)"
curl -sk -X PUT "${ES_URL}/_ilm/policy/wazuh-alerts-policy" \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": {
      "phases": {
        "hot": { "actions": {} },
        "delete": {
          "min_age": "3d",
          "actions": { "delete": {} }
        }
      }
    }
  }' \
  --fail-with-body \
  && echo "" && echo "[ES-INIT] wazuh-alerts-policy OK"

echo "[ES-INIT] applying ILM policy: soar-events-policy (delete after 7 days)"
curl -sk -X PUT "${ES_URL}/_ilm/policy/soar-events-policy" \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": {
      "phases": {
        "hot": { "actions": {} },
        "delete": {
          "min_age": "7d",
          "actions": { "delete": {} }
        }
      }
    }
  }' \
  --fail-with-body \
  && echo "" && echo "[ES-INIT] soar-events-policy OK"

# Attach the policies to the actual index templates so NEW indices pick them up.
# If wazuh-alerts-* and soar-events indices already exist without a lifecycle
# policy attached, existing indices won't retroactively get one just from the
# policy existing — you also need to PUT it onto the index/template settings.
# Adjust the index/template names below to match what's actually in your ES
# (check with: curl -sk "$ES_URL/_cat/indices?v").

echo "[ES-INIT] attaching soar-events-policy to soar-events index"
curl -sk -X PUT "${ES_URL}/soar-events/_settings" \
  -H 'Content-Type: application/json' \
  -d '{ "index.lifecycle.name": "soar-events-policy" }' \
  --fail-with-body \
  && echo "" && echo "[ES-INIT] soar-events index attached"

echo "[ES-INIT] attaching wazuh-alerts-policy to wazuh-alerts-* indices"
curl -sk -X PUT "${ES_URL}/wazuh-alerts-*/_settings" \
  -H 'Content-Type: application/json' \
  -d '{ "index.lifecycle.name": "wazuh-alerts-policy" }' \
  --fail-with-body \
  && echo "" && echo "[ES-INIT] wazuh-alerts-* indices attached"

echo "[ES-INIT] done"

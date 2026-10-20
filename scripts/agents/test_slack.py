# test_slack.py
import requests, os
from dotenv import load_dotenv
load_dotenv()

WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")

response = requests.post(
    WEBHOOK,
    json={"text": "✅ PROTEGO Notification Agent Slack working — #soar-incidents"}
)
print(f"Status: {response.status_code}")
# Check #soar-incidents channel in your Slack app
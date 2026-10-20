import requests
import os
from dotenv import load_dotenv

load_dotenv()

WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")

print("Webhook loaded:", bool(WEBHOOK))
print("Webhook prefix:", WEBHOOK[:30] if WEBHOOK else "EMPTY")

if not WEBHOOK:
    print("ERROR: SLACK_WEBHOOK_URL was not loaded from .env")
    exit(1)

response = requests.post(
    WEBHOOK,
    json={"text": "from watchdog saying hi and hello"},
    timeout=10
)

print("Status:", response.status_code)
print("Response:", response.text)
# test_misp.py
# Test MISP API independently

import requests
import os
from dotenv import load_dotenv

load_dotenv()

MISP_URL = os.getenv("MISP_URL", "")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")

if not MISP_URL or not MISP_API_KEY:
    print("ERROR: MISP_URL or MISP_API_KEY not set in .env")
    exit(1)

def test_misp_connection():
    """Test basic MISP connectivity"""
    print(f"Testing MISP connection at {MISP_URL}...")
    
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    response = requests.get(
        f"{MISP_URL}/events/index",
        headers=headers,
        timeout=60,
        verify=False
    )
    
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        events = response.json()
        print(f"MISP connection successful!")
        print(f"Total events in MISP: {len(events)}")
        return True
    else:
        print(f"MISP connection failed: {response.status_code}")
        print(response.text[:200])
        return False

def test_misp_search(indicator: str):
    """Test searching for an indicator in MISP"""
    print(f"\nSearching MISP for: {indicator}")
    
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    response = requests.post(
        f"{MISP_URL}/attributes/restSearch",
        headers=headers,
        json={
            "value": indicator,
            "limit": 5,
            "returnFormat": "json"
        },
        timeout=15,
        verify=False
    )
    
    if response.status_code == 200:
        data = response.json()
        attributes = data.get("response", {}).get("Attribute", [])
        print(f"Found {len(attributes)} matching attributes")
        
        for attr in attributes[:3]:
            print(f"  Type: {attr.get('type')}, Value: {attr.get('value', '')[:50]}")
        
        return len(attributes)
    else:
        print(f"Search failed: {response.status_code}")
        return 0

# Run tests
test_misp_connection()
test_misp_search("203.0.113.5")
test_misp_search("8.8.8.8")
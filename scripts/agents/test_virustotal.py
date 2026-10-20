# test_virustotal.py
# Test VirusTotal API independently before using in agent

import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "")

if not VT_API_KEY:
    print("ERROR: VT_API_KEY not set in .env file")
    exit(1)

def test_vt_ip(ip_address: str):
    """Test VirusTotal IP lookup"""
    print(f"\nQuerying VirusTotal for IP: {ip_address}")
    
    headers = {"x-apikey": VT_API_KEY}
    
    response = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
        headers=headers,
        timeout=15
    )
    
    print(f"Status code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)
        
        print(f"Total engines: {total}")
        print(f"Malicious detections: {malicious}")
        print(f"Detection ratio: {malicious/total:.1%}" if total > 0 else "N/A")
        print(f"Country: {attrs.get('country', 'unknown')}")
        print(f"AS owner: {attrs.get('as_owner', 'unknown')}")
        
        return True
    elif response.status_code == 401:
        print("ERROR: Invalid API key")
        return False
    elif response.status_code == 429:
        print("ERROR: Rate limit exceeded. Wait 60 seconds.")
        return False
    else:
        print(f"ERROR: {response.status_code}")
        return False

# Test with known malicious IP
print("Test 1: Known external IP")
test_vt_ip("203.0.113.5")

import time
time.sleep(16)  # Rate limit: 4 requests per minute

# Test with Google DNS (should be clean)
print("\nTest 2: Clean IP (Google DNS)")
test_vt_ip("8.8.8.8")
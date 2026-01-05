import time
import requests
import json
import base64
import sys

# Assume server is running at localhost:8000
BASE_URL = "http://127.0.0.1:8000"

def test_replay_attack():
    print("--- Testing Replay Attack ---")

    # 1. Init
    resp = requests.post(f"{BASE_URL}/auth/init", json={"browser_key": "test_key"})
    if resp.status_code != 200:
        print("Init failed")
        sys.exit(1)

    data = resp.json()
    login_id = data["login_id"]
    qr_payload_str = data["qr_payload"]

    # 2. First Scan (Should succeed)
    print("2. First Scan...")
    resp = requests.post(f"{BASE_URL}/auth/scan", json={"qr_raw_payload": qr_payload_str})
    if resp.status_code != 200:
        print(f"First scan failed: {resp.text}")
        sys.exit(1)
    print("   First scan successful.")

    # 3. Second Scan (Should fail due to Replay or State)
    print("3. Second Scan (Replay Attempt)...")
    resp = requests.post(f"{BASE_URL}/auth/scan", json={"qr_raw_payload": qr_payload_str})

    if resp.status_code == 400:
        print("   Replay attack correctly rejected.")
    else:
        print(f"   Replay attack NOT rejected! Status: {resp.status_code}")
        sys.exit(1)

    print("SUCCESS: Replay protection verified.")

if __name__ == "__main__":
    test_replay_attack()

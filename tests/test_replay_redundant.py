import time
import requests
import json
import sys
import urllib3

# Disable warnings for self-signed localhost certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIGURATION =================
BASE_URL = "https://127.0.0.1:8000"
CERT_PATH = ("../client.crt", "../client.key")
# =================================================

def test_replay_attack():
    print("--- Testing Replay Attack ---")

    # Helper: Valid Dummy Key (Server likely validates JWK format now)
    dummy_key = {
        "kty": "RSA", 
        "n": "fake_modulus", 
        "e": "AQAB",
        "alg": "RS256"
    }

    # 1. Init
    try:
        resp = requests.post(
            f"{BASE_URL}/auth/init", 
            json={"browser_key": json.dumps(dummy_key)},
            cert=CERT_PATH, verify=False
        )
    except requests.exceptions.SSLError:
        print("Error: SSL connection failed. Check cert paths.")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to server.")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"Init failed: {resp.text}")
        sys.exit(1)

    data = resp.json()
    qr_payload_str = data["qr_payload"]

    # 2. First Scan (Should succeed)
    print("2. First Scan...")
    resp = requests.post(
        f"{BASE_URL}/auth/scan", 
        json={"qr_raw_payload": qr_payload_str},
        cert=CERT_PATH, verify=False
    )
    if resp.status_code != 200:
        print(f"First scan failed: {resp.text}")
        sys.exit(1)
    print("   First scan successful.")

    # 3. Second Scan (Should fail due to Replay or State)
    print("3. Second Scan (Replay Attempt)...")
    resp = requests.post(
        f"{BASE_URL}/auth/scan", 
        json={"qr_raw_payload": qr_payload_str},
        cert=CERT_PATH, verify=False
    )

    if resp.status_code == 400:
        print(f"   Replay attack correctly rejected. Message: {resp.json().get('detail')}")
    else:
        print(f"   FAILURE: Replay attack NOT rejected! Status: {resp.status_code}")
        sys.exit(1)

    print("SUCCESS: Replay protection verified.")

if __name__ == "__main__":
    test_replay_attack()
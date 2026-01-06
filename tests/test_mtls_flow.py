import time
import requests
import json
import base64
import sys
import os

# Assume server is running at localhost:8000 (HTTPS)
BASE_URL = "https://127.0.0.1:8000"

# Certs
CERT_DIR = "certs"
CLIENT_CERT = (os.path.join(CERT_DIR, "client.crt"), os.path.join(CERT_DIR, "client.key"))
CA_CERT = os.path.join(CERT_DIR, "ca.crt")

def test_login_flow():
    print("1. Initiating Login (Secure)...")
    try:
        # Use verify=CA_CERT to verify server, and cert=CLIENT_CERT to authenticate
        resp = requests.post(f"{BASE_URL}/auth/init", json={"browser_key": "test_key"}, verify=CA_CERT, cert=CLIENT_CERT)
    except requests.exceptions.SSLError as e:
        print(f"SSL Error: {e}")
        print("Ensure the server is running with mTLS enabled (run_secure.sh)")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("Error: Server not reachable. Make sure 'run_secure.sh' is running.")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"Failed to init: {resp.text}")
        sys.exit(1)

    data = resp.json()
    login_id = data["login_id"]
    qr_payload_str = data["qr_payload"]
    print(f"   Login ID: {login_id}")
    print(f"   QR Payload: {qr_payload_str}")

    # 2. Poll (Should be PENDING)
    print("2. Polling status (should be PENDING)...")
    resp = requests.get(f"{BASE_URL}/auth/poll/{login_id}", verify=CA_CERT, cert=CLIENT_CERT)
    status = resp.json()["status"]
    print(f"   Status: {status}")
    assert status == "PENDING"

    # 3. Scan
    print("3. Simulating Scan...")
    resp = requests.post(f"{BASE_URL}/auth/scan", json={"qr_raw_payload": qr_payload_str}, verify=CA_CERT, cert=CLIENT_CERT)
    if resp.status_code != 200:
         print(f"Scan failed: {resp.text}")
         sys.exit(1)
    print("   Scan successful.")

    # 4. Poll (Should be SCANNED)
    print("4. Polling status (should be SCANNED)...")
    resp = requests.get(f"{BASE_URL}/auth/poll/{login_id}", verify=CA_CERT, cert=CLIENT_CERT)
    status = resp.json()["status"]
    print(f"   Status: {status}")
    assert status == "SCANNED"

    # 5. Approve
    print("5. Simulating Approval...")
    resp = requests.post(f"{BASE_URL}/auth/approve", json={"login_id": login_id, "user_id": "alice"}, verify=CA_CERT, cert=CLIENT_CERT)
    if resp.status_code != 200:
         print(f"Approve failed: {resp.text}")
         sys.exit(1)
    print("   Approval successful.")

    # 6. Poll (Should be AUTHORIZED)
    print("6. Polling status (should be AUTHORIZED)...")
    resp = requests.get(f"{BASE_URL}/auth/poll/{login_id}", verify=CA_CERT, cert=CLIENT_CERT)
    data = resp.json()
    status = data["status"]
    print(f"   Status: {status}")
    assert status == "AUTHORIZED"
    print(f"   Session Token: {data['session_token']}")

    print("\nSUCCESS: Full mTLS flow verified.")

if __name__ == "__main__":
    test_login_flow()

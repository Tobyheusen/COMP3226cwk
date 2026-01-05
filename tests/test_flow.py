import time
import requests
import json
import base64
import sys

# Assume server is running at localhost:8000
BASE_URL = "http://127.0.0.1:8000"

def test_login_flow():
    print("1. Initiating Login...")
    try:
        resp = requests.post(f"{BASE_URL}/auth/init", json={"browser_key": "test_key"})
    except requests.exceptions.ConnectionError:
        print("Error: Server not reachable. Make sure 'uvicorn app.main:app' is running.")
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
    resp = requests.get(f"{BASE_URL}/auth/poll/{login_id}")
    status = resp.json()["status"]
    print(f"   Status: {status}")
    assert status == "PENDING"

    # 3. Scan
    print("3. Simulating Scan...")
    resp = requests.post(f"{BASE_URL}/auth/scan", json={"qr_raw_payload": qr_payload_str})
    if resp.status_code != 200:
         print(f"Scan failed: {resp.text}")
         sys.exit(1)
    print("   Scan successful.")

    # 4. Poll (Should be SCANNED)
    print("4. Polling status (should be SCANNED)...")
    resp = requests.get(f"{BASE_URL}/auth/poll/{login_id}")
    status = resp.json()["status"]
    print(f"   Status: {status}")
    assert status == "SCANNED"

    # 5. Approve
    print("5. Simulating Approval...")
    resp = requests.post(f"{BASE_URL}/auth/approve", json={"login_id": login_id, "user_id": "alice"})
    if resp.status_code != 200:
         print(f"Approve failed: {resp.text}")
         sys.exit(1)
    print("   Approval successful.")

    # 6. Poll (Should be AUTHORIZED)
    print("6. Polling status (should be AUTHORIZED)...")
    resp = requests.get(f"{BASE_URL}/auth/poll/{login_id}")
    data = resp.json()
    status = data["status"]
    print(f"   Status: {status}")
    assert status == "AUTHORIZED"
    print(f"   Session Token: {data['session_token']}")

    print("\nSUCCESS: Full flow verified.")

if __name__ == "__main__":
    # We need to start the server in background if it's not running
    # But in this environment, I can't easily start background process and talk to it from same script
    # unless I use subprocess or threads.
    # I'll rely on the user or a separate tool call to start it.
    # Actually, I can start it in background with 'run_in_bash_session' and '&',
    # but I'll write this script assuming server is up.
    test_login_flow()

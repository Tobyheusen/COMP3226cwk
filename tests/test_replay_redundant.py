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

def test_double_scan_before_approval():
    """
    Tests that scanning a QR code twice before approval is rejected.
    Flow: PENDING -> SCANNED (first scan) -> Reject second scan
    """
    import pytest
    
    dummy_key = {
        "kty": "RSA",
        "n": "fake_modulus",
        "e": "AQAB",
        "alg": "RS256"
    }
    
    # 1. Init
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": json.dumps(dummy_key)},
        cert=CERT_PATH,
        verify=False
    )
    if init_resp.status_code != 200:
        print(f"Init failed: {init_resp.text}")
        sys.exit(1)
    
    init_data = init_resp.json()
    login_id = init_data["login_id"]
    qr_payload = init_data["qr_payload"]
    
    # 2. First scan (should succeed)
    first_scan_resp = requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    if first_scan_resp.status_code != 200:
        print(f"First scan failed: {first_scan_resp.text}")
        sys.exit(1)
    
    first_scan_data = first_scan_resp.json()
    if first_scan_data.get("status") != "SCANNED":
        print(f"First scan should set status to SCANNED, got: {first_scan_data.get('status')}")
        sys.exit(1)
    
    # Step 3: Verify status is SCANNED
    poll_resp = requests.get(
        f"{BASE_URL}/auth/poll/{login_id}",
        cert=CERT_PATH,
        verify=False
    )
    if poll_resp.status_code != 200:
        print(f"Poll failed: {poll_resp.text}")
        sys.exit(1)
    
    poll_data = poll_resp.json()
    if poll_data.get("status") != "SCANNED":
        print(f"Status should be SCANNED after first scan, got: {poll_data.get('status')}")
        sys.exit(1)
    
    # Step 4: Second scan attempt (should fail)
    second_scan_resp = requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    if second_scan_resp.status_code != 400:
        print(f"FAILURE: Second scan should be rejected with 400, got {second_scan_resp.status_code}")
        sys.exit(1)
    
    # Verify error message
    error_data = second_scan_resp.json()
    error_detail = error_data.get("detail", "").lower()
    
    if not any(keyword in error_detail for keyword in [
        "status", "scanned", "validation", "already", "invalid"
    ]):
        print(f"Error message should indicate why scan failed, got: {error_detail}")
        sys.exit(1)
    
    # Step 5: Verify status remains SCANNED
    final_poll_resp = requests.get(
        f"{BASE_URL}/auth/poll/{login_id}",
        cert=CERT_PATH,
        verify=False
    )
    if final_poll_resp.status_code != 200:
        print(f"Final poll failed: {final_poll_resp.text}")
        sys.exit(1)
    
    final_poll_data = final_poll_resp.json()
    if final_poll_data.get("status") != "SCANNED":
        print(f"Status should remain SCANNED after rejected second scan, got: {final_poll_data.get('status')}")
        sys.exit(1)
    
    print("SUCCESS: Double scan before approval correctly rejected.")

def test_token_expiry():
    """
    Tests that expired login requests cannot be scanned.
    Should test case where: Create login -> Wait for expiry (60 seconds) -> Try to scan -> Should fail
    """
    
    dummy_key = {
        "kty": "RSA",
        "n": "fake_modulus",
        "e": "AQAB",
        "alg": "RS256"
    }
    
    # 1. Init login request
    print("1. Creating login request...")
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": json.dumps(dummy_key)},
        cert=CERT_PATH,
        verify=False
    )
    if init_resp.status_code != 200:
        print(f"Init failed: {init_resp.text}")
        sys.exit(1)
    
    init_data = init_resp.json()
    login_id = init_data["login_id"]
    qr_payload = init_data["qr_payload"]
    
    # 2. Verify request is initially valid (status should be PENDING)
    print("2. Verifying initial status is PENDING...")
    poll_resp = requests.get(
        f"{BASE_URL}/auth/poll/{login_id}",
        cert=CERT_PATH,
        verify=False
    )
    
    poll_data = poll_resp.json()
    if poll_data.get("status") != "PENDING":
        print(f"Initial status should be PENDING, got: {poll_data.get('status')}")
        sys.exit(1)
    
    # 3. Wait for token to expire (60 seconds + buffer)
    print("3. Waiting for token to expire (61 seconds)...")
    time.sleep(61)
    print("Wait complete.")
    
    # 4. Verify status changed to EXPIRED
    print("4. Checking if status changed to EXPIRED...")
    expired_poll_resp = requests.get(
        f"{BASE_URL}/auth/poll/{login_id}",
        cert=CERT_PATH,
        verify=False
    )
    
    expired_poll_data = expired_poll_resp.json()
    if expired_poll_data.get("status") != "EXPIRED":
        print(f"Status should be EXPIRED after 61 seconds, got: {expired_poll_data.get('status')}")
        sys.exit(1)
    else:
        print("Status is EXPIRED")
    
    # 5. Try to scan expired QR code (should fail)
    print("5. Attempting to scan expired QR code...")
    scan_resp = requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    if scan_resp.status_code != 400:
        print(f"FAILURE: Expired scan should be rejected with 400, got {scan_resp.status_code}")
        sys.exit(1)
    else:
        print("SUCCESS: Token expiry protection verified.")

def test_scan_after_approval():
    """
    Tests that scanning a QR code after approval is rejected.
    Flow: PENDING -> SCANNED -> AUTHORIZED -> Reject scan attempt
    """
    dummy_key = {
        "kty": "RSA",
        "n": "fake_modulus",
        "e": "AQAB",
        "alg": "RS256"
    }
    
    # 1. Init login request
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": json.dumps(dummy_key)},
        cert=CERT_PATH,
        verify=False
    )
    if init_resp.status_code != 200:
        print(f"Init failed: {init_resp.text}")
        sys.exit(1)
    
    init_data = init_resp.json()
    login_id = init_data["login_id"]
    qr_payload = init_data["qr_payload"]
    
    # 2. First scan (should succeed, status: PENDING -> SCANNED)
    scan_resp = requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    if scan_resp.status_code != 200:
        print(f"First scan failed: {scan_resp.text}")
        sys.exit(1)
    
    # 3. Verify status is SCANNED
    poll_resp = requests.get(
        f"{BASE_URL}/auth/poll/{login_id}",
        cert=CERT_PATH,
        verify=False
    )
    poll_data = poll_resp.json()
    if poll_data.get("status") != "SCANNED":
        print(f"Status should be SCANNED after scan, got: {poll_data.get('status')}")
        sys.exit(1)
    
    # 4. Approve the login (status: SCANNED -> AUTHORIZED)
    approve_resp = requests.post(
        f"{BASE_URL}/admin/approve",
        data={"login_id": login_id},
        cert=CERT_PATH,
        verify=False
    )
    if approve_resp.status_code == 404:
        approve_resp = requests.post(
            f"{BASE_URL}/auth/approve",
            json={"login_id": login_id, "user_id": "test_user"},
            cert=CERT_PATH,
            verify=False
        )
    if approve_resp.status_code != 200:
        print(f"Approval failed: {approve_resp.text}")
        sys.exit(1)
    
    # 5. Verify status is AUTHORIZED
    approved_poll_resp = requests.get(
        f"{BASE_URL}/auth/poll/{login_id}",
        cert=CERT_PATH,
        verify=False
    )
    approved_poll_data = approved_poll_resp.json()
    if approved_poll_data.get("status") != "AUTHORIZED":
        print(f"Status should be AUTHORIZED after approval, got: {approved_poll_data.get('status')}")
        sys.exit(1)
    
    # 6. Try to scan after approval (should fail)
    post_approval_scan_resp = requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    if post_approval_scan_resp.status_code != 400:
        print(f"FAILURE: Scan after approval should be rejected with 400, got {post_approval_scan_resp.status_code}")
        sys.exit(1)
    
    # 7. Verify status remains AUTHORIZED
    final_poll_resp = requests.get(
        f"{BASE_URL}/auth/poll/{login_id}",
        cert=CERT_PATH,
        verify=False
    )
    final_poll_data = final_poll_resp.json()
    if final_poll_data.get("status") != "AUTHORIZED":
        print(f"Status should remain AUTHORIZED after rejected scan, got: {final_poll_data.get('status')}")
        sys.exit(1)
    
    print("SUCCESS: Scan after approval correctly rejected.")

if __name__ == "__main__":
    test_replay_attack()
    test_double_scan_before_approval()
    test_token_expiry()
    test_scan_after_approval()

"""
Tests for RQ1: Browser/Device Binding to Prevent Authorization Hijacking

Tests verify that:
- Browser keys are required in secure mode
- Token exchange requires proof of possession (signature)
- Wrong browser keys cannot exchange tokens
- Session tokens are not leaked in poll responses
- Device-bound sessions prevent hijacking
"""

import pytest
import requests
import json
import base64
import urllib3
import sys
from jwcrypto import jwk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://127.0.0.1:8000"
CERT_PATH = ("../client.crt", "../client.key")


@pytest.fixture(scope="module")
def browser_key_pair():
    """Generate RSA key pair for browser (legitimate user)"""
    return jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig')


@pytest.fixture(scope="module")
def attacker_key_pair():
    """Generate RSA key pair for attacker (different browser)"""
    return jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig')


def test_browser_key_required_in_secure_mode():
    """
    RQ1: Browser Binding Enforcement
    
    Tests that secure mode requires browser_key during login initiation.
    Without browser_key, login should be rejected.
    """
    # Try to initiate login without browser_key
    resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={},  # No browser_key
        cert=CERT_PATH,
        verify=False
    )
    
    # Should be rejected in secure mode
    assert resp.status_code == 400, \
        f"Login without browser_key should be rejected in secure mode, got {resp.status_code}"
    
    error_detail = resp.json().get("detail", "").lower()
    assert "browser" in error_detail or "key" in error_detail, \
        f"Error should mention browser key requirement, got: {error_detail}"


def test_browser_key_stored_with_login_id(browser_key_pair):
    """
    RQ1: Browser Key Registration with Login ID
    
    Tests that the login server relates browser_key with login_id.
    This verifies that browser_key is stored and can be retrieved for proof verification.
    """
    # 1. Browser generates key and registers it with login_id
    browser_pub_key = browser_key_pair.export_public()
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": browser_pub_key},
        cert=CERT_PATH,
        verify=False
    )
    assert init_resp.status_code == 200, f"Init failed: {init_resp.text}"
    
    login_id = init_resp.json()["login_id"]
    qr_payload = init_resp.json()["qr_payload"]
    
    # 2. Complete flow to authorization
    requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    approve_resp = requests.post(
        f"{BASE_URL}/admin/approve",
        data={"login_id": login_id},
        cert=CERT_PATH,
        verify=False
    )
    if approve_resp.status_code == 404:
        requests.post(
            f"{BASE_URL}/auth/approve",
            json={"login_id": login_id, "user_id": "test_user"},
            cert=CERT_PATH,
            verify=False
        )
    
    # 3. Verify browser_key is stored and can be used for proof
    # Generate signature with the SAME browser key that was registered
    browser_priv_pem = browser_key_pair.export_to_pem(private_key=True, password=None)
    browser_priv_key = load_pem_private_key(browser_priv_pem, password=None)
    
    signature = browser_priv_key.sign(
        login_id.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    
    # 4. Token exchange should succeed because browser_key matches
    # This proves browser_key was stored with login_id and can be retrieved
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": sig_b64},
        cert=CERT_PATH,
        verify=False
    )
    
    assert token_resp.status_code == 200, \
        f"Token exchange should succeed when browser_key matches stored key, got {token_resp.status_code}"
    
    # This test verifies that:
    # - browser_key was registered with login_id during /auth/init
    # - browser_key is stored and can be retrieved for verification
    # - Proof of possession works because the relationship exists


def test_browser_key_mismatch(browser_key_pair, attacker_key_pair):
    """
    RQ1: Browser Binding - Wrong Browser Prevention
    
    Tests that an attacker with a different browser key cannot exchange
    tokens even if they have the login_id. This prevents session hijacking.
    """
    # 1. Legitimate browser initiates login
    browser_pub_key = browser_key_pair.export_public()
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": browser_pub_key},
        cert=CERT_PATH,
        verify=False
    )
    assert init_resp.status_code == 200, f"Init failed: {init_resp.text}"
    
    init_data = init_resp.json()
    login_id = init_data["login_id"]
    qr_payload = init_data["qr_payload"]
    
    # 2. Scan and approve (normal flow)
    scan_resp = requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    assert scan_resp.status_code == 200, f"Scan failed: {scan_resp.text}"
    
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
    assert approve_resp.status_code == 200, f"Approval failed: {approve_resp.text}"
    
    # 3. Attacker tries to exchange token with different browser key
    # Attacker has login_id but wrong private key
    attacker_priv_pem = attacker_key_pair.export_to_pem(private_key=True, password=None)
    attacker_priv_key = load_pem_private_key(attacker_priv_pem, password=None)
    
    # Attacker signs login_id with their own key (wrong key)
    attacker_signature = attacker_priv_key.sign(
        login_id.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    attacker_sig_b64 = base64.b64encode(attacker_signature).decode('utf-8')
    
    # 4. Attacker attempts token exchange (should fail)
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": attacker_sig_b64},
        cert=CERT_PATH,
        verify=False
    )
    
    # Should be rejected - wrong browser key
    assert token_resp.status_code == 400, \
        f"Token exchange with wrong browser key should be rejected, got {token_resp.status_code}"
    
    error_detail = token_resp.json().get("detail", "").lower()
    assert any(keyword in error_detail for keyword in [
        "signature", "invalid", "proof", "possession"
    ]), f"Error should indicate signature verification failed, got: {error_detail}"


def test_token_exchange_without_signature(browser_key_pair):
    """
    RQ1: Proof of Possession Required
    
    Tests that token exchange without a signature is rejected.
    This ensures proof of possession is mandatory.
    """
    # 1. Initiate and complete login flow
    browser_pub_key = browser_key_pair.export_public()
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": browser_pub_key},
        cert=CERT_PATH,
        verify=False
    )
    assert init_resp.status_code == 200
    
    login_id = init_resp.json()["login_id"]
    qr_payload = init_resp.json()["qr_payload"]
    
    # Scan and approve
    requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    approve_resp = requests.post(
        f"{BASE_URL}/admin/approve",
        data={"login_id": login_id},
        cert=CERT_PATH,
        verify=False
    )
    if approve_resp.status_code == 404:
        requests.post(
            f"{BASE_URL}/auth/approve",
            json={"login_id": login_id, "user_id": "test_user"},
            cert=CERT_PATH,
            verify=False
        )
    
    # 2. Try to exchange token without signature (should fail)
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": ""},  # Empty signature
        cert=CERT_PATH,
        verify=False
    )
    
    assert token_resp.status_code == 400, \
        f"Token exchange without signature should be rejected, got {token_resp.status_code}"


def test_token_exchange_with_invalid_signature(browser_key_pair):
    """
    RQ1: Invalid Signature Rejection
    
    Tests that token exchange with an invalid signature (garbage data) is rejected.
    """
    # 1. Initiate and complete login flow
    browser_pub_key = browser_key_pair.export_public()
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": browser_pub_key},
        cert=CERT_PATH,
        verify=False
    )
    assert init_resp.status_code == 200
    
    login_id = init_resp.json()["login_id"]
    qr_payload = init_resp.json()["qr_payload"]
    
    # Scan and approve
    requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    approve_resp = requests.post(
        f"{BASE_URL}/admin/approve",
        data={"login_id": login_id},
        cert=CERT_PATH,
        verify=False
    )
    if approve_resp.status_code == 404:
        requests.post(
            f"{BASE_URL}/auth/approve",
            json={"login_id": login_id, "user_id": "test_user"},
            cert=CERT_PATH,
            verify=False
        )
    
    # 2. Try to exchange with invalid signature (garbage data)
    fake_sig = base64.b64encode(b"this_is_not_a_valid_signature").decode('utf-8')
    
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": fake_sig},
        cert=CERT_PATH,
        verify=False
    )
    
    assert token_resp.status_code == 400, \
        f"Token exchange with invalid signature should be rejected, got {token_resp.status_code}"


def test_correct_browser_key_and_signature(browser_key_pair):
    """
    RQ1: Valid Proof of Possession (Happy Path)
    
    Tests that token exchange with correct browser key and signature succeeds.
    This verifies the legitimate flow works correctly.
    """
    # 1. Initiate login with browser key
    browser_pub_key = browser_key_pair.export_public()
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": browser_pub_key},
        cert=CERT_PATH,
        verify=False
    )
    assert init_resp.status_code == 200
    
    init_data = init_resp.json()
    login_id = init_data["login_id"]
    qr_payload = init_data["qr_payload"]
    
    # 2. Scan QR code
    scan_resp = requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    assert scan_resp.status_code == 200
    
    # 3. Approve login
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
    assert approve_resp.status_code == 200
    
    # 4. Generate correct signature with browser's private key
    browser_priv_pem = browser_key_pair.export_to_pem(private_key=True, password=None)
    browser_priv_key = load_pem_private_key(browser_priv_pem, password=None)
    
    signature = browser_priv_key.sign(
        login_id.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    
    # 5. Exchange token with correct signature (should succeed)
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": sig_b64},
        cert=CERT_PATH,
        verify=False
    )
    
    assert token_resp.status_code == 200, \
        f"Token exchange with correct signature should succeed, got {token_resp.status_code}"
    
    token_data = token_resp.json()
    assert "session_token" in token_data, \
        "Token exchange should return session_token"
    assert token_data["session_token"] is not None, \
        "Session token should not be None"


def test_token_not_leaked_in_poll(browser_key_pair):
    """
    RQ1: Token Not Leaked in Poll Response
    
    Tests that session tokens are not returned in poll responses in secure mode.
    Tokens should only be available after proof of possession.
    """
    # 1. Initiate and complete login flow
    browser_pub_key = browser_key_pair.export_public()
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": browser_pub_key},
        cert=CERT_PATH,
        verify=False
    )
    assert init_resp.status_code == 200
    
    login_id = init_resp.json()["login_id"]
    qr_payload = init_resp.json()["qr_payload"]
    
    # Scan and approve
    requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    approve_resp = requests.post(
        f"{BASE_URL}/admin/approve",
        data={"login_id": login_id},
        cert=CERT_PATH,
        verify=False
    )
    if approve_resp.status_code == 404:
        requests.post(
            f"{BASE_URL}/auth/approve",
            json={"login_id": login_id, "user_id": "test_user"},
            cert=CERT_PATH,
            verify=False
        )
    
    # 2. Poll for status (should not include session_token)
    poll_resp = requests.get(
        f"{BASE_URL}/auth/poll/{login_id}",
        cert=CERT_PATH,
        verify=False
    )
    assert poll_resp.status_code == 200
    
    poll_data = poll_resp.json()
    assert poll_data.get("status") == "AUTHORIZED", \
        f"Status should be AUTHORIZED, got: {poll_data.get('status')}"
    
    # Critical: session_token should NOT be in poll response
    assert "session_token" not in poll_data, \
        "Vulnerability: Session token leaked in poll response! Token should only be available after proof of possession."


def test_session_hijacking_prevention(browser_key_pair, attacker_key_pair):
    """
    RQ1: Session Hijacking Prevention
    
    Tests that an attacker who intercepts a login_id cannot exchange it for a token
    without the correct browser private key. This simulates a session hijacking attempt.
    """
    # 1. Legitimate user initiates login
    browser_pub_key = browser_key_pair.export_public()
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": browser_pub_key},
        cert=CERT_PATH,
        verify=False
    )
    assert init_resp.status_code == 200
    
    login_id = init_resp.json()["login_id"]
    qr_payload = init_resp.json()["qr_payload"]
    
    # 2. Complete normal flow (scan and approve)
    requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    approve_resp = requests.post(
        f"{BASE_URL}/admin/approve",
        data={"login_id": login_id},
        cert=CERT_PATH,
        verify=False
    )
    if approve_resp.status_code == 404:
        requests.post(
            f"{BASE_URL}/auth/approve",
            json={"login_id": login_id, "user_id": "test_user"},
            cert=CERT_PATH,
            verify=False
        )
    
    # 3. Attacker intercepts login_id (e.g., from network traffic)
    # Attacker does NOT have the browser's private key
    
    # 4. Attacker tries to exchange token with their own key (should fail)
    attacker_priv_pem = attacker_key_pair.export_to_pem(private_key=True, password=None)
    attacker_priv_key = load_pem_private_key(attacker_priv_pem, password=None)
    
    attacker_signature = attacker_priv_key.sign(
        login_id.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    attacker_sig_b64 = base64.b64encode(attacker_signature).decode('utf-8')
    
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": attacker_sig_b64},
        cert=CERT_PATH,
        verify=False
    )
    
    # Should be rejected - attacker doesn't have correct browser key
    assert token_resp.status_code == 400, \
        f"Session hijacking attempt should be rejected, got {token_resp.status_code}"
    
    error_detail = token_resp.json().get("detail", "").lower()
    assert any(keyword in error_detail for keyword in [
        "signature", "invalid", "proof", "possession"
    ]), f"Error should indicate proof of possession failed, got: {error_detail}"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main(["-v", __file__]))


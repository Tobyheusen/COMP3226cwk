"""
Tests for RQ1: Browser/Device Binding to Prevent Authorization Hijacking

These tests verify that binding QR tokens to browsers, sessions, and devices
prevents authorisation hijacking and token replay attacks.

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
import os
from pathlib import Path
from jwcrypto import jwk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://127.0.0.1:8000"


_test_dir = Path(__file__).parent
_project_root = _test_dir.parent
_cert_crt = _project_root / "client.crt"
_cert_key = _project_root / "client.key"
CERT_PATH = (str(_cert_crt), str(_cert_key))


@pytest.fixture(scope="module")
def browser_key_pair():
    """
    Generate RSA key pair for the legitimate browser (user).
    
    This fixture creates a 2048-bit RSA key pair that simulates the browser's
    Web Crypto API key generation. The key pair is reused across all tests
    in this module for efficiency.
    
    Returns:
        JWK object containing both public and private keys
    """
    return jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig')


@pytest.fixture(scope="module")
def attacker_key_pair():
    """
    Generate RSA key pair for the attacker (different browser/device).
    
    This fixture creates a separate key pair that simulates an attacker
    attempting to hijack a session. The attacker's key is different from
    the legitimate browser's key, so they cannot produce valid signatures.
    
    Returns:
        JWK object containing attacker's key pair
    """
    return jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig')


def test_browser_key_required_in_secure_mode():
    """
    RQ1: Browser Binding Enforcement
    
    Tests that secure mode requires browser_key during login initiation.
    Without browser_key, login should be rejected.
    
    This test verifies the first requirement: browser keys must be generated
    and registered when the user first visits the site.
    """
    # Attempt to initiate login without providing a browser_key
    # In secure mode, this should be rejected as browser binding is mandatory
    resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={},  # Empty JSON - no browser_key provided
        cert=CERT_PATH,  # mTLS client certificate
        verify=False  # Disable SSL verification for self-signed certs
    )
    
    # The server should reject the request with a 400 Bad Request status
    # This enforces that browser keys are required in secure mode
    assert resp.status_code == 400, \
        f"Login without browser_key should be rejected in secure mode, got {resp.status_code}"
    
    # Verify the error message mentions the browser key requirement
    # This ensures users understand why the request was rejected
    error_detail = resp.json().get("detail", "").lower()
    assert "browser" in error_detail or "key" in error_detail, \
        f"Error should mention browser key requirement, got: {error_detail}"


def test_browser_key_stored_with_login_id(browser_key_pair):
    """
    RQ1: Browser Key Registration with Login ID
    
    Tests that the login server relates browser_key with login_id.
    This verifies that browser_key is stored and can be retrieved for proof verification.
    
    This test verifies the requirement that the login server relates browser_key
    with login_id, ensuring the relationship is maintained throughout the login flow.
    """
    # Step 1: Browser generates a key pair and registers the public key with the server
    # The public key is exported in JWK (JSON Web Key) format, which is what
    # the Web Crypto API produces in real browsers
    browser_pub_key = browser_key_pair.export_public()
    
    # Send the browser_key to the server during login initiation
    # The server should store this key and associate it with the login_id
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": browser_pub_key},
        cert=CERT_PATH,
        verify=False
    )
    assert init_resp.status_code == 200, f"Init failed: {init_resp.text}"
    
    # Extract the login_id and QR payload from the server response
    # The login_id is the unique identifier for this login attempt
    login_id = init_resp.json()["login_id"]
    qr_payload = init_resp.json()["qr_payload"]
    
    # Step 2: Complete the authentication flow to reach AUTHORIZED status
    # This simulates the normal login process: scan QR code and approve
    
    # Mobile device scans the QR code
    requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    
    # Admin/user approves the login request
    approve_resp = requests.post(
        f"{BASE_URL}/admin/approve",
        data={"login_id": login_id},
        cert=CERT_PATH,
        verify=False
    )
    # Fallback to auth endpoint if admin endpoint doesn't exist
    if approve_resp.status_code == 404:
        requests.post(
            f"{BASE_URL}/auth/approve",
            json={"login_id": login_id, "user_id": "test_user"},
            cert=CERT_PATH,
            verify=False
        )
    
    # Step 3: Verify that browser_key was stored and can be used for proof verification
    # Generate a signature using the SAME browser key that was registered during init
    # This proves that the browser_key was stored correctly and can be retrieved
    
    # Export the private key in PEM format so we can use it for signing
    browser_priv_pem = browser_key_pair.export_to_pem(private_key=True, password=None)
    browser_priv_key = load_pem_private_key(browser_priv_pem, password=None)
    
    # Sign the login_id using the browser's private key
    # The signature proves that we possess the private key corresponding to
    # the public key (browser_key) that was registered with this login_id
    signature = browser_priv_key.sign(
        login_id.encode('utf-8'),  # Data to sign (the login_id)
        padding.PKCS1v15(),  # RSA padding scheme
        hashes.SHA256()  # Hash algorithm
    )
    # Encode the signature in base64 for transmission
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    
    # Step 4: Attempt token exchange with the correct signature
    # This should succeed because:
    # 1. The browser_key was stored with login_id during /auth/init
    # 2. The signature was created with the matching private key
    # 3. The server can verify the signature using the stored browser_key
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": sig_b64},
        cert=CERT_PATH,
        verify=False
    )
    
    # Token exchange should succeed, proving that browser_key was correctly
    # stored with login_id and can be retrieved for verification
    assert token_resp.status_code == 200, \
        f"Token exchange should succeed when browser_key matches stored key, got {token_resp.status_code}"


def test_browser_key_mismatch(browser_key_pair, attacker_key_pair):
    """
    RQ1: Browser Binding - Wrong Browser Prevention
    
    Tests that an attacker with a different browser key cannot exchange
    tokens even if they have the login_id. This prevents session hijacking.
    
    This test simulates an attacker who intercepts a login_id but does not
    have access to the legitimate browser's private key.
    """
    # Step 1: Legitimate browser initiates login with its browser_key
    # The browser generates a key pair and sends the public key to the server
    browser_pub_key = browser_key_pair.export_public()
    init_resp = requests.post(
        f"{BASE_URL}/auth/init",
        json={"browser_key": browser_pub_key},
        cert=CERT_PATH,
        verify=False
    )
    assert init_resp.status_code == 200, f"Init failed: {init_resp.text}"
    
    # Extract login_id and QR payload from the response
    init_data = init_resp.json()
    login_id = init_data["login_id"]
    qr_payload = init_data["qr_payload"]
    
    # Step 2: Complete the normal authentication flow (scan and approve)
    # This brings the login request to AUTHORIZED status
    scan_resp = requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    assert scan_resp.status_code == 200, f"Scan failed: {scan_resp.text}"
    
    # Approve the login request
    approve_resp = requests.post(
        f"{BASE_URL}/admin/approve",
        data={"login_id": login_id},
        cert=CERT_PATH,
        verify=False
    )
    # Fallback if admin endpoint doesn't exist
    if approve_resp.status_code == 404:
        approve_resp = requests.post(
            f"{BASE_URL}/auth/approve",
            json={"login_id": login_id, "user_id": "test_user"},
            cert=CERT_PATH,
            verify=False
        )
    assert approve_resp.status_code == 200, f"Approval failed: {approve_resp.text}"
    
    # Step 3: Attacker attempts to exchange token using a different browser key
    # The attacker has intercepted the login_id (e.g., from network traffic)
    # but does NOT have the legitimate browser's private key
    
    # Export the attacker's private key (different from legitimate browser)
    attacker_priv_pem = attacker_key_pair.export_to_pem(private_key=True, password=None)
    attacker_priv_key = load_pem_private_key(attacker_priv_pem, password=None)
    
    # Attacker signs the login_id with their own private key (wrong key)
    # This signature will not match the browser_key stored with the login_id
    attacker_signature = attacker_priv_key.sign(
        login_id.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    attacker_sig_b64 = base64.b64encode(attacker_signature).decode('utf-8')
    
    # Step 4: Attacker attempts token exchange (should fail)
    # The server will verify the signature against the browser_key stored
    # with this login_id, and it will not match because the attacker used
    # a different key pair
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": attacker_sig_b64},
        cert=CERT_PATH,
        verify=False
    )
    
    # The server should reject this request because the signature does not
    # match the browser_key that was registered with this login_id
    assert token_resp.status_code == 400, \
        f"Token exchange with wrong browser key should be rejected, got {token_resp.status_code}"
    
    # Verify the error message indicates signature verification failure
    error_detail = token_resp.json().get("detail", "").lower()
    assert any(keyword in error_detail for keyword in [
        "signature", "invalid", "proof", "possession"
    ]), f"Error should indicate signature verification failed, got: {error_detail}"


def test_token_exchange_without_signature(browser_key_pair):
    """
    RQ1: Proof of Possession Required
    
    Tests that token exchange without a signature is rejected.
    This ensures proof of possession is mandatory before the server issues a session ID.
    
    This test verifies the requirement that the browser must prove possession
    of the browser_key before the server issues a session ID.
    """
    # Step 1: Initiate and complete the login flow normally
    # This sets up a login request with a browser_key registered
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
    
    # Complete the scan and approval steps
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
    
    # Step 2: Attempt token exchange without providing a signature
    # This simulates an attacker trying to skip the proof of possession step
    # The server should require a valid signature before issuing the session token
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": ""},  # Empty signature - no proof provided
        cert=CERT_PATH,
        verify=False
    )
    
    # The server should reject this request because proof of possession is required
    assert token_resp.status_code == 400, \
        f"Token exchange without signature should be rejected, got {token_resp.status_code}"


def test_token_exchange_with_invalid_signature(browser_key_pair):
    """
    RQ1: Invalid Signature Rejection
    
    Tests that token exchange with an invalid signature (garbage data) is rejected.
    This ensures that only cryptographically valid signatures are accepted.
    """
    # Step 1: Initiate and complete the login flow
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
    
    # Complete scan and approval
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
    
    # Step 2: Attempt token exchange with invalid signature (garbage data)
    # This simulates an attacker trying to bypass signature verification
    # by sending random data instead of a proper cryptographic signature
    fake_sig = base64.b64encode(b"this_is_not_a_valid_signature").decode('utf-8')
    
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": fake_sig},
        cert=CERT_PATH,
        verify=False
    )
    
    # The server should reject this because the signature is not valid
    # Signature verification will fail when trying to verify against the stored browser_key
    assert token_resp.status_code == 400, \
        f"Token exchange with invalid signature should be rejected, got {token_resp.status_code}"


def test_correct_browser_key_and_signature(browser_key_pair):
    """
    RQ1: Valid Proof of Possession (Happy Path)
    
    Tests that token exchange with correct browser key and signature succeeds.
    This verifies the legitimate flow works correctly.
    
    This is the "happy path" test that ensures the system works for legitimate users
    who follow the correct authentication flow.
    """
    # Step 1: Initiate login with browser key
    # The browser generates a key pair and registers the public key
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
    
    # Step 2: Scan QR code with mobile device
    scan_resp = requests.post(
        f"{BASE_URL}/auth/scan",
        json={"qr_raw_payload": qr_payload},
        cert=CERT_PATH,
        verify=False
    )
    assert scan_resp.status_code == 200
    
    # Step 3: Approve the login request
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
    
    # Step 4: Generate correct signature using the browser's private key
    # This is the proof of possession - the browser proves it owns the
    # private key corresponding to the public key (browser_key) registered earlier
    
    # Export the private key for signing
    browser_priv_pem = browser_key_pair.export_to_pem(private_key=True, password=None)
    browser_priv_key = load_pem_private_key(browser_priv_pem, password=None)
    
    # Sign the login_id with the browser's private key
    # The signature proves possession of the private key without revealing it
    signature = browser_priv_key.sign(
        login_id.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    
    # Step 5: Exchange token with correct signature (should succeed)
    # The server will:
    # 1. Retrieve the browser_key stored with this login_id
    # 2. Verify the signature using the browser_key
    # 3. If verification succeeds, issue the session token
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": sig_b64},
        cert=CERT_PATH,
        verify=False
    )
    
    # Token exchange should succeed because:
    # - The browser_key was registered with login_id
    # - The signature was created with the matching private key
    # - The server can verify the signature successfully
    assert token_resp.status_code == 200, \
        f"Token exchange with correct signature should succeed, got {token_resp.status_code}"
    
    # Verify that a session token is returned
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
    
    This test verifies that tokens are not prematurely exposed, ensuring that
    proof of possession is required before the session ID is issued.
    """
    # Step 1: Initiate and complete the login flow
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
    
    # Complete scan and approval steps
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
    
    # Step 2: Poll for login status after approval
    # In secure mode, the poll response should indicate AUTHORIZED status
    # but should NOT include the session_token
    # The token should only be available after proof of possession via /auth/token
    poll_resp = requests.get(
        f"{BASE_URL}/auth/poll/{login_id}",
        cert=CERT_PATH,
        verify=False
    )
    assert poll_resp.status_code == 200
    
    poll_data = poll_resp.json()
    assert poll_data.get("status") == "AUTHORIZED", \
        f"Status should be AUTHORIZED, got: {poll_data.get('status')}"
    
    # Critical security check: session_token should NOT be in poll response
    # If the token is leaked here, an attacker could obtain it without proof of possession
    # This would defeat the purpose of browser binding
    assert "session_token" not in poll_data, \
        "Vulnerability: Session token leaked in poll response! Token should only be available after proof of possession."


def test_session_hijacking_prevention(browser_key_pair, attacker_key_pair):
    """
    RQ1: Session Hijacking Prevention
    
    Tests that an attacker who intercepts a login_id cannot exchange it for a token
    without the correct browser private key. This simulates a session hijacking attempt.
    
    This test directly addresses RQ1 by demonstrating that even if an attacker
    intercepts the login_id, they cannot complete the token exchange without
    the legitimate browser's private key.
    """
    # Step 1: Legitimate user initiates login with their browser key
    # The browser generates a key pair and registers the public key
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
    
    # Step 2: Complete the normal authentication flow (scan and approve)
    # This brings the login to AUTHORIZED status, ready for token exchange
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
    
    # Step 3: Attacker intercepts login_id (e.g., from network traffic, logs, etc.)
    # The attacker has the login_id but does NOT have the browser's private key
    # This simulates a common attack scenario where login identifiers are exposed
    
    # Step 4: Attacker attempts to exchange token using their own key pair
    # The attacker generates their own signature using their private key
    # However, this signature will not match the browser_key stored with the login_id
    attacker_priv_pem = attacker_key_pair.export_to_pem(private_key=True, password=None)
    attacker_priv_key = load_pem_private_key(attacker_priv_pem, password=None)
    
    # Attacker signs the login_id with their own private key
    # This signature will fail verification because it doesn't match the stored browser_key
    attacker_signature = attacker_priv_key.sign(
        login_id.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    attacker_sig_b64 = base64.b64encode(attacker_signature).decode('utf-8')
    
    # Attacker attempts token exchange (should fail)
    token_resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"login_id": login_id, "signature": attacker_sig_b64},
        cert=CERT_PATH,
        verify=False
    )
    
    # The server should reject this because:
    # 1. The browser_key stored with login_id does not match the attacker's public key
    # 2. Signature verification will fail
    # 3. The attacker cannot prove possession of the legitimate browser's private key
    assert token_resp.status_code == 400, \
        f"Session hijacking attempt should be rejected, got {token_resp.status_code}"
    
    # Verify the error message indicates proof of possession failure
    error_detail = token_resp.json().get("detail", "").lower()
    assert any(keyword in error_detail for keyword in [
        "signature", "invalid", "proof", "possession"
    ]), f"Error should indicate proof of possession failed, got: {error_detail}"


if __name__ == "__main__":
    # Allow running tests directly with Python
    import sys
    sys.exit(pytest.main(["-v", __file__]))

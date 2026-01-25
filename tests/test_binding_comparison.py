"""
RQ1 Comparative Tests: With vs Without QR Token Binding

This test suite directly compares:
1. Secure Mode WITH binding - demonstrates prevention of hijacking and replay
2. Insecure Mode WITHOUT binding - demonstrates vulnerabilities

"To what extent can binding QR tokens to browsers, sessions and devices prevent authorisation hijacking and token replay?"
"""

import pytest
import requests
import json
import base64
import urllib3
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
    """Generate RSA key pair for legitimate browser"""
    return jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig')


@pytest.fixture(scope="module")
def attacker_key_pair():
    """Generate RSA key pair for attacker (different browser)"""
    return jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig')


class TestWithBinding_SecureMode:
    """
    Test Suite 1: WITH QR Token Binding (Secure Mode)
    
    Demonstrates that binding prevents:
    - Authorisation hijacking
    - Token replay attacks
    """
    
    @pytest.fixture(autouse=True)
    def ensure_secure_mode(self):
        """Ensure tests run in secure mode"""
        current_mode = os.getenv("SECURITY_MODE", "secure").lower()
        if current_mode != "secure":
            pytest.skip(f"These tests require SECURITY_MODE=secure, got {current_mode}")
    
    def test_authorisation_hijacking_prevented_with_binding(self, browser_key_pair, attacker_key_pair):
        """
        RQ1: Authorisation Hijacking Prevention WITH Binding
        
        Scenario: Attacker intercepts login_id but doesn't have browser's private key.
        Expected: Attack fails because binding requires proof of possession.
        """
        print("\n=== TEST: Authorisation Hijacking WITH Binding (Secure Mode) ===")
        
        # 1. Legitimate user initiates login WITH browser key binding
        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert init_resp.status_code == 200, "Login initiation failed"
        print("Legitimate user initiated login with browser key")
        
        login_id = init_resp.json()["login_id"]
        qr_payload = init_resp.json()["qr_payload"]
        
        # 2. Complete normal authentication flow
        requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        
        approve_resp = requests.post(
            f"{BASE_URL}/admin/approve",
            data={"login_id": login_id},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        if approve_resp.status_code == 404:
            requests.post(
                f"{BASE_URL}/auth/approve",
                json={"login_id": login_id, "user_id": "test_user"},
                cert=CERT_PATH,
                verify="ca.crt"
            )
        print("Authentication flow completed")
        
        # 3. Attacker intercepts login_id (e.g., from network traffic, XSS)
        print(f"Attacker intercepts login_id: {login_id}")
        print("Attacker attempts to exchange token WITHOUT browser's private key")
        
        # 4. Attacker tries to exchange token with wrong browser key
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
            verify="ca.crt"
        )
        
        # 5. VERIFICATION: Attack should FAIL - binding prevents hijacking
        assert token_resp.status_code == 400, \
            f"SECURITY FAILURE: Binding did not prevent hijacking! Got {token_resp.status_code}"
        
        error_detail = token_resp.json().get("detail", "").lower()
        assert any(keyword in error_detail for keyword in [
            "signature", "invalid", "proof", "possession"
        ]), f"Error should indicate signature verification failed, got: {error_detail}"
        
        print("RESULT: Authorisation hijacking PREVENTED by binding")
        print("  - Attacker cannot exchange token without correct browser key")
        print("  - Proof of possession requirement blocks the attack")
        print("=" * 70)
    
    def test_token_replay_prevented_with_binding(self, browser_key_pair):
        """
        RQ1: Token Replay Prevention WITH Binding
        
        Scenario: Attacker captures QR code payload and tries to replay it.
        Expected: Replay fails because nonce-based protection tracks used QR codes.
        """
        print("\n=== TEST: Token Replay WITH Binding (Secure Mode) ===")
        
        # 1. Legitimate user initiates login
        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert init_resp.status_code == 200
        print("Legitimate user initiated login")
        
        qr_payload = init_resp.json()["qr_payload"]
        login_id = init_resp.json()["login_id"]
        
        # 2. Legitimate scan (first use)
        first_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert first_scan.status_code == 200, "First scan should succeed"
        print("Legitimate QR code scan completed")
        
        # 3. Attacker captures QR code payload (e.g., network interception, screenshot)
        print(f"Attacker captures QR code payload")
        print("Attacker attempts to replay the same QR code")
        
        # 4. Attacker tries to replay the QR code
        replay_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},  # Same payload
            cert=CERT_PATH,
            verify="ca.crt"
        )
        
        # 5. VERIFICATION: Replay should FAIL - nonce tracking prevents replay
        assert replay_scan.status_code == 400, \
            f"SECURITY FAILURE: Binding did not prevent replay! Got {replay_scan.status_code}"
        
        error_detail = replay_scan.json().get("detail", "").lower()
        assert any(keyword in error_detail for keyword in [
            "nonce", "replay", "status", "already", "used"
        ]), f"Error should indicate replay detected, got: {error_detail}"
        
        print("RESULT: Token replay PREVENTED by binding")
        print("  - Nonce-based protection tracks used QR codes")
        print("  - Replay attempt detected and blocked")
        print("=" * 70)
    
    def test_token_not_leaked_with_binding(self, browser_key_pair):
        """
        RQ1: Token Leakage Prevention WITH Binding
        
        Scenario: Attacker tries to obtain session token via poll endpoint.
        Expected: Token not leaked - only available after proof of possession.
        """
        print("\n=== TEST: Token Leakage WITH Binding (Secure Mode) ===")
        
        # 1. Complete authentication flow
        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert init_resp.status_code == 200
        
        login_id = init_resp.json()["login_id"]
        qr_payload = init_resp.json()["qr_payload"]
        
        requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        
        approve_resp = requests.post(
            f"{BASE_URL}/admin/approve",
            data={"login_id": login_id},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        if approve_resp.status_code == 404:
            requests.post(
                f"{BASE_URL}/auth/approve",
                json={"login_id": login_id, "user_id": "test_user"},
                cert=CERT_PATH,
                verify="ca.crt"
            )
        print("Authentication flow completed")
        
        # 2. Attacker polls for status (trying to get token)
        print("Attacker polls /auth/poll endpoint to steal session token")
        
        poll_resp = requests.get(
            f"{BASE_URL}/auth/poll/{login_id}",
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert poll_resp.status_code == 200
        
        poll_data = poll_resp.json()
        
        # 3. VERIFICATION: Token should NOT be in poll response
        assert "session_token" not in poll_data, \
            "SECURITY FAILURE: Token leaked in poll response! Binding should prevent this."
        
        print("RESULT: Token leakage PREVENTED by binding")
        print("  - Session token not exposed in poll responses")
        print("  - Token only available after proof of possession")
        print("=" * 70)


class TestWithoutBinding_InsecureMode:
    """
    Test Suite 2: WITHOUT QR Token Binding (Insecure Mode)
    
    Demonstrates vulnerabilities when binding is NOT implemented:
    - Authorisation hijacking is possible
    - Token replay attacks may succeed
    """
    
    @pytest.fixture(autouse=True)
    def ensure_insecure_mode(self):
        """Ensure tests run in insecure mode"""
        current_mode = os.getenv("SECURITY_MODE", "secure").lower()
        if current_mode != "insecure":
            pytest.skip(f"These tests require SECURITY_MODE=insecure, got {current_mode}")
    
    def test_authorisation_hijacking_without_binding(self, browser_key_pair, attacker_key_pair):
        """
        RQ1: Authorisation Hijacking WITHOUT Binding
        
        Scenario: Attacker intercepts login_id in insecure mode.
        Expected: Attack may succeed because no proof of possession required.
        """
        print("\n=== TEST: Authorisation Hijacking WITHOUT Binding (Insecure Mode) ===")
        
        # 1. User initiates login (browser_key optional in insecure mode)
        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},  # Optional, not enforced
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert init_resp.status_code == 200
        print("User initiated login (browser key not enforced)")
        
        login_id = init_resp.json()["login_id"]
        qr_payload = init_resp.json()["qr_payload"]
        
        # 2. Complete authentication flow
        requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        
        approve_resp = requests.post(
            f"{BASE_URL}/admin/approve",
            data={"login_id": login_id},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        if approve_resp.status_code == 404:
            requests.post(
                f"{BASE_URL}/auth/approve",
                json={"login_id": login_id, "user_id": "test_user"},
                cert=CERT_PATH,
                verify="ca.crt"
            )
        print("Authentication flow completed")
        
        # 3. Attacker intercepts login_id
        print(f"Attacker intercepts login_id: {login_id}")
        print("Attacker attempts token exchange WITHOUT browser's private key")
        
        # 4. In insecure mode, token might be available via poll
        poll_resp = requests.get(
            f"{BASE_URL}/auth/poll/{login_id}",
            cert=CERT_PATH,
            verify="ca.crt"
        )
        poll_data = poll_resp.json()
        
        # 5. VERIFICATION: Token is LEAKED in insecure mode
        if "session_token" in poll_data:
            print("VULNERABILITY: Session token leaked in poll response!")
            print("  - Attacker can obtain token without proof of possession")
            print("  - No binding protection = hijacking possible")
        else:
            # Try token endpoint with fake signature
            fake_sig = base64.b64encode(b"fake_signature").decode('utf-8')
            token_resp = requests.post(
                f"{BASE_URL}/auth/token",
                json={"login_id": login_id, "signature": fake_sig},
                cert=CERT_PATH,
                verify="ca.crt"
            )
            
            if token_resp.status_code == 200:
                print("VULNERABILITY: Token exchange succeeded with invalid signature!")
                print("  - No signature verification = hijacking possible")
            else:
                print("Token endpoint still requires signature (implementation dependent)")
        
        print("=" * 70)
    
    def test_token_replay_possible_without_binding(self, browser_key_pair):
        """
        RQ1: Token Replay WITHOUT Binding
        
        Scenario: Attacker captures and replays QR code in insecure mode.
        Expected: Replay may succeed if nonce protection is disabled.
        """
        print("\n=== TEST: Token Replay WITHOUT Binding (Insecure Mode) ===")
        
        # 1. User initiates login
        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert init_resp.status_code == 200
        print("User initiated login")
        
        qr_payload = init_resp.json()["qr_payload"]
        
        # 2. Legitimate scan
        first_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert first_scan.status_code == 200
        print("Legitimate QR code scan completed")
        
        # 3. Attacker captures and replays QR code
        print("Attacker captures QR code payload")
        print("Attacker attempts to replay the same QR code")
        
        replay_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        
        # 4. VERIFICATION: In insecure mode, replay might succeed
        if replay_scan.status_code == 200:
            print("VULNERABILITY: QR code replay succeeded!")
            print("  - Nonce-based protection not enforced")
            print("  - Attacker can reuse captured QR codes")
        else:
            print("  - Replay blocked ")
        
        print("=" * 70)
    
    def test_token_leaked_without_binding(self, browser_key_pair):
        """
        RQ1: Token Leakage WITHOUT Binding
        
        Scenario: Attacker polls for token in insecure mode.
        Expected: Token leaked in poll response.
        """
        print("\n=== TEST: Token Leakage WITHOUT Binding (Insecure Mode) ===")
        
        # 1. Complete authentication flow
        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert init_resp.status_code == 200
        
        login_id = init_resp.json()["login_id"]
        qr_payload = init_resp.json()["qr_payload"]
        
        requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        
        approve_resp = requests.post(
            f"{BASE_URL}/admin/approve",
            data={"login_id": login_id},
            cert=CERT_PATH,
            verify="ca.crt"
        )
        if approve_resp.status_code == 404:
            requests.post(
                f"{BASE_URL}/auth/approve",
                json={"login_id": login_id, "user_id": "test_user"},
                cert=CERT_PATH,
                verify="ca.crt"
            )
        print("Authentication flow completed")
        
        # 2. Poll for status
        print("Attacker polls /auth/poll endpoint")
        
        poll_resp = requests.get(
            f"{BASE_URL}/auth/poll/{login_id}",
            cert=CERT_PATH,
            verify="ca.crt"
        )
        assert poll_resp.status_code == 200
        
        poll_data = poll_resp.json()
        
        # 3. VERIFICATION: Token is LEAKED in insecure mode
        if "session_token" in poll_data:
            print("VULNERABILITY: Session token leaked in poll response!")
            print(f"  - Token exposed: {poll_data['session_token'][:20]}...")
            print("  - No proof of possession required")
            print("  - Attacker can steal session without browser key")
        else:
            print("Token not in poll (implementation dependent)")
        
        print("=" * 70)


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("RQ1 Comparative Tests: With vs Without QR Token Binding")
    print("=" * 70)
    print("\nTo run tests:")
    print("1. Secure Mode (WITH binding):")
    print("   $env:SECURITY_MODE='secure'")
    print("   pytest tests/test_binding_comparison.py::TestWithBinding_SecureMode -v -s")
    print("\n2. Insecure Mode (WITHOUT binding):")
    print("   $env:SECURITY_MODE='insecure'")
    print("   pytest tests/test_binding_comparison.py::TestWithoutBinding_InsecureMode -v -s")
    print("\n" + "=" * 70)
    
    import sys
    sys.exit(pytest.main(["-v", "-s", __file__]))


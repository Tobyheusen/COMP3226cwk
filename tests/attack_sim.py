import pytest
import requests
import json
import base64
import urllib3
import sys
from requests.exceptions import ConnectionError, SSLError

# Crypto libraries for generating real keys and signatures
from jwcrypto import jwk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------
# We suppress warnings because we are likely testing against localhost with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://127.0.0.1:8000"
# These must point to valid certificates for the "Authorized" tests to work
CERT_PATH = ("../client.crt", "../client.key")

# ------------------------------------------------------------------------------
# FIXTURES (Setup Helpers)
# ------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client_key_pair():
    """
    Generates a fresh RSA key pair for the test session.
    We need this to prove to the server that we own the 'browser_key' we sent.
    """
    return jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig')

@pytest.fixture
def dummy_jwk():
    """A simple dummy key for tests that don't need to sign anything (like Replay checks)."""
    return {
        "kty": "RSA", "n": "fake_modulus", "e": "AQAB", "alg": "RS256"
    }

@pytest.fixture
def active_session(client_key_pair):
    """
    Helper that initializes a login session and returns the details.
    Useful so we don't have to repeat the /init call in every test.
    """
    pub_key = client_key_pair.export_public()
    try:
        resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": pub_key},
            cert=CERT_PATH, verify=False
        )
        resp.raise_for_status()
        return resp.json() # Returns dict with login_id, qr_payload, etc.
    except Exception as e:
        pytest.fail(f"Setup failed: Could not init session. Is server running? Error: {e}")

# ------------------------------------------------------------------------------
# TEST SUITE 1: THE PERIMETER (Attack Sim Logic)
# ------------------------------------------------------------------------------
class TestPerimeterDefense:
    """
    These tests act like a hacker trying to break down the front door.
    We are checking Transport Security (mTLS) and Input Validation.
    """

    def test_mtls_blocks_no_cert(self):
        """
        RQ1: mTLS Enforcement
        Scenario: An attacker tries to hit the API without a client certificate.
        Expected: The server should immediately kill the connection (TCP Reset/Abort).
        """
        try:
            # We intentionally leave out 'cert=CERT_PATH' here
            requests.get(f"{BASE_URL}/", verify=False, timeout=2)
            
            # If we reach this line, the server let us in. That's bad.
            pytest.fail("Vulnerability: Server accepted connection without a certificate!")
            
        except (SSLError, ConnectionError, ConnectionAbortedError, ConnectionResetError):
            # If the code crashes here, that's actually Good!
            # It means the server hung up on us.
            pass 

    def test_payload_tampering(self, active_session):
        """
        RQ3: Payload Integrity
        Scenario: An attacker scans a valid QR code but modifies the data inside 
        (changing the login_id) while trying to reuse the original signature.
        """
        # 1. Crack open the QR payload
        raw_payload = active_session['qr_payload']
        login_id = active_session['login_id']
        
        wrapper = json.loads(raw_payload)
        original_data = wrapper.get("data_str")
        original_sig = wrapper.get("sig")

        # 2. Tamper: Change the ID in the data, but keep the old signature
        tampered_data = original_data.replace(login_id, "ATTACKER_ID_999")
        
        malicious_payload = json.dumps({
            "data_str": tampered_data,
            "sig": original_sig 
        })

        # 3. Try to scan with the fake payload
        resp = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": malicious_payload},
            cert=CERT_PATH, verify=False
        )

        # 4. The server should notice the signature doesn't match the new data
        assert resp.status_code == 400, "Server should reject tampered payload"
        assert "Invalid" in resp.text or "Tampered" in resp.text

# ------------------------------------------------------------------------------
# TEST SUITE 2: THE PROCESS (Advanced Flow Logic)
# ------------------------------------------------------------------------------
class TestAuthenticationLogic:
    """
    These tests verify the actual secure authentication protocol.
    We act like a legitimate user to ensure the crypto handshake works,
    and then try subtle logic attacks (replay, bad signatures).
    """

    def test_full_proof_of_possession_flow(self, client_key_pair, active_session):
        """
        RQ1: Session Hijacking Prevention (PoP)
        This tests the 'Happy Path' to ensure the complex crypto actually works.
        """
        login_id = active_session["login_id"]
        qr_payload = active_session["qr_payload"]

        # 1. Scan the QR Code
        scan_resp = requests.post(
            f"{BASE_URL}/auth/scan", 
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH, verify=False
        )
        assert scan_resp.status_code == 200, "Valid scan failed"

        # 2. Administrator/User Approves the Login
        # We try the /admin path first, then fall back to /auth if needed
        approve_resp = requests.post(
            f"{BASE_URL}/admin/approve",
            data={"login_id": login_id},
            cert=CERT_PATH, verify=False
        )
        if approve_resp.status_code == 404:
            approve_resp = requests.post(
                f"{BASE_URL}/auth/approve",
                json={"login_id": login_id, "user_id": "test_user"},
                cert=CERT_PATH, verify=False
            )
        assert approve_resp.status_code == 200, "Approval failed"

        # 3. Poll for Status (CRITICAL SECURITY CHECK)
        # The status should be 'AUTHORIZED', but the token MUST be hidden.
        # The token should only be released if we prove we own the private key.
        poll_resp = requests.get(
            f"{BASE_URL}/auth/poll/{login_id}",
            cert=CERT_PATH, verify=False
        )
        poll_data = poll_resp.json()
        
        assert poll_data["status"] == "AUTHORIZED"
        assert "session_token" not in poll_data, "Vulnerability: Token leaked in poll response!"

        # 4. Generate the Proof (Sign the login_id)
        # This is the 'Proof of Possession' step.
        priv_pem = client_key_pair.export_to_pem(private_key=True, password=None)
        priv_key_obj = load_pem_private_key(priv_pem, password=None)

        signature = priv_key_obj.sign(
            login_id.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        sig_b64 = base64.b64encode(signature).decode('utf-8')

        # 5. Exchange Proof for Token
        token_resp = requests.post(
            f"{BASE_URL}/auth/token",
            json={"login_id": login_id, "signature": sig_b64},
            cert=CERT_PATH, verify=False
        )
        
        assert token_resp.status_code == 200, "Token exchange failed with valid signature"
        assert "session_token" in token_resp.json(), "Server did not return session token!"

    def test_replay_attack_prevention(self, active_session):
        """
        RQ2: Replay Protection
        Scenario: An attacker records a valid QR scan and tries to 'replay' it 
        to log themselves in as the victim.
        """
        qr_payload = active_session["qr_payload"]

        # 1. First Scan (Legitimate) - Should work
        first = requests.post(
            f"{BASE_URL}/auth/scan", 
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH, verify=False
        )
        assert first.status_code == 200, "First scan should succeed"

        # 2. Second Scan (Replay) - Should be blocked
        second = requests.post(
            f"{BASE_URL}/auth/scan", 
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH, verify=False
        )
        
        # We expect a 400 Bad Request
        assert second.status_code == 400, "Vulnerability: Server allowed a Replay Attack!"
        
        # Optional: Check if the error message is specific
        detail = second.json().get('detail', '')
        assert any(x in detail for x in ["Nonce", "Replay", "Status"]), \
            f"Blocked, but error message was unclear: {detail}"

    def test_bad_signature_rejection(self, active_session):
        """
        RQ1: Signature Verification
        Scenario: An attacker tries to skip the 'Proof of Possession' by sending
        garbage data as a signature.
        """
        login_id = active_session["login_id"]
        
        # Create a fake signature
        bad_sig = base64.b64encode(b"this_is_not_a_valid_sig").decode("utf-8")
        
        resp = requests.post(
            f"{BASE_URL}/auth/token", 
            json={"login_id": login_id, "signature": bad_sig},
            cert=CERT_PATH, verify=False
        )
        
        assert resp.status_code in [400, 401], f"Server accepted invalid signature! Code: {resp.status_code}"

# ------------------------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # This allows you to run the script directly with 'python test_security_suite.py'
    print("Running Security Suite via Pytest...")
    sys.exit(pytest.main(["-v", __file__]))
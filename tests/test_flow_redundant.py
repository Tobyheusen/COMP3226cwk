import pytest
import requests
import json
import base64
import urllib3
from jwcrypto import jwk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Disable warnings for self-signed localhost certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIGURATION =================
BASE_URL = "https://127.0.0.1:8000"
CERT_PATH = ("../client.crt", "../client.key")
# =================================================

@pytest.fixture(scope="module")
def client_key_pair():
    """Generates a real RSA key pair for the PoP test once per session."""
    key = jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig')
    return key

@pytest.fixture
def dummy_jwk():
    """A simple dummy JWK for tests that don't need real signing (like Replay)."""
    return {
        "kty": "RSA", "n": "fake_modulus", "e": "AQAB", "alg": "RS256"
    }

class TestProofOfPossessionFlow:
    """
    Refactored from test_flow.py
    Tests the full lifecycle: Init -> Scan -> Approve -> Poll -> Token Exchange
    """
    
    def test_full_pop_lifecycle(self, client_key_pair):
        # 1. Export Public Key
        public_key_json = client_key_pair.export_public()

        # 2. Init
        resp = requests.post(
            f"{BASE_URL}/auth/init", 
            json={"browser_key": public_key_json},
            cert=CERT_PATH, verify=False
        )
        assert resp.status_code == 200, f"Init failed: {resp.text}"
        
        data = resp.json()
        login_id = data["login_id"]
        qr_payload_str = data["qr_payload"]
        assert login_id is not None

        # 3. Scan
        resp = requests.post(
            f"{BASE_URL}/auth/scan", 
            json={"qr_raw_payload": qr_payload_str},
            cert=CERT_PATH, verify=False
        )
        assert resp.status_code == 200, f"Scan failed: {resp.text}"

        # 4. Approve (Try Admin path first, then fallback)
        resp = requests.post(
            f"{BASE_URL}/admin/approve",
            data={"login_id": login_id},
            cert=CERT_PATH, verify=False
        )
        if resp.status_code == 404:
            resp = requests.post(
                f"{BASE_URL}/auth/approve",
                json={"login_id": login_id, "user_id": "alice"},
                cert=CERT_PATH, verify=False
            )
        assert resp.status_code == 200, f"Approve failed: {resp.text}"

        # 5. Poll (Check Status)
        resp = requests.get(
            f"{BASE_URL}/auth/poll/{login_id}",
            cert=CERT_PATH, verify=False
        )
        poll_data = resp.json()
        assert poll_data["status"] == "AUTHORIZED"
        assert "session_token" not in poll_data, "Security Risk: Token leaked in poll!"

        # 6. Generate Signature (Proof of Possession)
        priv_pem = client_key_pair.export_to_pem(private_key=True, password=None)
        priv_key_obj = load_pem_private_key(priv_pem, password=None)

        signature = priv_key_obj.sign(
            login_id.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        sig_b64 = base64.b64encode(signature).decode('utf-8')

        # 7. Token Exchange
        resp = requests.post(
            f"{BASE_URL}/auth/token",
            json={"login_id": login_id, "signature": sig_b64},
            cert=CERT_PATH, verify=False
        )
        assert resp.status_code == 200, f"Token exchange failed: {resp.text}"
        assert "session_token" in resp.json(), "No session token returned!"

    def test_bad_signature_rejection(self, client_key_pair):
        """Negative Test: Ensures invalid signatures are rejected."""
        # Setup a quick session just for this test
        pub_key = client_key_pair.export_public()
        resp = requests.post(f"{BASE_URL}/auth/init", json={"browser_key": pub_key}, cert=CERT_PATH, verify=False)
        login_id = resp.json()["login_id"]
        
        # Try to exchange with garbage signature
        bad_sig = base64.b64encode(b"invalid_sig").decode("utf-8")
        resp = requests.post(
            f"{BASE_URL}/auth/token", 
            json={"login_id": login_id, "signature": bad_sig},
            cert=CERT_PATH, verify=False
        )
        
        assert resp.status_code in [400, 401], f"Server accepted bad signature! Code: {resp.status_code}"


class TestReplayProtection:
    """
    Refactored from test_replay.py
    Tests that QR codes cannot be reused.
    """

    def test_replay_attack(self, dummy_jwk):
        # 1. Init
        resp = requests.post(
            f"{BASE_URL}/auth/init", 
            json={"browser_key": json.dumps(dummy_jwk)},
            cert=CERT_PATH, verify=False
        )
        assert resp.status_code == 200, "Init failed"
        qr_payload = resp.json()["qr_payload"]

        # 2. First Scan (Should Pass)
        resp1 = requests.post(
            f"{BASE_URL}/auth/scan", 
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH, verify=False
        )
        assert resp1.status_code == 200, f"First scan failed: {resp1.text}"

        # 3. Second Scan (Should Fail)
        resp2 = requests.post(
            f"{BASE_URL}/auth/scan", 
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH, verify=False
        )
        
        assert resp2.status_code == 400, f"Replay not blocked! Got {resp2.status_code}"
        assert "detail" in resp2.json(), "No error detail returned"

if __name__ == "__main__":
    # Allows running directly with 'python test_advanced_flows.py'
    import sys
    sys.exit(pytest.main(["-v", __file__]))
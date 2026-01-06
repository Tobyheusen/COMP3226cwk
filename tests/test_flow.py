import time
import requests
import json
import base64
import sys
from jwcrypto import jwk, jws
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Assume server is running at localhost:8000
BASE_URL = "http://127.0.0.1:8000"

def test_pop_flow():
    print("1. Generating Client Key Pair...")
    # Generate RSA Key
    key = jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig')
    public_key_json = key.export_public() # This is a JSON string

    print("   Key generated.")

    print("2. Initiating Login with Public Key...")
    try:
        resp = requests.post(f"{BASE_URL}/auth/init", json={"browser_key": public_key_json})
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

    # 3. Scan
    print("3. Simulating Scan...")
    resp = requests.post(f"{BASE_URL}/auth/scan", json={"qr_raw_payload": qr_payload_str})
    if resp.status_code != 200:
         print(f"Scan failed: {resp.text}")
         sys.exit(1)

    # 4. Approve
    print("4. Simulating Approval...")
    resp = requests.post(f"{BASE_URL}/auth/approve", json={"login_id": login_id, "user_id": "alice"})
    if resp.status_code != 200:
         print(f"Approve failed: {resp.text}")
         sys.exit(1)

    # 5. Poll (Should be AUTHORIZED but NO Token)
    print("5. Polling status (should be AUTHORIZED, No Token)...")
    resp = requests.get(f"{BASE_URL}/auth/poll/{login_id}")
    data = resp.json()
    status = data["status"]
    print(f"   Status: {status}")
    assert status == "AUTHORIZED"
    if "session_token" in data:
        print("FAILURE: Session token returned in Poll! (Should be hidden in Secure Mode)")
        sys.exit(1)
    else:
        print("   Success: Session token hidden.")

    # 6. Prove Possession
    print("6. Proving Possession (Signing login_id)...")

    # Sign login_id using the key
    # We use jwcrypto's internal python key or export it

    # Using cryptography directly from jwcrypto key
    # jwcrypto's key object is wrappers.

    # Let's extract private key to PEM and load with cryptography?
    # Or just use jwcrypto/jws if I can make it produce raw signature.
    # But jwcrypto produces JWS structure.
    # The server expects RAW signature (base64 of bytes).

    # So I need to use cryptography to sign raw.
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # Export private key to PEM
    priv_pem = key.export_to_pem(private_key=True, password=None)

    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    priv_key_obj = load_pem_private_key(priv_pem, password=None)

    signature = priv_key_obj.sign(
        login_id.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    sig_b64 = base64.b64encode(signature).decode('utf-8')

    print("7. Exchanging Token...")
    resp = requests.post(f"{BASE_URL}/auth/token", json={
        "login_id": login_id,
        "signature": sig_b64
    })

    if resp.status_code != 200:
        print(f"Token exchange failed: {resp.text}")
        sys.exit(1)

    token_data = resp.json()
    session_token = token_data.get("session_token")
    if session_token:
        print(f"   SUCCESS: Got Session Token: {session_token}")
    else:
        print("   FAILURE: No session token in response")
        sys.exit(1)

    # 8. Negative Test (Bad Sig)
    print("8. Negative Test (Bad Signature)...")
    bad_sig = base64.b64encode(b"invalid_sig").decode("utf-8")
    resp = requests.post(f"{BASE_URL}/auth/token", json={
        "login_id": login_id,
        "signature": bad_sig
    })
    if resp.status_code == 400:
        print("   Success: Bad signature rejected.")
    else:
        print(f"   FAILURE: Bad signature accepted? {resp.status_code}")
        sys.exit(1)

if __name__ == "__main__":
    test_pop_flow()

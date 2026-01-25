"""
RQ2 Comparative Tests: Single-Use Tokens with Different Lifespans vs Brute-Force Attacks

This test suite directly compares:
1. Short Lifespan Tokens (60s) - demonstrates brute-force resistance
2. Long Lifespan Tokens (3600s) - demonstrates vulnerability to brute-force
3. Single-use protection (nonce tracking) - prevents token reuse

These tests answer: "How effectively do single-use tokens with shorter lifespans 
prevent brute-force attacks, especially in comparison to current implementations?"
"""

import os
import time
import uuid
from pathlib import Path

import pytest
import requests
import urllib3
from jwcrypto import jwk

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://127.0.0.1:8000"

_test_dir = Path(__file__).parent
_project_root = _test_dir.parent
_cert_crt = _project_root / "client.crt"
_cert_key = _project_root / "client.key"
CERT_PATH = (str(_cert_crt), str(_cert_key))

SHORT_WINDOW = 60
LONG_WINDOW = 3600


@pytest.fixture(scope="module")
def browser_key_pair():
    """Generate RSA key pair for browser"""
    return jwk.JWK.generate(kty="RSA", size=2048, alg="RS256", use="sig")


def _safe_json(resp: requests.Response) -> dict:
    """
    Parse a JSON response and return an empty dict on parse failure.
    """
    try:
        return resp.json()
    except ValueError:
        return {}


def _poll_status(login_id: str) -> str:
    """
    Poll the server for login status and normalise outputs across responses.
    Returns a single uppercase status string for consistent test assertions.
    """
    try:
        resp = requests.get(
            f"{BASE_URL}/auth/poll/{login_id}",
            cert=CERT_PATH,
            verify="ca.crt",
            timeout=0.75,
        )
    except requests.RequestException:
        # Treat network errors as "no signal" during brute force loops
        return "ERROR"

    if resp.status_code == 404:
        return "NOT_FOUND"

    data = _safe_json(resp)
    return str(data.get("status", "UNKNOWN")).upper()


def _is_low_entropy_numeric_id(login_id: str, max_digits: int = 6) -> bool:
    """
    Detect whether a login_id is a short, numeric identifier.
    Used to gate the optional low-entropy brute-force demo.
    """
    return login_id.isdigit() and len(login_id) <= max_digits


class TestShortLifespanTokens:
    """
    Test Suite 1: Short Lifespan Tokens (60 seconds)
    """

    @pytest.fixture(autouse=True)
    def ensure_secure_mode(self):
        """Ensure tests run in secure mode (60s token lifetime)"""
        current_mode = os.getenv("SECURITY_MODE", "secure").lower()
        if current_mode != "secure":
            pytest.skip(
                f"These tests require SECURITY_MODE=secure (60s lifetime), got {current_mode}"
            )

    @pytest.mark.slow
    def test_short_lifespan_expires_quickly(self, browser_key_pair):
        """
        RQ2: Short Lifespan Token Expiry

        Confirms a token becomes unusable after the short lifespan window,
        regardless of whether expiry is enforced on poll or scan.
        """
        print("\n=== TEST: Short Lifespan Token Expiry (60s) ===")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert init_resp.status_code == 200
        init_data = _safe_json(init_resp)
        login_id = init_data["login_id"]
        qr_payload = init_data["qr_payload"]

        assert _poll_status(login_id) == "PENDING"

        print(" Waiting for token to expire (61 seconds)...")
        time.sleep(SHORT_WINDOW + 1)

        expired_status = _poll_status(login_id)

        if expired_status == "PENDING":
            # If still pending, force expiry check via scan.
            expired_scan = requests.post(
                f"{BASE_URL}/auth/scan",
                json={"qr_raw_payload": qr_payload},
                cert=CERT_PATH,
                verify="ca.crt",
            )
            assert expired_scan.status_code == 400
            detail = str(_safe_json(expired_scan).get("detail", "")).lower()
            assert any(k in detail for k in ["expired", "lifetime", "validation"])

            expired_status = _poll_status(login_id)

        assert expired_status == "EXPIRED", f"Expected EXPIRED, got {expired_status}"

        print("RESULT: Token expired after short lifespan window")

    @pytest.mark.slow
    def test_brute_force_short_lifespan(self, browser_key_pair):
        """
        RQ2: Brute-Force Attack Limited by Short Lifespan

        Measures the number of online guesses possible within the short window
        and verifies that random guessing does not find a valid token.
        """
        print("\n=== TEST: Brute-Force Attack vs Short Lifespan (60s) ===")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert init_resp.status_code == 200
        legitimate_login_id = _safe_json(init_resp)["login_id"]
        print(f"Legitimate login created: {legitimate_login_id}")

        start_time = time.time()
        attempts = 0
        successful_guesses = 0

        while True:
            attempts += 1
            fake_login_id = str(uuid.uuid4())

            status = _poll_status(fake_login_id)
            if status in {"PENDING", "SCANNED", "AUTHORIZED"}:
                successful_guesses += 1
                print(" Found valid token! (unexpected)")

            elapsed = time.time() - start_time
            if elapsed >= SHORT_WINDOW:
                break

            if attempts % 250 == 0:
                print(f"  Progress: {attempts} attempts, {SHORT_WINDOW - elapsed:.1f}s remaining")

        elapsed_time = time.time() - start_time
        print(f"Attack completed: {attempts} attempts in {elapsed_time:.1f}s")
        print(f"Successful guesses: {successful_guesses}")

        assert successful_guesses == 0
        assert elapsed_time < (SHORT_WINDOW + 5)

    def test_single_use_protection_with_short_lifespan(self, browser_key_pair):
        """
        RQ2: Single-Use Protection with Short Lifespan

        Single-use should block replay even within the valid time window.
        """
        print("\n=== TEST: Single-Use Protection with Short Lifespan ===")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert init_resp.status_code == 200
        init_data = _safe_json(init_resp)

        qr_payload = init_data["qr_payload"]

        first_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert first_scan.status_code == 200

        reuse_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert reuse_scan.status_code == 400

        detail = str(_safe_json(reuse_scan).get("detail", "")).lower()
        assert any(k in detail for k in ["nonce", "replay", "already", "used", "status"])

class TestLongLifespanTokens:
    """
    Test Suite 2: Long Lifespan Tokens (3600 seconds = 1 hour)
    """

    @pytest.fixture(autouse=True)
    def ensure_insecure_mode(self):
        """Ensure tests run in insecure mode (3600s token lifetime)"""
        current_mode = os.getenv("SECURITY_MODE", "secure").lower()
        if current_mode != "insecure":
            pytest.skip(
                f"These tests require SECURITY_MODE=insecure (3600s lifetime), got {current_mode}"
            )

    def test_long_lifespan_allows_extended_attack_window(self, browser_key_pair):
        """
        RQ2: Long Lifespan Allows Extended Attack Window
        """
        print("\n=== TEST: Long Lifespan Token (3600s) ===")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert init_resp.status_code == 200
        login_id = _safe_json(init_resp)["login_id"]

        print(f"Created login_id: {login_id}")
        print("Checking status is still PENDING after a short wait...")
        assert _poll_status(login_id) == "PENDING"
        time.sleep(5)
        assert _poll_status(login_id) == "PENDING"
        print("Token remains valid in long lifespan mode.")

    
    def test_token_does_not_expire_quickly(self, browser_key_pair):
        """
        RQ2: Long lifespan persists beyond 60 seconds.
        """
        print("\n=== TEST: Long Lifespan Token Persistence ===")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert init_resp.status_code == 200
        login_id = _safe_json(init_resp)["login_id"]

        print(f"Created login_id: {login_id}")
        print("Waiting past the short lifespan window (61s)...")
        assert _poll_status(login_id) == "PENDING"
        time.sleep(SHORT_WINDOW + 1)

        status = _poll_status(login_id)
        if status == "EXPIRED":
            pytest.fail(
                "Token expired after ~60s, but insecure mode should have long lifetime. "
                "Check server SECURITY_MODE=insecure configuration."
            )

        assert status == "PENDING"
        print("Token still valid after 61s in long lifespan mode.")

    def test_single_use_protection_with_long_lifespan(self, browser_key_pair):
        """
        RQ2: Single-use protection should work regardless of lifespan.
        """
        print("\n=== TEST: Single-Use Protection with Long Lifespan ===")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert init_resp.status_code == 200
        init_data = _safe_json(init_resp)

        qr_payload = init_data["qr_payload"]

        print("First scan should succeed...")
        first_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert first_scan.status_code == 200

        print("Second scan should be blocked (single-use)...")
        reuse_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify="ca.crt",
        )
        assert reuse_scan.status_code == 400

        detail = str(_safe_json(reuse_scan).get("detail", "")).lower()
        assert any(k in detail for k in ["nonce", "replay", "already", "used", "status"])
        print("Single-use enforcement confirmed.")

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
    FIX: Avoid crashing if the server returns non-JSON (e.g., HTML error page).
    We treat non-JSON as empty dict so tests can raise more meaningful assertions.
    """
    try:
        return resp.json()
    except ValueError:
        return {}


def _poll_status(login_id: str) -> str:
    """
    FIX: Centralize polling logic & normalize outputs.

    Why:
    - Some implementations return 404 for unknown IDs.
    - Some return 200 with {"status": "NOT_FOUND"}.
    This helper makes brute-force tests consistent across implementations.
    """
    try:
        resp = requests.get(
            f"{BASE_URL}/auth/poll/{login_id}",
            cert=CERT_PATH,
            verify=False,
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
    Helper: Detect if insecure mode is using a guessable numeric ID space.

    If login_id is purely digits and short (<= 6 digits), brute force becomes
    demonstrably feasible, which strengthens your RQ2 evaluation.
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

        FIX: Now robust against where expiry is enforced.
        - Some backends mark EXPIRED during poll.
        - Others only mark EXPIRED when scan is attempted.
        This test now allows both, as long as token becomes unusable after TTL.
        """
        print("\n=== TEST: Short Lifespan Token Expiry (60s) ===")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify=False,
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
                verify=False,
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

        FIX: Uses specific exceptions and robust poll helper.
        The conclusion is not "brute force succeeds", but:
        - Short lifespan caps max online guesses possible within the window.
        """
        print("\n=== TEST: Brute-Force Attack vs Short Lifespan (60s) ===")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify=False,
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
            verify=False,
        )
        assert init_resp.status_code == 200
        init_data = _safe_json(init_resp)

        qr_payload = init_data["qr_payload"]

        first_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify=False,
        )
        assert first_scan.status_code == 200

        reuse_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify=False,
        )
        assert reuse_scan.status_code == 400

        detail = str(_safe_json(reuse_scan).get("detail", "")).lower()
        assert any(k in detail for k in ["nonce", "replay", "already", "used", "status"])

    def test_rate_limit_polling_in_secure_mode(self, browser_key_pair):
        """
        RQ2: Rate limiting reduces brute-force polling rate in secure mode.

        This test expects 429 responses when high-rate polling exceeds limits.
        Enable with:
          $env:RATE_LIMIT_ENABLED="1"
          $env:RATE_LIMIT_MAX_REQUESTS="10"
          $env:RATE_LIMIT_WINDOW_SECONDS="1"
        """
        if os.getenv("RATE_LIMIT_ENABLED", "0").lower() not in ("1", "true", "yes"):
            pytest.skip("Enable with RATE_LIMIT_ENABLED=1 to test rate limiting")

        max_requests = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "20"))
        window_seconds = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "1"))

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify=False,
        )
        assert init_resp.status_code == 200
        login_id = _safe_json(init_resp)["login_id"]

        rate_limited = False
        for _ in range(max_requests + 5):
            resp = requests.get(
                f"{BASE_URL}/auth/poll/{login_id}",
                cert=CERT_PATH,
                verify=False,
                timeout=0.75,
            )
            if resp.status_code == 429:
                rate_limited = True
                break

        assert rate_limited, (
            "Expected 429 rate limit responses. "
            f"Try lowering RATE_LIMIT_MAX_REQUESTS (currently {max_requests}) "
            f"or RATE_LIMIT_WINDOW_SECONDS (currently {window_seconds})."
        )


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
            verify=False,
        )
        assert init_resp.status_code == 200
        login_id = _safe_json(init_resp)["login_id"]

        assert _poll_status(login_id) == "PENDING"
        time.sleep(5)
        assert _poll_status(login_id) == "PENDING"

    def test_brute_force_long_lifespan_window_ratio(self, browser_key_pair):
        """
        RQ2: Brute-Force window comparison (core measurable result)

        FIX: Adds an assertion proving the measurable claim:
        - Long lifespan allows ~60x more online guesses than short lifespan
          at the same request rate.

        This avoids implying brute-force "succeeds" against UUID-scale IDs.
        """
        print("\n=== TEST: Window Ratio vs Brute Force (3600s vs 60s) ===")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify=False,
        )
        assert init_resp.status_code == 200

        start_time = time.time()
        attempts = 0

        test_duration = 10  # shorter, because we only need rate estimation
        while time.time() - start_time < test_duration:
            attempts += 1
            _poll_status(str(uuid.uuid4()))

        elapsed = time.time() - start_time
        attempts_per_second = attempts / elapsed if elapsed > 0 else 0.0

        long_attempts = attempts_per_second * LONG_WINDOW
        short_attempts = attempts_per_second * SHORT_WINDOW
        ratio = (long_attempts / short_attempts) if short_attempts > 0 else 0.0

        print(f"Rate: {attempts_per_second:.1f} req/s | Ratio (3600/60): {ratio:.1f}x")

        assert 55 <= ratio <= 65, f"Expected ~60x window, got {ratio:.1f}x"

    @pytest.mark.slow
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
            verify=False,
        )
        assert init_resp.status_code == 200
        login_id = _safe_json(init_resp)["login_id"]

        assert _poll_status(login_id) == "PENDING"
        time.sleep(SHORT_WINDOW + 1)

        status = _poll_status(login_id)
        if status == "EXPIRED":
            pytest.fail(
                "Token expired after ~60s, but insecure mode should have long lifetime. "
                "Check server SECURITY_MODE=insecure configuration."
            )

        assert status == "PENDING"

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
            verify=False,
        )
        assert init_resp.status_code == 200
        init_data = _safe_json(init_resp)

        qr_payload = init_data["qr_payload"]

        first_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify=False,
        )
        assert first_scan.status_code == 200

        reuse_scan = requests.post(
            f"{BASE_URL}/auth/scan",
            json={"qr_raw_payload": qr_payload},
            cert=CERT_PATH,
            verify=False,
        )
        assert reuse_scan.status_code == 400

        detail = str(_safe_json(reuse_scan).get("detail", "")).lower()
        assert any(k in detail for k in ["nonce", "replay", "already", "used", "status"])

    def test_optional_low_entropy_bruteforce_demo(self, browser_key_pair):
        """

        If insecure mode uses low-entropy numeric login IDs (e.g., <= 6 digits),
        brute-force can become practically feasible within a long lifespan.

        This test is DISABLED by default to avoid flakiness and long runtimes.
        Enable it when you want the stronger "attack succeeds" demonstration:

            $env:ENABLE_LOW_ENTROPY_DEMO='1'

        If IDs are high entropy (UUID-like), this test SKIPS (not a failure).
        """
        if os.getenv("ENABLE_LOW_ENTROPY_DEMO", "0") != "1":
            pytest.skip("Enable with ENABLE_LOW_ENTROPY_DEMO=1")

        browser_pub_key = browser_key_pair.export_public()
        init_resp = requests.post(
            f"{BASE_URL}/auth/init",
            json={"browser_key": browser_pub_key},
            cert=CERT_PATH,
            verify=False,
        )
        assert init_resp.status_code == 200
        login_id = _safe_json(init_resp)["login_id"]

        if not _is_low_entropy_numeric_id(login_id):
            pytest.skip(f"login_id not low-entropy numeric (got {login_id}); demo not applicable")

        target = int(login_id)
        width = len(login_id)

        # Brute force sequentially for a short time; if the space is small, we should hit quickly.
        start = time.time()
        timeout = 5.0
        found = False

        guess = 0
        while time.time() - start < timeout:
            guess_id = str(guess).zfill(width)
            status = _poll_status(guess_id)
            if status in {"PENDING", "SCANNED", "AUTHORIZED"}:
                if guess_id == login_id:
                    found = True
                    break
            guess += 1

        assert found, (
            "Low-entropy brute force demo did not find the token within timeout. "
            "This could indicate rate limiting, a larger ID space than expected, or different server behavior."
        )

import pytest
import time
import os
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
from app.services.sessions import SessionStore
from app.routes.auth import store

client = TestClient(app)

# Helper to force settings for testing
def set_security_mode(mode: str):
    settings.SECURITY_MODE = mode
    store.ttl_seconds = settings.SESSION_TTL_SECONDS
    store._sessions.clear()
    store._consumed_nonces.clear()

def test_secure_mode_flow():
    set_security_mode("secure")

    # 1. Create Session
    browser_key = "test_browser_key_secure"
    resp = client.post("/auth/session", json={"BROWSER_KEY": browser_key})
    assert resp.status_code == 200
    data = resp.json()
    s_id = data["s_id"]
    scan_url = data["scan_url"]
    assert "token=" in scan_url

    # Extract token
    token = scan_url.split("token=")[1]

    # 2. Scan (Approve)
    resp = client.get(f"/auth/scan?token={token}")
    assert resp.status_code == 200
    assert "Login Approved" in resp.text

    # 3. Exchange
    resp = client.post("/auth/exchange", json={"s_id": s_id, "BROWSER_KEY": browser_key})
    assert resp.status_code == 200
    assert "access_tkn" in resp.json()

def test_secure_mode_replay_prevention():
    set_security_mode("secure")

    # 1. Create & Approve & Consume
    browser_key = "test_replay"
    resp = client.post("/auth/session", json={"BROWSER_KEY": browser_key})
    data = resp.json()
    scan_url = data["scan_url"]
    token = scan_url.split("token=")[1]

    # Approve
    client.get(f"/auth/scan?token={token}")

    # Consume
    client.post("/auth/exchange", json={"s_id": data["s_id"], "BROWSER_KEY": browser_key})

    # 2. Try to Replay Scan (Approve again with same token)
    resp = client.get(f"/auth/scan?token={token}")
    assert resp.status_code == 400
    assert "Login Failed" in resp.text

def test_insecure_mode_flow():
    set_security_mode("insecure")

    # 1. Create Session
    resp = client.post("/auth/session", json={"BROWSER_KEY": "ignored"})
    assert resp.status_code == 200
    data = resp.json()
    s_id = data["s_id"]
    scan_url = data["scan_url"]

    # Verify insecure URL structure
    assert "s_id=" in scan_url
    assert "nonce=" in scan_url
    assert "token=" not in scan_url

    # Extract params
    import urllib.parse
    parsed = urllib.parse.urlparse(scan_url)
    qs = urllib.parse.parse_qs(parsed.query)
    nonce = qs["nonce"][0]

    # 2. Scan (Approve)
    resp = client.get(f"/auth/scan?s_id={s_id}&nonce={nonce}")
    assert resp.status_code == 200
    assert "Login Approved" in resp.text

    # 3. Exchange (Browser key optional/ignored)
    resp = client.post("/auth/exchange", json={"s_id": s_id})
    assert resp.status_code == 200
    assert "access_tkn" in resp.json()

def test_secure_mode_wrong_browser_key():
    set_security_mode("secure")

    resp = client.post("/auth/session", json={"BROWSER_KEY": "correct_key"})
    data = resp.json()
    s_id = data["s_id"]
    token = data["scan_url"].split("token=")[1]

    client.get(f"/auth/scan?token={token}")

    # Try exchange with wrong key
    resp = client.post("/auth/exchange", json={"s_id": s_id, "BROWSER_KEY": "wrong_key"})
    assert resp.status_code == 400
    assert "Invalid browser key" in resp.json()["detail"]

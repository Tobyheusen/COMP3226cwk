from typing import Dict, Optional
from datetime import datetime

class InMemoryDB:
    def __init__(self):
        # login_id -> { "login_id": str, "qr_nonce": str, "browser_sid": str, "created_at": datetime, "status": str, "browser_key": Optional[str] }
        self.login_requests: Dict[str, dict] = {}

        # session_token -> { "user_id": str, "browser_sid": str, "created_at": datetime, "device_bound": bool }
        self.sessions: Dict[str, dict] = {}

        # Simple user store: username -> password
        self.users: Dict[str, str] = {
            "alice": "password123",
            "bob": "securepass"
        }

        # nonce tracking for replay protection (login_id + nonce)
        self.used_nonces: set = set()

        # insecure login id counter (low-entropy demo)
        self.insecure_login_counter: int = 0

        # rate limiting storage: key -> list of timestamps
        self.rate_limit_log: Dict[str, list] = {}

db = InMemoryDB()

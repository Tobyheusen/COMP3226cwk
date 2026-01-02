# In-memory QR login session management (creation, approval, 
# expiry, and consumption).


import time
import secrets
import threading
from dataclasses import dataclass

@dataclass
class LoginSession:
    session_id: str
    created_at: int
    expires_at: int
    browser_key: str | None  # RQ1: Browser Binding
    approved: bool = False
    approved_at: int | None = None
    consumed: bool = False
    approval_nonce: str = ""

class SessionStore:
    def __init__(self, ttl_seconds: int):
        if ttl_seconds <= 0:
            raise ValueError("TTL must be greater than 0")
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, LoginSession] = {}
        self.lock = threading.Lock()

    def _now(self) -> int:
        return int(time.time())

    def _cleanup(self) -> None:
        # Remove expired sessions
        now = self._now()
        expired = [
            s_id for s_id, session in self._sessions.items()
            if session.expires_at <= now
        ]
        for s_id in expired:
            self._sessions.pop(s_id, None)

    def create(self, browser_key: str | None = None) -> LoginSession:
        # Create a new session for login
        with self.lock:
            self._cleanup()
            now = self._now()
            session_id = secrets.token_urlsafe(24)
            approval_nonce = secrets.token_urlsafe(16)
            s = LoginSession(
                session_id=session_id,
                created_at=now,
                expires_at=now + self.ttl_seconds,
                browser_key=browser_key,
                approved=False,
                approved_at=None,
                consumed=False,
                approval_nonce=approval_nonce
            )
            self._sessions[session_id] = s
            return s

    def get(self, s_id: str) -> LoginSession | None:
        # Return the session if it exists and is not expired
        with self.lock:
            self._cleanup()
            s = self._sessions.get(s_id)
            if not s:
                return None
            if s.expires_at <= self._now() or s.consumed:
                return None
            return s

    
    def approve(self, s_id: str, nonce: str) -> bool:
        # Session is approved if it exists and is not expired
        # and has not been consumed
        # and the nonce matches the one used for approval
        with self.lock:
            self._cleanup()
            s = self._sessions.get(s_id)
            if not s:
                return False
            
            now = self._now()
            
            if s.expires_at <= now or s.consumed:
                self._sessions.pop(s_id, None)
                return False
            
            if not nonce or nonce != s.approval_nonce:
                return False
            
            if not s.approved:
                s.approved = True
                s.approved_at = now
            return True
        
    
    def consume(self, s_id: str) -> bool:
        # Consume session once if it exists and is not expired
        # and has not been consumed
        # And approved
        with self.lock:
            self._cleanup()
            s = self._sessions.get(s_id)
            if not s:
                return False
            
            now = self._now()
            if s.expires_at <= now:
                self._sessions.pop(s_id, None)
                return False
            
            if s.consumed or not s.approved:
                return False
            
            s.consumed = True
            self._sessions.pop(s_id, None)
            return True
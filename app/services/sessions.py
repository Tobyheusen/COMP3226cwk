# In-memory QR login session management (creation, approval, 
# expiry, and consumption).


import time
import secrets
import threading
from dataclasses import dataclass
from app.core.config import settings

@dataclass
class LoginSession:
    session_id: str
    created_at: int
    expires_at: int
    approved: bool = False
    approved_at: int | None = None
    consumed: bool = False
    approval_nonce: str = ""
    BROWSER_KEY: str | None = None  # Optional field for browser key auth, for secure model

class SessionStore:
    def __init__(self, ttl_seconds: int):
        if ttl_seconds <= 0:
            raise ValueError("TTL must be greater than 0")
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, LoginSession] = {}
        # Stores recently consumed nonces to detect replays: {nonce: expire_time}
        self._consumed_nonces: dict[str, int] = {}
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

        # Remove expired consumed nonces
        expired_nonces = [
            nonce for nonce, exp in self._consumed_nonces.items()
            if exp <= now
        ]
        for nonce in expired_nonces:
            self._consumed_nonces.pop(nonce, None)

    def is_replay(self, nonce: str) -> bool:
        """Check if a nonce has been recently consumed."""
        with self.lock:
            self._cleanup()
            return nonce in self._consumed_nonces

    def create(self, BROWSER_KEY: str | None = None) -> LoginSession:
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
                approved=False,
                approved_at=None,
                consumed=False,
                approval_nonce=approval_nonce,
                BROWSER_KEY=BROWSER_KEY
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

        if settings.IS_SECURE and self.is_replay(nonce):
            return False

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

            # Record nonce as consumed to prevent replay
            # Keep it in cache for a while (e.g. 5 minutes) to detect immediate replays
            if settings.IS_SECURE:
                self._consumed_nonces[s.approval_nonce] = now + 300

            self._sessions.pop(s_id, None)
            return True

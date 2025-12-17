# In-memory QR login session management (creation, approval, 
# expiry, and consumption).


import time
import secrets
from dataclasses import dataclass

@dataclass
class LoginSession:
    session_id: str
    created_at: int
    expires_at: int
    approved: bool = False
    approved_at: int | None = None
    consumed: bool = False
    approval_nonce: str = ""

class SessionStore:
    def __init__(self, ttl_second: int):
    # Add shit

    def _now(self) -> int:
    # Add shit

    def _cleanup(self) -> None:
    # Add shit
    
    def create(self) -> LoginSession:
    # Add shit

    def get(self, s_id: str) -> LoginSession | None:
    # Add shit
    
    def approve(self, s_id: str, nonce: str) -> bool:
    # Add shit
    
    def consume(self, s_id: str) -> bool:
    # Add shit
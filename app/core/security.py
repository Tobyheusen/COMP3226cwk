# Security-related helpers such as JWT creation and token handling.
import time
import jwt
from app.core.config import settings

def create_access_token (sub: str, extra: dict | None = None, exp_seconds: int = 900) -> str:
    now = int(time.time())
    payload = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + exp_seconds,
        "sub": sub,
    }

    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")
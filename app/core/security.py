# Security-related helpers such as JWT creation and token handling.
import time
import jwt
from app.core.config import settings
from cryptography.fernet import Fernet

cipher = Fernet(settings.ENCRYPTION_KEY.encode())

def create_access_token (sub: str, extra: dict | None = None, exp_seconds: int = 900) -> str:
    """
    :param sub: Description
    :type sub: str

    :param extra: Description
    :type extra: dict | None

    :param exp_seconds: Description
    :type exp_seconds: int
    
    :return: Description
    :rtype: str
    """
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

def encrypt_qr_payload(session_id: str, nonce: str) -> str:
    """
    Combines session_id and nonce, then encrypts them.
    """
    raw_data = f"{session_id}:{nonce}"
    return cipher.encrypt(raw_data.encode()).decode()

def decrypt_qr_payload(token: str) -> tuple[str, str] | None:
    """
    Decrypts the token and returns (session_id, nonce).
    """
    try:
        decrypted = cipher.decrypt(token.encode()).decode()
        s_id, nonce = decrypted.split(":")
        return s_id, nonce
    except Exception:
        return None
import os
from enum import Enum
from pydantic import BaseModel

class SecurityMode(str, Enum):
    INSECURE = "insecure"
    SECURE = "secure"

class Settings(BaseModel):
    # App Config
    APP_NAME: str = "QR Login Prototype"
    # Read from environment variable, default to SECURE
    SECURITY_MODE: SecurityMode = SecurityMode(os.getenv("SECURITY_MODE", "secure").lower())

    # Secrets
    SECRET_KEY: str = "supersecretkey" 

    # Timeouts (in seconds)
    LOGIN_TIMEOUT: int = 60  # Default 60s
    SESSION_TIMEOUT: int = 3600 # 1 hour

    # Insecure demo toggles
    LOW_ENTROPY_LOGIN_IDS: bool = os.getenv("LOW_ENTROPY_LOGIN_IDS", "0").lower() in ("1", "true", "yes")
    INSECURE_LOGIN_ID_DIGITS: int = int(os.getenv("INSECURE_LOGIN_ID_DIGITS", "6"))

    # Rate limit toggles (poll endpoint)
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "0").lower() in ("1", "true", "yes")
    RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "20"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "1"))

    # Configuration toggles based on Security Mode
    @property
    def token_lifetime(self) -> int:
        # Allow override via environment variable for testing
        env_lifetime = os.getenv("TOKEN_LIFETIME")
        if env_lifetime:
            try:
                return int(env_lifetime)
            except ValueError:
                pass
        
        if self.SECURITY_MODE == SecurityMode.INSECURE:
            return 3600  # insecure mode
        return 60  # secure mode

    @property
    def require_browser_binding(self) -> bool:
        return self.SECURITY_MODE == SecurityMode.SECURE

    @property
    def use_signed_qr(self) -> bool:
        return self.SECURITY_MODE == SecurityMode.SECURE

    @property
    def use_low_entropy_login_ids(self) -> bool:
        return self.SECURITY_MODE == SecurityMode.INSECURE and self.LOW_ENTROPY_LOGIN_IDS

    @property
    def insecure_login_id_digits(self) -> int:
        # Clamp to a sane range to avoid excessive memory/time usage
        digits = self.INSECURE_LOGIN_ID_DIGITS
        if digits < 1:
            return 1
        if digits > 6:
            return 6
        return digits

    @property
    def rate_limit_enabled(self) -> bool:
        return self.SECURITY_MODE == SecurityMode.SECURE and self.RATE_LIMIT_ENABLED

settings = Settings()

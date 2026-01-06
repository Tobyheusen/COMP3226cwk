import os
from enum import Enum
from pydantic import BaseModel

class SecurityMode(str, Enum):
    INSECURE = "insecure"
    SECURE = "secure"

class Settings(BaseModel):
    # App Config
    APP_NAME: str = "QR Login Prototype"
    SECURITY_MODE: SecurityMode = SecurityMode.SECURE

    # Secrets
    SECRET_KEY: str = "supersecretkey"  # In prod, get from env

    # Timeouts (in seconds)
    LOGIN_TIMEOUT: int = 60  # Default 60s
    SESSION_TIMEOUT: int = 3600 # 1 hour

    # Configuration toggles based on Security Mode
    @property
    def token_lifetime(self) -> int:
        if self.SECURITY_MODE == SecurityMode.INSECURE:
            return 3600  # Long life in insecure mode
        return 60  # Short life (30-60s) in secure mode

    @property
    def require_browser_binding(self) -> bool:
        return self.SECURITY_MODE == SecurityMode.SECURE

    @property
    def use_signed_qr(self) -> bool:
        return self.SECURITY_MODE == SecurityMode.SECURE

    # mTLS settings
    USE_MTLS: bool = False

settings = Settings()

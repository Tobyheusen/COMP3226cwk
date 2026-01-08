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

    # Configuration toggles based on Security Mode
    @property
    def token_lifetime(self) -> int:
        if self.SECURITY_MODE == SecurityMode.INSECURE:
            return 3600  # insecure mode
        return 60  # secure mode

    @property
    def require_browser_binding(self) -> bool:
        return self.SECURITY_MODE == SecurityMode.SECURE

    @property
    def use_signed_qr(self) -> bool:
        return self.SECURITY_MODE == SecurityMode.SECURE

settings = Settings()

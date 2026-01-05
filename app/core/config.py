# Centralised application configuration 
# (environment variables, constants, timeouts).

import os
from cryptography.fernet import Fernet

class Settings:
    """
    QR code login application settings.
    """
    APP_NAME = "QR Login Prototype"
    JWT_SECRET = os.getenv("JWT_SECRET", "dev-change-me")
    JWT_ISSUER = os.getenv("JWT_ISSUER", "qr-login-local")
    JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "qr-login-browser")

    # Security Mode: "secure" or "insecure"
    SECURITY_MODE = os.getenv("SECURITY_MODE", "secure").lower()

    @property
    def IS_SECURE(self) -> bool:
        return self.SECURITY_MODE == "secure"

    # RQ3 implementation
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())

    @property
    def ENCRYPTION_ENABLED(self) -> bool:
        return self.IS_SECURE

    # RQ1 implementation: Browser Binding
    @property
    def BROWSER_KEY(self) -> bool:
        # In secure mode, we enforce browser binding
        return self.IS_SECURE

    # RQ2 implementation: Token Lifecycle & Rate Limiting
    @property
    def SESSION_TTL_SECONDS(self) -> int:
        # Secure: 30-60 seconds (spec says 30-60 considered acceptable)
        # Insecure: Extended life-span (e.g. 10 minutes)
        if self.IS_SECURE:
            return 60
        else:
            return 600

    @property
    def POLL_MIN_INTERVAL_MS(self) -> int:
        # Secure: Faster polling allowed or standard?
        # Spec doesn't explicitly limit polling speed for security, but rate limiting applies.
        # We'll keep it standard.
        return 300

    @property
    def RATE_LIMIT_ENABLED(self) -> bool:
        return self.IS_SECURE

    @property
    def MAX_REQUESTS_PER_MINUTE(self) -> int:
        return 5

    
# All saved settings instance
settings = Settings()

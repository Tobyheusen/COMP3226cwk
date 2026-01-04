# Centralised application configuration 
# (environment variables, constants, timeouts).

import os
from cryptography.fernet import Fernet

class Settings:
    """
    QR code login application settings.
    """
    APP_NAME = "OR Login Prototype"
    JWT_SECRET = os.getenv("JWT_SECRET", "dev-change-me")
    JWT_ISSUER = os.getenv("JWT_ISSUER", "qr-login-local")
    JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "qr-login-browser")

    #Security settings
    BROWSER_KEY = os.getenv("BROWSER_KEY", "True").lower() == "true"  # To get a secure mode (will change to have more settings later)

    SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "0")) # 2 Minutes
    LONG_SESSION_TTL_SECONDS = os.getenv("SESSION_TTL_SECONDS", "True").lower() == "true"
    @property
    def SESSION_TTL_SECONDS(self) -> int:
        if self.LONG_SESSION_TTL_SECONDS:
            return 60  # 1 Minute
        else:
            return 600  # 10 Minutes
    
    LONG_POLL_MIN_INTERVAL_MS = os.getenv("POLL_MIN_INTERVAL_MS", "True").lower() == "true"
    POLL_MIN_INTERVAL_MS = int(os.getenv("POLL_MIN_INTERVAL_MS", "0"))
    @property
    def POLL_MIN_INTERVAL_MS(self) -> int:
        if self.LONG_POLL_MIN_INTERVAL_MS:
            return 800  # 800 ms
        else:
            return 300  # 300 ms

    #RQ3 implementation
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
    
    #RQ2 implementation 
    RATE_LIMIT_ENABLED = True
    MAX_REQUESTS_PER_MINUTE = 5

    
    
# All saved settings instance
settings = Settings()
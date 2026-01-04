# Centralised application configuration 
# (environment variables, constants, timeouts).

import os
class Settings:
    APP_NAME = "OR Login Prototype"
    JWT_SECRET = os.getenv("JWT_SECRET", "dev-change-me")
    JWT_ISSUER = os.getenv("JWT_ISSUER", "qr-login-local")
    JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "qr-login-browser")
    SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "0")) # 2 Minutes
    POLL_MIN_INTERVAL_MS = int(os.getenv("POLL_MIN_INTERVAL_MS", "0"))
    LONG_SESSION_TTL_SECONDS = os.getenv("SESSION_TTL_SECONDS", "True").lower() == "true"
    LONG_POLL_MIN_INTERVAL_MS = os.getenv("POLL_MIN_INTERVAL_MS", "True").lower() == "true"

    BROWSER_KEY = os.getenv("BROWSER_KEY", "True").lower() == "true"  # To get a secure mode (will change to have more settings later)

    @property
    def SESSION_TTL_SECONDS(self) -> int:
        if self.LONG_SESSION_TTL_SECONDS:
            return 60  # 1 Minute
        else:
            return 600  # 10 Minutes
        
    @property
    def POLL_MIN_INTERVAL_MS(self) -> int:
        if self.LONG_POLL_MIN_INTERVAL_MS:
            return 800  # 800 ms
        else:
            return 300  # 300 ms
    

settings = Settings()
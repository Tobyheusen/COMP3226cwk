# Centralised application configuration 
# (environment variables, constants, timeouts).

import os
class Settings:
    APP_NAME = "OR Login Prototype"
    JWT_SECRET = os.getenv("JWT_SECRET", "dev-change-me")
    JWT_ISSUER = os.getenv("JWT_ISSUER", "qr-login-local")
    JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "qr-login-browser")
    SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "120")) # 2 Minutes
    POLL_MIN_INTERVAL_MS = int(os.getenv("POLL_MIN_INTERVAL_MS", "800"))

settings = Settings()
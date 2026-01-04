import time
from fastapi import Request, HTTPException
from app.core.config import settings

class RateLimiter:
    def __init__(self):
        """
        __init__ Initializes the rate limiter
        
        :param self: Description
        """
        self._requests = {}  # Stores IP -> [timestamp1, timestamp2...]

    def check(self, request: Request):
        """
        check Enforces rate limiting based on client IP
        
        :param self: Description
        :param request: Description
        :type request: Request
        """
        if not settings.RATE_LIMIT_ENABLED:
            return

        client_ip = request.client.host
        now = time.time()
        
        # Initialize if new IP
        if client_ip not in self._requests:
            self._requests[client_ip] = []

        # Filter out requests older than 1 minute
        self._requests[client_ip] = [t for t in self._requests[client_ip] if now - t < 60]

        # Check count
        if len(self._requests[client_ip]) >= settings.MAX_REQUESTS_PER_MINUTE:
            raise HTTPException(status_code=429, detail="Too many login attempts. Please wait.")

        # Add current request
        self._requests[client_ip].append(now)

limiter = RateLimiter()
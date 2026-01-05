import uuid
import secrets
import logging
from datetime import datetime, timedelta
from app.db import db
from app.core.config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthService:
    @staticmethod
    def initiate_login(browser_key: str = None) -> dict:
        """
        Creates a new login request.
        Returns details needed for the frontend (login_id, browser_sid, qr_code_base64).
        """
        # Enforce Browser Binding in Secure Mode
        if settings.require_browser_binding and not browser_key:
            logger.warning("Login initiation rejected: Missing browser_key in Secure Mode")
            raise ValueError("Browser key is required in Secure Mode")

        login_id = str(uuid.uuid4())
        browser_sid = secrets.token_hex(16)
        qr_nonce = secrets.token_hex(16)

        # Store in DB
        db.login_requests[login_id] = {
            "login_id": login_id,
            "qr_nonce": qr_nonce,
            "browser_sid": browser_sid,
            "created_at": datetime.utcnow(),
            "status": "PENDING",
            "browser_key": browser_key
        }

        logger.info(f"Login Initiated: login_id={login_id}, secure_mode={settings.SECURITY_MODE}")

        return {
            "login_id": login_id,
            "browser_sid": browser_sid,
            "qr_nonce": qr_nonce
        }

    @staticmethod
    def validate_scan(login_id: str, qr_payload: dict) -> bool:
        """
        Validates the scanned QR payload against the stored login request.
        """
        request = db.login_requests.get(login_id)
        if not request:
            logger.warning(f"Scan failed: login_id={login_id} not found")
            return False

        if request["status"] != "PENDING":
            logger.warning(f"Scan failed: login_id={login_id} status is {request['status']}")
            return False

        # Check Expiry
        created_at = request["created_at"]
        if datetime.utcnow() - created_at > timedelta(seconds=settings.token_lifetime):
            request["status"] = "EXPIRED"
            logger.info(f"Scan failed: login_id={login_id} expired")
            return False

        # Verify Payload content matches DB
        if qr_payload.get("login_id") != login_id:
            return False

        if qr_payload.get("browser_sid") != request["browser_sid"]:
            logger.warning(f"Scan failed: login_id={login_id} browser_sid mismatch")
            return False

        # Check Nonce (Secure Mode)
        if settings.SECURITY_MODE == "secure":
            received_nonce = qr_payload.get("qr_nonce")
            stored_nonce = request["qr_nonce"]

            # 1. Nonce Matching
            if received_nonce != stored_nonce:
                logger.warning(f"Scan failed: login_id={login_id} invalid nonce")
                return False

            # 2. Replay Protection
            if received_nonce in db.used_nonces:
                logger.warning(f"Replay detected: login_id={login_id} nonce used")
                return False

            db.used_nonces.add(received_nonce)

        # Mark as Scanned
        request["status"] = "SCANNED"
        logger.info(f"Scan success: login_id={login_id}")
        return True

    @staticmethod
    def approve_login(login_id: str, user_id: str) -> bool:
        """
        User approves the login on their device.
        """
        request = db.login_requests.get(login_id)
        if not request or request["status"] != "SCANNED":
            return False

        # Create session
        session_token = secrets.token_urlsafe(32)
        device_bound = bool(request.get("browser_key"))

        db.sessions[session_token] = {
            "user_id": user_id,
            "browser_sid": request["browser_sid"],
            "created_at": datetime.utcnow(),
            "device_bound": device_bound
        }

        request["status"] = "AUTHORIZED"
        request["session_token"] = session_token
        logger.info(f"Login Approved: login_id={login_id}, user={user_id}, device_bound={device_bound}")
        return True

    @staticmethod
    def get_login_status(login_id: str) -> dict:
        request = db.login_requests.get(login_id)
        if not request:
            return {"status": "NOT_FOUND"}

        if request["status"] == "AUTHORIZED":
            return {
                "status": "AUTHORIZED",
                "session_token": request.get("session_token"),
                "redirect_url": "/dashboard"
            }

        return {"status": request["status"]}

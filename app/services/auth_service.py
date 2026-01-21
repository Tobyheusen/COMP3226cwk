import uuid
import secrets
import logging
from datetime import datetime, timedelta
import json
from app.db import db
from app.core.config import settings
from app.services.crypto_utils import CryptoUtils

"""AuthService: Handles the core authentication logic for QR code login flow"""


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthService:
    @staticmethod
    def _next_insecure_login_id() -> str:
        """
        Generates a low-entropy numeric login_id for insecure demo mode.
        This makes brute-force feasible for demonstration purposes.
        """
        digits = settings.insecure_login_id_digits
        max_value = 10 ** digits

        # Try up to max_value times to avoid collisions
        for _ in range(max_value):
            candidate = str(db.insecure_login_counter % max_value).zfill(digits)
            db.insecure_login_counter += 1
            if candidate not in db.login_requests:
                return candidate

        raise RuntimeError("No available insecure login_id values")

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

        if settings.use_low_entropy_login_ids:
            login_id = AuthService._next_insecure_login_id()
        else:
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
            logger.warning(f"Scan failed: login_id={login_id} status is already {request['status']}")
            return False

        # Check Expiry
        created_at = request["created_at"]
        if datetime.utcnow() - created_at > timedelta(seconds=settings.token_lifetime):
            request["status"] = "EXPIRED"
            logger.info(f"Scan failed: login_id={login_id} expired")
            return False

        # Verify Payload content matches DB
        if qr_payload.get("login_id") != login_id:
            logger.warning(f"Scan failed: login_id={login_id} mismatch")
            return False

        if qr_payload.get("browser_sid") != request["browser_sid"]:
            logger.warning(f"Scan failed: login_id={login_id} browser_sid mismatch")
            return False

        # Check Nonce (Secure Mode)
        if settings.SECURITY_MODE == "secure":
            received_nonce = qr_payload.get("qr_nonce")
            stored_nonce = request["qr_nonce"]

            # Nonce Matching
            if received_nonce != stored_nonce:
                logger.warning(f"Scan failed: login_id={login_id} invalid nonce")
                return False

            # Replay Protection
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
            logger.warning(f"Approve failed: login_id={login_id} not found or not scanned")
            return False

        # Create session, and encrypt the session token if needed
        session_token = secrets.token_urlsafe(32)
        device_bound = bool(request.get("browser_key"))  # prevents session hijacking if browser_key is set

        db.sessions[session_token] = {  # Saves to memory db
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
            logger.warning(f"Status check failed: login_id={login_id} not found")
            return {"status": "NOT_FOUND"}

        # Check if token has expired (for PENDING tokens)
        if request["status"] == "PENDING":
            created_at = request["created_at"]
            if datetime.utcnow() - created_at > timedelta(seconds=settings.token_lifetime):
                request["status"] = "EXPIRED"
                logger.info(f"Token expired during status check: login_id={login_id}")

        if request["status"] == "AUTHORIZED":
            # In Secure Mode, do not return session_token here.
            # Client must prove possession of the key.
            response = {
                "status": "AUTHORIZED",
                "redirect_url": "/dashboard"
            }

            if not settings.require_browser_binding:
                # Legacy/Insecure mode: return token directly
                response["session_token"] = request.get("session_token")

            return response  # returns the response 

        return {"status": request["status"]}  # Searches for the status fort that request 

    @staticmethod
    def verify_session_proof(login_id: str, signature: str) -> dict:
        """
        Verifies that the client possesses the private key corresponding to the
        public key (browser_key) provided during initiation.
        """
        request = db.login_requests.get(login_id)
        if not request:
            logger.warning(f"Session proof failed: login_id={login_id} not found")
            raise ValueError("Login request not found")

        if request["status"] != "AUTHORIZED":
            logger.warning(f"Session proof failed: login_id={login_id} not authorized")
            raise ValueError("Login not yet authorized")

        if not settings.require_browser_binding:
            # If not in secure mode, maybe just return token?
            # But this endpoint is specifically for proof.
            return {"session_token": request.get("session_token")}

        browser_key_jwk = request.get("browser_key")
        if not browser_key_jwk:
             logger.error(f"Session proof failed: login_id={login_id} missing browser key")
             raise ValueError("No browser key bound to this session")

        try:
            jwk_dict = json.loads(browser_key_jwk)
        except json.JSONDecodeError:
            logger.error(f"Session proof failed: login_id={login_id} invalid browser key format")
            raise ValueError("Invalid Browser Key format")

        # Verify signature over login_id
        if CryptoUtils.verify_raw_signature(jwk_dict, login_id, signature):
            return {"session_token": request.get("session_token")}
        else:
            logger.warning(f"Signature verification failed for login_id={login_id}")
            raise ValueError("Invalid Signature or Proof of Possession failed")

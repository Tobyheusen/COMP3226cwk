from fastapi import APIRouter, HTTPException, Request, Depends
import time
from pydantic import BaseModel
from app.services.auth_service import AuthService
from app.services.qr_service import QRService
from app.core.config import settings
from app.db import db
import urllib.parse
"""
Auth handles the QR code data and calls auth_service methods to process the login activities etc
"""
router = APIRouter(prefix="/auth", tags=["auth"])

def _enforce_rate_limit(request: Request, key_suffix: str) -> None:
    """
    Simple in-memory rate limiter for demo/testing.
    Applies only when rate limiting is enabled in secure mode.
    """
    if not settings.rate_limit_enabled:
        return

    client_ip = request.client.host if request.client else "unknown"
    key = f"{client_ip}:{key_suffix}"
    now = time.time()

    window = max(1, settings.RATE_LIMIT_WINDOW_SECONDS)
    max_requests = max(1, settings.RATE_LIMIT_MAX_REQUESTS)

    timestamps = db.rate_limit_log.get(key, [])
    # Keep only timestamps within the window
    timestamps = [t for t in timestamps if now - t <= window]

    if len(timestamps) >= max_requests:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    timestamps.append(now)
    db.rate_limit_log[key] = timestamps

class InitLoginRequest(BaseModel):
    browser_key: str = None  # For DBSC

class InitLoginResponse(BaseModel):
    login_id: str
    qr_image: str # Base64, the actual QR code image
    qr_payload: str # Raw Data
    qr_link: str # The URL encoded in the QR

class ScanLoginRequest(BaseModel):
    qr_raw_payload: str # The string scanned from the QR

class ApproveLoginRequest(BaseModel):
    login_id: str
    user_id: str

class TokenExchangeRequest(BaseModel):
    login_id: str
    signature: str # Base64 encoded signature of login_id

# This is called in the main.py method inside startLogin()
@router.post("/init", response_model=InitLoginResponse)
def initiate_login(body: InitLoginRequest, request: Request):
    """
    Called by the browser to start the login flow.
    """
    try:
        details = AuthService.initiate_login(browser_key=body.browser_key) # Initiate login, passing the the val of browser_key in body
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))  # if it cannot fail

    # Construct Payload of the login_id and the browser_sid
    payload_data = {
        "login_id": details["login_id"],
        "browser_sid": details["browser_sid"]
    }

    # if its in Secure Mode use a nonce
    if settings.SECURITY_MODE == "secure":
        payload_data["qr_nonce"] = details["qr_nonce"]

    # Generate Signed QR Payload based off the data
    # signing 
    qr_str = QRService.generate_signed_payload(payload_data)

    # Generate URL Link
    # request.base_url gives e.g. "http://127.0.0.1:8000/"
    base_url = str(request.base_url).rstrip("/")
    encoded_payload = urllib.parse.quote(qr_str)
    qr_link = f"{base_url}/mobile-sim?p={encoded_payload}"

    # Generate QR Image from the Link
    qr_img = QRService.create_qr_image(qr_link)

    # Returns info to the in the InitLoginResponse class 
    return InitLoginResponse(
        login_id=details["login_id"],
        qr_image=qr_img,
        qr_payload=qr_str,
        qr_link=qr_link
    )

# Called in the main.py method inside onScan() for the mobile app simulation
@router.post("/scan")
def scan_login(request: ScanLoginRequest):
    """
    Called by the mobile app (simulated) when scanning.
    """
    # Verify Signature for the QR code payload
    data = QRService.verify_qr_payload(request.qr_raw_payload)
    if not data:
        raise HTTPException(status_code=400, detail="Invalid or Tampered QR")

    # compare login_id from the db
    login_id = data.get("login_id")
    if not login_id:
        raise HTTPException(status_code=400, detail="Missing login_id")

    # Validate the nonce and expary (Nonce, Expiry)
    # validate_scan takes the login_id and the data dictonary thats vlaidated in the validate_scan method in auth_service.py
    if not AuthService.validate_scan(login_id, data):
        raise HTTPException(status_code=400, detail="Validation Failed (Expired, Invalid Nonce, or Replay)")

    return {"status": "SCANNED", "login_id": login_id}

@router.post("/approve")
def approve_login(request: ApproveLoginRequest):
    """
    Called by the mobile app (simulated) to approve login.
    """
    # Approve the login in the with the login_id and user_id (user id is only a name no real security implications)
    if AuthService.approve_login(request.login_id, request.user_id):
        return {"status": "APPROVED"}

    raise HTTPException(status_code=400, detail="Approval Failed")

@router.get("/poll/{login_id}")
def poll_login(login_id: str, request: Request):
    """
    Called by the browser to check status.
    """
    _enforce_rate_limit(request, "poll")
    return AuthService.get_login_status(login_id)

@router.post("/token")
def exchange_token(body: TokenExchangeRequest):
    """
    Called by the browser to exchange a proof of possession for a session token.
    """
    try:
        # The signature is the encodded signature of the login_id to stop sessoin_hijacking
        return AuthService.verify_session_proof(body.login_id, body.signature)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

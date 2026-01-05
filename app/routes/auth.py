from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from app.services.auth_service import AuthService
from app.services.qr_service import QRService
from app.core.config import settings
import urllib.parse

router = APIRouter(prefix="/auth", tags=["auth"])

class InitLoginRequest(BaseModel):
    browser_key: str = None  # For DBSC

class InitLoginResponse(BaseModel):
    login_id: str
    qr_image: str # Base64
    qr_payload: str # Raw Data (for debugging/legacy)
    qr_link: str # The URL encoded in the QR

class ScanLoginRequest(BaseModel):
    qr_raw_payload: str # The string scanned from the QR

class ApproveLoginRequest(BaseModel):
    login_id: str
    user_id: str

@router.post("/init", response_model=InitLoginResponse)
def initiate_login(body: InitLoginRequest, request: Request):
    """
    Called by the browser to start the login flow.
    """
    try:
        details = AuthService.initiate_login(browser_key=body.browser_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Construct Payload
    payload_data = {
        "login_id": details["login_id"],
        "browser_sid": details["browser_sid"]
    }

    # Include nonce in Secure Mode
    if settings.SECURITY_MODE == "secure":
        payload_data["qr_nonce"] = details["qr_nonce"]

    qr_str = QRService.generate_signed_payload(payload_data)

    # Generate URL Link
    # request.base_url gives e.g. "http://127.0.0.1:8000/"
    base_url = str(request.base_url).rstrip("/")
    encoded_payload = urllib.parse.quote(qr_str)
    qr_link = f"{base_url}/mobile-sim?p={encoded_payload}"

    # Generate QR Image from the Link
    qr_img = QRService.create_qr_image(qr_link)

    return InitLoginResponse(
        login_id=details["login_id"],
        qr_image=qr_img,
        qr_payload=qr_str,
        qr_link=qr_link
    )

@router.post("/scan")
def scan_login(request: ScanLoginRequest):
    """
    Called by the mobile app (simulated) when scanning.
    """
    # Verify Signature first
    data = QRService.verify_qr_payload(request.qr_raw_payload)
    if not data:
        raise HTTPException(status_code=400, detail="Invalid or Tampered QR")

    login_id = data.get("login_id")
    if not login_id:
        raise HTTPException(status_code=400, detail="Missing login_id")

    # Validate Logic (Nonce, Expiry)
    if not AuthService.validate_scan(login_id, data):
        raise HTTPException(status_code=400, detail="Validation Failed (Expired, Invalid Nonce, or Replay)")

    return {"status": "SCANNED", "login_id": login_id}

@router.post("/approve")
def approve_login(request: ApproveLoginRequest):
    """
    Called by the mobile app (simulated) to approve login.
    """
    if AuthService.approve_login(request.login_id, request.user_id):
        return {"status": "APPROVED"}

    raise HTTPException(status_code=400, detail="Approval Failed")

@router.get("/poll/{login_id}")
def poll_login(login_id: str):
    """
    Called by the browser to check status.
    """
    return AuthService.get_login_status(login_id)

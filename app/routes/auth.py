# Authentication-related routes, including QR session creation, 
# approval, polling, and token exchange.

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from app.core.config import settings
from app.core.security import create_access_token
from app.services.sessions import SessionStore
from app.services.limiter import limiter
from app.core.security import encrypt_qr_payload, decrypt_qr_payload

import qrcode
import io
import os
import base64

router = APIRouter(prefix="/auth", tags=["auth"])
store = SessionStore(ttl_seconds=settings.SESSION_TTL_SECONDS)

class CreateSessionResp(BaseModel):
    s_id: str
    scan_url: str
    qr_base64: str

class CreateSessionReq(BaseModel):
    BROWSER_KEY: str | None = None  # Optional field for secure mode

class ApprovedReq(BaseModel):
    s_id: str
    nonce: str

class PollResp(BaseModel):
    status: str

class ExchangeReq(BaseModel):
    s_id: str
    BROWSER_KEY: str | None = None  # for secure mode

class ExchangeResp(BaseModel):
    access_tkn: str

@router.post("/session", response_model=CreateSessionResp)  #Logic here has been moved from main.py
def create_session(request: Request, body: CreateSessionReq):
    """
    creates a new login session and returns the QR code data
    
    :param request: Description
    :type request: Request
    :param body: Description
    :type body: CreateSessionReq
    """
    # Create a login session
    s = store.create(BROWSER_KEY=body.BROWSER_KEY)
    print(f"Browser Key is: {s}")

    base_url_str = os.getenv("BASE_URL", str(request.base_url).rstrip("/"))

    #Encrypted handelling 
    encrypted_token = encrypt_qr_payload(s.session_id, s.approval_nonce)
    scan_url = f"{base_url_str}/auth/scan?token={encrypted_token}"

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(scan_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    qr_image_base64 = base64.b64encode(buffer.getvalue()).decode()

    print(f"Created session {s.session_id} with scan URL: {scan_url}")
    print(f"Encrypted version is: {encrypted_token}")
    print(f"Which decodes to: {decrypt_qr_payload(encrypted_token)}")
    
    return CreateSessionResp(s_id=s.session_id, scan_url=scan_url,qr_base64=qr_image_base64)

@router.get("/scan", response_class=HTMLResponse)
def scan_link(request: Request, token: str):
    """
    scan link is endpoint for QR code approval
    
    :param request: Description
    :type request: Request
    :param token: Description
    :type token: str
    """

    limiter.check(request)

    decrypted = decrypt_qr_payload(token)

    if not decrypted:
        return HTMLResponse(content="<h1>Error</h1><p>Invalid or tampered QR code</p>", status_code=400)
    
    s_id, nonce = decrypted

    ok = store.approve(s_id, nonce)

    if not ok:
        return HTMLResponse(
            content="""
            <!DOCTYPE html>
            <html>
            <head><title>Login Failed</title></head>
            <body style="text-align: center; padding: 50px;">
                <h1> X Login Failed</h1>
                <p>Invalid or expired session. Please try scanning again.</p>
                <p><small>Session ID: {}</small></p>
            </body>
            </html>
            """.format(s_id),
            status_code=400
        )
    
    print (f"Session {s_id} approved via scan")
    print (f'The security settings used where {settings.LONG_SESSION_TTL_SECONDS}, {settings.LONG_POLL_MIN_INTERVAL_MS} and {settings.BROWSER_KEY}')
    
    return HTMLResponse(
        content="""
        <!DOCTYPE html>
        <html>
        <head><title>Login Successful</title></head>
        <body style="text-align: center; padding: 50px;">
            <h1>:) Login Approved</h1>
            <p>You can now close this page.</p>
            <p>Authenticating on your computer...</p>
            <script>
                // Auto-close after 3 seconds (optional)
                setTimeout(() => window.close(), 3000);
            </script>
        </body>
        </html>
        """,
        status_code=200
    )


@router.get("/poll", response_model=PollResp)
def poll(session_id: str):
    """
    polls for session approval status
    
    :param session_id: Description
    :type session_id: str
    """
    # Desktop polls for session approval
    s = store.get(session_id)
    if not s:
        return PollResp(status="not_found")
    
    if s.consumed:
        return PollResp(status="consumed")
    
    if s.expires_at <= store._now():
        return PollResp(status="expired")
    
    if s.approved:
        return PollResp(status="approved")
    
    return PollResp(status="pending")


@router.post("/exchange", response_model=ExchangeResp)
def exchange(req: ExchangeReq):
    """
    exchanges approved session for access token
    
    :param req: Description
    :type req: ExchangeReq
    """
    # Desktop exchanges the session for an access token

    s = store.get(req.s_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if settings.BROWSER_KEY:  #check secure mode 
        print(f"Secure Mode Enabled. Validating browser key: {req.BROWSER_KEY} against {s.BROWSER_KEY}")
        if not req.BROWSER_KEY or req.BROWSER_KEY != s.BROWSER_KEY:  # Validate browser key
            raise HTTPException(status_code=400, detail="Invalid browser key for secure mode")
    
    if not s.approved:
        raise HTTPException(status_code=400, detail="Session not approved")
    
    if not store.consume(req.s_id):
        raise HTTPException(status_code=400, detail="Session already consumed or invalid")
    
    # Minimal "user" placeholder for now
    # Replace with actual user/device identifier later
    access_token = create_access_token("qr_user")

    return ExchangeResp(access_tkn=access_token)
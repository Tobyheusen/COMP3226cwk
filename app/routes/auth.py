# Authentication-related routes, including QR session creation, 
# approval, polling, and token exchange.

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from app.core.config import settings
from app.core.security import create_access_token
from app.services.sessions import SessionStore

router = APIRouter(prefix="/auth", tags=["auth"])
store = SessionStore(ttl_seconds=settings.SESSION_TTL_SECONDS)

class CreateSessionResp(BaseModel):
    s_id: str
    scan_url: str


class ApprovedReq(BaseModel):
    s_id: str
    nonce: str

class PollResp(BaseModel):
    status: str

class ExchangeReq(BaseModel):
    s_id: str

class ExchangeResp(BaseModel):
    access_tkn: str

@router.post("/session", response_model=CreateSessionResp)
def create_session(request: Request):
    # Create a login session
    s = store.create()

    base = str(request.base_url).rstrip("/")
    scan_url = f"{base}/auth/scan?s_id={s.session_id}&nonce={s.approval_nonce}"
    
    return CreateSessionResp(s_id=s.session_id, scan_url=scan_url)

@router.get("/scan", response_class=HTMLResponse)
def scan_link(s_id: str, nonce: str):
    # Approve the session if nonce matches
    ok = store.approve(s_id, nonce)
    if not ok:
        return HTMLResponse(
            content="""
            <html>
            <head><title>Login Failed</title></head>
            <body style="font-family: Arial; text-align: center; padding: 2rem;">
                <h1 style="color: #dc3545;">✗ Login Failed</h1>
                <p>Invalid or expired session. Please try scanning again.</p>
            </body>
            </html>
            """,
            status_code=400
        )
    return HTMLResponse(
        content="""
        <html>
        <head><title>Login Approved</title></head>
        <body style="font-family: Arial; text-align: center; padding: 2rem;">
            <h1 style="color: #28a745;">✓ Login Approved</h1>
            <p>You can close this page. The login will complete on your computer.</p>
        </body>
        </html>
        """
    )

@router.get("/poll", response_model=PollResp)
def poll(session_id: str):
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
    # Desktop exchanges the session for an access token

    s = store.get(req.s_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not s.approved:
        raise HTTPException(status_code=400, detail="Session not approved")
    
    if not store.consume(req.s_id):
        raise HTTPException(status_code=400, detail="Session already consumed or invalid")
    
    # Minimal "user" placeholder for now
    # Replace with actual user/device identifier later
    access_token = create_access_token("qr_user")

    return ExchangeResp(access_tkn=access_token)
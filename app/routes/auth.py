# Authentication-related routes, including QR session creation, 
# approval, polling, and token exchange.

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from app.core.config import settings
from app.core.security import create_access_token
from app.services.sessions import SessionStore

router = APIRouter(prefix="/auth", tags=["auth"])
store = SessionStore(ttl_seconds=settings.SESSION_TTL_SECONDS)

class CreateSessionResp(BaseModel):
    s_id: str


class ApprovedReq (BaseModel):
    s_id = str

class PollResp(BaseModel):
    status: str

class ExhangeResp (BaseModel):
    s_id: str

class ExchangeResp(BaseModel):
    access_tkn: str

@router.post("/session", response_model=CreateSessionResp)
def create_session(request: Request):
    # More shit

@router.get("/scan")
def scan_link(sid: str, nonce: str):
    # Add shit

@router.get("/poll", response_model=PollResp)
def poll(session_id: str):
    # Add shit

@router.post("/exchange", response_model=ExchangeResp)
def exchange(req: ExchangeReq):
    # Add shit
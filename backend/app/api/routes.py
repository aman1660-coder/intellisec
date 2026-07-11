from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

from app.core.config import settings
from app.core.security import create_token, decode_token, hash_password, verify_password
from app.core.storage import storage
from app.services.case_study import build_case_study_scan
from app.services.scan_service import run_scan
from app.utils.target_validator import TargetValidationError, validate_target


router = APIRouter()
bearer = HTTPBearer(auto_error=False)
scan_windows: dict[str, deque[float]] = defaultdict(deque)


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ScanRequest(BaseModel):
    target_url: str
    authorization_confirmed: bool
    context: dict[str, Any] = Field(default_factory=dict)


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {"id": user["id"], "name": user["name"], "email": user["email"], "created_at": user.get("created_at")}


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict[str, Any]:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    try:
        payload = decode_token(credentials.credentials)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = storage.get_user(payload["sub"])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def enforce_rate_limit(key: str) -> None:
    now = time.time()
    window = scan_windows[key]
    while window and now - window[0] > 3600:
        window.popleft()
    if len(window) >= settings.rate_limit:
        raise HTTPException(status_code=429, detail="Scan rate limit exceeded. Try again later.")
    window.append(now)


@router.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": settings.app_name, "environment": settings.environment}


@router.post("/auth/register")
def register(payload: RegisterRequest) -> dict[str, Any]:
    email = payload.email.lower()
    if storage.get_user_by_email(email):
        raise HTTPException(status_code=409, detail="Email is already registered")
    user = storage.create_user({"name": payload.name, "email": email, "password_hash": hash_password(payload.password)})
    token = create_token(user["id"], {"email": email})
    return {"token": token, "user": public_user(user)}


@router.post("/auth/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    user = storage.get_user_by_email(payload.email.lower())
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token(user["id"], {"email": user["email"]})
    return {"token": token, "user": public_user(user)}


@router.get("/auth/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"user": public_user(user)}


@router.post("/targets/validate")
def validate(payload: dict[str, str]) -> dict[str, Any]:
    try:
        target = validate_target(payload.get("target_url", ""))
        return {"valid": True, **target.__dict__}
    except TargetValidationError as exc:
        return {"valid": False, "error": str(exc)}


@router.post("/scans")
async def create_scan(payload: ScanRequest, request: Request, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    enforce_rate_limit(user["id"] or request.client.host)
    try:
        return await run_scan(user["id"], payload.target_url, payload.context, payload.authorization_confirmed)
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc.__class__.__name__}")


@router.get("/scans")
def list_scans(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    return storage.list_scans(user["id"])


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    scan = storage.get_scan(user["id"], scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/findings")
def get_findings(scan_id: str, user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    return get_scan(scan_id, user)["findings"]


@router.get("/scans/{scan_id}/attack-paths")
def get_attack_paths(scan_id: str, user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    return get_scan(scan_id, user)["attack_paths"]


@router.get("/scans/{scan_id}/compliance")
def get_compliance(scan_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    scan = get_scan(scan_id, user)
    return {"summary": scan["compliance_summary"], "mappings": scan["compliance_mappings"]}


@router.get("/scans/{scan_id}/pqc")
def get_pqc(scan_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return get_scan(scan_id, user)["pqc_readiness"]


@router.get("/scans/{scan_id}/reports")
def get_reports(scan_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return get_scan(scan_id, user)["reports"]


@router.get("/case-study")
def case_study() -> dict[str, Any]:
    return build_case_study_scan()


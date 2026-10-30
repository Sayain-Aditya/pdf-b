import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field


password_hasher = PasswordHasher()

router = APIRouter(prefix="/auth", tags=["Authentication"])

SESSION_COOKIE = "mks_admin_session"
SESSION_DAYS = 7


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)


def get_database(request: Request):
    return request.app.state.db


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_origin(request: Request):
    origin = request.headers.get("origin")
    allowed_origins = {
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    }
    frontend_url = os.getenv("FRONTEND_URL", "").rstrip("/")
    if frontend_url:
        allowed_origins.add(frontend_url)
    if origin and origin.rstrip("/") not in allowed_origins:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Request origin not allowed: {origin}"
        )


async def get_current_admin(
    request: Request,
    db=Depends(get_database),
):
    validate_origin(request)
    raw_token = request.cookies.get(SESSION_COOKIE)

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please log in."
        )

    token_hash = hash_token(raw_token)
    now = datetime.now(timezone.utc)

    session = await db["sessions"].find_one({
        "token_hash": token_hash,
        "expires_at": {"$gt": now},
    })

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your session has expired. Please log in again."
        )

    admin = await db["users"].find_one({
        "_id": session["user_id"],
        "role": "admin",
        "is_active": True,
    })

    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin account is inactive."
        )

    return {
        "id": str(admin["_id"]),
        "email": admin["email"],
        "role": "admin",
    }


@router.post("/login")
async def login_admin(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db=Depends(get_database),
):
    validate_origin(request)

    email = payload.email.strip().lower()

    admin = await db["users"].find_one({
        "email": email,
        "role": "admin",
        "is_active": True,
    })

    # Use the same response for unknown email and incorrect password.
    invalid_login = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password."
    )

    if not admin:
        raise invalid_login

    try:
        password_hasher.verify(admin["password_hash"], payload.password)
    except (VerifyMismatchError, VerificationError, KeyError):
        raise invalid_login

    # Upgrade the stored hash automatically when Argon2 parameters change.
    if password_hasher.check_needs_rehash(admin["password_hash"]):
        await db["users"].update_one(
            {"_id": admin["_id"]},
            {"$set": {
                "password_hash": password_hasher.hash(payload.password)
            }}
        )

    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)

    await db["sessions"].insert_one({
        "user_id": admin["_id"],
        "token_hash": token_hash,
        "expires_at": expires_at,
        "created_at": datetime.now(timezone.utc),
    })

    secure_cookie = os.getenv("COOKIE_SECURE", "false").lower() == "true"

    response.set_cookie(
        key=SESSION_COOKIE,
        value=raw_token,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        max_age=SESSION_DAYS * 24 * 60 * 60,
        path="/",
    )

    return {
        "message": "Login successful.",
        "user": {
            "email": email,
            "role": "admin",
        },
    }


@router.get("/me")
async def get_me(admin=Depends(get_current_admin)):
    return {"authenticated": True, "user": admin}


@router.post("/logout")
async def logout_admin(
    request: Request,
    response: Response,
    db=Depends(get_database),
):
    validate_origin(request)

    raw_token = request.cookies.get(SESSION_COOKIE)

    if raw_token:
        await db["sessions"].delete_one({
            "token_hash": hash_token(raw_token)
        })

    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        samesite="lax",
    )

    return {"message": "Logged out successfully."}
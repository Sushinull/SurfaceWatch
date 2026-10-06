import secrets
import time
from collections import OrderedDict, deque
from datetime import UTC, datetime, timedelta

from argon2.exceptions import VerificationError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.api.schemas import LoginInput, UserOut
from app.core.auth import DUMMY_HASH, current_user, password_hasher, token_hash
from app.core.config import get_settings
from app.db.models import AuthSession, User
from app.db.session import get_db

router = APIRouter(prefix="/auth", tags=["Authentication"])
attempts = OrderedDict()
global_attempts = deque(maxlen=30)


def throttle(ip: str):
    now = time.monotonic()
    history = attempts.setdefault(ip, deque(maxlen=5))
    attempts.move_to_end(ip)
    if len(attempts) > 1024:
        attempts.popitem(last=False)
    if (len(history) == 5 and now - history[0] < 60) or (
        len(global_attempts) == 30 and now - global_attempts[0] < 60
    ):
        raise HTTPException(429, "Too many sign-in attempts; try again in one minute")
    history.append(now)
    global_attempts.append(now)


@router.post("/login", response_model=UserOut)
def login(data: LoginInput, request: Request, response: Response, db: Session = Depends(get_db)):
    throttle(request.client.host if request.client else "local")
    user = db.scalar(select(User).where(User.username == data.username))
    try:
        valid = password_hasher.verify(user.password_hash if user else DUMMY_HASH, data.password)
    except VerificationError:
        valid = False
    if not user or not valid:
        raise HTTPException(401, "Invalid username or password")
    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = password_hasher.hash(data.password)
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    db.execute(delete(AuthSession).where(AuthSession.expires_at < datetime.now(UTC)))
    db.add(
        AuthSession(
            token_hash=token_hash(token),
            user_id=user.id,
            expires_at=datetime.now(UTC) + timedelta(hours=settings.session_hours),
        )
    )
    db.commit()
    response.set_cookie(
        "sw_session",
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        max_age=settings.session_hours * 3600,
        path="/api",
    )
    return user


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    db.execute(
        delete(AuthSession).where(
            AuthSession.token_hash == token_hash(request.cookies["sw_session"])
        )
    )
    db.commit()
    response.delete_cookie("sw_session", path="/api")

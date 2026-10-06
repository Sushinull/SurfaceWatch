import hashlib
import hmac
import secrets
from datetime import UTC, datetime

from argon2 import PasswordHasher
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import AuthSession, User
from app.db.session import get_db
from app.services.scans import utc

password_hasher = PasswordHasher()
DUMMY_HASH = password_hasher.hash(secrets.token_urlsafe(24))


def token_hash(token: str) -> str:
    return hmac.new(get_settings().secret_key.encode(), token.encode(), hashlib.sha256).hexdigest()


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("sw_session", "")
    session = db.get(AuthSession, token_hash(token)) if token else None
    if session is None or utc(session.expires_at) <= datetime.now(UTC):
        raise HTTPException(401, "Please sign in")
    user = db.get(User, session.user_id)
    if user is None:
        raise HTTPException(401, "Please sign in")
    return user

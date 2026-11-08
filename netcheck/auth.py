"""Local accounts and cookie-backed sessions for the NetCheck web app."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from typing import Any

from . import history


SESSION_COOKIE = "netcheck_session"
SESSION_DAYS = 30


def _password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
    )
    return f"scrypt${salt.hex()}${digest.hex()}"


def _password_matches(password: str, stored: str) -> bool:
    try:
        algorithm, salt, digest = stored.split("$", 2)
        if algorithm != "scrypt":
            return False
        candidate = _password_hash(password, bytes.fromhex(salt)).split("$", 2)[2]
        return hmac.compare_digest(candidate, digest)
    except (ValueError, TypeError):
        return False


def create_user(username: str, password: str) -> dict[str, Any]:
    username = username.strip().lower()
    if len(username) < 3 or len(username) > 120 or "@" not in username:
        raise ValueError("invalid_username")
    if len(password) < 8:
        raise ValueError("password_too_short")
    try:
        user_id = history.create_user(username, _password_hash(password))
    except ValueError as exc:
        raise ValueError("username_taken") from exc
    history.claim_legacy_data(user_id)
    return {"id": user_id, "username": username}


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    user = history.get_user_by_username(username.strip().lower())
    if not user or not _password_matches(password, user["password_hash"]):
        return None
    return {"id": user["id"], "username": user["username"]}


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
    history.create_session(token, user_id, expires)
    return token


def get_session(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    session = history.get_session(token)
    if not session:
        return None
    if datetime.fromisoformat(session["expires_at"]) <= datetime.now(timezone.utc):
        history.delete_session(token)
        return None
    return {"id": session["user_id"], "username": session["username"]}


def delete_session(token: str | None) -> None:
    if token:
        history.delete_session(token)

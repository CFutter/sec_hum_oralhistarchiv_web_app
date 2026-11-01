"""Signed session-token extraction and anonymous identifiers for CSRF binding.

The signer captures SESSION_SECRET at import; settings changes require restart.
"""

import secrets

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app import security_cookie_names
from config import settings

PRE_SESSION_COOKIE_NAME = settings.pre_session_cookie_name

__all__ = [
    "PRE_SESSION_COOKIE_NAME",
    "SESSION_SIGNER",
    "generate_pre_session_id",
    "get_current_identifier",
    "get_session_id_from_cookie",
    "reject_ambiguous_security_cookies",
]


def reject_ambiguous_security_cookies(request: Request) -> None:
    """Raise HTTPException(400) for repeated active session, CSRF or pre-session cookies."""
    csrf_name, pre_name = security_cookie_names(hardened=settings.is_hardened)
    security_names = {settings.session_cookie_name, csrf_name, pre_name}
    seen: set[str] = set()
    for header in request.headers.getlist("cookie"):
        for part in header.split(";"):
            name, separator, _value = part.strip().partition("=")
            if separator and name in security_names:
                if name in seen:
                    raise HTTPException(400, detail="Ambiguous security cookies.")
                seen.add(name)


def _get_signer() -> URLSafeTimedSerializer:
    """Build a timed serializer with SESSION_SECRET and the session-cookie-v1 salt."""
    return URLSafeTimedSerializer(
        settings.session_secret.get_secret_value(),
        salt="session-cookie-v1",
    )


SESSION_SIGNER = _get_signer()


def get_current_identifier(request: Request) -> str | None:
    """Return a valid signed token, otherwise the raw pre-session cookie or None.

    Raise HTTPException(400) for duplicate security cookies; no database session
    or authentication check occurs.
    """
    session_id = get_session_id_from_cookie(request)
    if session_id is not None:
        return session_id

    return request.cookies.get(settings.pre_session_cookie_name)


def generate_pre_session_id() -> str:
    """Return a URL-safe identifier containing 32 random bytes."""
    return secrets.token_urlsafe(32)


def get_session_id_from_cookie(request: Request) -> str | None:
    """Return a valid signed string token or None for absent, invalid or expired cookies.

    Use SESSION_COOKIE_NAME and SESSION_MAX_AGE_SECONDS without a database
    lookup; raise HTTPException(400) for duplicate security cookies.
    """
    reject_ambiguous_security_cookies(request)
    cookie_value = request.cookies.get(settings.session_cookie_name)
    if not cookie_value:
        return None

    try:
        session_id = SESSION_SIGNER.loads(cookie_value, max_age=settings.session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    return session_id if isinstance(session_id, str) else None

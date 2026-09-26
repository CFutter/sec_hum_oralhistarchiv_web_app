"""Signed session-token extraction and anonymous identifiers for CSRF binding.

The signer captures SESSION_SECRET at import; settings changes require restart.
"""

import secrets

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from config import settings

from ..cookie_contract import PRE_SESSION_COOKIE_NAME

__all__ = [
    "PRE_SESSION_COOKIE_NAME",
    "SESSION_SIGNER",
    "generate_pre_session_id",
    "get_current_identifier",
    "get_session_id_from_cookie",
]


def _get_signer() -> URLSafeTimedSerializer:
    """Build a timed serializer with SESSION_SECRET and the session-cookie-v1 salt."""
    return URLSafeTimedSerializer(
        settings.session_secret.get_secret_value(),
        salt="session-cookie-v1",
    )


SESSION_SIGNER = _get_signer()


def get_current_identifier(request: Request) -> str | None:
    """Prefer a valid signed cookie token, otherwise return the raw pre-session cookie or None.

    Does not verify database session existence or authentication.
    """
    session_id = get_session_id_from_cookie(request)
    if session_id is not None:
        return session_id

    return request.cookies.get(PRE_SESSION_COOKIE_NAME)


def generate_pre_session_id() -> str:
    """Return a URL-safe identifier containing 32 random bytes."""
    return secrets.token_urlsafe(32)


def get_session_id_from_cookie(request: Request) -> str | None:
    """Return the string token from a valid signed, unexpired session cookie, otherwise None.

    Use SESSION_COOKIE_NAME and SESSION_MAX_AGE_SECONDS; no database lookup.
    """
    cookie_value = request.cookies.get(settings.session_cookie_name)
    if not cookie_value:
        return None

    try:
        session_id = SESSION_SIGNER.loads(cookie_value, max_age=settings.session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    return session_id if isinstance(session_id, str) else None

"""Cookie signing and identifier helpers for sessions and CSRF.

Provides the itsdangerous signer for the session cookie, extraction/
validation of the session ID from the request, generation of anonymous
pre-session IDs, and resolution of the "current identifier" (session ID
if logged in, else pre-session ID) used to bind CSRF tokens.
"""

import secrets
from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from config import settings

PRE_SESSION_COOKIE_NAME = "pre_session_id"


def _get_signer() -> URLSafeTimedSerializer:
    """Create a signer for session cookie values.

    Uses itsdangerous to sign the session ID so clients cannot
    forge or tamper with the cookie value.
    """
    return URLSafeTimedSerializer(
        settings.session_secret.get_secret_value(),
        salt="session-cookie-v1",
    )

SESSION_SIGNER = _get_signer()

def get_current_identifier(request: Request) -> str | None:
    """Return the identifier to use for CSRF binding.

    Prefers the real session ID if the user is authenticated; otherwise
    returns the pre-session ID cookie. Returns None whenever neither a valid session 
    cookie nor a pre-session cookie is present.
    """
    session_id = get_session_id_from_cookie(request)
    if session_id is not None:
        return session_id

    # Fall back to pre-session
    return request.cookies.get(PRE_SESSION_COOKIE_NAME)


def generate_pre_session_id() -> str:
    """Generate a random pre-session identifier for anonymous visitors.
    Used to bind a CSRF token before the visitor has a real session."""
    return secrets.token_urlsafe(32)


def get_session_id_from_cookie(request: Request) -> str | None:
    """Extract and validate the session ID from the request cookie.

    Returns the session ID if the cookie is valid and not expired,
    or None if missing/invalid/expired.
    """
    cookie_value = request.cookies.get(settings.session_cookie_name)
    if not cookie_value:
        return None

    try:
        return SESSION_SIGNER.loads(cookie_value, max_age=settings.session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None

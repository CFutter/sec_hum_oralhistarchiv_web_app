"""CSRF protection — double-submit cookie pattern.

Protects POST forms against cross-site request forgery using an
  HMAC-bound double-submit cookie:

  1. A CSRF cookie middleware sets a token cookie on GET responses. The token
     is HMAC(session_secret, identifier), where identifier is the session ID
     (or a pre-session ID for anonymous visitors), not a raw random value.
  2. Templates embed the token in a hidden form field via {{ csrf_token(request) }}.
  3. On POST, the verify_csrf dependency checks three things: cookie and form
     field are both present, they match, and the cookie equals the HMAC
     recomputed from the request's current identifier.
  4. If any check fails, the request is rejected with 403.

This is implemented as a dependency (not pure middleware) so that CSRF
protection is explicit on each POST route — you can see which routes
are protected by reading their signatures.

Explicit CSRF cookie rotation (rotate_csrf_cookie) is only triggered on logout; 
because the token is HMAC-bound to the identifier, the cookie also rotates 
automatically whenever the identifier changes (pre-session → session).

No external dependencies required.
"""

import hmac
import logging
import hashlib

from fastapi import FastAPI, Response, Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from .cookies import (
    PRE_SESSION_COOKIE_NAME, 
    get_session_id_from_cookie, 
    generate_pre_session_id, 
    get_current_identifier
)
from config import settings

logger = logging.getLogger(__name__)

CSRF_COOKIE_NAME = "csrf_token"
CSRF_FORM_FIELD = "csrf_token"

# Domain-separated CSRF HMAC key — derived once from session_secret.
# The prefix ensures this key is independent of the cookie-signing key
# (cookies.py uses URLSafeTimedSerializer with salt="session-cookie-v1").
# If you ever need to rotate CSRF keys without invalidating sessions,
# bump the version: b"csrf-hmac-v2|".
_CSRF_HMAC_KEY = hashlib.sha256(
    b"csrf-hmac-v1|" + settings.session_secret.get_secret_value().encode()
).digest()

def _compute_csrf_token(session_id: str) -> str:
    """Derive a CSRF token from a session identifier via HMAC.

    The token is deterministic for a given session — same session always
    produces the same token. A stolen CSRF cookie without the matching
    session is useless, because an attacker's session (or lack of one)
    produces a different HMAC.
    """
    return hmac.new(
        _CSRF_HMAC_KEY,
        session_id.encode(),
        hashlib.sha256,
    ).hexdigest()

# =============================================================================
# Token retrieval
# =============================================================================

def get_csrf_token(request: Request) -> str:
    """Get the current CSRF token for template rendering.
    
    Prefers the freshly-minted token from middleware state (set when the
    cookie needs to be rotated due to a session transition). Falls back
    to the existing cookie value (the steady-state case where no rotation
    is needed).
    
    This ordering matters: during a session transition, the incoming
    cookie is stale but the response will carry a Set-Cookie with the
    new value. The form must use the new value to match the new cookie.
    """
    new_token = getattr(request.state, "csrf_token", None)
    if new_token:
        return new_token
    return request.cookies.get(CSRF_COOKIE_NAME, "")

# =============================================================================
# Verification dependency
# =============================================================================

async def verify_csrf(request: Request) -> bool:
    """FastAPI dependency that verifies the CSRF double-submit cookie.

    Rejects the request with 403 unless all checks pass: the cookie and the
    form field are both present, the form value is a string, the two match
    (constant-time compare), a current identifier (session or pre-session)
    exists, and the cookie equals the HMAC recomputed from that identifier.
    The HMAC binding is what makes a stolen cookie useless without the
    matching session.

    Usage:
        @router.post("/submit", dependencies=[Depends(verify_csrf)])
        async def handle_submit(...):
    """
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    form = await request.form()
    form_token = form.get(CSRF_FORM_FIELD)

    extra = {"request_id": getattr(request.state, "request_id", "unknown")}

    if not cookie_token or not form_token:
        logger.warning(
            "CSRF token missing on %s", request.url.path,
            extra=extra,
        )
        raise HTTPException(403, detail="Missing CSRF token.")

    if not isinstance(form_token, str):
        logger.warning("CSRF token was not a string form field on %s", request.url.path, extra=extra)
        raise HTTPException(403, detail="CSRF validation failed.")

    if not hmac.compare_digest(cookie_token, form_token):
        logger.warning(
            "CSRF double-submit mismatch on %s", request.url.path,
            extra=extra,
        )
        raise HTTPException(403, detail="CSRF validation failed.")

    identifier = get_current_identifier(request)
    if identifier is None:
        logger.warning(
            "CSRF verification with no identifier on %s", request.url.path,
            extra=extra,
        )
        raise HTTPException(403, detail="CSRF validation failed.")

    expected = _compute_csrf_token(identifier)
    if not hmac.compare_digest(cookie_token, expected):
        logger.warning(
            "CSRF HMAC mismatch on %s", request.url.path,
            extra=extra,
        )
        raise HTTPException(403, detail="CSRF validation failed.")

    return True


# =============================================================================
# Cookie middleware — sets the CSRF cookie on GET responses
# =============================================================================

class CSRFCookieMiddleware(BaseHTTPMiddleware):
    """Manages pre-session identifier and CSRF token cookies.

    Every GET ensures two invariants:
      1. The visitor has an identifier (session or pre-session).
      2. The CSRF cookie matches HMAC(secret, identifier).
    """

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        new_pre_session = None
        new_csrf = None
        delete_pre_session = False

        if request.method == "GET":
            session_id = get_session_id_from_cookie(request)
            existing_pre = request.cookies.get(PRE_SESSION_COOKIE_NAME)
            existing_csrf = request.cookies.get(CSRF_COOKIE_NAME)

            if session_id is not None:
                identifier = session_id
                if existing_pre is not None:
                    delete_pre_session = True
            else:
                if existing_pre is None:
                    new_pre_session = generate_pre_session_id()
                    identifier = new_pre_session
                else:
                    identifier = existing_pre

            expected_csrf = _compute_csrf_token(identifier)
            if existing_csrf != expected_csrf:
                new_csrf = expected_csrf
                request.state.csrf_token = new_csrf

        response = await call_next(request)

        if new_pre_session is not None:
            response.set_cookie(
                key=PRE_SESSION_COOKIE_NAME,
                value=new_pre_session,
                max_age=settings.session_max_age_seconds,
                httponly=True,
                secure=settings.cookies_secure,
                samesite="strict",
                path="/",
            )

        if delete_pre_session:
            response.delete_cookie(key=PRE_SESSION_COOKIE_NAME, path="/")

        if new_csrf is not None:
            response.set_cookie(
                key=CSRF_COOKIE_NAME,
                value=new_csrf,
                max_age=settings.session_max_age_seconds,
                httponly=True,
                secure=settings.cookies_secure,
                samesite="strict",
                path="/",
            )

        return response


def setup_csrf_middleware(app: FastAPI) -> None:
    """Add CSRF cookie middleware to the application"""
    app.add_middleware(CSRFCookieMiddleware)


def rotate_csrf_cookie(response: Response) -> None:
    """Invalidate the current CSRF cookie so the next GET gets a fresh token.

    The middleware (CSRFCookieMiddleware) mints the replacement on the
    following GET request. This function only clears; it does not mint.
    """
    response.delete_cookie(key=CSRF_COOKIE_NAME, path="/")
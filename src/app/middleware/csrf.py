"""HMAC-bound double-submit CSRF protection.

``CSRFCookieMiddleware`` prepares tokens for outgoing forms, including failed
POST re-renders. ``verify_csrf`` validates the incoming cookie snapshot and HMAC.
Application route modules do not attach that dependency themselves:
``SecureAPIRouter`` installs it on every mutation method except the two exact,
centrally reviewed token-capability POSTs.
"""

import hashlib
import hmac
import logging
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings

from ..cookie_contract import CSRF_COOKIE_NAME
from ..request_utils import safe_request_path
from .cookies import (
    PRE_SESSION_COOKIE_NAME,
    generate_pre_session_id,
    get_current_identifier,
    get_session_id_from_cookie,
)

logger = logging.getLogger(__name__)

CSRF_FORM_FIELD = "csrf_token"

__all__ = [
    "CSRF_COOKIE_NAME",
    "CSRF_FORM_FIELD",
    "CSRFCookieMiddleware",
    "get_csrf_token",
    "setup_csrf_middleware",
    "verify_csrf",
]

# Domain-separated CSRF HMAC key — derived once from session_secret.
# The prefix ensures this key is independent of the cookie-signing key
# (cookies.py uses URLSafeTimedSerializer with salt="session-cookie-v1").
_CSRF_HMAC_KEY = hashlib.sha256(
    b"csrf-hmac-v1|" + settings.session_secret.get_secret_value().encode()
).digest()


def _compute_csrf_token(session_id: str) -> str:
    """Return the identifier's SHA-256 HMAC hex using the
    import-time domain-separated session key.
    """
    return hmac.new(
        _CSRF_HMAC_KEY,
        session_id.encode(),
        hashlib.sha256,
    ).hexdigest()


def get_csrf_token(request: Request) -> str:
    """Return the pending middleware token, then the incoming cookie, or an empty string.

    Templates need the pending value to match a rotated response cookie.
    """
    new_token: str | None = getattr(request.state, "csrf_token", None)
    if new_token:
        return new_token
    return request.cookies.get(CSRF_COOKIE_NAME, "")


async def verify_csrf(request: Request) -> bool:
    """Parse and close the form; return True for matching identifier-bound cookie/form tokens.

    Raise HTTPException(403) for missing, nonstring, mismatched, or invalid
    HMAC tokens. Form parsing errors propagate. Use the signed cookie token
    or pre-session identifier; this does not authorize the database session.
    """
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    # Existing routes consume strings only. Own cleanup even when the route
    # declares no Form body (logout); FastAPI's later second close is harmless.
    async with request.form() as form:
        form_token = form.get(CSRF_FORM_FIELD)

    extra = {
        "request_id": getattr(request.state, "request_id", "unknown"),
        "path": safe_request_path(request),
    }

    if not cookie_token or not form_token:
        logger.warning("CSRF token missing", extra=extra)
        raise HTTPException(403, detail="Missing CSRF token.")

    if not isinstance(form_token, str):
        logger.warning(
            "CSRF token was not a string form field",
            extra=extra,
        )
        raise HTTPException(403, detail="CSRF validation failed.")

    if not hmac.compare_digest(
        cookie_token.encode("utf-8", "replace"),
        form_token.encode("utf-8", "replace"),
    ):
        logger.warning("CSRF double-submit mismatch", extra=extra)
        raise HTTPException(403, detail="CSRF validation failed.")

    identifier = get_current_identifier(request)
    if identifier is None:
        logger.warning(
            "CSRF verification with no identifier",
            extra=extra,
        )
        raise HTTPException(403, detail="CSRF validation failed.")

    expected = _compute_csrf_token(identifier)
    if not hmac.compare_digest(
        cookie_token.encode("utf-8", "replace"),
        expected.encode("utf-8", "replace"),
    ):
        logger.warning("CSRF HMAC mismatch", extra=extra)
        raise HTTPException(403, detail="CSRF validation failed.")

    return True


class CSRFCookieMiddleware(BaseHTTPMiddleware):
    """Prepare identifier-bound CSRF cookies and template state for resolved requests.

    Skip explicitly unresolved health/static/unmatched traffic. Avoid cookie
    writes when downstream sets a session cookie, preserving explicit transitions.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Prepare CSRF state for GETs or completed session resolution, then call downstream.

        Set/delete pre-session and CSRF cookies as needed unless a session
        Set-Cookie is present; failures propagate without writing cookies.
        """
        resolved = getattr(request.state, "session_resolution_completed", None)
        if resolved is False:
            # Probes/static responses have no forms and skip session lookup.
            # They must not race a rendered page by rewriting its cookies
            # from an unchecked (possibly revoked) incoming session.
            return await call_next(request)
        new_pre_session = None
        new_csrf = None
        delete_pre_session = False

        if request.method == "GET" or resolved:
            session_id = get_session_id_from_cookie(request)
            if resolved and request.state.session_id is not None:
                session_id = request.state.session_id
            existing_pre = request.cookies.get(PRE_SESSION_COOKIE_NAME)
            existing_csrf = request.cookies.get(CSRF_COOKIE_NAME)

            if session_id is not None:
                identifier = session_id
                if existing_pre is not None:
                    delete_pre_session = True
            elif existing_pre is None:
                new_pre_session = generate_pre_session_id()
                identifier = new_pre_session
            else:
                identifier = existing_pre

            expected_csrf = _compute_csrf_token(identifier)
            if existing_csrf != expected_csrf:
                new_csrf = expected_csrf
                request.state.csrf_token = new_csrf

        response = await call_next(request)

        if any(
            cookie.startswith(f"{settings.session_cookie_name}=")
            for cookie in response.headers.getlist("set-cookie")
        ):
            return response

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
    """Register the CSRF cookie middleware; route dependencies perform verification."""
    app.add_middleware(CSRFCookieMiddleware)

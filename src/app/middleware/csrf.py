"""HMAC-bound double-submit CSRF protection.

``CSRFCookieMiddleware`` prepares tokens for outgoing forms, including failed
POST re-renders. ``verify_csrf`` validates the incoming cookie snapshot and HMAC.
Application route modules do not attach that dependency themselves:
``SecureAPIRouter`` installs it on every mutation method except the exact
entries in ``route_security._CSRF_EXEMPT_ROUTE_KEYS``.
"""

import hashlib
import hmac
import logging
from collections.abc import Awaitable, Callable
from typing import Literal, NoReturn
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings

from ..request_utils import safe_request_path
from .cookies import (
    generate_pre_session_id,
    get_current_identifier,
    get_session_id_from_cookie,
)

logger = logging.getLogger(__name__)

CSRF_COOKIE_NAME = settings.csrf_cookie_name

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
    """Return the identifier HMAC hex using the import-time domain-separated session key."""
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
    return request.cookies.get(settings.csrf_cookie_name, "")


def _origin(value: str, *, referer: bool = False) -> tuple[str, str, int] | None:
    """Return normalized (scheme, host, port), or None for malformed HTTP origin input.

    referer permits paths/queries; credentials, fragments and whitespace fail.
    Omitted ports become 80 for HTTP and 443 for HTTPS.
    """
    if not value or not value.isprintable() or any(char.isspace() for char in value):
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or (not referer and (parsed.path not in {"", "/"} or parsed.query))
        ):
            return None
        return (
            parsed.scheme,
            parsed.hostname.casefold(),
            parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80),
        )
    except ValueError:
        return None


def _reject_browser_origin(
    request: Request,
    *,
    reason: Literal["ambiguous_origin_headers", "missing_origin", "origin_mismatch"],
    detail: str,
) -> NoReturn:
    """Log safe origin metadata and raise HTTPException(403) with detail."""
    logger.warning(
        "CSRF origin validation failed",
        extra={
            "request_id": getattr(request.state, "request_id", "unknown"),
            "path": safe_request_path(request),
            "reason": reason,
        },
    )
    raise HTTPException(403, detail=detail)


def _verify_browser_origin(request: Request) -> None:
    """Require matching Origin, or Referer fallback; raise HTTPException(403) on refusal.

    Compare with PUBLIC_BASE_URL. Reject duplicate Origin/Referer headers;
    missing both is allowed only outside staging/production.
    """
    origins = request.headers.getlist("origin")
    referers = request.headers.getlist("referer")
    if len(origins) > 1 or len(referers) > 1:
        _reject_browser_origin(
            request,
            reason="ambiguous_origin_headers",
            detail="Request origin validation failed.",
        )
    if not origins and not referers:
        if settings.is_hardened:
            _reject_browser_origin(
                request, reason="missing_origin", detail="Request origin is required."
            )
        return
    expected = _origin(settings.public_base_url, referer=True)
    observed = _origin(origins[0]) if origins else _origin(referers[0], referer=True)
    if expected is None or observed != expected:
        _reject_browser_origin(
            request, reason="origin_mismatch", detail="Request origin validation failed."
        )


def _reject_csrf_token(
    request: Request, message: str, *, detail: str = "CSRF validation failed."
) -> NoReturn:
    """Log refusal and raise HTTPException(403), except inert anonymous logout retries.

    Call after origin validation/form cleanup. A completed anonymous POST
    /logout without a session cookie sets the retry flag and raises a 303 to /;
    even a stale session cookie blocks this exception.
    """
    extra = {
        "request_id": getattr(request.state, "request_id", "unknown"),
        "path": safe_request_path(request),
    }
    if (
        (request.method, request.url.path) == ("POST", "/logout")
        and getattr(request.state, "session_resolution_completed", False) is True
        and getattr(request.state, "user", False) is None
        and getattr(request.state, "session_id", False) is None
        and settings.session_cookie_name not in request.cookies
    ):
        # The cookie middleware may already have prepared anonymous cookies.
        # A late retry must not overwrite cookies from a concurrent new login.
        request.state.csrf_anonymous_logout_retry = True
        logger.info(
            "Anonymous logout retry ignored",
            extra={**extra, "event_type": "logout_already_anonymous"},
        )
        raise HTTPException(303, headers={"Location": "/"})

    logger.warning(message, extra=extra)
    raise HTTPException(403, detail=detail)


async def verify_csrf(request: Request) -> bool:
    """Verify browser origin and identifier-bound cookie/form proof; return True.

    Parse and close the form. Raise HTTPException(403) for invalid/missing
    origin or proof and HTTPException(400) for duplicate security cookies;
    form errors propagate. An invalid-proof POST /logout instead redirects
    303 to / only after completed anonymous resolution without a session
    cookie. Signed-cookie/pre-session proof does not authorize a DB session.
    """
    _verify_browser_origin(request)
    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    # Existing routes consume strings only. Own cleanup even when the route
    # declares no Form body (logout); FastAPI's later second close is harmless.
    async with request.form() as form:
        form_token = form.get(CSRF_FORM_FIELD)

    if not cookie_token or not form_token:
        _reject_csrf_token(request, "CSRF token missing", detail="Missing CSRF token.")

    if not isinstance(form_token, str):
        _reject_csrf_token(request, "CSRF token was not a string form field")

    if not hmac.compare_digest(
        cookie_token.encode("utf-8", "replace"),
        form_token.encode("utf-8", "replace"),
    ):
        _reject_csrf_token(request, "CSRF double-submit mismatch")

    identifier = get_current_identifier(request)
    if identifier is None:
        _reject_csrf_token(request, "CSRF verification with no identifier")

    expected = _compute_csrf_token(identifier)
    if not hmac.compare_digest(
        cookie_token.encode("utf-8", "replace"),
        expected.encode("utf-8", "replace"),
    ):
        _reject_csrf_token(request, "CSRF HMAC mismatch")

    return True


class CSRFCookieMiddleware(BaseHTTPMiddleware):
    """Prepare identifier-bound CSRF cookies and template state for resolved requests.

    Skip explicitly unresolved health/static/unmatched traffic. Avoid cookie
    writes when downstream sets a session cookie or accepts an inert anonymous
    logout retry, preserving explicit transitions and newer browser state.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Prepare CSRF state for GETs or completed session resolution, then call downstream.

        Set/delete pre-session and CSRF cookies as needed unless a session
        Set-Cookie is present or an anonymous logout retry was ignored;
        failures propagate without writing cookies.
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
            existing_pre = request.cookies.get(settings.pre_session_cookie_name)
            existing_csrf = request.cookies.get(settings.csrf_cookie_name)

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

        if getattr(request.state, "csrf_anonymous_logout_retry", False):
            return response

        if any(
            cookie.startswith(f"{settings.session_cookie_name}=")
            for cookie in response.headers.getlist("set-cookie")
        ):
            return response

        if new_pre_session is not None:
            response.set_cookie(
                key=settings.pre_session_cookie_name,
                value=new_pre_session,
                max_age=settings.session_max_age_seconds,
                httponly=True,
                secure=settings.cookies_secure,
                samesite="strict",
                path="/",
            )

        if delete_pre_session:
            response.delete_cookie(
                key=settings.pre_session_cookie_name,
                path="/",
                secure=settings.cookies_secure,
                httponly=True,
                samesite="strict",
            )

        if new_csrf is not None:
            response.set_cookie(
                key=settings.csrf_cookie_name,
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

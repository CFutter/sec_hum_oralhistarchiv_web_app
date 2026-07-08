"""Session middleware — attaches the current user to every request.

Reads the session cookie, validates it against the database, and
sets request.state.user to the authenticated User or None for guests.

This runs on every request. Routes and templates can then check
request.state.user without repeating the lookup logic.

Also enforces two access restrictions:

1. Purpose-limited sessions: sessions created with purpose="totp_setup"
   can only access TOTP enrollment and logout pages. This is a hard
   boundary — even if future routes skip the TOTP check, the purpose
   gate blocks access.

2. Mandatory TOTP enrollment: local-auth users who have not yet
   configured an authenticator are redirected to /setup-totp on every
   request until they complete setup (defense-in-depth, backs up #1).
"""

import urllib.parse

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from ..services import get_session_user, consume_flash
from .csrf import CSRF_COOKIE_NAME
from .cookies import get_session_id_from_cookie, SESSION_SIGNER


# Paths that skip session resolution entirely — no cookie parsing,
# no database lookup. These never need a user context.
_SESSION_SKIP_PREFIXES = ("/static", "/health")

# Paths exempt from TOTP setup gate. Uses prefix matching (path.startswith),
# so /setup-totp also covers /setup-totp/{token} if such routes are added.
_TOTP_EXEMPT_PREFIXES = (
    "/setup-totp",
    "/logout",
    "/verify-email"
)

def _path_matches(path: str, prefixes: tuple[str, ...]) -> bool:
    """True if path equals a prefix or is a proper sub-path (prefix + '/…').

    Uses exact-or-slash matching rather than bare startswith, so '/health'
    matches '/health' and '/health/detail' but NOT '/healthiness'. Prevents
    a future route whose name prefix-collides with an entry from silently
    inheriting skip/exempt behaviour.
    """
    return any(path == p or path.startswith(p + "/") for p in prefixes)

class SessionResolutionMiddleware(BaseHTTPMiddleware):
    """Resolve the session cookie and attach the user to request.state.

    Registered OUTSIDE the audit middleware so request.state.user is populated
    before audit logs the request. Does NOT enforce the TOTP/purpose gates —
    those live in TotpGateMiddleware, which runs inside the security-headers
    and audit layers so its redirects get CSP/HSTS and an audit line.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        request.state.user = None
        request.state.session_purpose = None
        request.state.session_id = None
        request.state.flash_present = False
        request.state.flash = None

        if _path_matches(request.url.path, _SESSION_SKIP_PREFIXES):
            return await call_next(request)

        clear_cookie = False
        raw_cookie = request.cookies.get(settings.session_cookie_name)

        session_id = get_session_id_from_cookie(request)
        if session_id:
            pool = request.app.state.db_pool
            user, purpose, flash_present = await get_session_user(pool, session_id)
            if user:
                request.state.user = user
                request.state.session_purpose = purpose
                request.state.session_id = session_id
                request.state.flash_present = flash_present
                if flash_present:
                    request.state.flash = await consume_flash(pool, session_id)
            else:
                clear_cookie = True
        elif raw_cookie:
            clear_cookie = True

        response = await call_next(request)
        if clear_cookie:
            clear_session_cookie(response)
        return response



class TotpGateMiddleware(BaseHTTPMiddleware):
    """Enforce the purpose and TOTP-enrollment gates.

    Registered INSIDE the security-headers and audit middleware so the 303
    redirects it issues pick up the standard security headers and land in the
    audit log — unlike an early return from the outer session middleware,
    which bypasses both. Reads request.state.user / session_purpose, which
    SessionResolutionMiddleware (registered outside this one) has already set.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        if _path_matches(request.url.path, _TOTP_EXEMPT_PREFIXES):
            return await call_next(request)

        if request.state.session_purpose == "totp_setup":
            return RedirectResponse(url="/setup-totp", status_code=303)

        user = request.state.user
        if user and user.auth_method == "local" and not user.totp_configured:
            return RedirectResponse(url="/setup-totp", status_code=303)

        return await call_next(request)



def set_session_cookie(response: Response, session_id: str) -> None:
    """Set a signed, secure session cookie on the response."""
    signed_value = SESSION_SIGNER.dumps(session_id)

    response.set_cookie(
        key=settings.session_cookie_name,
        value=signed_value,
        max_age=settings.session_max_age_seconds,
        httponly=True,       
        secure=settings.cookies_secure,  
        samesite="strict",
        path="/",
    )

def clear_session_cookie(response: Response) -> None:
    """Remove the session cookie and CSRF token from the response.

    Clearing the CSRF cookie forces a fresh token on the next GET request,
    preventing a stale token from persisting across session boundaries.
    """
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
    )
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
    )


def setup_session_middleware(app: FastAPI) -> None:
    """Add the session-resolution middleware (outer)."""
    app.add_middleware(SessionResolutionMiddleware)


def setup_totp_gate_middleware(app: FastAPI) -> None:
    """Add the TOTP/purpose gate middleware (inner of headers + audit)."""
    app.add_middleware(TotpGateMiddleware)


def require_login(request: Request) -> None:
    """FastAPI dependency that enforces authentication.

    Raises a redirect to the login page if the user is not
    authenticated. The original URL (path + query) is preserved
    in the `next` parameter so login can redirect back after success.
    """
    if not request.state.user:
        next_url = request.url.path
        if request.url.query:
            next_url += "?" + request.url.query
        encoded = urllib.parse.quote(next_url, safe="")
        raise HTTPException(
            status_code=303,
            headers={"Location": f"/login?next={encoded}"},
        )

def require_admin(request: Request) -> None:
    """FastAPI dependency that enforces admin access.

    Raises a 404 (not 403) to avoid revealing the endpoint exists
    to non-admin users. Use as a route dependency:

        @router.get("/admin", dependencies=[Depends(require_admin)])
    """
    user = request.state.user
    if not user or not user.is_admin:
        raise HTTPException(status_code=404)
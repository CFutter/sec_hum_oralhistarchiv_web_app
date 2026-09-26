"""Resolve session state and supply route authorization dependencies.

Skip reviewed DB-free/unmatched requests; other lookups can revoke
invalid sessions and consume/restore flash state. SecureAPIRouter
installs authorization dependencies; recovery sessions also receive an
exact-route restriction in middleware.
"""

import logging
import urllib.parse
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings

from ..exceptions import UserFacingForbidden
from ..services import consume_flash, get_session_user, restore_flash_if_empty
from .cookies import SESSION_SIGNER, get_session_id_from_cookie
from .csrf import CSRF_COOKIE_NAME

logger = logging.getLogger(__name__)

_SESSION_SKIP_ROUTE_KEYS = frozenset(
    {
        ("GET", "/health"),
        ("GET", "/health/detail"),
        ("GET", "/favicon.ico"),
        ("HEAD", "/favicon.ico"),
        ("GET", "/robots.txt"),
        ("HEAD", "/robots.txt"),
    }
)

_TOTP_RECOVERY_ROUTE_KEYS = frozenset(
    {
        ("GET", "/setup-totp"),
        ("POST", "/setup-totp"),
        ("POST", "/logout"),
    }
)


def _skip_session_resolution(request: Request) -> bool:
    """Skip pre-admitted unmatched requests and exact health/favicon/robots/static safe methods.

    These requests cannot consume session authority and must not spend DB capacity.
    """
    if getattr(request.state, "rate_limit_route_unmatched", False):
        return True
    route_key = (request.method.upper(), request.url.path)
    if route_key in _SESSION_SKIP_ROUTE_KEYS:
        return True
    return request.method.upper() in {"GET", "HEAD"} and (
        request.url.path == "/static" or request.url.path.startswith("/static/")
    )


class SessionResolutionMiddleware(BaseHTTPMiddleware):
    """Initialize request state, resolve eligible sessions, and enforce recovery-route confinement.

    Register inside rate admission and audit; DB errors propagate.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Resolve user/purpose/token/flash state unless the request is exempt.

        Redirect recovery sessions outside setup/logout to /setup-totp. Consume
        flash on GET and restore it if downstream redirects and no newer flash
        exists. Do not delete stale browser cookies on passive responses.
        """
        request.state.user = None
        request.state.session_purpose = None
        request.state.session_id = None
        request.state.session_resolution_completed = False
        request.state.flash_present = False
        request.state.flash = None

        if _skip_session_resolution(request):
            return await call_next(request)

        session_id = get_session_id_from_cookie(request)
        if session_id:
            pool = request.app.state.db_pool
            user, purpose, flash_present = await get_session_user(pool, session_id)
            if user:
                request.state.user = user
                request.state.session_purpose = purpose
                request.state.session_id = session_id
                request.state.flash_present = flash_present

                # Recovery is a capability, not an authenticated full session.
                # Constrain it here as a backstop before routing so even a route
                # whose policy is later loosened cannot consume its authority.
                if (
                    purpose == "totp_recovery"
                    and (request.method.upper(), request.url.path) not in _TOTP_RECOVERY_ROUTE_KEYS
                ):
                    request.state.session_resolution_completed = True
                    recovery_response = RedirectResponse(url="/setup-totp", status_code=303)
                    recovery_response.headers["Cache-Control"] = "no-store"
                    return recovery_response

                if flash_present and request.method == "GET":
                    request.state.flash = await consume_flash(pool, session_id)

        request.state.session_resolution_completed = True
        response = await call_next(request)

        flash = request.state.flash
        resolved_session_id = request.state.session_id

        if (
            flash is not None
            and resolved_session_id is not None
            and status.HTTP_300_MULTIPLE_CHOICES
            <= response.status_code
            < status.HTTP_400_BAD_REQUEST
            and "location" in response.headers
        ):
            message, category = flash
            await restore_flash_if_empty(
                request.app.state.db_pool,
                resolved_session_id,
                message,
                category or "info",
            )

        # Passive responses must not delete a newer cookie issued concurrently.
        # Only explicit login/logout transitions replace browser session state.
        return response


def set_session_cookie(
    response: Response,
    session_id: str,
    *,
    max_age_seconds: int | None = None,
) -> None:
    """Set a signed HttpOnly, SameSite=Strict root-path session cookie.

    Secure follows COOKIES_SECURE. None max_age_seconds uses the configured
    session age; nonpositive ages raise ValueError. Does not create a DB session.
    """
    signed_value = SESSION_SIGNER.dumps(session_id)
    max_age = settings.session_max_age_seconds if max_age_seconds is None else max_age_seconds
    if max_age <= 0:
        raise ValueError("Session cookie max age must be positive")

    response.set_cookie(
        key=settings.session_cookie_name,
        value=signed_value,
        max_age=max_age,
        httponly=True,
        secure=settings.cookies_secure,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    """Expire browser session and CSRF cookies; this does not revoke the database session."""
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
    )
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
    )


def setup_session_middleware(app: FastAPI) -> None:
    """Register session resolution; main.py controls its final stack order."""
    app.add_middleware(SessionResolutionMiddleware)


def require_login(request: Request) -> None:
    """Require request.state.user or raise HTTPException(303) to login.

    GET/HEAD preserve path/query in next. Mutations set resubmit=1 and
    return to /account except reviewed setup/reset-TOTP/change-email paths.
    Partial sessions pass this dependency.
    """
    if not request.state.user:
        next_url = "/account"
        if request.method in {"GET", "HEAD"}:
            next_url = request.url.path
            if request.url.query:
                next_url += "?" + request.url.query
        elif request.url.path in {"/setup-totp", "/account/reset-totp", "/account/change-email"}:
            next_url = request.url.path
        encoded = urllib.parse.quote(next_url, safe="")
        resubmit = "&resubmit=1" if request.method not in {"GET", "HEAD"} else ""
        raise HTTPException(
            status_code=303,
            headers={"Location": f"/login?next={encoded}{resubmit}"},
        )


def require_full_session(request: Request) -> None:
    """Require an active full session with completed local or approved federated authentication.

    Use resolved request state. Raise HTTPException redirects for login,
    local recovery/enrollment, or verification; reject inactive, unsupported,
    or wrong-purpose states with 403. Local users need verified email and TOTP.
    """
    require_login(request)
    user = request.state.user

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    purpose = request.state.session_purpose
    if user.auth_method == "local" and user.totp_recovery_required:
        destination = "/setup-totp" if purpose == "totp_recovery" else "/recover-totp"
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": destination},
        )

    if purpose == "totp_setup":
        if user.auth_method != "local":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/setup-totp"},
        )
    if purpose != "full":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if user.auth_method == "local":
        if not user.email_verified:
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": "/send_verification"},
            )
        if not user.totp_configured:
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": "/setup-totp"},
            )
        return

    if user.auth_method == "shibboleth" and user.federated_status == "approved":
        return

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


def require_public_or_full_session(request: Request) -> None:
    """Allow guests; present users must satisfy require_full_session
    and may receive its redirects/errors.
    """
    if request.state.user is not None:
        require_full_session(request)


def require_totp_enrollment_session(request: Request) -> None:
    """Require an active local user with full/setup purpose or a valid recovery-purpose state.

    Recovery requires recovery_required with no configured TOTP. Other
    invalid states raise HTTPException(403); missing users redirect to login.
    This dependency itself does not require email verification.
    """
    require_login(request)
    user = request.state.user
    purpose = request.state.session_purpose
    if not user.is_active or user.auth_method != "local":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if purpose == "totp_recovery":
        if not user.totp_recovery_required or user.totp_configured:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        return

    if user.totp_recovery_required or purpose not in {"full", "totp_setup"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


def require_admin(request: Request) -> None:
    """Require full administrator authority from resolved state.

    Missing/non-admin users receive 404; full-session failures retain their
    redirect/403 behavior. Local admins also need a positive active recovery
    generation and available codes or receive 403 with an error log.
    """
    user = request.state.user
    if not user or not user.is_admin:
        raise HTTPException(status_code=404)
    require_full_session(request)
    if user.auth_method == "local" and (
        user.totp_recovery_code_generation <= 0 or not user.totp_recovery_codes_available
    ):
        logger.error(
            "Local administrator %s has no active recovery-code generation",
            user.id,
            extra={"event_type": "admin_recovery_codes_missing"},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


def require_local_auth(request: Request) -> None:
    """Require a full session, then raise UserFacingForbidden(403) for non-local accounts."""
    require_full_session(request)
    user = request.state.user
    if user.auth_method != "local":
        logger.warning(
            "Local-auth-only action attempted by non-local user on %s",
            request.url.path,
        )
        raise UserFacingForbidden("This action is not available for your account type.")

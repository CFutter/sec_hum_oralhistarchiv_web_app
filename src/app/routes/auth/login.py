"""Login and Shibboleth authentication routes."""

import hmac
import logging
from urllib.parse import urlencode

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from psycopg_pool import AsyncConnectionPool

from app.request_utils import get_client_ip
from config import settings

from ...credentials import LOCAL_EMAIL_MAX_CHARS, LOCAL_PASSWORD_MAX_CHARS
from ...federation_contract import (
    AFFILIATION_MAX_LENGTH,
    AUTHN_CONTEXT_MAX_LENGTH,
    COUNTRY_MAX_LENGTH,
    DISPLAY_NAME_MAX_LENGTH,
    EMAIL_MAX_LENGTH,
    ISSUER_MAX_LENGTH,
    SUBJECT_MAX_LENGTH,
)
from ...middleware import (
    clear_session_cookie,
    get_session_id_from_cookie,
    limiter,
    set_session_cookie,
)
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    CREDENTIAL_INTEGRITY_FAULTS,
    REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    SHIBBOLETH_AFFILIATION_HEADER,
    SHIBBOLETH_AUTHN_CONTEXT_HEADER,
    SHIBBOLETH_COUNTRY_HEADER,
    SHIBBOLETH_DISPLAY_NAME_HEADER,
    SHIBBOLETH_INTERNAL_AUTH_HEADER,
    SHIBBOLETH_ISSUER_HEADER,
    SHIBBOLETH_MAIL_HEADER,
    SHIBBOLETH_SUBJECT_HEADER,
    FederatedLoginFailure,
    FederatedPrincipal,
    InvalidFederatedPrincipal,
    LocalLoginFailure,
    TotpDecryptionError,
    User,
    audit_user_event,
    build_account_credential_fault_notice,
    build_account_locked_notice,
    build_federated_principal,
    delete_session,
    finalize_local_login,
    finalize_shibboleth_login,
    get_db_cursor,
    is_trusted_federated_principal,
    normalize_email,
    record_login_failure_cur,
    verify_password,
)
from ...services.authentication import queue_lockout_notice_cur
from ...template_setup import templates
from .helpers import safe_redirect_url

logger = logging.getLogger(__name__)

public_router = SecureAPIRouter(access=RouteAccess.PUBLIC)
capability_router = SecureAPIRouter(access=RouteAccess.CAPABILITY)
open_router = SecureAPIRouter(access=RouteAccess.OPEN_DURING_ENROLLMENT)
routers = (public_router, capability_router, open_router)

_COUNTED_FAILURE_REASONS = frozenset({"wrong_password"}) | CREDENTIAL_INTEGRITY_FAULTS

_INTERNAL_SECRET_HEADER_MAX_LENGTH = 1024
_FEDERATED_REQUIRED_HEADER_LIMITS = {
    SHIBBOLETH_ISSUER_HEADER: ISSUER_MAX_LENGTH,
    SHIBBOLETH_SUBJECT_HEADER: SUBJECT_MAX_LENGTH,
    SHIBBOLETH_MAIL_HEADER: EMAIL_MAX_LENGTH,
    SHIBBOLETH_AUTHN_CONTEXT_HEADER: AUTHN_CONTEXT_MAX_LENGTH,
}
_FEDERATED_OPTIONAL_HEADER_LIMITS = {
    SHIBBOLETH_DISPLAY_NAME_HEADER: DISPLAY_NAME_MAX_LENGTH,
    SHIBBOLETH_AFFILIATION_HEADER: AFFILIATION_MAX_LENGTH,
    SHIBBOLETH_COUNTRY_HEADER: COUNTRY_MAX_LENGTH,
}

_SHIBBOLETH_LOGOUT_PATH = "/Shibboleth.sso/Logout"


class _FederatedHeaderRejected(ValueError):
    """A fixed proxy header was absent, ambiguous, or structurally unsafe."""


def _contains_nonprintable(value: str) -> bool:
    """Return whether text contains nonprintable characters or is empty."""
    return not value.isprintable()


def _single_federated_header(
    request: Request,
    name: str,
    *,
    max_length: int,
    required: bool,
) -> str | None:
    """Decode one header as UTF-8 without normalization.

    Return None for an optional missing/empty value; otherwise raise
    _FederatedHeaderRejected for missing required, duplicate, invalid UTF-8,
    nonprintable, or overlong text. max_length counts decoded characters.
    """
    values = request.headers.getlist(name)
    if not values:
        if required:
            raise _FederatedHeaderRejected(f"{name}:missing")
        return None
    if len(values) != 1:
        raise _FederatedHeaderRejected(f"{name}:duplicate")

    try:
        value = values[0].encode("latin-1").decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise _FederatedHeaderRejected(f"{name}:invalid_utf8") from exc
    if not value:
        if required:
            raise _FederatedHeaderRejected(f"{name}:blank")
        return None
    if len(value) > max_length:
        raise _FederatedHeaderRejected(f"{name}:oversized")
    if _contains_nonprintable(value):
        raise _FederatedHeaderRejected(f"{name}:nonprintable")
    return value


def _read_federated_principal(request: Request) -> FederatedPrincipal:
    """Parse fixed headers into a canonical principal after the caller trusts the proxy.

    _FederatedHeaderRejected and InvalidFederatedPrincipal propagate; this
    helper does not check the secret, issuer allowlist, or MFA context.
    """
    required = {
        name: _single_federated_header(
            request,
            name,
            max_length=max_length,
            required=True,
        )
        for name, max_length in _FEDERATED_REQUIRED_HEADER_LIMITS.items()
    }
    optional = {
        name: _single_federated_header(
            request,
            name,
            max_length=max_length,
            required=False,
        )
        for name, max_length in _FEDERATED_OPTIONAL_HEADER_LIMITS.items()
    }

    issuer = required[SHIBBOLETH_ISSUER_HEADER]
    subject_id = required[SHIBBOLETH_SUBJECT_HEADER]
    email = required[SHIBBOLETH_MAIL_HEADER]
    authn_context = required[SHIBBOLETH_AUTHN_CONTEXT_HEADER]
    if issuer is None or subject_id is None or email is None or authn_context is None:
        # ``required=True`` currently makes this unreachable. Keep a runtime
        # guard (rather than an assert removed by ``python -O``) so a future
        # header-reader refactor still fails closed.
        raise _FederatedHeaderRejected("required-assertion-header:missing")

    return build_federated_principal(
        issuer=issuer,
        subject_id=subject_id,
        email=email,
        authn_context=authn_context,
        display_name=optional[SHIBBOLETH_DISPLAY_NAME_HEADER],
        affiliation=optional[SHIBBOLETH_AFFILIATION_HEADER],
        country=optional[SHIBBOLETH_COUNTRY_HEADER],
    )


def _has_valid_shibboleth_internal_auth(request: Request) -> bool:
    """Validate the callback-only proxy credential without exposing its value."""
    secret = settings.shibboleth_internal_secret
    if secret is None:
        # Should be unreachable: settings require this whenever federation is on.
        logger.error(
            "Shibboleth callback: internal secret is None despite shibboleth_enabled=True. "
            "Configuration invariant violated — rejecting."
        )
        return False

    try:
        provided = _single_federated_header(
            request,
            SHIBBOLETH_INTERNAL_AUTH_HEADER,
            max_length=_INTERNAL_SECRET_HEADER_MAX_LENGTH,
            required=True,
        )
    except _FederatedHeaderRejected:
        logger.warning("Shibboleth callback rejected: invalid internal-auth header")
        return False

    if provided is None:
        # Defense in depth against future drift in the required-value contract.
        logger.warning("Shibboleth callback rejected: missing internal-auth header")
        return False

    valid = hmac.compare_digest(
        provided.encode("utf-8", "replace"),
        secret.get_secret_value().encode("utf-8", "replace"),
    )
    if not valid:
        logger.warning("Shibboleth callback rejected: invalid internal-auth credential")
    return valid


def _login_error(request: Request, email: str, error: str) -> Response:
    """Render an uncached 401 login error with the submitted email."""
    response = templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": error,
            "email": email,
        },
        status_code=401,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


async def _record_failure_and_queue_notice(
    pool: AsyncConnectionPool,
    user: User,
    reason: str,
    *,
    expected_auth_revision: int,
) -> tuple[int | None, bool]:
    """Commit a revision-guarded failure/notice; return (count, entered_lockout).

    Integrity reasons select repair guidance; other reasons select lockout mail.
    The boolean reports the transition, not whether enqueueing claimed a notice.
    """
    async with get_db_cursor(pool) as cur:
        count, entered_lockout = await record_login_failure_cur(
            cur,
            user.id,
            expected_auth_revision=expected_auth_revision,
        )

        if entered_lockout:
            if reason in CREDENTIAL_INTEGRITY_FAULTS:
                email = build_account_credential_fault_notice(user.email)
            else:
                email = build_account_locked_notice(user.email)

            await queue_lockout_notice_cur(
                cur,
                user_id=user.id,
                expected_auth_revision=expected_auth_revision,
                email=email,
            )

        return count, entered_lockout


_LOGIN_ERROR_MESSAGES: dict[str, str] = {
    "account_conflict": (
        "This email address is already linked to another account. "
        "Please contact support to resolve the account conflict."
    ),
    "shibboleth_invalid_email": (
        "Your institution did not provide a valid email address. "
        "Please contact your institution's support team."
    ),
    "totp_setup_completed": ("Authenticator setup is complete. Please sign in again."),
    "totp_recovery_completed": (
        "Your replacement authenticator is configured. Please sign in again."
    ),
    "admin_promotion_completed": ("Administrator setup is complete. Please sign in again."),
    "session_expired": "Your session has expired. Please sign in again.",
}


@public_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    """Render an uncached login form with allowlisted error text, or 303-redirect users home."""
    if request.state.user:
        return RedirectResponse(url="/", status_code=303)

    response = templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": _LOGIN_ERROR_MESSAGES.get(request.query_params.get("error", "")),
        },
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@public_router.post("/login", response_class=HTMLResponse)
@limiter.limit("5/minute;20/hour")
async def login_submit(
    request: Request,
    email: str = Form(..., max_length=LOCAL_EMAIL_MAX_CHARS),
    password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    totp_code: str = Form(default="", max_length=16),
) -> Response:
    """Verify local credentials and issue a fresh signed-session cookie after commit.

    Count eligible failures with their captured revision; ordinary rejection
    renders generic 401. Unverified email or undecryptable TOTP gets specific
    401 guidance; recovery-required users redirect to /recover-totp. Success
    audits and redirects 303 to setup or safe next. Old-session deletion is
    best-effort and may leave it valid. See authentication services for lockout,
    TOTP consumption, and dummy-hash timing limits.
    """
    pool = request.app.state.db_pool
    client_ip = get_client_ip(request)
    old_session = get_session_id_from_cookie(request)

    totp_code = "".join(totp_code.split())
    normalized = normalize_email(email)
    lookup_email = normalized if normalized is not None else email
    check = await verify_password(pool, lookup_email, password)
    user, password_ok, locked_until = check.user, check.password_ok, check.locked_until

    if locked_until is not None:
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="login_blocked_locked",
            user_id=user.id if user else None,
            locked_until=locked_until.isoformat(),
        )
        return _login_error(request, email, "Invalid email, password, or authentication code.")

    if not password_ok:
        new_count = None

        if user is not None and check.failure_reason in _COUNTED_FAILURE_REASONS:
            if check.auth_revision is None:
                raise RuntimeError("Counted password failure is missing its captured revision")
            new_count, entered_lockout = await _record_failure_and_queue_notice(
                pool,
                user,
                check.failure_reason,
                expected_auth_revision=check.auth_revision,
            )

            if entered_lockout:
                if check.failure_reason in CREDENTIAL_INTEGRITY_FAULTS:
                    audit_user_event(
                        level=logging.ERROR,
                        request=request,
                        event_type="account_locked_integrity_fault",
                        user_id=user.id,
                        reason=check.failure_reason,
                    )
                else:
                    audit_user_event(
                        level=logging.INFO,
                        request=request,
                        event_type="account_locked",
                        user_id=user.id,
                        reason=check.failure_reason,
                    )

        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="login_failed",
            user_id=user.id if user else None,
            reason=check.failure_reason,
            failed_count=new_count,
            email_was_registered=user is not None,
        )

        return _login_error(
            request,
            email,
            "Invalid email, password, or authentication code.",
        )

    if check.user is None or check.auth_revision is None:
        raise RuntimeError("Successful password verification lacks user or auth revision")

    try:
        result = await finalize_local_login(
            pool,
            user_id=check.user.id,
            expected_auth_revision=check.auth_revision,
            totp_code=totp_code,
            ip_address=client_ip,
        )
    except TotpDecryptionError:
        audit_user_event(
            level=logging.ERROR,
            request=request,
            event_type="totp_secret_undecryptable",
            user_id=check.user.id,
            exc_info=True,
        )
        return _login_error(
            request,
            email,
            "We can't verify your account right now. Please contact support.",
        )

    if isinstance(result, LocalLoginFailure):
        failed_user_id = result.user.id if result.user is not None else None

        if result.reason == "totp_recovery_required":
            audit_user_event(
                level=logging.INFO,
                request=request,
                event_type="login_recovery_required",
                user_id=failed_user_id,
            )
            return RedirectResponse(url="/recover-totp", status_code=303)

        if result.reason == "unverified_email":
            audit_user_event(
                level=logging.INFO,
                request=request,
                event_type="login_blocked_unverified",
                user_id=failed_user_id,
            )
            return _login_error(
                request,
                email,
                "Please verify your email before logging in. "
                "Use the link below to request a new verification email.",
            )

        if result.just_locked:
            audit_user_event(
                level=logging.INFO,
                request=request,
                event_type="account_locked",
                user_id=failed_user_id,
                reason=result.reason,
            )

        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type=(
                "login_blocked_locked" if result.reason == "account_locked" else "login_failed"
            ),
            user_id=failed_user_id,
            reason=result.reason,
            failed_count=result.failed_count,
        )

        return _login_error(
            request,
            email,
            "Invalid email, password, or authentication code.",
        )

    user = result.user
    session_id = result.session_id
    session_purpose = result.purpose

    redirect_to = safe_redirect_url(request) if session_purpose == "full" else "/setup-totp"

    if old_session:
        try:
            await delete_session(pool, old_session)
        except Exception:
            logger.warning(
                "Failed to revoke prior session on re-login for user %s",
                user.id,
                exc_info=True,
            )

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="login_success",
        user_id=user.id,
        auth_method=user.auth_method,
        session_purpose=session_purpose,
        access_tier=user.access_tier,
    )

    response = RedirectResponse(url=redirect_to, status_code=303)
    set_session_cookie(response, session_id)
    return response


@capability_router.get("/auth/shibboleth/callback")
async def shibboleth_callback(request: Request) -> Response:
    """Validate trusted SP headers and complete institutional login.

    Require enabled federation, a Unix-socket peer, callback secret, canonical
    attributes, trusted issuer, and fixed MFA context. Reject pre-service checks
    with 303 login redirects; service rejection renders generic 401. Success
    commits/audits a full session, best-effort revokes the old token, sets signed
    cookies, and redirects to safe next. Deploy nginx header replacement and
    socket permissions; forwarded headers must not define request.client.
    """
    old_session = get_session_id_from_cookie(request)
    if not settings.shibboleth_enabled:
        return RedirectResponse(url="/login", status_code=303)

    # A Unix peer alone proves no SP authentication; this only catches TCP exposure.
    if request.client is not None:
        logger.error("Shibboleth callback over TCP peer %s — refusing", request.client.host)
        return RedirectResponse("/login", status_code=303)

    # Nginx supplies the callback-only internal credential. Validate it before
    # reading or trusting any asserted identity attributes.
    if not _has_valid_shibboleth_internal_auth(request):
        return RedirectResponse(url="/login", status_code=303)

    pool = request.app.state.db_pool
    try:
        principal = _read_federated_principal(request)
    except (_FederatedHeaderRejected, InvalidFederatedPrincipal) as exc:
        # Log only the fixed reason code; never persist an asserted value.
        logger.warning("Shibboleth callback rejected: invalid assertion headers (%s)", exc)
        location = (
            "/login?error=shibboleth_invalid_email"
            if isinstance(exc, InvalidFederatedPrincipal) and exc.reason == "invalid_email"
            else "/login"
        )
        return RedirectResponse(url=location, status_code=303)

    if not is_trusted_federated_principal(principal):
        logger.warning(
            "Shibboleth callback rejected: issuer or authentication assurance not approved"
        )
        return RedirectResponse(url="/login", status_code=303)

    result = await finalize_shibboleth_login(
        pool,
        principal=principal,
        ip_address=get_client_ip(request),
    )
    if isinstance(result, FederatedLoginFailure):
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type=f"shibboleth_login_blocked_{result.reason}",
            user_id=result.user.id if result.user is not None else None,
        )
        return _login_error(
            request,
            principal.email,
            "We can't sign you in with this institutional account. Please contact support.",
        )

    user = result.user
    session_id = result.session_id

    if old_session:
        try:
            await delete_session(pool, old_session)
        except Exception:
            logger.warning(
                "Failed to revoke prior session on re-login for user %s",
                user.id,
                exc_info=True,
            )

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="login_success",
        user_id=user.id,
        auth_method="shibboleth",
        access_tier=user.access_tier,
        federated_issuer=principal.issuer,
        federated_authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    )

    redirect_to = safe_redirect_url(request)
    response = RedirectResponse(url=redirect_to, status_code=303)
    set_session_cookie(response, session_id)
    return response


@open_router.post("/logout")
async def logout(request: Request) -> Response:
    """Delete the presented session, clear cookies, and return a 303 redirect.

    Redirect through the fixed SP logout handler whenever federation is enabled,
    otherwise /. Its return URL uses PUBLIC_BASE_URL; request parameters cannot
    choose it. Database deletion failures propagate before cookies are cleared.
    """
    pool = request.app.state.db_pool
    federated_logout = settings.shibboleth_enabled

    session_id = get_session_id_from_cookie(request)
    if session_id:
        await delete_session(pool, session_id)

    redirect_to = "/"
    if federated_logout:
        return_url = f"{settings.public_base_url}/"
        redirect_to = f"{_SHIBBOLETH_LOGOUT_PATH}?{urlencode({'return': return_url})}"

    response = RedirectResponse(url=redirect_to, status_code=303)
    clear_session_cookie(response)
    return response

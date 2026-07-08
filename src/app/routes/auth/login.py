"""Login and Shibboleth authentication routes."""
import logging
import hmac
from fastapi import (
    APIRouter, 
    Response, 
    Request, 
    Form, 
    Depends,
    BackgroundTasks
    )
from fastapi.responses import RedirectResponse, HTMLResponse
from email_validator import validate_email, EmailNotValidError

from ...middleware import (
    limiter,
    verify_csrf,
    validate_form_content_type, 
    get_client_ip, 
    set_session_cookie,
    get_session_id_from_cookie,
    clear_session_cookie,
    rotate_csrf_cookie 
    )
from ...template_setup import templates
from ...services import (
    SessionPurpose,
    TotpDecryptionError,
    verify_password, 
    get_totp_secret,
    send_account_locked_notice,
    create_shibboleth_user,
    create_session,
    delete_session,
    clear_login_failures,
    record_login_failure,
    update_last_login,
    audit_user_event,
    verify_and_consume_totp
    )

from .helpers import safe_redirect_url
from config import settings

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("audit")
router = APIRouter()

def _login_error(request: Request, email: str, error: str) -> Response:
    """Render the login page with an error message and preserved email."""
    return templates.TemplateResponse(request, "login.html", {
        "error": error,
        "email": email,
    }, status_code=401)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    """Show the login page."""
    if request.state.user:
        return RedirectResponse(url="/", status_code=303)

    response = templates.TemplateResponse(request, "login.html", {
        "error": None,
    })
    response.headers["Cache-Control"] = "no-store"
    return response

@router.post("/login", response_class=HTMLResponse, dependencies=[Depends(validate_form_content_type), Depends(verify_csrf)])
@limiter.limit("5/minute;20/hour")
async def login_submit(
    request: Request,
    background_tasks: BackgroundTasks,
    email: str = Form(..., max_length=200),
    password: str = Form(..., max_length=200),
    totp_code: str = Form(default="", max_length=6),
) -> Response:
    """Handle local login form submission.

    Verifies the password; locked, inactive, non-local, and unknown
    accounts all fail with the same generic 401 message and equalized
    timing. If the user has TOTP configured, the code is verified and its
    time-step consumed (replay protection); if not (two-step registration,
    TOTP not yet set up), the user is logged in with password only into a
    purpose="totp_setup" session and redirected to /setup-totp. Local users
    must have a verified email before login completes. On success any prior
    session is revoked, a new session is created, and the user is
    redirected to the validated `next` URL.
    """
    pool = request.app.state.db_pool
    client_ip = get_client_ip(request)
    request_id = getattr(request.state, "request_id", None)
    old_session = get_session_id_from_cookie(request)

    user, password_ok, locked_until = await verify_password(pool, email, password)

    # Locked account → reject (timing already equalised inside verify_password).
    if locked_until is not None:
        audit_logger.info(
            "login_blocked_locked",
            extra={
                "event_type": "login_blocked_locked",
                "user_id": user.id if user else None,
                "ip": client_ip,
                "request_id": request_id,
                "locked_until": locked_until.isoformat(),
            },
        )
        return _login_error(request, email, "Invalid email, password, or authentication code.")

    # Wrong password / no user / inactive / non-local → record + log failure.
    if not password_ok:
        new_count = None
        if user and user.auth_method == "local":
            new_count, just_locked = await record_login_failure(pool, user.id)
            if just_locked:
                background_tasks.add_task(send_account_locked_notice, email)
                audit_logger.info(
                    "account_locked",
                    extra={
                        "event_type": "account_locked",
                        "user_id": user.id,
                        "ip": client_ip,
                        "request_id": request_id,
                        "reason": "wrong_password",
                    },
                )
        audit_logger.info(
            "login_failed",
            extra={
                "event_type": "login_failed",
                "user_id": user.id if user else None,
                "ip": client_ip,
                "request_id": request_id,
                "reason": "wrong_password",
                "failed_count": new_count,
                "email_was_registered": user is not None,
            },
        )
        return _login_error(request, email, "Invalid email, password, or authentication code.")

    # password_ok is True → user is guaranteed non-None (local, active, correct).
    assert user is not None  # nosec B101 — password_ok is only True when user is set

    try:
        totp_secret = await get_totp_secret(pool, user.id)
    except TotpDecryptionError:
        audit_logger.exception(
            "totp_secret_undecryptable", 
            extra={
                "event_type": "totp_secret_undecryptable",
                "user_id": user.id, 
                "ip": client_ip
                }
            )
        return _login_error(request, email, "We can't verify your account right now. Please contact support.")

    if totp_secret:
        if not await verify_and_consume_totp(pool, user.id, totp_secret, totp_code):
            new_count, just_locked = await record_login_failure(pool, user.id)
            if just_locked:
                background_tasks.add_task(send_account_locked_notice, email)
                audit_logger.info(
                    "account_locked",
                    extra={
                        "event_type": "account_locked",
                        "user_id": user.id,
                        "ip": client_ip,
                        "request_id": request_id,
                        "reason": "wrong_totp",
                    },
                )
            audit_logger.info(
                "login_failed",
                extra={
                    "event_type": "login_failed",
                    "user_id": user.id,
                    "ip": client_ip,
                    "request_id": request_id,
                    "reason": "wrong_totp",
                    "failed_count": new_count,
                },
            )
            return _login_error(request, email, "Invalid email, password, or authentication code.")

    if user.auth_method == "local":
        await clear_login_failures(pool, user.id)

    if user.auth_method == "local" and not user.email_verified:
        audit_logger.info(
            "login_blocked_unverified",
            extra={
                "event_type": "login_blocked_unverified",
                "user_id": user.id,
                "ip": client_ip,
                "request_id": request_id,
            },
        )
        return _login_error(
            request, email,
            "Please verify your email before logging in. "
            "Use the link below to request a new verification email."
        )

    await update_last_login(pool, user.id)

    session_purpose: SessionPurpose = "full" if totp_secret else "totp_setup"
    session_id = await create_session(
        pool,
        user_id=user.id,
        ip_address=client_ip,
        max_age_seconds=settings.session_max_age_seconds,
        purpose=session_purpose,
    )

    if old_session:
        try:
            await delete_session(pool, old_session)
        except Exception:
            logger.warning("Failed to revoke prior session on re-login for user %s", user.id, exc_info=True)

    audit_logger.info(
        "login_success",
        extra={
            "event_type": "login_success",
            "user_id": user.id,
            "ip": client_ip,
            "request_id": request_id,
            "auth_method": user.auth_method,
            "session_purpose": session_purpose,
            "access_tier": user.access_tier,
        },
    )

    if not totp_secret:
        redirect_to = "/setup-totp"
    else:
        redirect_to = safe_redirect_url(request)

    response = RedirectResponse(url=redirect_to, status_code=303)
    set_session_cookie(response, session_id)
    return response
    

@router.get("/auth/shibboleth/callback")
async def shibboleth_callback(request: Request) -> Response:
    """Handle Shibboleth authentication callback.

    mod_shib authenticates the user at the IdP; nginx forwards the result as
    request headers (REMOTE_USER, mail, displayName, ...). This route trusts
    those headers, so it must be certain the request came from nginx.

    Trust model (NOT an app-level IP check):
      1. gunicorn binds only a Unix socket — there is no TCP listener to hit;
         reaching the app requires local filesystem access to the socket.
      2. nginx injects X-Internal-Auth and the mod_shib attribute headers ONLY
         on this location, and strips them on every other location.
      3. X-Internal-Auth must match the configured secret (constant-time below).
         The settings validator makes the secret mandatory when Shibboleth is on.
    Keep gunicorn's forwarded_allow_ips="" so request.client is never derived
    from forwarded headers; do not switch this route to a spoofable IP check.
    """
    if not settings.shibboleth_enabled:
        return RedirectResponse(url="/login", status_code=303)

    # NOT an authentication boundary. Over the production Unix socket, request.client
    # is None for every nginx-proxied request — internal and external alike. This only
    # catches the app being accidentally exposed on TCP. The real gate is X-Internal-Auth
    # below, backed by nginx stripping client-supplied auth headers on all locations
    if request.client is not None:
        logger.error("Shibboleth callback over TCP peer %s — refusing", request.client.host)
        return RedirectResponse("/login", status_code=303)

    # TODO: DEPLOYMENT: nginx must inject "X-Internal-Auth: <secret>" on this path.
    # See deploy/nginx.conf.example (proxy_set_header directive on /auth/shibboleth/callback).
    secret = settings.shibboleth_internal_secret
    if secret is None:
        # Should be unreachable: the settings validator requires this whenever
        # shibboleth_enabled is True.
        logger.error(
            "Shibboleth callback: internal secret is None despite shibboleth_enabled=True. "
            "Configuration invariant violated — rejecting."
        )
        return RedirectResponse(url="/login", status_code=303)
    
    provided = request.headers.get("X-Internal-Auth", "")
    if not hmac.compare_digest(provided, secret.get_secret_value()):
        logger.warning(
            "Shibboleth callback rejected: missing or invalid X-Internal-Auth header"
        )
        return RedirectResponse(url="/login", status_code=303)

    pool = request.app.state.db_pool

    remote_user = request.headers.get(settings.shibboleth_header_remote_user)
    email_provided = request.headers.get(settings.shibboleth_header_mail)
    display_name = request.headers.get(settings.shibboleth_header_display_name)
    affiliation = request.headers.get(settings.shibboleth_header_affiliation)


    if not remote_user or not email_provided:
        logger.warning(
            "Shibboleth callback missing required headers. "
            "REMOTE_USER=%s, mail=%s",
            remote_user, email_provided,
        )
        return RedirectResponse(url="/login", status_code=303)

    try:
        email_info = validate_email(email_provided, check_deliverability=False)
        email = email_info.normalized.lower()

    except EmailNotValidError as e:
        logger.warning(
            "Shibboleth callback rejected: invalid email format: %s (%s)",
            email_provided, str(e),
        )
        return RedirectResponse(url="/login?error=shibboleth_invalid_email", status_code=303)

    # Auto-provision or update user
    user = await create_shibboleth_user(
        pool,
        email=email,
        display_name=display_name,
        affiliation=affiliation,
        country=request.headers.get(settings.shibboleth_header_country),
    )
    if user is None or user.auth_method != "shibboleth":
        audit_user_event(request, "shibboleth_login_blocked_local_collision",
                        user_id=getattr(user, "id", None))
        return RedirectResponse(url="/login?error=account_conflict", status_code=303)

    # Create session
    session_id = await create_session(
        pool,
        user_id=user.id,
        ip_address=get_client_ip(request),
        max_age_seconds=settings.session_max_age_seconds,
        purpose="full",
    )

    audit_user_event(
        request,
        "login_success",
        user_id=user.id,
        auth_method="shibboleth",
        access_tier=user.access_tier,
    )

    redirect_to = safe_redirect_url(request)
    response = RedirectResponse(url=redirect_to, status_code=303)
    set_session_cookie(response, session_id)
    return response


@router.post("/logout", dependencies=[Depends(validate_form_content_type), Depends(verify_csrf)])
async def logout(request: Request) -> Response:
    """Log out the current user and clear the session."""
    pool = request.app.state.db_pool

    session_id = get_session_id_from_cookie(request)
    if session_id:
        await delete_session(pool, session_id)

    response = RedirectResponse(url="/", status_code=303)
    clear_session_cookie(response)
    rotate_csrf_cookie(response)
    return response
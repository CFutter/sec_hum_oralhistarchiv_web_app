"""TOTP setup and reset routes."""
import logging
import pyotp

from fastapi import APIRouter, Depends, Form, Response, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from ...middleware import (
    limiter,
    require_login, 
    verify_csrf, 
    validate_form_content_type,
    get_session_id_from_cookie
)
from ...services import (
    TotpDecryptionError,
    generate_totp_secret, 
    get_pending_totp_secret,
    get_totp_secret, 
    store_pending_totp_secret,
    update_totp_secret,
    matched_step,
    upgrade_session_purpose,
    audit_user_event,
    set_flash,
    verify_and_consume_totp
)
from config import settings
from ...template_setup import templates

from .helpers import generate_totp_qr

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/setup-totp", response_class=HTMLResponse, dependencies=[Depends(require_login)])
@limiter.limit("10/minute;30/hour")
async def setup_totp_page(request: Request) -> Response:
    """Render the TOTP enrollment page.

    NOTE: This GET writes (mints + stores a pending TOTP secret), which is a
    deliberate exception to the GET-safety doctrine in verify_email.py /
    email_change.py. The secret must exist server-side before the QR can be
    rendered (the QR encodes it). Known caveat: a prefetch/second-visit rotates
    the pending secret, so a QR scanned from an earlier visit fails verification
    (self-heals on retry). Accepted because the write is authenticated, TTL'd
    (10 min), and overwritten-not-accumulated.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    
    # If TOTP is already configured, redirect to account
    if user.totp_configured:
        return RedirectResponse(url="/account", status_code=303)
    
    if not user.email_verified:
        return templates.TemplateResponse(request, "verify_email_pending.html", {
            "email": user.email,
        })

    totp_secret = await get_pending_totp_secret(pool, user.id)
    if totp_secret is None:
        totp_secret = generate_totp_secret()
        await store_pending_totp_secret(pool, user.id, totp_secret)

    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name=settings.totp_issuer_name,
    )

    return templates.TemplateResponse(request, "setup_totp.html", {
        "totp_secret": totp_secret,
        "totp_qr_data": await run_in_threadpool(generate_totp_qr, provisioning_uri),
        "error": None,
    })


@router.post("/setup-totp", response_class=HTMLResponse, dependencies=[Depends(require_login), Depends(verify_csrf), Depends(validate_form_content_type)])
@limiter.limit("5/minute;20/hour")
async def setup_totp_submit(
    request: Request,
    totp_code: str = Form(..., max_length=6),
) -> Response:
    """Handle TOTP setup verification — save secret if code is valid.

    Reads the pending secret from the database rather than from the form,
    preventing a client from substituting an attacker-known secret.
    """
    pool = request.app.state.db_pool
    user = request.state.user

    totp_secret = await get_pending_totp_secret(pool, user.id)
    if not totp_secret:
        return RedirectResponse(url="/setup-totp", status_code=303)

    step = matched_step(totp_secret, totp_code)
    if step is None:
        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name=settings.totp_issuer_name,
        )
        return templates.TemplateResponse(request, "setup_totp.html", {
            "totp_secret": totp_secret,
            "totp_qr_data": await run_in_threadpool(generate_totp_qr, provisioning_uri),
            "error": "Invalid code. Please scan the QR code and try again.",
        }, status_code=422)

    await update_totp_secret(pool, user.id, totp_secret, consumed_step=step)
    audit_user_event(
        request,
        "totp_configured",
        user_id=user.id,
    )

    session_id = get_session_id_from_cookie(request)
    if session_id:
        try:
            await upgrade_session_purpose(pool, session_id, "full")
        except ValueError as e:
            logger.warning("Session upgrade failed: %s", e)
            return RedirectResponse(url="/login?error=session_expired", status_code=303)

    return RedirectResponse(url="/account", status_code=303)


@router.get("/account/reset-totp", response_class=HTMLResponse, dependencies=[Depends(require_login)])
@limiter.limit("10/minute;30/hour")
async def reset_totp_page(request: Request) -> Response:
    """Show the TOTP change page — verify current code, scan new QR.

    Requires the user to prove they have their current authenticator
    before allowing a change to a new one. The new secret is stored
    server-side so the POST handler retrieves it by user ID.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    if user.auth_method != "local":
        session_id = get_session_id_from_cookie(request)
        if session_id:
            await set_flash(
                pool, session_id,
                "Two-factor authentication is managed by your identity provider (SWITCH edu-ID).",
                "info",
            )
        return RedirectResponse(url="/account", status_code=303)

    try:
        current_secret = await get_totp_secret(pool, user.id)
    except TotpDecryptionError:
        audit_user_event(request, "totp_secret_undecryptable", user_id=user.id)
        return templates.TemplateResponse(
            request, 
            "error.html", {
                "error_title": "Two-factor temporarily unavailable",
                "error_message": "We can't access your authenticator settings right now. Please contact support.",
            }, 
            status_code=503
        )

    if current_secret is None:
        return RedirectResponse(url="/setup-totp", status_code=303)

    totp_secret = await get_pending_totp_secret(pool, user.id)
    if totp_secret is None:
        totp_secret = generate_totp_secret()
        await store_pending_totp_secret(pool, user.id, totp_secret)

    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name=settings.totp_issuer_name,
    )

    return templates.TemplateResponse(request, "reset_totp.html", {
        "new_totp_secret": totp_secret,
        "totp_qr_data": await run_in_threadpool(generate_totp_qr, provisioning_uri),
        "error": None,
    })


@router.post("/account/reset-totp", response_class=HTMLResponse, dependencies=[Depends(require_login), Depends(verify_csrf), Depends(validate_form_content_type)])
@limiter.limit("5/minute;20/hour")
async def reset_totp_submit(
    request: Request,
    current_totp_code: str = Form(..., max_length=6),
    new_totp_code: str = Form(..., max_length=6),
) -> Response:
    """Handle authenticator change — verify old code, verify new code, save.

    Reads the pending new secret from the database rather than from the form,
    preventing a client from substituting an attacker-known secret.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    user_id = user.id


    if user.auth_method != "local":
        return RedirectResponse(url="/account", status_code=303)

    # Must already have TOTP configured to use the reset flow.
    # Users without TOTP belong in /setup-totp (first-time enrollment).
    current_secret = await get_totp_secret(pool, user_id)
    if current_secret is None:
        return RedirectResponse(url="/setup-totp", status_code=303)

    new_totp_secret = await get_pending_totp_secret(pool, user_id)
    if not new_totp_secret:
        # Expired or missing — user must restart the change flow
        return RedirectResponse(url="/account/reset-totp", status_code=303)

    errors = []

    if not await verify_and_consume_totp(pool, user_id, current_secret, current_totp_code, valid_window=1):
        audit_user_event(request, "totp_reset_blocked_invalid_current", user_id=user_id)
        errors.append("Current authentication code is incorrect.")

    new_step = matched_step(new_totp_secret, new_totp_code)
    if new_step is None:
        errors.append("New authentication code is incorrect. Please scan the QR code and try again.")

    if errors:
        new_totp = pyotp.TOTP(new_totp_secret)
        provisioning_uri = new_totp.provisioning_uri(
            name=user.email,
            issuer_name=settings.totp_issuer_name,
        )
        return templates.TemplateResponse(request, "reset_totp.html", {
            "new_totp_secret": new_totp_secret,
            "totp_qr_data": await run_in_threadpool(generate_totp_qr, provisioning_uri),
            "error": " ".join(errors),
        }, status_code=422)

    await update_totp_secret(pool, user_id, new_totp_secret, consumed_step=new_step)
    audit_user_event(
        request,
        "totp_changed",
        user_id=user_id,
    )

    return RedirectResponse(url="/account", status_code=303)

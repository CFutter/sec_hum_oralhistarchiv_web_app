"""TOTP setup and reset routes."""

import logging

import pyotp
from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from config import settings

from ...credentials import LOCAL_PASSWORD_MAX_CHARS
from ...middleware import (
    clear_session_cookie,
    get_session_id_from_cookie,
    limiter,
)
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    TOTP_RECOVERY_CODE_MAX_CHARS,
    PendingTotpOutcome,
    PendingTotpPurpose,
    TotpDecryptionError,
    TotpEnrollmentOutcome,
    TotpRotationOutcome,
    TotpRotationStartOutcome,
    audit_user_event,
    begin_totp_rotation,
    confirm_totp_rotation,
    delete_session,
    get_or_create_pending_totp_secret,
    set_flash_if_exists,
    verify_and_enroll_totp,
)
from ...template_setup import templates
from .helpers import generate_totp_qr

logger = logging.getLogger(__name__)

enrollment_router = SecureAPIRouter(access=RouteAccess.TOTP_ENROLLMENT)
full_router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)
routers = (enrollment_router, full_router)


async def _restart_after_completed_setup(request: Request) -> Response:
    """Best-effort revoke the cookie token, clear cookies, and redirect 303 to login."""
    session_id = get_session_id_from_cookie(request)
    if session_id is not None:
        try:
            await delete_session(request.app.state.db_pool, session_id)
        except Exception:
            logger.warning(
                "Failed to revoke completed TOTP setup session",
                exc_info=True,
            )

    response = RedirectResponse(
        url="/login?error=totp_setup_completed",
        status_code=303,
    )
    clear_session_cookie(response)
    return response


async def _restart_after_recovery_session(
    request: Request,
    *,
    completed: bool,
) -> Response:
    """Best-effort revoke the cookie token and clear cookies before a 303 redirect.

    completed selects login-success guidance; False selects recovery-expired
    guidance. Failed deletion is logged and does not prevent the redirect.
    """
    session_id = get_session_id_from_cookie(request)
    if session_id is not None:
        try:
            await delete_session(request.app.state.db_pool, session_id)
        except Exception:
            logger.warning(
                "Failed to revoke TOTP recovery session",
                exc_info=True,
            )

    destination = (
        "/login?error=totp_recovery_completed"
        if completed
        else "/recover-totp?error=session_expired"
    )
    response = RedirectResponse(url=destination, status_code=303)
    clear_session_cookie(response)
    return response


@enrollment_router.get("/setup-totp", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def setup_totp_page(request: Request) -> Response:  # noqa: PLR0911 - typed state mapping
    """Render pending TOTP seed/QR and a freshly staged recovery-code set.

    This authenticated GET writes: reuse a valid seed for ten minutes, but
    replace recovery codes on every render. Existing factors redirect to account
    or restart partial sessions; unverified email renders instructions; service
    ineligibility returns 403. Session rejection restarts login/recovery. QR
    generation runs in a thread using TOTP_ISSUER_NAME.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    session_id = request.state.session_id
    if session_id is None:
        raise RuntimeError("TOTP-enrollment route reached without a session ID")

    recovery_enrollment = request.state.session_purpose == "totp_recovery"
    pending_purpose = (
        PendingTotpPurpose.RECOVERY if recovery_enrollment else PendingTotpPurpose.ENROLLMENT
    )

    if user.totp_configured:
        if recovery_enrollment:
            return await _restart_after_recovery_session(request, completed=True)
        if request.state.session_purpose == "totp_setup":
            return await _restart_after_completed_setup(request)
        return RedirectResponse(url="/account", status_code=303)

    if not user.email_verified:
        return templates.TemplateResponse(
            request,
            "verify_email_pending.html",
            {
                "email": user.email,
            },
        )

    pending = await get_or_create_pending_totp_secret(
        pool,
        user.id,
        purpose=pending_purpose,
        session_id=session_id,
    )

    if pending.outcome is PendingTotpOutcome.SESSION_EXPIRED:
        if recovery_enrollment:
            return await _restart_after_recovery_session(request, completed=False)
        return await _restart_after_completed_setup(request)

    if pending.outcome is PendingTotpOutcome.ALREADY_CONFIGURED:
        if request.state.session_purpose == "totp_setup":
            return await _restart_after_completed_setup(request)
        return RedirectResponse(url="/account", status_code=303)

    if pending.outcome is PendingTotpOutcome.INELIGIBLE:
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Authenticator setup unavailable",
                "error_message": "This account cannot configure an authenticator.",
            },
            status_code=403,
        )

    if pending.outcome is not PendingTotpOutcome.READY or pending.secret is None:
        raise RuntimeError(f"Unhandled pending TOTP result: {pending!r}")

    totp_secret = pending.secret

    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name=settings.totp_issuer_name,
    )

    return templates.TemplateResponse(
        request,
        "setup_totp.html",
        {
            "totp_secret": totp_secret,
            "totp_qr_data": await run_in_threadpool(generate_totp_qr, provisioning_uri),
            "recovery_codes": pending.recovery_codes,
            "recovery_code_max_chars": TOTP_RECOVERY_CODE_MAX_CHARS,
            "error": None,
        },
    )


@enrollment_router.post("/setup-totp", response_class=HTMLResponse)
@limiter.limit("5/minute;20/hour")
async def setup_totp_submit(  # noqa: PLR0911 - typed state mapping
    request: Request,
    totp_code: str = Form(..., max_length=16),
    recovery_code_confirmation: str = Form(..., max_length=TOTP_RECOVERY_CODE_MAX_CHARS),
) -> Response:
    """Enroll with TOTP plus a staged recovery code via verify_and_enroll_totp.

    Success audits and redirects 303 to account; recovery completion clears
    cookies and redirects to login. Bad codes render 422 with a replacement
    recovery-code set, invalidating the previous display. Missing seed redirects
    to setup; ineligible state returns 403 or restarts recovery; already-
    configured state returns 409 or restarts a partial session. Expired sessions
    restart login/recovery. Unexpected service outcomes raise RuntimeError.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    recovery_enrollment = request.state.session_purpose == "totp_recovery"
    pending_purpose = (
        PendingTotpPurpose.RECOVERY if recovery_enrollment else PendingTotpPurpose.ENROLLMENT
    )

    session_id = request.state.session_id
    if session_id is None:
        raise RuntimeError("TOTP-enrollment route reached without a session ID")

    outcome = await verify_and_enroll_totp(
        pool,
        user.id,
        totp_code,
        recovery_code_confirmation,
        session_id=session_id,
    )

    if outcome is TotpEnrollmentOutcome.SESSION_EXPIRED:
        if recovery_enrollment:
            return await _restart_after_recovery_session(request, completed=False)
        return await _restart_after_completed_setup(request)

    if outcome is TotpEnrollmentOutcome.ALREADY_CONFIGURED:
        if recovery_enrollment:
            return await _restart_after_recovery_session(request, completed=True)
        if request.state.session_purpose == "totp_setup":
            return await _restart_after_completed_setup(request)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Authenticator already configured",
                "error_message": (
                    "Sign out and sign in again. To change your "
                    "authenticator, use your account settings."
                ),
            },
            status_code=409,
        )

    if outcome is TotpEnrollmentOutcome.INELIGIBLE:
        if recovery_enrollment:
            return await _restart_after_recovery_session(request, completed=False)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Authenticator setup unavailable",
                "error_message": (
                    "This account cannot complete authenticator setup. Please contact support."
                ),
            },
            status_code=403,
        )

    if outcome is TotpEnrollmentOutcome.PENDING_SECRET_MISSING:
        return RedirectResponse(url="/setup-totp", status_code=303)

    if outcome in {
        TotpEnrollmentOutcome.INVALID_CODE,
        TotpEnrollmentOutcome.INVALID_RECOVERY_CODE,
    }:
        # Plaintext recovery codes are intentionally not recoverable from their
        # hashes. Re-rendering therefore rotates only the staged set while the
        # active set (if any) remains usable.
        pending = await get_or_create_pending_totp_secret(
            pool,
            user.id,
            purpose=pending_purpose,
            session_id=session_id,
        )
        if pending.outcome is not PendingTotpOutcome.READY or pending.secret is None:
            return RedirectResponse(url="/setup-totp", status_code=303)

        provisioning_uri = pyotp.TOTP(pending.secret).provisioning_uri(
            name=user.email,
            issuer_name=settings.totp_issuer_name,
        )
        error = (
            "Invalid authenticator code. Scan the current QR code and try again."
            if outcome is TotpEnrollmentOutcome.INVALID_CODE
            else "That recovery code is not in the current displayed set. Try again."
        )
        return templates.TemplateResponse(
            request,
            "setup_totp.html",
            {
                "totp_secret": pending.secret,
                "totp_qr_data": await run_in_threadpool(generate_totp_qr, provisioning_uri),
                "recovery_codes": pending.recovery_codes,
                "recovery_code_max_chars": TOTP_RECOVERY_CODE_MAX_CHARS,
                "error": error,
            },
            status_code=422,
        )

    if outcome is TotpEnrollmentOutcome.RECOVERED:
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="totp_recovery_completed",
            user_id=user.id,
        )
        response = RedirectResponse(
            url="/login?error=totp_recovery_completed",
            status_code=303,
        )
        clear_session_cookie(response)
        return response

    if outcome is not TotpEnrollmentOutcome.ENROLLED:
        raise RuntimeError(f"Unhandled TOTP enrollment outcome: {outcome!r}")

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="totp_configured",
        user_id=user.id,
    )

    return RedirectResponse(url="/account", status_code=303)


@full_router.get("/account/reset-totp", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def reset_totp_page(request: Request) -> Response:
    """Render rotation-proof form; redirect federated users to account with feedback.

    An unconfigured local snapshot redirects 303 to setup; this handler creates
    no replacement seed.
    """
    pool = request.app.state.db_pool
    user = request.state.user

    if user.auth_method != "local":
        session_id = get_session_id_from_cookie(request)
        if session_id:
            await set_flash_if_exists(
                pool,
                session_id,
                "Two-factor authentication is managed by your identity provider (SWITCH edu-ID).",
                "info",
            )
        return RedirectResponse(url="/account", status_code=303)

    if not user.totp_configured:
        return RedirectResponse(url="/setup-totp", status_code=303)

    return templates.TemplateResponse(
        request,
        "reset_totp.html",
        {
            "error": None,
            "password_max_chars": LOCAL_PASSWORD_MAX_CHARS,
        },
    )


@full_router.post("/account/reset-totp", response_class=HTMLResponse)
@limiter.limit("5/minute;20/hour")
async def reset_totp_start(
    request: Request,
    current_password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    current_totp_code: str = Form(..., max_length=16),
) -> Response:
    """Prove credentials through begin_totp_rotation and render the replacement seed/QR once.

    Federated users redirect to account; missing factor redirects to setup.
    Bad/replayed proofs render 422, lockout 423, ineligibility 403, and decryption
    failure 503. Invalid/exhausted sessions clear cookies and redirect to login.
    Success/rejections are audited; the service's step-up attempt remains spent.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    user_id = user.id

    if user.auth_method != "local":
        return RedirectResponse(url="/account", status_code=303)

    session_id = request.state.session_id
    if session_id is None:
        raise RuntimeError("Full-session route reached without a session ID")

    try:
        result = await begin_totp_rotation(
            pool,
            user_id,
            current_password,
            current_totp_code,
            session_id=session_id,
        )
    except TotpDecryptionError:
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="totp_secret_undecryptable",
            user_id=user_id,
        )
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Two-factor temporarily unavailable",
                "error_message": (
                    "We can't access your authenticator settings right now. Please contact support."
                ),
            },
            status_code=503,
        )

    if result.outcome is TotpRotationStartOutcome.CURRENT_SECRET_MISSING:
        return RedirectResponse(url="/setup-totp", status_code=303)

    if result.outcome in {
        TotpRotationStartOutcome.SESSION_EXPIRED,
        TotpRotationStartOutcome.ATTEMPTS_EXHAUSTED,
    }:
        audit_user_event(
            level=logging.WARNING,
            request=request,
            event_type="totp_rotation_step_up_session_rejected",
            user_id=user_id,
            reason=result.outcome.value,
        )
        response = RedirectResponse(url="/login?error=session_expired", status_code=303)
        clear_session_cookie(response)
        return response

    if result.outcome is TotpRotationStartOutcome.ACCOUNT_LOCKED:
        audit_user_event(
            level=logging.WARNING,
            request=request,
            event_type="totp_rotation_step_up_blocked",
            user_id=user_id,
            reason="account_locked",
        )
        return templates.TemplateResponse(
            request,
            "reset_totp.html",
            {
                "error": "This account is temporarily unavailable. Try again later.",
                "password_max_chars": LOCAL_PASSWORD_MAX_CHARS,
            },
            status_code=423,
        )

    if result.outcome is TotpRotationStartOutcome.INELIGIBLE:
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Authenticator reset unavailable",
                "error_message": "This account cannot reset its authenticator.",
            },
            status_code=403,
        )

    if result.outcome in {
        TotpRotationStartOutcome.INVALID_CREDENTIALS,
        TotpRotationStartOutcome.REPLAYED_CURRENT_CODE,
    }:
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="totp_rotation_step_up_rejected",
            user_id=user_id,
        )
        error = (
            "That authenticator code was already used. Wait for the next code and try again."
            if result.outcome is TotpRotationStartOutcome.REPLAYED_CURRENT_CODE
            else "The password or authenticator code is incorrect."
        )
        return templates.TemplateResponse(
            request,
            "reset_totp.html",
            {
                "error": error,
                "password_max_chars": LOCAL_PASSWORD_MAX_CHARS,
            },
            status_code=422,
        )

    if result.outcome is not TotpRotationStartOutcome.READY or result.secret is None:
        raise RuntimeError(f"Unhandled TOTP rotation-start result: {result!r}")

    replacement_totp = pyotp.TOTP(result.secret)
    provisioning_uri = replacement_totp.provisioning_uri(
        name=user.email,
        issuer_name=settings.totp_issuer_name,
    )

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="totp_rotation_started",
        user_id=user_id,
    )
    return templates.TemplateResponse(
        request,
        "reset_totp_confirm.html",
        {
            "new_totp_secret": result.secret,
            "totp_qr_data": await run_in_threadpool(generate_totp_qr, provisioning_uri),
            "error": None,
        },
    )


@full_router.post("/account/reset-totp/confirm", response_class=HTMLResponse)
@limiter.limit("5/minute;20/hour")
async def reset_totp_confirm(
    request: Request,
    new_totp_code: str = Form(..., max_length=16),
) -> Response:
    """Complete rotation through confirm_totp_rotation, audit, and map its outcome.

    Success clears cookies and redirects 303 to login after session revocation.
    Invalid new codes render 422 without redisclosing seed/QR; stale/exhausted
    challenge or lockout redirects to restart with flash. Invalid/ineligible
    sessions clear cookies and redirect to login; decryption faults render 503.
    Federated users redirect to account. Unexpected outcomes raise RuntimeError.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    user_id = user.id

    if user.auth_method != "local":
        return RedirectResponse(url="/account", status_code=303)

    session_id = request.state.session_id
    if session_id is None:
        raise RuntimeError("Full-session route reached without a session ID")

    try:
        outcome = await confirm_totp_rotation(
            pool,
            user_id,
            new_totp_code,
            session_id=session_id,
        )
    except TotpDecryptionError:
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="totp_secret_undecryptable",
            user_id=user_id,
        )
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Two-factor temporarily unavailable",
                "error_message": (
                    "We can't access your authenticator settings right now. Please contact support."
                ),
            },
            status_code=503,
        )

    if outcome is TotpRotationOutcome.ROTATED:
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="totp_changed",
            user_id=user_id,
        )
        response = RedirectResponse(url="/login?totp_changed=1", status_code=303)
        clear_session_cookie(response)
        return response

    if outcome is TotpRotationOutcome.PENDING_SECRET_MISSING:
        await set_flash_if_exists(
            pool,
            session_id,
            "The authenticator change expired or was replaced. Authenticate again to restart.",
            "error",
        )
        return RedirectResponse(url="/account/reset-totp", status_code=303)

    if outcome is TotpRotationOutcome.ATTEMPTS_EXHAUSTED:
        audit_user_event(
            level=logging.WARNING,
            request=request,
            event_type="totp_rotation_confirmation_blocked",
            user_id=user_id,
            reason="attempts_exhausted",
        )
        await set_flash_if_exists(
            pool,
            session_id,
            "Too many confirmation attempts. Authenticate again to restart the change.",
            "error",
        )
        return RedirectResponse(url="/account/reset-totp", status_code=303)

    if outcome is TotpRotationOutcome.ACCOUNT_LOCKED:
        audit_user_event(
            level=logging.WARNING,
            request=request,
            event_type="totp_rotation_confirmation_blocked",
            user_id=user_id,
            reason="account_locked",
        )
        await set_flash_if_exists(
            pool,
            session_id,
            "Authenticator changes are temporarily unavailable. Try again later.",
            "error",
        )
        return RedirectResponse(url="/account/reset-totp", status_code=303)

    if outcome in {TotpRotationOutcome.SESSION_EXPIRED, TotpRotationOutcome.INELIGIBLE}:
        audit_user_event(
            level=logging.WARNING,
            request=request,
            event_type="totp_rotation_confirmation_session_rejected",
            user_id=user_id,
            reason=outcome.value,
        )
        response = RedirectResponse(url="/login?error=session_expired", status_code=303)
        clear_session_cookie(response)
        return response

    if outcome is not TotpRotationOutcome.INVALID_NEW_CODE:
        raise RuntimeError(f"Unhandled TOTP rotation outcome: {outcome!r}")

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="totp_rotation_confirmation_rejected",
        user_id=user_id,
    )
    error = (
        "The new authenticator code is incorrect. Try the current code from "
        "the authenticator you just added, or restart the change."
    )
    return templates.TemplateResponse(
        request,
        "reset_totp_confirm.html",
        {
            # Deliberately do not redisclose the seed after the first response.
            "new_totp_secret": None,
            "totp_qr_data": None,
            "error": error,
        },
        status_code=422,
    )

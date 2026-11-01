"""Stage local email changes and consume session-independent confirmation links."""

import logging
from secrets import compare_digest

from fastapi import Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...action_token_contract import ACTION_PUBLIC_ID_CHARS, ACTION_TOKEN_MAX_CHARS
from ...credentials import (
    LOCAL_EMAIL_MAX_CHARS,
    LOCAL_PASSWORD_MAX_CHARS,
    TOTP_CODE_RAW_MAX_CHARS,
)
from ...middleware import (
    clear_session_cookie,
    limiter,
    require_resolved_session_id,
)
from ...reason_contracts import require_reason_coverage
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    SelfEmailChangeRejected,
    TotpDecryptionError,
    action_token_public_id,
    audit_user_event,
    confirm_email_change,
    set_flash_if_exists,
    stage_self_email_change,
    valid_action_public_id,
    validate_email_change_token,
)
from ...services.email_change import SelfEmailChangeReason
from ...template_setup import templates

logger = logging.getLogger(__name__)

local_router = SecureAPIRouter(access=RouteAccess.LOCAL_FULL_SESSION)
capability_router = SecureAPIRouter(access=RouteAccess.CAPABILITY)
routers = (local_router, capability_router)

_SELF_EMAIL_CHANGE_ERRORS = {
    "invalid_email": "Please enter a valid email address.",
    "ineligible_account": "This account cannot change its email address.",
    "invalid_password": "Current password is incorrect.",
    "invalid_totp": (
        "Enter a fresh authentication code. If you just used a code, wait for the next one."
    ),
    "account_locked": "This account is temporarily unavailable. Try again later.",
    "same_email": "That is already your email address.",
    "retry_required": (
        "Your credentials were refreshed while this request was processed. Please try again."
    ),
}


_SESSION_REJECTIONS = frozenset({"invalid_session", "step_up_exhausted"})
require_reason_coverage(
    SelfEmailChangeReason, _SELF_EMAIL_CHANGE_ERRORS, separately_handled=_SESSION_REJECTIONS
)


@local_router.get("/account/change-email", response_class=HTMLResponse)
async def change_email_page(request: Request) -> Response:
    """Show the email-change form."""
    return templates.TemplateResponse(
        request,
        "change_email.html",
        {
            "user": request.state.user,
            "error": None,
        },
    )


@local_router.post("/account/change-email")
@limiter.limit("5/minute;20/hour")
async def change_email_submit(
    request: Request,
    new_email: str = Form(..., max_length=LOCAL_EMAIL_MAX_CHARS),
    current_password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    totp_code: str = Form(..., max_length=TOTP_CODE_RAW_MAX_CHARS),
) -> Response:
    """Prove password/fresh TOTP and queue an enumeration-neutral email change.

    Audit/flash success and redirect 303 to /account. Render 422 for policy
    refusals, 423 lockout, 409 stale credentials or 503 unreadable TOTP. Invalid/
    exhausted sessions clear cookies and redirect to login; staging RuntimeError/
    ValueError renders 500. The durable step-up attempt survives staging refusal.
    Missing resolved session state raises RuntimeError before staging.
    """
    user = request.state.user
    pool = request.app.state.db_pool
    session_id = require_resolved_session_id(request)

    def _form_error(msg: str, status: int = 422) -> Response:
        """Render the submitted address and error without echoing the password."""
        return templates.TemplateResponse(
            request,
            "change_email.html",
            {
                "user": user,
                "error": msg,
                "new_email": new_email,
            },
            status_code=status,
        )

    try:
        result = await stage_self_email_change(
            pool,
            user_id=user.id,
            session_id=session_id,
            current_password=current_password,
            new_email=new_email,
            totp_code=totp_code,
        )
    except SelfEmailChangeRejected as exc:
        if exc.reason in _SESSION_REJECTIONS:
            audit_user_event(
                level=logging.WARNING,
                request=request,
                event_type="email_change_step_up_session_rejected",
                user_id=user.id,
                reason=exc.reason,
            )
            response = RedirectResponse(url="/login?error=session_expired", status_code=303)
            clear_session_cookie(response)
            return response
        if exc.reason == "account_locked":
            audit_user_event(
                level=logging.WARNING,
                request=request,
                event_type="email_change_step_up_blocked",
                user_id=user.id,
                reason=exc.reason,
            )
            return _form_error(_SELF_EMAIL_CHANGE_ERRORS[exc.reason], status=423)
        if exc.reason == "retry_required":
            return _form_error(_SELF_EMAIL_CHANGE_ERRORS[exc.reason], status=409)
        if exc.reason in {"invalid_password", "invalid_totp"}:
            audit_user_event(
                level=logging.INFO,
                request=request,
                event_type=(
                    "email_change_blocked_invalid_password"
                    if exc.reason == "invalid_password"
                    else "email_change_blocked_invalid_totp"
                ),
                user_id=user.id,
            )
        return _form_error(_SELF_EMAIL_CHANGE_ERRORS[exc.reason])
    except TotpDecryptionError:
        return _form_error(
            "Your authenticator is temporarily unavailable. Please contact support.",
            status=503,
        )
    except (RuntimeError, ValueError):
        logger.exception(
            "Email-change staging failed",
            extra={"event_type": "email_change_staging_failed", "user_id": user.id},
        )
        return _form_error(
            "Something went wrong. Please try again.",
            status=500,
        )

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="email_change_requested",
        user_id=result.user_id,
    )

    if session_id:
        await set_flash_if_exists(
            pool,
            session_id,
            "If the requested address can be used, a confirmation email will be sent shortly.",
            "success",
        )
    return RedirectResponse(url="/account", status_code=303)


@capability_router.get("/account/confirm-email/{public_id}", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def confirm_email_page(request: Request, public_id: str) -> Response:
    """Render unresolved confirmation fields; raise HTTPException(404) for malformed public IDs."""
    if not valid_action_public_id(public_id):
        raise HTTPException(status_code=404)

    return templates.TemplateResponse(
        request,
        "confirm_email.html",
        {
            "public_id": public_id,
            "token": None,
        },
    )


@capability_router.post("/account/confirm-email", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def confirm_email_submit(
    request: Request,
    public_id: str = Form(..., max_length=ACTION_PUBLIC_ID_CHARS),
    token: str = Form(..., max_length=ACTION_TOKEN_MAX_CHARS),
) -> Response:
    """Consume the signed change, revoke target sessions, and redirect 303 to login.

    Invalid/stale/colliding capabilities return 400. Success audits the signed
    initiator, clearing cookies only when the presenting user is the target.
    The central CSRF exception permits cross-device use; content checks remain.
    """
    pool = request.app.state.db_pool

    data = (
        validate_email_change_token(token)
        if valid_action_public_id(public_id)
        and compare_digest(public_id, action_token_public_id(token))
        else None
    )
    if not data:
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Invalid or expired link",
                "error_message": "This email-change link is invalid or has expired. "
                "Please request the change again.",
            },
            status_code=400,
        )

    success = await confirm_email_change(
        pool,
        data["user_id"],
        data["new_email"],
        token,
        expected_auth_revision=data["auth_revision"],
    )

    if not success:
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="email_change_failed",
            user_id=data["user_id"],
        )
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Could not change email",
                "error_message": "The change could not be completed. The link may "
                "have already been used, or the address may now be "
                "taken. Please try again.",
            },
            status_code=400,
        )

    acting_admin_id = data.get("acting_admin_id")
    if acting_admin_id is not None:
        # Confirmation may be anonymous or presented by another account.
        # audit_admin_action takes its actor from request.state.user; use
        # the initiating administrator ID from the validated token instead.
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="admin_email_changed",
            user_id=data["user_id"],
            actor_admin_id=acting_admin_id,
            target_user_id=data["user_id"],
        )
    else:
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="email_changed",
            user_id=data["user_id"],
        )

    response = RedirectResponse(url="/login?notice=email_changed", status_code=303)
    if request.state.user and request.state.user.id == data["user_id"]:
        clear_session_cookie(response)
    return response

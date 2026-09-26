"""Stage local email changes and consume session-independent confirmation links."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...credentials import LOCAL_EMAIL_MAX_CHARS, LOCAL_PASSWORD_MAX_CHARS
from ...middleware import (
    clear_session_cookie,
    get_session_id_from_cookie,
    limiter,
)
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    SelfEmailChangeRejected,
    audit_user_event,
    confirm_email_change,
    hash_token,
    pending_email_change_matches,
    set_flash_if_exists,
    stage_self_email_change,
    validate_email_change_token,
)
from ...template_setup import templates

logger = logging.getLogger(__name__)

local_router = SecureAPIRouter(access=RouteAccess.LOCAL_FULL_SESSION)
capability_router = SecureAPIRouter(access=RouteAccess.CAPABILITY)
routers = (local_router, capability_router)

_SELF_EMAIL_CHANGE_ERRORS = {
    "invalid_email": "Please enter a valid email address.",
    "ineligible_account": "This account cannot change its email address.",
    "invalid_password": "Current password is incorrect.",
    "account_locked": "This account is temporarily unavailable. Try again later.",
    "same_email": "That is already your email address.",
    "retry_required": (
        "Your credentials were refreshed while this request was processed. Please try again."
    ),
}


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
) -> Response:
    """Prove the password and queue a revision-bound change without membership disclosure.

    Success audits/flashes and redirects 303 to /account. Policy errors render
    422, lockout 423, and a refreshed hash 409. Invalid/exhausted sessions clear
    cookies and redirect to login. RuntimeError/ValueError render 500; the
    service's committed step-up attempt survives staging rejection.
    """
    user = request.state.user
    pool = request.app.state.db_pool
    session_id = get_session_id_from_cookie(request)

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
            session_id=session_id or "",
            current_password=current_password,
            new_email=new_email,
        )
    except SelfEmailChangeRejected as exc:
        if exc.reason in {"invalid_session", "step_up_exhausted"}:
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
        if exc.reason == "invalid_password":
            audit_user_event(
                level=logging.INFO,
                request=request,
                event_type="email_change_blocked_invalid_password",
                user_id=user.id,
            )
        return _form_error(_SELF_EMAIL_CHANGE_ERRORS[exc.reason])
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


@capability_router.get("/account/confirm-email/{token}", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def confirm_email_page(request: Request, token: str) -> Response:
    """Render a current signed pending change, or 400; never consume its token."""
    pool = request.app.state.db_pool

    data = validate_email_change_token(token)
    if not data or not await pending_email_change_matches(
        pool,
        data["user_id"],
        data["new_email"],
        expected_auth_revision=data["auth_revision"],
        expected_token_hash=hash_token(token),
    ):
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Link no longer valid",
                "error_message": "This email-change link is invalid, has expired, "
                "or has already been used. If you still want to "
                "change your email, please request it again.",
            },
            status_code=400,
        )

    return templates.TemplateResponse(
        request,
        "confirm_email.html",
        {
            "token": token,
            "new_email": data["new_email"],
            "is_admin_initiated": data.get("acting_admin_id") is not None,
        },
    )


@capability_router.post("/account/confirm-email", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def confirm_email_submit(
    request: Request,
    token: str = Form(..., max_length=2000),
) -> Response:
    """Consume the signed change, revoke target sessions, and redirect 303 to login.

    Invalid/stale/colliding capabilities return 400. Success audits the signed
    initiator, clearing cookies only when the presenting user is the target.
    The central CSRF exception permits cross-device use; content checks remain.
    """
    pool = request.app.state.db_pool

    data = validate_email_change_token(token)
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
        hash_token(token),
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
        # Deliberately audit_user_event, NOT audit_admin_action: that helper
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

    response = RedirectResponse(url="/login?email_changed=1", status_code=303)
    if request.state.user and request.state.user.id == data["user_id"]:
        clear_session_cookie(response)
    return response

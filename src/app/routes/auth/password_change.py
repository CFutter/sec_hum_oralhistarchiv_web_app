"""Authenticated local password changes with fresh password and TOTP proof."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...credentials import LOCAL_PASSWORD_MAX_CHARS, TOTP_CODE_RAW_MAX_CHARS
from ...middleware import clear_session_cookie, limiter, require_resolved_session_id
from ...reason_contracts import require_reason_coverage
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    PasswordChangeReason,
    PasswordChangeRejected,
    TotpDecryptionError,
    audit_user_event,
    change_password,
)
from ...template_setup import templates

local_router = SecureAPIRouter(access=RouteAccess.LOCAL_FULL_SESSION)
routers = (local_router,)

_PASSWORD_CHANGE_ERRORS = {
    "account_locked": "Password changes are temporarily unavailable. Try again later.",
    "ineligible_account": "This account cannot change its password here. Contact support.",
    "invalid_password": "Your current password is incorrect.",
    "invalid_totp": (
        "Your authentication code is invalid or was already used. "
        "Wait for the next code and try again."
    ),
    "retry_required": "Your account changed while this request was processed. Please try again.",
    "password_reused": "Please choose a different password from your current one.",
}
_SESSION_REJECTIONS = frozenset({"invalid_session", "step_up_exhausted"})
require_reason_coverage(
    PasswordChangeReason,
    _PASSWORD_CHANGE_ERRORS,
    separately_handled=_SESSION_REJECTIONS | {"password_policy"},
)


def _render_password_change(
    request: Request, *, error: str | None = None, status_code: int = 200
) -> Response:
    """Render feedback without retaining submitted passwords or TOTP codes."""
    return templates.TemplateResponse(
        request,
        "change_password.html",
        {"error": error},
        status_code=status_code,
    )


@local_router.get("/account/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request) -> Response:
    """Show the password-change form for a local full-session account."""
    return _render_password_change(request)


@local_router.post("/account/change-password", response_class=HTMLResponse)
@limiter.limit("5/minute;20/hour")
async def change_password_submit(
    request: Request,
    current_password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    new_password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    password_confirm: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    totp_code: str = Form(..., max_length=TOTP_CODE_RAW_MAX_CHARS),
) -> Response:
    """Change the local password after fresh proof; clear cookies and redirect 303 to login.

    Render 422 for confirmation/policy/proof refusals, 423 if locked, 409 for
    retryable account changes or 503 for TOTP decryption failure. Invalid/exhausted
    sessions clear cookies and redirect to login; audit success after commit.
    """
    if new_password != password_confirm:
        return _render_password_change(request, error="Passwords do not match.", status_code=422)
    user = request.state.user
    try:
        await change_password(
            request.app.state.db_pool,
            user_id=user.id,
            session_id=require_resolved_session_id(request),
            current_password=current_password,
            new_password=new_password,
            totp_code=totp_code,
        )
    except PasswordChangeRejected as exc:
        if exc.reason in _SESSION_REJECTIONS:
            response = RedirectResponse(url="/login?error=session_expired", status_code=303)
            clear_session_cookie(response)
            return response
        error = (
            exc.password_error or "Please choose a password meeting the password requirements."
            if exc.reason == "password_policy"
            else _PASSWORD_CHANGE_ERRORS[exc.reason]
        )
        return _render_password_change(
            request,
            error=error,
            status_code={"account_locked": 423, "retry_required": 409}.get(exc.reason, 422),
        )
    except TotpDecryptionError:
        return _render_password_change(
            request,
            error="We cannot access your authenticator settings right now. Please contact support.",
            status_code=503,
        )
    audit_user_event(
        level=logging.INFO, request=request, event_type="password_changed", user_id=user.id
    )
    response = RedirectResponse(url="/login?notice=password_changed", status_code=303)
    clear_session_cookie(response)
    return response

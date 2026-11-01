"""Confirm and audit permanent account deletion after fresh credential proof."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...credentials import LOCAL_PASSWORD_MAX_CHARS, TOTP_CODE_RAW_MAX_CHARS
from ...middleware import clear_session_cookie, limiter, require_resolved_session_id
from ...reason_contracts import require_reason_coverage
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    AccountDeletionRejected,
    TotpDecryptionError,
    User,
    audit_admin_action,
    audit_user_event,
    delete_account_as_admin,
    delete_own_account,
    get_user_by_id,
    set_flash_if_exists,
)
from ...services.account_deletion import AccountDeletionReason
from ...template_setup import templates

local_router = SecureAPIRouter(access=RouteAccess.LOCAL_FULL_SESSION)
admin_router = SecureAPIRouter(access=RouteAccess.ADMIN)
routers = (local_router, admin_router)

_DELETION_ERRORS = {
    "account_locked": "Account deletion is temporarily unavailable. Try again later.",
    "ineligible_account": (
        "This account cannot use self-service deletion. Contact an administrator."
    ),
    "invalid_password": "Your current password is incorrect.",
    "invalid_totp": (
        "Your authentication code is invalid or was already used. "
        "Wait for the next code and try again."
    ),
    "retry_required": "Your account changed while this request was processed. Please start again.",
    "user_not_found": "This account no longer exists.",
    "self_admin_deletion": "Use your own account page to delete your account.",
    "last_active_admin": "At least one active administrator must remain.",
}
_SESSION_REJECTIONS = frozenset({"invalid_session", "step_up_exhausted", "admin_required"})
_CONFIRMATION_ERROR = "Confirm that you understand this will permanently delete the account."
_TOTP_UNAVAILABLE = (
    "We cannot access your authenticator settings right now. Please contact support."
)


require_reason_coverage(
    AccountDeletionReason, _DELETION_ERRORS, separately_handled=_SESSION_REJECTIONS
)


def _no_store(response: Response) -> Response:
    """Prevent caching and hide referrer paths and queries for confirmation responses."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "strict-origin"
    return response


def _render_deletion(
    request: Request,
    target: User,
    *,
    admin_action: bool,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    """Render escaped account details without retaining submitted credentials."""
    return _no_store(
        templates.TemplateResponse(
            request,
            "account_deletion.html",
            {"target": target, "admin_action": admin_action, "error": error},
            status_code=status_code,
        )
    )


def _session_expired() -> Response:
    """Clear browser security cookies and return a no-store 303 to login?error=session_expired."""
    response = RedirectResponse(url="/login?error=session_expired", status_code=303)
    clear_session_cookie(response)
    return _no_store(response)


def _deletion_rejected(
    request: Request,
    target: User,
    rejection: AccountDeletionRejected,
    *,
    admin_action: bool,
) -> Response:
    """Render locked/changed/missing/policy 423/409/404/422; redirect session refusals."""
    if rejection.reason in _SESSION_REJECTIONS:
        return _session_expired()
    status = {"account_locked": 423, "retry_required": 409, "user_not_found": 404}.get(
        rejection.reason, 422
    )
    return _render_deletion(
        request,
        target,
        admin_action=admin_action,
        error=_DELETION_ERRORS[rejection.reason],
        status_code=status,
    )


@local_router.get("/account/delete", response_class=HTMLResponse)
async def account_delete_page(request: Request) -> Response:
    """Show permanent deletion confirmation for a local full-session account."""
    return _render_deletion(request, request.state.user, admin_action=False)


@local_router.post("/account/delete", response_class=HTMLResponse)
@limiter.limit("3/minute;10/hour")
async def account_delete_submit(
    request: Request,
    password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    totp_code: str = Form(..., max_length=TOTP_CODE_RAW_MAX_CHARS),
    confirm: str = Form(default="", max_length=6),
) -> Response:
    """Delete the local account after confirm="delete" and fresh password/TOTP proof.

    The service spends a step-up attempt and rechecks live authority before the
    cascade. Audit success after commit, clear cookies and redirect 303 to login.
    Missing confirmation renders 422; typed rejections use _deletion_rejected;
    TOTP decryption failure renders 503.
    """
    user = request.state.user
    if confirm != "delete":
        return _render_deletion(
            request,
            user,
            admin_action=False,
            error=_CONFIRMATION_ERROR,
            status_code=422,
        )
    try:
        result = await delete_own_account(
            request.app.state.db_pool,
            user_id=user.id,
            session_id=require_resolved_session_id(request),
            password=password,
            totp_code=totp_code,
        )
    except AccountDeletionRejected as exc:
        return _deletion_rejected(request, user, exc, admin_action=False)
    except TotpDecryptionError:
        return _render_deletion(
            request,
            user,
            admin_action=False,
            error=_TOTP_UNAVAILABLE,
            status_code=503,
        )

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="account_deleted",
        user_id=result.target_user_id,
        email_hash=result.email_hash,
        auth_method=result.auth_method,
    )
    response = RedirectResponse(url="/login?notice=account_deleted", status_code=303)
    clear_session_cookie(response)
    return _no_store(response)


async def _admin_target(request: Request, user_id: int) -> User | Response:
    """Read the target account or render a no-store 404 when absent."""
    target = await get_user_by_id(request.app.state.db_pool, user_id)
    if target is not None:
        return target
    return _no_store(
        templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Account not found",
                "error_message": _DELETION_ERRORS["user_not_found"],
            },
            status_code=404,
        )
    )


@admin_router.get("/admin/users/{user_id}/delete", response_class=HTMLResponse)
async def admin_account_delete_page(request: Request, user_id: int) -> Response:
    """Render target deletion confirmation; absent targets return 404 and self-targets 422."""
    target = await _admin_target(request, user_id)
    if isinstance(target, Response):
        return target
    error = _DELETION_ERRORS["self_admin_deletion"] if target.id == request.state.user.id else None
    return _render_deletion(
        request,
        target,
        admin_action=True,
        error=error,
        status_code=422 if error else 200,
    )


@admin_router.post("/admin/users/{user_id}/delete", response_class=HTMLResponse)
@limiter.limit("3/minute;10/hour")
async def admin_account_delete_submit(
    request: Request,
    user_id: int,
    password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    totp_code: str = Form(..., max_length=TOTP_CODE_RAW_MAX_CHARS),
    confirm: str = Form(default="", max_length=6),
) -> Response:
    """Delete another account after confirm="delete" and the administrator's fresh proofs.

    Audit after commit, store best-effort success flash and redirect 303 to /admin.
    Missing targets return 404, missing consent 422 and unreadable TOTP 503;
    typed refusals use _deletion_rejected.
    """
    target = await _admin_target(request, user_id)
    if isinstance(target, Response):
        return target
    if confirm != "delete":
        return _render_deletion(
            request,
            target,
            admin_action=True,
            error=_CONFIRMATION_ERROR,
            status_code=422,
        )
    try:
        result = await delete_account_as_admin(
            request.app.state.db_pool,
            actor_id=request.state.user.id,
            actor_session_id=require_resolved_session_id(request),
            target_user_id=user_id,
            password=password,
            totp_code=totp_code,
        )
    except AccountDeletionRejected as exc:
        return _deletion_rejected(request, target, exc, admin_action=True)
    except TotpDecryptionError:
        return _render_deletion(
            request,
            target,
            admin_action=True,
            error=_TOTP_UNAVAILABLE,
            status_code=503,
        )

    audit_admin_action(
        level=logging.INFO,
        request=request,
        event_type="admin_account_deleted",
        target_user_id=result.target_user_id,
        email_hash=result.email_hash,
        auth_method=result.auth_method,
    )
    session_id = require_resolved_session_id(request)
    if session_id:
        await set_flash_if_exists(
            request.app.state.db_pool,
            session_id,
            "The account was permanently deleted.",
            "success",
        )
    return _no_store(RedirectResponse(url="/admin", status_code=303))

"""Target-side acceptance or decline of an administrator invitation."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...credentials import LOCAL_PASSWORD_MAX_CHARS
from ...middleware import clear_session_cookie, limiter
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    TOTP_RECOVERY_CODE_MAX_CHARS,
    AdminPromotion,
    AdminPromotionRejected,
    accept_admin_promotion,
    audit_user_event,
    decline_admin_promotion,
    get_admin_promotion,
    prepare_admin_promotion,
    set_flash_if_exists,
)
from ...template_setup import templates

logger = logging.getLogger(__name__)

router = SecureAPIRouter(access=RouteAccess.LOCAL_FULL_SESSION)
routers = (router,)

_PROMOTION_ERRORS = {
    "user_not_found": "This account is no longer available.",
    "already_admin": "This account already has administrator access.",
    "ineligible_account": "This account is not eligible to accept the invitation.",
    "no_request": "There is no administrator invitation to accept.",
    "invitation_expired": (
        "This administrator invitation expired. Ask an administrator to reissue it."
    ),
    "invalid_session": "Your session expired. Sign in and start again.",
    "account_locked": "This account is temporarily unavailable. Try again later.",
    "step_up_exhausted": "Your session expired. Sign in and start again.",
    "invalid_credentials": "Your current password is incorrect.",
    "invalid_totp": "The authenticator code is invalid or was already used.",
    "state_changed": (
        "Your authentication state changed. Ask an administrator to reissue the invitation."
    ),
    "requester_ineligible": (
        "The inviting administrator is no longer authorized. "
        "Ask another administrator to reissue the invitation."
    ),
    "codes_not_prepared": "Generate a fresh recovery-code set before accepting the invitation.",
    "invalid_recovery_code": "That code is not in the current displayed recovery-code set.",
}


def _no_store(response: Response) -> Response:
    """Set no-store/no-cache/no-referrer headers and return the same response."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _render_promotion(
    request: Request,
    promotion: AdminPromotion,
    *,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    """Render invitation state/errors without caching or exposing referrers."""
    return _no_store(
        templates.TemplateResponse(
            request,
            "admin_promotion.html",
            {
                "promotion": promotion,
                "error": error,
                "recovery_code_max_chars": TOTP_RECOVERY_CODE_MAX_CHARS,
            },
            status_code=status_code,
        )
    )


async def _redirect_account(
    request: Request,
    message: str,
    category: str = "error",
) -> Response:
    """Store best-effort feedback on the current session and redirect 303 to /account."""
    session_id = request.state.session_id
    if session_id:
        await set_flash_if_exists(
            request.app.state.db_pool,
            session_id,
            message,
            category,
        )
    return RedirectResponse(url="/account", status_code=303)


async def _current_promotion(request: Request) -> AdminPromotion | None:
    """Read the current user/session invitation, or None without a session/request."""
    session_id = request.state.session_id
    if session_id is None:
        return None
    return await get_admin_promotion(
        request.app.state.db_pool,
        user_id=request.state.user.id,
        session_id=session_id,
    )


@router.get("/account/admin-promotion", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def admin_promotion_page(request: Request) -> Response:
    """Render an uncached invitation, or redirect 303 to /account with an informational flash."""
    promotion = await _current_promotion(request)
    if promotion is None:
        return await _redirect_account(
            request,
            "There is no pending administrator invitation.",
            "info",
        )
    return _render_promotion(request, promotion)


@router.post("/account/admin-promotion/prepare", response_class=HTMLResponse)
@limiter.limit("3/minute;10/hour")
async def admin_promotion_prepare(
    request: Request,
    current_password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    totp_code: str = Form(..., max_length=16),
) -> Response:
    """Prove password/TOTP and render freshly committed plaintext recovery codes.

    Use prepare_admin_promotion's durable attempt and expiry rules. Audit
    success/rejection; invalid/exhausted sessions clear cookies and redirect to
    login, locked/missing-request outcomes redirect to account, other policy
    failures render 422. Code responses disable caching/referrers.
    """
    session_id = request.state.session_id
    if session_id is None:
        raise RuntimeError("Admin-promotion route reached without a session ID")

    try:
        prepared = await prepare_admin_promotion(
            request.app.state.db_pool,
            user_id=request.state.user.id,
            session_id=session_id,
            password=current_password,
            totp_code=totp_code,
        )
    except AdminPromotionRejected as exc:
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="admin_promotion_prepare_failed",
            user_id=request.state.user.id,
            reason=exc.reason,
        )
        if exc.reason in {"invalid_session", "step_up_exhausted"}:
            response = RedirectResponse(url="/login?error=session_expired", status_code=303)
            clear_session_cookie(response)
            return response
        if exc.reason == "account_locked":
            return await _redirect_account(request, _PROMOTION_ERRORS[exc.reason])
        promotion = await _current_promotion(request)
        if promotion is None:
            return await _redirect_account(request, _PROMOTION_ERRORS[exc.reason])
        return _render_promotion(
            request,
            promotion,
            error=_PROMOTION_ERRORS[exc.reason],
            status_code=422,
        )

    audit_user_event(
        level=logging.WARNING,
        request=request,
        event_type="admin_promotion_codes_prepared",
        user_id=prepared.user_id,
        invitation_expires_at=prepared.invitation_expires_at.isoformat(),
        preparation_expires_at=prepared.preparation_expires_at.isoformat(),
    )
    return _no_store(
        templates.TemplateResponse(
            request,
            "admin_promotion_codes.html",
            {
                "prepared": prepared,
                "recovery_code_max_chars": TOTP_RECOVERY_CODE_MAX_CHARS,
            },
        )
    )


@router.post("/account/admin-promotion/accept", response_class=HTMLResponse)
@limiter.limit("5/minute;15/hour")
async def admin_promotion_accept(
    request: Request,
    recovery_code: str = Form(..., max_length=TOTP_RECOVERY_CODE_MAX_CHARS),
) -> Response:
    """Activate promotion through accept_admin_promotion, then clear cookies and redirect to login.

    Audit success/rejection. Invalid/exhausted sessions redirect to login;
    locked/missing requests redirect to account; other policy errors render
    uncached 422. Acceptance revokes all target sessions.
    """
    session_id = request.state.session_id
    if session_id is None:
        raise RuntimeError("Admin-promotion route reached without a session ID")

    try:
        accepted = await accept_admin_promotion(
            request.app.state.db_pool,
            user_id=request.state.user.id,
            session_id=session_id,
            recovery_code=recovery_code,
        )
    except AdminPromotionRejected as exc:
        audit_user_event(
            level=logging.WARNING,
            request=request,
            event_type="admin_promotion_accept_failed",
            user_id=request.state.user.id,
            reason=exc.reason,
        )
        if exc.reason in {"invalid_session", "step_up_exhausted"}:
            response = RedirectResponse(url="/login?error=session_expired", status_code=303)
            clear_session_cookie(response)
            return response
        if exc.reason == "account_locked":
            return await _redirect_account(request, _PROMOTION_ERRORS[exc.reason])
        promotion = await _current_promotion(request)
        if promotion is None:
            return await _redirect_account(request, _PROMOTION_ERRORS[exc.reason])
        return _render_promotion(
            request,
            promotion,
            error=_PROMOTION_ERRORS[exc.reason],
            status_code=422,
        )

    audit_user_event(
        level=logging.WARNING,
        request=request,
        event_type="admin_promotion_accepted",
        user_id=accepted.user_id,
        requested_by=accepted.requested_by,
    )
    response = RedirectResponse(url="/login?error=admin_promotion_completed", status_code=303)
    clear_session_cookie(response)
    return response


@router.post("/account/admin-promotion/decline")
@limiter.limit("5/minute;15/hour")
async def admin_promotion_decline(request: Request) -> Response:
    """Discard invitation/staged codes and redirect to account with feedback.

    Audit success. Invalid sessions clear cookies and redirect to login; other
    policy errors return account feedback. Existing authority/codes remain.
    """
    session_id = request.state.session_id
    if session_id is None:
        raise RuntimeError("Admin-promotion route reached without a session ID")

    try:
        requested_by = await decline_admin_promotion(
            request.app.state.db_pool,
            user_id=request.state.user.id,
            session_id=session_id,
        )
    except AdminPromotionRejected as exc:
        if exc.reason == "invalid_session":
            response = RedirectResponse(url="/login?error=session_expired", status_code=303)
            clear_session_cookie(response)
            return response
        return await _redirect_account(request, _PROMOTION_ERRORS[exc.reason])

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="admin_promotion_declined",
        user_id=request.state.user.id,
        requested_by=requested_by,
    )
    return await _redirect_account(
        request,
        "Administrator invitation declined.",
        "success",
    )

"""Public redemption of owner-retained TOTP recovery codes."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...credentials import LOCAL_EMAIL_MAX_CHARS, LOCAL_PASSWORD_MAX_CHARS
from ...middleware import limiter, set_session_cookie
from ...request_utils import get_client_ip
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    TOTP_RECOVERY_AUTHORIZATION_MAX_AGE_SECONDS,
    TOTP_RECOVERY_CODE_MAX_CHARS,
    TOTP_RECOVERY_SESSION_MAX_AGE_SECONDS,
    TotpRecoveryRedemptionRejected,
    audit_user_event,
    redeem_totp_recovery,
)
from ...template_setup import templates

router = SecureAPIRouter(access=RouteAccess.PUBLIC)
routers = (router,)

_GENERIC_RECOVERY_ERROR = "Invalid email, password, or recovery code."
_RECOVERY_PAGE_ERRORS = {
    "session_expired": (
        "Your recovery session expired. Ask an administrator to authorize recovery again."
    ),
}


def _render_recovery_page(
    request: Request,
    *,
    email: str = "",
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    """Render email/error with no-store/no-cache/no-referrer headers."""
    response = templates.TemplateResponse(
        request,
        "totp_recover.html",
        {
            "email": email,
            "error": error,
            "recovery_code_max_chars": TOTP_RECOVERY_CODE_MAX_CHARS,
            "recovery_authorization_lifetime_minutes": (
                TOTP_RECOVERY_AUTHORIZATION_MAX_AGE_SECONDS // 60
            ),
        },
        status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@router.get("/recover-totp", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def totp_recovery_page(request: Request) -> Response:
    """Render recovery form with allowlisted error text, or redirect 303 home if authenticated."""
    if request.state.user is not None:
        return RedirectResponse(url="/", status_code=303)
    return _render_recovery_page(
        request,
        error=_RECOVERY_PAGE_ERRORS.get(request.query_params.get("error", "")),
    )


@router.post("/recover-totp", response_class=HTMLResponse)
@limiter.limit("3/minute;10/hour")
async def totp_recovery_submit(
    request: Request,
    email: str = Form(..., max_length=LOCAL_EMAIL_MAX_CHARS),
    password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    recovery_code: str = Form(..., max_length=TOTP_RECOVERY_CODE_MAX_CHARS),
) -> Response:
    """Redeem code/password and set a 15-minute recovery cookie; redirect 303 to setup.

    Expected service rejections render the same uncached 401 and anonymous audit
    event. Success audits the user; database errors propagate. The service
    consumes code/authorization and replaces target sessions atomically.
    """
    try:
        redemption = await redeem_totp_recovery(
            request.app.state.db_pool,
            email=email,
            password=password,
            recovery_code=recovery_code,
            ip_address=get_client_ip(request),
        )
    except TotpRecoveryRedemptionRejected:
        # This is a public endpoint.  Do not copy the service's internal
        # rejection reason or matched user ID into the audit record: either
        # field would turn privileged log access into an account/code oracle.
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="totp_recovery_redemption_failed",
            user_id=None,
        )
        return _render_recovery_page(
            request,
            email=email,
            error=_GENERIC_RECOVERY_ERROR,
            status_code=401,
        )

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="totp_recovery_redeemed",
        user_id=redemption.user_id,
    )
    response = RedirectResponse(url="/setup-totp", status_code=303)
    set_session_cookie(
        response,
        redemption.session_id,
        max_age_seconds=TOTP_RECOVERY_SESSION_MAX_AGE_SECONDS,
    )
    response.headers["Cache-Control"] = "no-store"
    return response

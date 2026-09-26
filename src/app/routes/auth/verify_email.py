"""Email verification route."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...middleware import get_session_id_from_cookie, limiter
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    audit_user_event,
    confirm_email_verification,
    get_user_by_id,
    hash_token,
    set_flash_if_exists,
    validate_verification_token,
)
from ...template_setup import templates

router = SecureAPIRouter(access=RouteAccess.CAPABILITY)
routers = (router,)


def _verify_error(request: Request) -> Response:
    """Audit an anonymous invalid-token failure and render a 400 error page."""
    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="email_verification_failed",
        user_id=None,
        reason="invalid_or_expired_token",
    )
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "error_title": "Invalid verification link",
            "error_message": (
                "This link is invalid or has expired. Please request "
                "a new verification email from the login page."
            ),
        },
        status_code=400,
    )


@router.get("/verify-email/{token}", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def verify_email_page(request: Request, token: str) -> Response:
    """Render confirmation for a valid signed token; invalid signatures render 400.

    This GET does not check the stored hash or consume the capability.
    """
    data = validate_verification_token(token)
    if not data:
        return _verify_error(request)
    return templates.TemplateResponse(
        request,
        "confirm_verify_email.html",
        {
            "token": token,
            "email": data["email"],
        },
    )


@router.post("/verify-email", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def verify_email_submit(
    request: Request, token: str = Form(..., max_length=2000)
) -> Response:
    """Consume signed verification state and audit the outcome.

    Invalid capability returns 400, except a currently verified target yields
    an already-verified 200 page. Success redirects 303 to setup with best-effort
    flash for the matching logged-in user, otherwise login. The central CSRF
    exception permits session-free use; content checks remain.
    """
    pool = request.app.state.db_pool
    data = validate_verification_token(token)
    if not data:
        return _verify_error(request)

    success = await confirm_email_verification(
        pool,
        data["user_id"],
        data["email"],
        hash_token(token),
    )

    if not success:
        user = await get_user_by_id(pool, data["user_id"])
        already_verified = user is not None and user.email_verified

        if already_verified:
            audit_user_event(
                level=logging.INFO,
                request=request,
                event_type="email_verification_noop_already_verified",
                user_id=data["user_id"],
            )
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "error_title": "Already verified",
                    "error_message": "Your email is already verified — you can log in.",
                },
                status_code=200,
            )

        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="email_verification_failed",
            user_id=data["user_id"],
            reason="invalid_or_expired_token",
        )
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Verification link no longer valid",
                "error_message": "This link is invalid or has expired. Please "
                "request a new verification email from the login page.",
            },
            status_code=400,
        )

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="email_verified",
        user_id=data["user_id"],
    )

    session_id = get_session_id_from_cookie(request)
    if session_id and request.state.user and request.state.user.id == data["user_id"]:
        await set_flash_if_exists(
            pool,
            session_id,
            "Email verified. Please set up two-factor authentication.",
            "success",
        )
        return RedirectResponse(url="/setup-totp", status_code=303)

    return RedirectResponse(url="/login", status_code=303)

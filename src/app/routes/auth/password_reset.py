"""Password reset routes — request, validate, and apply."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from psycopg import Error as DatabaseError
from psycopg_pool import PoolTimeout

from config import settings

from ...credentials import LOCAL_EMAIL_MAX_CHARS, LOCAL_PASSWORD_MAX_CHARS, normalize_email
from ...middleware import limiter
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    audit_email_hash,
    audit_user_event,
    build_password_reset_email,
    enqueue_outbound_email_cur,
    generate_reset_token,
    get_db_cursor,
    get_user_by_email,
    hash_token,
    reset_token_email_metadata,
    store_reset_token_hash_cur,
    update_password_with_token,
    validate_reset_token,
    verify_reset_token_hash,
)
from ...services.password_reset import InvalidResetToken
from ...template_setup import templates

logger = logging.getLogger(__name__)

public_router = SecureAPIRouter(access=RouteAccess.PUBLIC)
capability_router = SecureAPIRouter(access=RouteAccess.CAPABILITY)
routers = (public_router, capability_router)


def _reset_error(
    request: Request,
    error: str,
    token: str | None = None,
    email: str | None = None,
    status_code: int = 422,
) -> Response:
    """Render the reset password page with an error message."""
    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {
            "error": error,
            "token": token,
            "email": email,
        },
        status_code=status_code,
    )


@public_router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request) -> Response:
    """Render the reset-request form, or 303-redirect an authenticated user home."""
    if request.state.user:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {
            "error": None,
            "success": None,
        },
    )


@public_router.post("/forgot-password", response_class=HTMLResponse)
@limiter.limit("3/minute;10/hour")
async def forgot_password_submit(
    request: Request,
    email: str = Form(..., max_length=LOCAL_EMAIL_MAX_CHARS),
) -> Response:
    """Queue reset mail for an active local account; render generic success for valid email.

    Invalid email renders 422. DatabaseError, PoolTimeout, and ValueError are
    logged but retain the generic success response. Hash replacement and mail
    commit together; response shape, not timing, conceals account eligibility.
    """
    pool = request.app.state.db_pool

    normalized = normalize_email(email)
    if normalized is None:
        return templates.TemplateResponse(
            request,
            "forgot_password.html",
            {
                "error": "Please enter a valid email address.",
                "success": None,
            },
            status_code=422,
        )

    email = normalized
    try:
        user = await get_user_by_email(pool, email)

        if user and user.auth_method == "local" and user.is_active:
            token = generate_reset_token(user.id, user.email)
            action = reset_token_email_metadata(token)

            reset_url = f"{settings.public_base_url}/reset-password/{token}"
            email_message = build_password_reset_email(
                user.email,
                reset_url,
                expires_at=action.expires_at,
            )

            async with get_db_cursor(pool) as cur:
                await store_reset_token_hash_cur(
                    cur,
                    user.id,
                    action.token_hash,
                    expected_email=user.email,
                )
                await enqueue_outbound_email_cur(
                    cur,
                    user_id=user.id,
                    email=email_message,
                    action=action,
                )

            audit_user_event(
                level=logging.INFO,
                request=request,
                event_type="password_reset_requested",
                user_id=user.id,
            )
            logger.info(
                "Password-reset email durably queued for user %d",
                user.id,
            )
        else:
            audit_user_event(
                level=logging.INFO,
                request=request,
                event_type="password_reset_requested_unknown_email",
                user_id=None,
                email_attempted_hash=audit_email_hash(email),
            )
    except (DatabaseError, PoolTimeout, ValueError):
        # Preserve the generic client-visible response. The shared transaction
        # ensures a failure stores neither the replacement token nor its email.
        logger.exception("Could not process password-reset request")

    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {
            "error": None,
            "success": (
                "If an account with that email address exists, we'll send a "
                "password reset link shortly. Please check your inbox and spam folder."
            ),
        },
    )


@capability_router.get("/reset-password/{token}", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def reset_password_page(request: Request, token: str) -> Response:
    """Render a signed, current reset form; invalid/used/expired capabilities return 422."""
    data = validate_reset_token(token)
    if not data:
        return _reset_error(
            request,
            "This reset link is invalid or has expired. Please request a new one.",
        )

    pool = request.app.state.db_pool
    if not await verify_reset_token_hash(
        pool,
        data["user_id"],
        hash_token(token),
        expected_email=data["email"],
    ):
        return _reset_error(
            request,
            "This reset link is invalid or has expired. Please request a new one.",
        )

    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {
            "error": None,
            "token": token,
            "email": data["email"],
        },
    )


@capability_router.post("/reset-password", response_class=HTMLResponse)
@limiter.limit("5/minute;20/hour")
async def reset_password_submit(
    request: Request,
    token: str = Form(..., max_length=2000),
    password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    password_confirm: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
) -> Response:
    """Consume a valid reset capability, change password, and revoke account sessions.

    Token, confirmation, and password-policy failures render 422; usable tokens
    are retained in password-error forms. Success audits and 303-redirects to
    /login without explicitly clearing browser cookies.
    """
    data = validate_reset_token(token)
    if not data:
        return _reset_error(
            request, "This reset link has already been used. Please request a new one."
        )

    if password != password_confirm:
        return _reset_error(
            request,
            "Passwords do not match.",
            token=token,
            email=data["email"],
            status_code=422,
        )

    pool = request.app.state.db_pool

    try:
        await update_password_with_token(
            pool,
            data["user_id"],
            hash_token(token),
            password,
            expected_email=data["email"],
        )
    except InvalidResetToken as e:
        return _reset_error(request, str(e))
    except ValueError as e:
        return _reset_error(request, str(e), token=token, email=data["email"], status_code=422)

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="password_reset_completed",
        user_id=data["user_id"],
    )
    return RedirectResponse(url="/login", status_code=303)

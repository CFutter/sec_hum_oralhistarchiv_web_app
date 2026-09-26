"""User registration routes."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from psycopg import Error as DatabaseError
from psycopg_pool import AsyncConnectionPool, PoolTimeout

from config import settings

from ...credentials import LOCAL_EMAIL_MAX_CHARS, LOCAL_PASSWORD_MAX_CHARS, normalize_email
from ...middleware import limiter
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    User,
    UserAlreadyExistsError,
    build_duplicate_registration_notice,
    enqueue_outbound_email_cur,
    get_db_cursor,
    get_user_by_email,
    normalize_display_name,
    validate_password_strength,
)
from ...services.registration import queue_verification_email_cur, register_local_user
from ...template_setup import templates

logger = logging.getLogger(__name__)

public_router = SecureAPIRouter(access=RouteAccess.PUBLIC)
open_router = SecureAPIRouter(access=RouteAccess.OPEN_DURING_ENROLLMENT)
routers = (public_router, open_router)


def _registration_pending(request: Request, email: str) -> Response:
    """Render generic registration success with the submitted email and no login session.

    New/duplicate outcomes share this page, not identical timing or mail effects.
    """
    return templates.TemplateResponse(
        request,
        "send_verification.html",
        {
            "success": (
                "Thank you. Please check your inbox and spam folder "
                "for an email with the next steps."
            ),
            "email": email,
        },
        status_code=200,
    )


def _send_verification_success(request: Request, email: str) -> Response:
    """Render the same response whether or not a message was queued."""
    return templates.TemplateResponse(
        request,
        "send_verification.html",
        {
            "success": (
                "If this address belongs to an unverified account, "
                "we'll send a new verification email shortly. "
                "Please check your inbox and spam folder."
            ),
            "email": email,
        },
    )


async def _queue_verification_email(
    pool: AsyncConnectionPool,
    user: User,
) -> None:
    """Atomically replace a verification token and enqueue its email."""
    async with get_db_cursor(pool) as cur:
        await queue_verification_email_cur(cur, user)


def _register_error(
    request: Request,
    error: str,
    email: str = "",
    display_name: str = "",
    affiliation: str = "",
    country: str = "",
    status_code: int = 422,
) -> Response:
    """Render the registration page with an error message and preserved fields."""
    return templates.TemplateResponse(
        request,
        "register.html",
        {
            "error": error,
            "display_name": display_name,
            "email": email,
            "affiliation": affiliation,
            "country": country,
        },
        status_code=status_code,
    )


@public_router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> Response:
    """Render registration; redirect 303 to login if disabled or home if authenticated."""
    if not settings.local_registration_enabled:
        return RedirectResponse(url="/login", status_code=303)

    if request.state.user:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(
        request,
        "register.html",
        {
            "error": None,
        },
    )


@public_router.post("/register", response_class=HTMLResponse)
@limiter.limit("3/minute;10/hour")
async def register_submit(
    request: Request,
    email: str = Form(..., max_length=LOCAL_EMAIL_MAX_CHARS),
    display_name: str = Form(..., max_length=200),
    affiliation: str = Form(default="", max_length=200),
    country: str = Form(default="", max_length=100),
    password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    password_confirm: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
) -> Response:
    """Create an unverified public local account and queue verification mail atomically.

    A duplicate instead queues a notice and renders the same 200 page; neither
    logs in. Invalid fields/passwords render 422, disabled registration redirects
    303 to login, and new-account database errors render 500. Duplicate-notice
    DatabaseError/PoolTimeout/ValueError is logged and suppressed. Middleware
    may still set anonymous/CSRF cookies.
    """
    if not settings.local_registration_enabled:
        return RedirectResponse(url="/login", status_code=303)

    pool = request.app.state.db_pool

    try:
        display_name = normalize_display_name(display_name)
    except ValueError as e:
        return _register_error(
            request,
            error=str(e),
            email=email,
            display_name=display_name,
            affiliation=affiliation,
            country=country,
            status_code=422,
        )

    normalized = normalize_email(email)
    if normalized is None:
        return _register_error(
            request,
            error="Please enter a valid email address.",
            email=email,
            display_name=display_name,
            affiliation=affiliation,
            country=country,
            status_code=422,
        )

    email = normalized
    if password != password_confirm:
        return _register_error(
            request,
            error="Passwords do not match.",
            email=email,
            display_name=display_name,
            affiliation=affiliation,
            country=country,
            status_code=422,
        )

    password_error = validate_password_strength(password, email=email, display_name=display_name)
    if password_error:
        return _register_error(
            request,
            error=password_error,
            email=email,
            display_name=display_name,
            affiliation=affiliation,
            country=country,
            status_code=422,
        )
    try:
        user = await register_local_user(
            pool,
            email=email,
            display_name=display_name,
            password=password,
            affiliation=affiliation,
            country=country,
        )
    except UserAlreadyExistsError:
        duplicate_notice = build_duplicate_registration_notice(email)

        try:
            async with get_db_cursor(pool) as cur:
                await enqueue_outbound_email_cur(
                    cur,
                    user_id=None,
                    email=duplicate_notice,
                    action=None,
                )
        except (DatabaseError, PoolTimeout, ValueError):
            # Keep the response enumeration-neutral even if queuing fails.
            logger.exception("Could not queue duplicate-registration notice")

        return _registration_pending(request, email)
    except ValueError as e:
        return _register_error(
            request,
            error=str(e),
            email=email,
            display_name=display_name,
            affiliation=affiliation,
            country=country,
            status_code=422,
        )
    except (DatabaseError, PoolTimeout):
        logger.exception("Registration database error for %s", email)
        return _register_error(
            request,
            error="Registration failed. Please try again.",
            email=email,
            display_name=display_name,
            affiliation=affiliation,
            country=country,
            status_code=500,
        )

    logger.info(
        "Verification email durably queued for user %d",
        user.id,
    )

    return _registration_pending(request, email)


@open_router.get("/send_verification", response_class=HTMLResponse)
async def send_verification_page(request: Request) -> Response:
    """Render resend form, prefilling email from the query string."""
    email = request.query_params.get("email", "")
    return templates.TemplateResponse(
        request,
        "send_verification.html",
        {
            "email": email,
        },
    )


@open_router.post("/send_verification")
@limiter.limit("3/hour;10/day")
async def send_verification_submit(
    request: Request,
    email: str = Form(..., max_length=LOCAL_EMAIL_MAX_CHARS),
) -> Response:
    """Replace token/mail only for an unverified local user; always render generic success.

    Invalid email and DatabaseError/PoolTimeout/ValueError retain the same
    response; failures are logged. Inactive unverified local users also qualify.
    """
    pool = request.app.state.db_pool

    normalized = normalize_email(email)
    if normalized is None:
        return _send_verification_success(request, email)

    try:
        user = await get_user_by_email(pool, normalized)

        if user and user.auth_method == "local" and not user.email_verified:
            await _queue_verification_email(pool, user)
            logger.info(
                "Verification email durably queued for user %d",
                user.id,
            )
    except (DatabaseError, PoolTimeout, ValueError):
        # Preserve the generic client-visible response. A failed transaction
        # stores neither the replacement token nor its email.
        logger.exception("Could not process verification-email resend")

    return _send_verification_success(request, email)

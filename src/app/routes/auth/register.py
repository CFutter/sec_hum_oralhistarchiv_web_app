"""Email-only local registration and enumeration-neutral capability resend."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from psycopg import Error as DatabaseError
from psycopg_pool import PoolTimeout

from app.service_errors import UserInputRejected, UserStateChanged
from config import settings

from ...credentials import LOCAL_EMAIL_MAX_CHARS, normalize_email
from ...middleware import limiter
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import begin_local_registration, resend_local_registration
from ...template_setup import templates

logger = logging.getLogger(__name__)
public_router = SecureAPIRouter(access=RouteAccess.PUBLIC)
open_router = SecureAPIRouter(access=RouteAccess.OPEN_DURING_ENROLLMENT)
routers = (public_router, open_router)


def _register_form(
    request: Request, *, error: str | None = None, email: str = "", status_code: int = 200
) -> Response:
    """Render the registration email/error form with the requested status."""
    return templates.TemplateResponse(
        request,
        "register.html",
        {"error": error, "email": email, "email_max_chars": LOCAL_EMAIL_MAX_CHARS},
        status_code=status_code,
    )


def _registration_pending(request: Request, email: str) -> Response:
    """Render neutral pending-registration feedback without disclosing account existence."""
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
    )


def _send_verification_success(request: Request, email: str) -> Response:
    """Render neutral resend feedback and the supplied email."""
    return templates.TemplateResponse(
        request,
        "send_verification.html",
        {
            "success": (
                "If this address belongs to an unverified account, "
                "delivery is subject to mail limits. An existing code keeps its "
                "original expiry; please check your inbox and spam folder."
            ),
            "email": email,
        },
    )


@public_router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> Response:
    """Render registration, or redirect 303 to login if disabled and home if signed in."""
    if not settings.local_registration_enabled:
        return RedirectResponse("/login", status_code=303)
    if request.state.user:
        return RedirectResponse("/", status_code=303)
    return _register_form(request)


@public_router.post("/register", response_class=HTMLResponse)
@limiter.limit("3/minute;10/hour")
async def register_submit(
    request: Request, email: str = Form(..., max_length=LOCAL_EMAIL_MAX_CHARS)
) -> Response:
    """Queue bounded mailbox proof and render neutral pending feedback.

    Redirect 303 to login when registration is disabled. Invalid email/preparation
    renders 422; expected storage errors render generic 500. New/duplicate
    addresses share feedback without guaranteed timing equality. No password,
    profile or login work occurs.
    """
    if not settings.local_registration_enabled:
        return RedirectResponse("/login", status_code=303)
    normalized = normalize_email(email)
    if normalized is None:
        return _register_form(
            request, error="Please enter a valid email address.", email=email, status_code=422
        )
    try:
        await begin_local_registration(request.app.state.db_pool, email=normalized)
    except UserInputRejected:
        # Input was already normalized; preserve diagnostics from preparation.
        request_id = getattr(request.state, "request_id", None)
        logger.exception(
            "Registration request preparation failed (request_id=%s)",
            request_id,
            extra={
                "event_type": "registration_preparation_failed",
                "phase": "request",
                "request_id": request_id,
            },
        )
        return _register_form(
            request, error="Please enter a valid email address.", email=email, status_code=422
        )
    except (DatabaseError, PoolTimeout):
        request_id = getattr(request.state, "request_id", None)
        logger.exception(
            "Registration request storage failed (request_id=%s)",
            request_id,
            extra={
                "event_type": "registration_storage_failed",
                "phase": "request",
                "request_id": request_id,
            },
        )
        return _register_form(
            request, error="Registration failed. Please try again.", email=email, status_code=500
        )
    return _registration_pending(request, normalized)


@open_router.get("/send_verification", response_class=HTMLResponse)
async def send_verification_page(request: Request) -> Response:
    """Render resend for existing pending setup, even when new registration closes."""
    return templates.TemplateResponse(
        request,
        "send_verification.html",
        {"email": request.query_params.get("email", "")[:LOCAL_EMAIL_MAX_CHARS]},
    )


@open_router.post("/send_verification")
@limiter.limit("3/hour;10/day")
async def send_verification_submit(
    request: Request, email: str = Form(..., max_length=LOCAL_EMAIL_MAX_CHARS)
) -> Response:
    """Render generic success after resend or expected eligibility/storage errors; log failures."""
    try:
        await resend_local_registration(request.app.state.db_pool, email=email)
    except UserStateChanged:
        # Invalid/ineligible addresses normally return without raising.
        request_id = getattr(request.state, "request_id", None)
        logger.exception(
            "Registration resend preparation failed (request_id=%s)",
            request_id,
            extra={
                "event_type": "registration_preparation_failed",
                "phase": "resend",
                "request_id": request_id,
            },
        )
    except (DatabaseError, PoolTimeout):
        request_id = getattr(request.state, "request_id", None)
        logger.exception(
            "Registration resend storage failed (request_id=%s)",
            request_id,
            extra={
                "event_type": "registration_storage_failed",
                "phase": "resend",
                "request_id": request_id,
            },
        )
    return _send_verification_success(request, email)

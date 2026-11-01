"""Mailbox-bound password/profile setup with CSRF and no automatic login."""

import logging
from secrets import compare_digest
from typing import Literal

from fastapi import Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from psycopg import Error as DatabaseError
from psycopg_pool import PoolTimeout

from app.service_errors import UserInputRejected

from ...action_token_contract import ACTION_PUBLIC_ID_CHARS
from ...credentials import LOCAL_PASSWORD_MAX_CHARS, MIN_PASSWORD_LENGTH
from ...middleware import limiter
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    DISPLAY_NAME_MAX_LENGTH,
    REGISTRATION_AFFILIATION_MAX_CHARS,
    REGISTRATION_COUNTRY_MAX_CHARS,
    REGISTRATION_TOKEN_MAX_CHARS,
    RegistrationSetup,
    action_token_public_id,
    audit_user_event,
    complete_local_registration,
    inspect_local_registration,
    valid_action_public_id,
)
from ...template_setup import templates

logger = logging.getLogger(__name__)
router = SecureAPIRouter(access=RouteAccess.CAPABILITY)
routers = (router,)


def _verify_error(request: Request) -> Response:
    """Audit anonymous verification failure and render the generic invalid-link 400."""
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


def _storage_error(
    request: Request,
    exc: DatabaseError | PoolTimeout,
    *,
    phase: Literal["inspect", "complete"],
) -> Response:
    """Log the exception with request/phase metadata and render generic setup-unavailable 500."""
    request_id = getattr(request.state, "request_id", None)
    logger.error(
        "Registration setup storage failed (phase=%s, request_id=%s)",
        phase,
        request_id,
        exc_info=(type(exc), exc, exc.__traceback__),
        extra={
            "event_type": "registration_storage_failed",
            "phase": phase,
            "request_id": request_id,
        },
    )
    return templates.TemplateResponse(
        request,
        "error.html",
        {"error_title": "Account setup unavailable", "error_message": "Please try again later."},
        status_code=500,
    )


def _setup_form(
    request: Request,
    setup: RegistrationSetup | None,
    token: str | None,
    *,
    error: str | None = None,
    display_name: str = "",
    affiliation: str = "",
    country: str = "",
    status_code: int = 200,
) -> Response:
    """Render setup/profile feedback without passwords; None token uses the path public_id.

    Require a public_id path parameter when token is None; otherwise derive it
    from token. setup=None omits the email.
    """
    return templates.TemplateResponse(
        request,
        "confirm_verify_email.html",
        {
            "token": token,
            "email": setup.email if setup is not None else None,
            "public_id": (
                action_token_public_id(token)
                if token is not None
                else request.path_params["public_id"]
            ),
            "error": error,
            "display_name": display_name,
            "affiliation": affiliation,
            "country": country,
            "display_name_max_chars": DISPLAY_NAME_MAX_LENGTH,
            "affiliation_max_chars": REGISTRATION_AFFILIATION_MAX_CHARS,
            "country_max_chars": REGISTRATION_COUNTRY_MAX_CHARS,
            "password_min_chars": MIN_PASSWORD_LENGTH,
            "password_max_chars": LOCAL_PASSWORD_MAX_CHARS,
        },
        status_code=status_code,
    )


@router.get("/verify-email/{public_id}", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def verify_email_page(request: Request, public_id: str) -> Response:
    """Render unresolved setup fields; raise HTTPException(404) for a malformed public ID."""
    if not valid_action_public_id(public_id):
        raise HTTPException(status_code=404)
    return _setup_form(request, None, None)


@router.post("/verify-email", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def verify_email_submit(
    request: Request,
    public_id: str = Form(..., max_length=ACTION_PUBLIC_ID_CHARS),
    token: str = Form(..., max_length=REGISTRATION_TOKEN_MAX_CHARS),
    display_name: str = Form(..., max_length=DISPLAY_NAME_MAX_LENGTH),
    password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    password_confirm: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    affiliation: str = Form(default="", max_length=REGISTRATION_AFFILIATION_MAX_CHARS),
    country: str = Form(default="", max_length=REGISTRATION_COUNTRY_MAX_CHARS),
) -> Response:
    """Validate mailbox proof before credential feedback, then complete setup without login.

    Success audits after commit and redirects 303 to login. Invalid/expired
    capabilities render 400, profile/password errors 422 and expected storage
    errors generic 500. Keep form/CSRF validation; eligibility is rechecked by
    the service after hashing/lock waits.
    """
    if not valid_action_public_id(public_id) or not compare_digest(
        public_id, action_token_public_id(token)
    ):
        return _verify_error(request)
    pool = request.app.state.db_pool
    try:
        setup = await inspect_local_registration(pool, token)
    except (DatabaseError, PoolTimeout) as exc:
        return _storage_error(request, exc, phase="inspect")
    if setup is None:
        return _verify_error(request)
    error = None
    if password != password_confirm:
        error = "Passwords do not match."
    else:
        try:
            user = await complete_local_registration(
                pool,
                token=token,
                display_name=display_name,
                password=password,
                affiliation=affiliation,
                country=country,
            )
        except UserInputRejected as exc:
            error = str(exc)
        except (DatabaseError, PoolTimeout) as exc:
            return _storage_error(request, exc, phase="complete")
        else:
            if user is None:
                return _verify_error(request)
            audit_user_event(
                level=logging.INFO,
                request=request,
                event_type="email_verified",
                user_id=user.id,
            )
            return RedirectResponse("/login?notice=registration_complete", status_code=303)
    return _setup_form(
        request,
        setup,
        token,
        error=error,
        display_name=display_name,
        affiliation=affiliation,
        country=country,
        status_code=422,
    )

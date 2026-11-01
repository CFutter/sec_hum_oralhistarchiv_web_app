"""Password reset routes — request, validate, and apply."""

import logging
from secrets import compare_digest

from fastapi import Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from psycopg import Error as DatabaseError
from psycopg_pool import PoolTimeout

from app.service_errors import UserInputRejected, UserStateChanged

from ... import get_client_ip
from ...action_token_contract import ACTION_PUBLIC_ID_CHARS, ACTION_TOKEN_MAX_CHARS
from ...credentials import (
    LOCAL_EMAIL_MAX_CHARS,
    LOCAL_PASSWORD_MAX_CHARS,
    TOTP_CODE_RAW_MAX_CHARS,
    normalize_email,
)
from ...middleware import limiter, set_session_cookie
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    TotpDecryptionError,
    action_token_public_id,
    audit_user_event,
    request_password_reset,
    unlock_account_with_token,
    update_password_with_token,
    valid_action_public_id,
    validate_reset_token,
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
    public_id: str | None = None,
) -> Response:
    """Render the reset password page with an error message."""
    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {
            "error": error,
            "token": token,
            "email": email,
            "public_id": public_id,
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

    Invalid email renders 422. Storage errors retain the generic success response.
    The service serializes mail budgets and preserves an existing live capability.
    Responses conceal account eligibility without promising equal elapsed time.
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

    try:
        await request_password_reset(pool, email=normalized)
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="password_reset_requested",
            user_id=None,
        )
    except (DatabaseError, PoolTimeout, UserStateChanged):
        # Preserve the generic client-visible response. The shared transaction
        # ensures a failure stores neither the replacement token nor its email.
        logger.exception("Could not process password-reset request")

    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {
            "error": None,
            "success": (
                "If this address is eligible, recovery email is sent within the delivery "
                "limits. An existing code stays valid for its original 30 minutes. "
                "Please check your inbox and spam folder before requesting another."
            ),
        },
    )


@capability_router.get("/reset-password/{public_id}", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def reset_password_page(request: Request, public_id: str) -> Response:
    """Render unresolved reset fields; raise HTTPException(404) for malformed public IDs."""
    if not valid_action_public_id(public_id):
        raise HTTPException(status_code=404)

    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {
            "error": None,
            "token": None,
            "email": None,
            "public_id": public_id,
        },
    )


@capability_router.post("/reset-password", response_class=HTMLResponse)
@limiter.limit("5/minute;20/hour")
async def reset_password_submit(
    request: Request,
    public_id: str = Form(..., max_length=ACTION_PUBLIC_ID_CHARS),
    token: str = Form(..., max_length=ACTION_TOKEN_MAX_CHARS),
    password: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    password_confirm: str = Form(..., max_length=LOCAL_PASSWORD_MAX_CHARS),
    totp_code: str = Form(..., max_length=TOTP_CODE_RAW_MAX_CHARS),
) -> Response:
    """Consume reset/TOTP proof, change the password and revoke account sessions.

    Token, confirmation, password-policy and credential refusals render 422;
    usable tokens remain in password-error forms. TOTP decryption failure audits
    and renders 503. Success audits and redirects 303 to /login without explicitly
    clearing browser cookies.
    """
    if not valid_action_public_id(public_id) or not compare_digest(
        public_id, action_token_public_id(token)
    ):
        return _reset_error(request, "This reset link is invalid. Please request a new one.")
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
            public_id=public_id,
        )

    pool = request.app.state.db_pool

    try:
        await update_password_with_token(
            pool,
            data["user_id"],
            token,
            password,
            expected_email=data["email"],
            totp_code=totp_code,
        )
    except InvalidResetToken as e:
        return _reset_error(request, str(e))
    except TotpDecryptionError:
        audit_user_event(
            level=logging.ERROR,
            request=request,
            event_type="totp_secret_undecryptable",
            user_id=data["user_id"],
            exc_info=True,
        )
        return _reset_error(
            request,
            "Your authenticator is temporarily unavailable. Please contact support.",
            status_code=503,
        )
    except UserInputRejected as e:
        return _reset_error(
            request, str(e), token=token, email=data["email"], status_code=422, public_id=public_id
        )

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="password_reset_completed",
        user_id=data["user_id"],
    )
    return RedirectResponse(url="/login", status_code=303)


@capability_router.post("/unlock-account", response_class=HTMLResponse)
@limiter.limit("5/minute;20/hour")
async def unlock_account_submit(
    request: Request,
    public_id: str = Form(..., max_length=ACTION_PUBLIC_ID_CHARS),
    token: str = Form(..., max_length=ACTION_TOKEN_MAX_CHARS),
    totp_code: str = Form(..., max_length=TOTP_CODE_RAW_MAX_CHARS),
) -> Response:
    """Consume live mailbox/TOTP proof, clear login lockout and set a full-session cookie.

    Audit success and redirect 303 to /account. Invalid proof/credential refusals
    render 422; TOTP decryption failure renders 503.
    """
    if not valid_action_public_id(public_id) or not compare_digest(
        public_id, action_token_public_id(token)
    ):
        return _reset_error(request, "This recovery link is invalid. Please request a new one.")
    data = validate_reset_token(token)
    if data is None:
        return _reset_error(request, "This recovery link has expired. Please request a new one.")
    try:
        session_id = await unlock_account_with_token(
            request.app.state.db_pool,
            data["user_id"],
            token,
            expected_email=data["email"],
            totp_code=totp_code,
            ip_address=get_client_ip(request),
        )
    except InvalidResetToken as error:
        return _reset_error(request, str(error))
    except TotpDecryptionError:
        return _reset_error(
            request,
            "Your authenticator is temporarily unavailable. Please contact support.",
            status_code=503,
        )
    except UserInputRejected as error:
        return _reset_error(
            request, str(error), token=token, email=data["email"], public_id=public_id
        )
    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="account_unlocked_with_mailbox_proof",
        user_id=data["user_id"],
    )
    response = RedirectResponse(url="/account", status_code=303)
    set_session_cookie(response, session_id)
    return response

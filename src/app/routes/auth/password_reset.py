"""Password reset routes — request, validate, and apply."""

from fastapi import (
    APIRouter,
    BackgroundTasks, 
    Depends, 
    Form, 
    Response, 
    Request
    )
from fastapi.responses import HTMLResponse, RedirectResponse
from email_validator import validate_email, EmailNotValidError

from ...middleware import (
    limiter, 
    verify_csrf, 
    validate_form_content_type
    )
from ...template_setup import templates
from ...services import (
    get_user_by_email, 
    generate_reset_token, 
    validate_reset_token, 
    hash_token, 
    store_reset_token_hash, 
    verify_reset_token_hash, 
    update_password_with_token,
    send_password_reset_email,
    audit_user_event,
    audit_email_hash
    )

from config import settings


router = APIRouter()

def _reset_error(
    request: Request,
    error: str,
    token: str | None = None,
    email: str | None = None,
    status_code: int = 422,
) -> Response:
    """Render the reset password page with an error message."""
    return templates.TemplateResponse(request, "reset_password.html", {
        "error": error,
        "token": token,
        "email": email,
    }, status_code=status_code)


@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request) -> Response:
    """Show the password reset request form."""
    if request.state.user:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(request, "forgot_password.html", {
        "error": None,
        "success": None,
    })


@router.post("/forgot-password", response_class=HTMLResponse, dependencies=[Depends(verify_csrf), Depends(validate_form_content_type)])
@limiter.limit("3/minute;10/hour")
async def forgot_password_submit(
    request: Request,
    background_tasks: BackgroundTasks,
    email: str = Form(..., max_length=200),
) -> Response:
    """Handle password reset request — generate token, send email.
    
    Sends a reset link to the user's email via background task. The 
    actual email send is gated by smtp_enabled — when SMTP is disabled
    (dev mode), send_email logs the body at DEBUG level so developers
    can copy the reset link from logs.
    
    Security: Always shows the same success message regardless of whether
    the email exists — prevents email enumeration.
    """
    pool = request.app.state.db_pool

    try:
        validated = validate_email(email, check_deliverability=False)
        email = validated.normalized.lower()
    except EmailNotValidError:
        return templates.TemplateResponse(request, "forgot_password.html", {
            "error": "Please enter a valid email address.",
            "success": None,
        }, status_code=422)

    user = await get_user_by_email(pool, email)

    if user and user.auth_method == "local" and user.is_active:
        token = generate_reset_token(user.email, user.id)
        await store_reset_token_hash(pool, user.id, hash_token(token))
        reset_url = f"{settings.public_base_url}/reset-password/{token}"

        background_tasks.add_task(send_password_reset_email, user.email, reset_url)
        audit_user_event(
            request,
            "password_reset_requested",
            user_id=user.id,
        )
    else:
        audit_user_event(
            request,
            "password_reset_requested_unknown_email",
            user_id=None,
            email_attempted_hash=audit_email_hash(email)
        )

    return templates.TemplateResponse(request, "forgot_password.html", {
        "error": None,
        "success": (
            "If an account with that email exists, a password reset link "
            "has been sent. Please check your inbox."
        ),
    })


@router.get("/reset-password/{token}", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def reset_password_page(request: Request, token: str) -> Response:
    """Show the new password form if the token is valid and unused."""
    data = validate_reset_token(token)
    if not data:
        return _reset_error(request, "This reset link is invalid or has expired. Please request a new one.")

    pool = request.app.state.db_pool
    if not await verify_reset_token_hash(pool, data["user_id"], hash_token(token)):
        return _reset_error(request, "This reset link is invalid or has expired. Please request a new one.")

    return templates.TemplateResponse(request, "reset_password.html", {
        "error": None,
        "token": token,
        "email": data["email"],
    })


@router.post("/reset-password/{token}", response_class=HTMLResponse, dependencies=[Depends(verify_csrf), Depends(validate_form_content_type)])
@limiter.limit("5/minute;20/hour")
async def reset_password_submit(
    request: Request,
    token: str,
    password: str = Form(..., max_length=200),
    password_confirm: str = Form(..., max_length=200),
) -> Response:
    """Handle new password submission — validate token, update password."""
    data = validate_reset_token(token)
    if not data:
        return _reset_error(request, "This reset link has already been used. Please request a new one.")

    if password != password_confirm:
        return _reset_error(request, "Passwords do not match.", token=token, email=data["email"], status_code=422)

    pool = request.app.state.db_pool

    user = await get_user_by_email(pool, data["email"])
    if not user or not user.is_active or user.auth_method != "local":
        return _reset_error(request, "Unable to reset password for this account.")

    try:
        await update_password_with_token(pool, user.id, hash_token(token), password)
    except ValueError as e:
        return _reset_error(request, str(e), token=token, email=user.email, status_code=422)

    audit_user_event(
        request,
        "password_reset_completed",
        user_id=user.id,
    )
    return RedirectResponse(url="/login", status_code=303)


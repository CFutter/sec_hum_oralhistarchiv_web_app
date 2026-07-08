"""User registration routes."""
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Response, Request 
from fastapi.responses import HTMLResponse, RedirectResponse
from psycopg import Error as DatabaseError
from email_validator import validate_email, EmailNotValidError

from ...middleware import (
    limiter,
    verify_csrf,
    validate_form_content_type, 
    get_client_ip
)
from ...services import (
    UserAlreadyExistsError,
    create_local_user, 
    validate_password_strength,
    send_verification_email,
    send_duplicate_registration_notice,
    generate_verification_token,
    store_verification_token_hash,
    hash_token,
    get_user_by_email,
    normalize_display_name
)

from config import settings
from ...template_setup import templates



logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("audit")
router = APIRouter()

def _registration_pending(request: Request, email: str) -> Response:
    """Generic 'check your inbox' page for registration.

    Rendered identically whether or not the email already existed, with no
    session, no Set-Cookie, and no address echoed back — so the response is
    indistinguishable between a new and a duplicate registration.
    """
    return templates.TemplateResponse(request, "send_verification.html", {
            "success": "Verification email sent",
            "email": email
        }, status_code=200)


def _send_verification_success(request: Request, email: str) -> Response:
    """Render the success page (same response regardless of whether email was sent)."""
    return templates.TemplateResponse(request, "send_verification.html", {
        "success": (
            "If your email is registered and not yet verified, "
            "a new verification email has been sent. "
            "Check your inbox (and spam folder)."
        ),
        "email": email,
    })

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
    return templates.TemplateResponse(request, "register.html", {
        "error": error,
        "display_name": display_name,        
        "email": email,
        "affiliation": affiliation,
        "country": country,
    }, status_code=status_code)


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> Response:
    """Show the registration page (account details only, no TOTP)."""
    if not settings.local_auth_enabled:
        return RedirectResponse(url="/login", status_code=303)

    if request.state.user:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(request, "register.html", {
        "error": None,
    })


@router.post("/register", response_class=HTMLResponse, dependencies=[ Depends(validate_form_content_type), Depends(verify_csrf)])
@limiter.limit("3/minute;10/hour")
async def register_submit(
    request: Request,
    background_tasks: BackgroundTasks,
    email: str = Form(..., max_length=200),
    display_name: str = Form(..., max_length=200),
    affiliation: str = Form(default="", max_length=200),
    country: str = Form(default="", max_length=100),
    password: str = Form(..., max_length=200),
    password_confirm: str = Form(..., max_length=200),
) -> Response:
    """Handle registration — create the account and send the verification email.

    Creates an unverified local account (no TOTP secret yet), stores the
    hashed verification token, queues the verification email, and renders
    the generic "check your inbox" page. No session is created and no
    cookie is set. Duplicate registrations render the identical page (the
    existing address is notified by email instead), so the response never
    reveals whether the email was already registered. TOTP enrollment
    happens after the first login.
    """
    if not settings.local_auth_enabled:
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
            status_code=422
        )

    try:
        validated = validate_email(email, check_deliverability=False)
        email = validated.normalized.lower()
    except EmailNotValidError:
        return _register_error(
            request, 
            error="Please enter a valid email address.", 
            email=email, 
            display_name=display_name, 
            affiliation=affiliation, 
            country=country, 
            status_code=422
            )

    if password != password_confirm:
        return _register_error(
            request, 
            error="Passwords do not match.", 
            email=email, 
            display_name=display_name, 
            affiliation=affiliation, 
            country=country, 
            status_code=422
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
            status_code=422
            )
    try:
        user = await create_local_user(
            pool,
            email=email,
            display_name=display_name,
            password=password,
            totp_secret=None,
            affiliation=affiliation,
            country=country,
        )
    except UserAlreadyExistsError:
        background_tasks.add_task(send_duplicate_registration_notice, email)
        return _registration_pending(request, email)
    except ValueError as e:              
        return _register_error(
            request, error=str(e), email=email, display_name=display_name,
            affiliation=affiliation, country=country, status_code=422,
        )  
    except DatabaseError:
        logger.exception("Registration database error for %s", email)
        return _register_error(
            request, 
            error="Registration failed. Please try again.", 
            email=email, 
            display_name=display_name, 
            affiliation=affiliation, 
            country=country, 
            status_code=500
            )
    
    token = generate_verification_token(user.email, user.id)
    await store_verification_token_hash(pool, user.id, hash_token(token))
    verification_url = f"{settings.public_base_url}/verify-email/{token}"

    background_tasks.add_task(send_verification_email, user.email, verification_url)
    logger.info("Verification email queued for: %s", email)


    return _registration_pending(request, email)


@router.get("/send_verification", response_class=HTMLResponse)
async def send_verification_page(request: Request) -> Response:
    """Show form to request a new verification email."""
    email = request.query_params.get("email", "")
    return templates.TemplateResponse(request, "send_verification.html", {
        "email": email,
    })


@router.post("/send_verification", dependencies=[Depends(validate_form_content_type), Depends(verify_csrf)])
@limiter.limit("3/hour;10/day")
async def send_verification_submit(
    request: Request,
    background_tasks: BackgroundTasks,
    email: str = Form(..., max_length=200),
) -> Response:
    """Send a fresh verification email to an unverified user.
    
    Always returns a generic success message to avoid email enumeration.
    The email is only actually sent if a matching unverified local account
    exists.
    """
    pool = request.app.state.db_pool

    try:
        validated = validate_email(email, check_deliverability=False)
        normalized = validated.normalized.lower()
    except EmailNotValidError:
        return _send_verification_success(request, email)

    user = await get_user_by_email(pool, normalized)
    if user and user.auth_method == "local" and not user.email_verified:
        token = generate_verification_token(user.email, user.id)
        await store_verification_token_hash(pool, user.id, hash_token(token))
        verification_url = f"{settings.public_base_url}/verify-email/{token}"

        background_tasks.add_task(send_verification_email, user.email, verification_url)
        logger.info("Verification email re-queued for: %s", user.email)

        audit_logger.info(
            "verification_email_resent",
            extra={
                "event_type": "verification_email_resent",
                "user_id": user.id,
                "ip": get_client_ip(request),
            },
        )

    return _send_verification_success(request, email)


"""Email verification route."""
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import RedirectResponse, HTMLResponse

from ...services import (
    validate_verification_token,
    confirm_email_verification,
    set_flash,
    hash_token,
    audit_user_event,
    get_user_by_id
)
from ...middleware import (
    get_session_id_from_cookie, 
    limiter
    )
from ...template_setup import templates

router = APIRouter()

def _verify_error(request: Request) -> Response:
    audit_user_event(
        request,
        "email_verification_failed",
        user_id=None,
        reason="invalid_or_expired_token",
    )
    return templates.TemplateResponse(request, "error.html", {
            "error_title": "Invalid verification link",
            "error_message": "This link is invalid or has expired. "
                            "Please register again or contact support.",
        }, status_code=400)

@router.get("/verify-email/{token}", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def verify_email_page(request: Request, token: str)-> Response:
    """Show a confirm page. SAFE — does not consume the token.

    Mirrors confirm_email_page: a GET must be side-effect-free so mail
    gateways / prefetchers can't burn the token before the user clicks.
    """
    data = validate_verification_token(token)
    if not data:
        return _verify_error(request)         
    return templates.TemplateResponse(request, "confirm_verify_email.html", {
        "token": token, "email": data["email"],
    })


@router.post("/verify-email", response_class=HTMLResponse)
@limiter.limit("10/minute;30/hour")
async def verify_email_submit(request: Request, token: str = Form(..., max_length=2000))-> Response:
    """Consume the token and mark the email verified.

    SECURITY — intentionally NOT behind verify_csrf: the link may be clicked
    on a different device with no app session or CSRF cookie. The signed,
    single-use, email-bound token IS the capability; a CSRF attacker has no
    token, and a prefetcher fetches the GET (side-effect-free), not this POST.
    """
    pool = request.app.state.db_pool
    data = validate_verification_token(token)
    if not data:
        return _verify_error(request)

    success = await confirm_email_verification(
        pool, data["user_id"], hash_token(token), data["email"]
    )

    if not success:
        user = await get_user_by_id(pool, data["user_id"])
        already_verified = user is not None and user.email_verified

        if already_verified:
            audit_user_event(
                request, "email_verification_noop_already_verified",
                user_id=data["user_id"],
            )
            return templates.TemplateResponse(request, "error.html", {
                "error_title": "Already verified",
                "error_message": "Your email is already verified — you can log in.",
            }, status_code=200) 

        audit_user_event(
            request, "email_verification_failed",
            user_id=data["user_id"], reason="invalid_or_expired_token",
        )
        return templates.TemplateResponse(request, "error.html", {
            "error_title": "Verification link no longer valid",
            "error_message": "This link is invalid or has expired. Please "
                             "request a new verification email from the login page.",
        }, status_code=400)

    audit_user_event(
        request,
        "email_verified",
        user_id=data["user_id"],
    )

    # If the user has an active session, send them to TOTP setup.
    # Otherwise, send them to login.
    session_id = get_session_id_from_cookie(request)
    if session_id and request.state.user and request.state.user.id == data["user_id"]:
        await set_flash(pool, session_id,
                  "Email verified. Please set up two-factor authentication.",
                  "success")
        return RedirectResponse(url="/setup-totp", status_code=303)

    return RedirectResponse(url="/login", status_code=303)

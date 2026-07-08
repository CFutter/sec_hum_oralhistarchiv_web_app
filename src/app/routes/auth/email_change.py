"""Email-change routes (self-service, local auth only)."""
import logging

from fastapi import (
    APIRouter, 
    Depends, 
    Request, 
    Response, 
    Form,
    BackgroundTasks
)
from fastapi.responses import HTMLResponse, RedirectResponse

from ...middleware import (
    limiter,
    require_login,
    validate_form_content_type, 
    verify_csrf, 
    get_session_id_from_cookie,
    clear_session_cookie
)
from ...services import (
    get_user_by_email,
    verify_current_password,
    set_flash,
    delete_user_sessions,
    generate_email_change_token,
    validate_email_change_token,
    store_pending_email,
    confirm_email_change,
    pending_email_change_matches,
    send_email_change_verification,
    send_email_change_notice,
    hash_token,
    normalize_email,
)
from ...template_setup import templates
from .helpers import require_local_auth

from config import settings

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("audit")
router = APIRouter()

@router.get(
    "/account/change-email",
    response_class=HTMLResponse,
    dependencies=[Depends(require_login), Depends(require_local_auth)],
)
async def change_email_page(request: Request) -> Response:
    """Show the email-change form."""
    return templates.TemplateResponse(request, "change_email.html", {
        "user": request.state.user,
        "error": None,
    })


@router.post(
    "/account/change-email",
    dependencies=[
        Depends(validate_form_content_type),
        Depends(verify_csrf),
        Depends(require_login),
        Depends(require_local_auth),
    ],
)
@limiter.limit("5/minute;20/hour")
async def change_email_submit(
    request: Request,
    background_tasks: BackgroundTasks, 
    new_email: str = Form(..., max_length=200),
    current_password: str = Form(..., max_length=200),
) -> Response:
    """Stage an email change: re-auth, validate, store pending, send link."""
    user = request.state.user
    pool = request.app.state.db_pool

    def _form_error(msg: str, status: int = 422) -> Response:
        return templates.TemplateResponse(request, "change_email.html", {
            "user": user, "error": msg,
        }, status_code=status)
        

    if not await verify_current_password(pool, user.id, current_password):
        audit_logger.info("email_change_blocked_invalid_password", extra={
            "event_type": "email_change_blocked_invalid_password",
            "user_id": user.id,
            "request_id": getattr(request.state, "request_id", "unknown"),
        })
        return _form_error("Current password is incorrect.")

    normalized = normalize_email(new_email)
    if normalized is None:
        return _form_error("Please enter a valid email address.")
    new_email = normalized

    if new_email.lower() == user.email.lower():
        return _form_error("That is already your email address.")
    if await get_user_by_email(pool, new_email) is not None:
        return _form_error("That email address cannot be used.")

    token = generate_email_change_token(user.id, new_email)
    try:
        await store_pending_email(pool, user.id, new_email, hash_token(token))
    except ValueError:
        return _form_error("Something went wrong. Please try again.", status=500)

    confirm_url = f"{settings.public_base_url}/account/confirm-email/{token}"

    background_tasks.add_task(send_email_change_verification, new_email, confirm_url)
    background_tasks.add_task(send_email_change_notice, user.email, new_email)

    audit_logger.info("email_change_requested", extra={
        "event_type": "email_change_requested",
        "user_id": user.id,
        "request_id": getattr(request.state, "request_id", "unknown"),
    })

    session_id = get_session_id_from_cookie(request)
    if session_id:
        await set_flash(
            pool, session_id,
            "Check your new email address for a confirmation link.",
            "success",
        )
    return RedirectResponse(url="/account", status_code=303)


@router.get("/account/confirm-email/{token}", response_class=HTMLResponse)
async def confirm_email_page(request: Request, token: str) -> Response:
    """Show the email-change confirmation page (SAFE — does not consume the token).

    A GET must be side-effect-free: mail scanners and link prefetchers fetch
    this automatically. Consuming the token here would let a scanner complete
    (or break) the change before the user clicks. So this only
    validates the token's signature/expiry and that a matching pending change
    still exists, then renders a form whose POST performs the actual change.
    """
    pool = request.app.state.db_pool

    data = validate_email_change_token(token)
    if not data or not await pending_email_change_matches(pool, data["user_id"], data["new_email"]):
        return templates.TemplateResponse(request, "error.html", {
            "error_title": "Link no longer valid",
            "error_message": "This email-change link is invalid, has expired, "
                             "or has already been used. If you still want to "
                             "change your email, please request it again.",
        }, status_code=400)

    return templates.TemplateResponse(request, "confirm_email.html", {
        "token": token,
        "new_email": data["new_email"],
        "is_admin_initiated": data.get("acting_admin_id") is not None,
    })


@router.post("/account/confirm-email", response_class=HTMLResponse)
async def confirm_email_submit(
    request: Request,
    token: str = Form(..., max_length=2000),
) -> Response:
    """Commit the staged email change (CONSUMES the token).

    SECURITY — intentionally NOT behind verify_csrf: this request can arrive
    from the user's email client with no app session and no CSRF cookie
    (they may click the link on a different device). The signed, single-use,
    email-bound token IS the capability — a CSRF attacker has no token, and a
    prefetch/scanner fetches the GET (which is side-effect-free), not this
    POST. Adding verify_csrf would require an active session and break the
    legitimate cross-device click.
    """
    pool = request.app.state.db_pool

    data = validate_email_change_token(token)
    if not data:
        return templates.TemplateResponse(request, "error.html", {
            "error_title": "Invalid or expired link",
            "error_message": "This email-change link is invalid or has expired. "
                             "Please request the change again.",
        }, status_code=400)

    success = await confirm_email_change(
        pool, data["user_id"], data["new_email"], hash_token(token)
    )

    if not success:
        audit_logger.info("email_change_failed", extra={
            "event_type": "email_change_failed",
            "user_id": data["user_id"],
            "request_id": getattr(request.state, "request_id", "unknown"),
        })
        return templates.TemplateResponse(request, "error.html", {
            "error_title": "Could not change email",
            "error_message": "The change could not be completed. The link may "
                             "have already been used, or the address may now be "
                             "taken. Please try again.",
        }, status_code=400)

    acting_admin_id = data.get("acting_admin_id")
    if acting_admin_id is not None:
        audit_logger.info("admin_email_changed", extra={
            "event_type": "admin_email_changed",
            "actor_admin_id": acting_admin_id,
            "target_user_id": data["user_id"],
            "request_id": getattr(request.state, "request_id", "unknown"),
        })
    else:
        audit_logger.info("email_changed", extra={
            "event_type": "email_changed",
            "user_id": data["user_id"],
            "request_id": getattr(request.state, "request_id", "unknown"),
        })

    await delete_user_sessions(pool, data["user_id"])

    response = RedirectResponse(url="/login?email_changed=1", status_code=303)
    clear_session_cookie(response)
    return response
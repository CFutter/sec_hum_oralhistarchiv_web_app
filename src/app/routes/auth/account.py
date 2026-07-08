"""Account management routes."""
import logging

from fastapi import APIRouter, Depends, Response, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from ...middleware import require_login, verify_csrf, get_session_id_from_cookie, validate_form_content_type
from ...services import update_display_name, set_flash, DISPLAY_NAME_MAX_LENGTH
from ...template_setup import templates
from .helpers import require_local_auth

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("audit")
router = APIRouter()


@router.get("/account", response_class=HTMLResponse, dependencies=[Depends(require_login)])
async def account_page(request: Request) -> Response:
    """Show the user's account page. Redirects to login if not authenticated."""
    user = request.state.user

    return templates.TemplateResponse(request, "account.html", {
        "user": user,
    })


@router.post(
    "/account/change-name",
    dependencies=[
        Depends(validate_form_content_type),
        Depends(require_login),
        Depends(verify_csrf),
        Depends(require_local_auth),
    ],
)
async def change_display_name(
    request: Request,
    display_name: str = Form(..., max_length=DISPLAY_NAME_MAX_LENGTH),
) -> Response:
    """Update the current user's display name (self-service, local auth only)."""
    user = request.state.user
    pool = request.app.state.db_pool
    session_id = get_session_id_from_cookie(request)

    try:
        await update_display_name(pool, user.id, display_name)
    except ValueError as e:
        if session_id:
            await set_flash(pool, session_id, str(e), "error")
        return RedirectResponse(url="/account", status_code=303)

    audit_logger.info(
        "display_name_changed",
        extra={
            "event_type": "display_name_changed",
            "user_id": user.id,
            "request_id": getattr(request.state, "request_id", "unknown"),
        },
    )

    if session_id:
        await set_flash(pool, session_id, "Display name updated.", "success")
    return RedirectResponse(url="/account", status_code=303)
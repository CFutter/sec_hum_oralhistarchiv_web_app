"""Account management routes."""

import logging

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...middleware import get_session_id_from_cookie
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    DISPLAY_NAME_MAX_LENGTH,
    audit_user_event,
    get_admin_promotion,
    set_flash_if_exists,
    update_display_name,
)
from ...template_setup import templates

full_router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)
local_router = SecureAPIRouter(access=RouteAccess.LOCAL_FULL_SESSION)
routers = (full_router, local_router)


@full_router.get("/account", response_class=HTMLResponse)
async def account_page(request: Request) -> Response:
    """Render the full-session account and any local administrator invitation."""
    user = request.state.user
    session_id = request.state.session_id
    promotion = None
    if user.auth_method == "local" and session_id is not None:
        promotion = await get_admin_promotion(
            request.app.state.db_pool,
            user_id=user.id,
            session_id=session_id,
        )

    return templates.TemplateResponse(
        request,
        "account.html",
        {
            "user": user,
            "admin_promotion": promotion,
        },
    )


@local_router.post("/account/change-name")
async def change_display_name(
    request: Request,
    display_name: str = Form(..., max_length=DISPLAY_NAME_MAX_LENGTH),
) -> Response:
    """Update the local name, audit success, and 303-redirect to /account.

    Validation failures also redirect with best-effort error flash; successful
    writes use best-effort success flash, so feedback loss does not undo the edit.
    """
    user = request.state.user
    pool = request.app.state.db_pool
    session_id = get_session_id_from_cookie(request)

    try:
        await update_display_name(pool, user.id, display_name)
    except ValueError as e:
        if session_id:
            await set_flash_if_exists(pool, session_id, str(e), "error")
        return RedirectResponse(url="/account", status_code=303)

    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="display_name_changed",
        user_id=user.id,
    )

    if session_id:
        await set_flash_if_exists(pool, session_id, "Display name updated.", "success")
    return RedirectResponse(url="/account", status_code=303)

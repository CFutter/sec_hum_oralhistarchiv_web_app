"""Admin routes — user management and system overview."""
import logging

from psycopg_pool import AsyncConnectionPool
from fastapi import (
    APIRouter, 
    Depends, 
    Form, 
    Response, 
    Request, 
    BackgroundTasks
)
from fastapi.responses import HTMLResponse, RedirectResponse


from ...middleware import (
    require_admin,
    verify_csrf,
    validate_form_content_type,
    get_session_id_from_cookie,
)
from ...services import (
    AccessTier,
    get_all_users,
    get_user_by_id,
    update_access_tier,
    set_user_active,
    set_user_admin,
    delete_user_sessions,
    set_flash,
    get_user_by_email,
    normalize_email,
    generate_email_change_token,
    store_pending_email,
    send_email_change_verification,
    send_email_change_notice,
    hash_token,
    audit_admin_action,
    audit_email_hash
)

from ...template_setup import templates

from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])

async def _admin_redirect(
    pool: AsyncConnectionPool, 
    session_id: str | None,
    msg: str, 
    category: str = "error"
) -> Response:
    if session_id:                                   
        await set_flash(pool, session_id, msg, category)
    return RedirectResponse(url="/admin", status_code=303)

@router.get("", response_class=HTMLResponse)
async def admin_dashboard(request: Request) -> Response:
    """Show the admin dashboard with user management."""
    pool = request.app.state.db_pool
    users = await get_all_users(pool)
    return templates.TemplateResponse(request, "admin.html", {"users": users})


@router.post(
    "/users/{user_id}/set-active",
    dependencies=[Depends(verify_csrf), Depends(validate_form_content_type)],
)
async def admin_set_active(
    request: Request,
    user_id: int,
    is_active: bool = Form(...),
) -> Response:
    """Activate or deactivate a user account."""
    pool = request.app.state.db_pool
    session_id = get_session_id_from_cookie(request)
    
    user = await get_user_by_id(pool, user_id)

    if not user:
        return await _admin_redirect(pool, session_id, "User not found.")

    if user.id == request.state.user.id and not is_active:
        return await _admin_redirect(pool, session_id, "You cannot deactivate your own account.")
    
    if user.is_active == is_active:
        return await _admin_redirect(pool, session_id, "No change — user already in that state.", "info")
    
    await set_user_active(pool, user_id, is_active)
    if not is_active:
        # Hard revoke: deactivation is a response to misuse, so end any
        # live sessions immediately rather than waiting for them to expire.
        # (Reactivation does not restore them — a re-login is required.)
        await delete_user_sessions(pool, user_id)
    audit_admin_action(
        request,
        "admin_user_active_changed",
        target_user_id=user_id,
        old_value=user.is_active,
        new_value=is_active,
    )

    return await _admin_redirect(pool, session_id, f"User {'activated' if is_active else 'deactivated'}.", "success")


@router.post(
    "/users/{user_id}/set-tier", 
    dependencies=[Depends(verify_csrf), Depends(validate_form_content_type)])
async def admin_set_tier(
    request: Request,
    user_id: int,
    access_tier: AccessTier = Form(...),
) -> Response:
    """Change a user's access tier."""
    pool = request.app.state.db_pool
    session_id = get_session_id_from_cookie(request)
    
    user = await get_user_by_id(pool, user_id)
    if not user:
        return await _admin_redirect(pool, session_id, "User not found.")
    
    if user.access_tier == access_tier:
        return await _admin_redirect(pool, session_id, f"User already has tier '{access_tier}'.", "info")

    old_tier = user.access_tier
    await update_access_tier(pool, user_id, access_tier)
    audit_admin_action(
        request,
        "admin_user_tier_changed",
        target_user_id=user_id,
        old_value=old_tier,
        new_value=access_tier,
    )
    return await _admin_redirect(pool, session_id, f"Tier changed: {old_tier} → {access_tier}.", "success")


@router.post(
    "/users/{user_id}/set-admin",
    dependencies=[Depends(verify_csrf), Depends(validate_form_content_type)],
)
async def admin_set_admin(
    request: Request,
    user_id: int,
    is_admin: bool = Form(...),
) -> Response:
    """Grant or revoke admin privileges."""
    pool = request.app.state.db_pool
    session_id = get_session_id_from_cookie(request)
    
    user = await get_user_by_id(pool, user_id)
    if not user:
        return await _admin_redirect(pool, session_id, "User not found.")
        
    if user.id == request.state.user.id and not is_admin:
        return await _admin_redirect(pool, session_id, "You cannot remove your own admin status.")
    
    if user.is_admin == is_admin:
        return await _admin_redirect(pool, session_id, "No change — user already in that state.", "info")
    
    await set_user_admin(pool, user_id, is_admin)
    audit_admin_action(
        request,
        "admin_user_admin_changed",
        target_user_id=user_id,
        old_value=user.is_admin,
        new_value=is_admin,
    )
    
    return await _admin_redirect(pool, session_id, f"User admin status: {is_admin}.", "success")


@router.post(
    "/users/{user_id}/change-email",
    dependencies=[Depends(verify_csrf), Depends(validate_form_content_type)],
)
async def admin_change_email(
    request: Request,
    background_tasks: BackgroundTasks,
    user_id: int,
    new_email: str = Form(..., max_length=200),
) -> Response:
    """Stage an email change for a user (admin-initiated).

    Admin authority replaces the current-password gate used in the
    self-service flow. The change is staged as pending_email and a
    confirmation link is sent to the NEW address — it commits only when
    the link is clicked (Option A: verification is the safety net against
    a mistyped address). Reuses the self-service confirm route.

    Self-change is permitted: an admin may change their own email here.
    Because the change only commits after the link is clicked, a mistyped
    address simply never commits and the admin stays logged in.
    """
    pool = request.app.state.db_pool
    admin = request.state.user
    session_id = get_session_id_from_cookie(request)

    target = await get_user_by_id(pool, user_id)
    if not target:
        return await _admin_redirect(pool, session_id, "User not found.")

    if target.auth_method != "local":
        return await _admin_redirect(pool, session_id, "Cannot change email for a federated account.")

    normalized = normalize_email(new_email)
    if normalized is None:
        return await _admin_redirect(pool, session_id, "Invalid email address.")
    new_email = normalized

    if new_email.lower() == target.email.lower():
        return await _admin_redirect(pool, session_id, "That is already the user's email.")
    if await get_user_by_email(pool, new_email) is not None:
        return await _admin_redirect(pool, session_id, "That email is already in use.")

    token = generate_email_change_token(target.id, new_email, acting_admin_id=admin.id)
    try:
        await store_pending_email(pool, target.id, new_email, hash_token(token))
    except ValueError:
        return await _admin_redirect(pool, session_id, "Something went wrong. Please try again.")

    confirm_url = f"{settings.public_base_url}/account/confirm-email/{token}"
    background_tasks.add_task(send_email_change_verification, new_email, confirm_url)
    background_tasks.add_task(send_email_change_notice, target.email, new_email)

    old_email_hash = audit_email_hash(target.email)
    new_email_hash = audit_email_hash(new_email)
    audit_admin_action(
        request, "admin_email_change_requested",
        target_user_id=target.id,
        old_value_hash=old_email_hash, new_value_hash=new_email_hash,
    )
    logger.info("Admin %s staged email change for %s → %s",
                admin.id, old_email_hash, new_email_hash)

    return await _admin_redirect(pool, session_id, "Confirmation link sent to the new address.", "success")
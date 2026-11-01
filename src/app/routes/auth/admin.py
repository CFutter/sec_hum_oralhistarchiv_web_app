"""Administrator account-management routes.

Router dependencies enforce admin access and mutation protection; services
recheck current actor/session authority. Mutations preserve dashboard
page/page_size in 303 redirects and store best-effort flash feedback;
unhandled storage failures propagate.
"""

import logging
from typing import Annotated
from urllib.parse import urlencode

from email_validator import EmailNotValidError, validate_email
from fastapi import Form, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from psycopg_pool import AsyncConnectionPool
from pydantic import AfterValidator

from app.service_errors import UserNotFound
from app.sources import AccessTier

from ...credentials import LOCAL_EMAIL_MAX_CHARS, TOTP_CODE_RAW_MAX_CHARS
from ...federation_contract import EMAIL_MAX_LENGTH as FEDERATED_EMAIL_MAX_CHARS
from ...federation_contract import ISSUER_MAX_LENGTH, REVIEW_REVISION_MAX, SUBJECT_MAX_LENGTH
from ...jinja_helpers import url_for_query
from ...middleware import clear_session_cookie, limiter
from ...reason_contracts import require_reason_coverage
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    AdminActionRejected,
    AdminEmailChangeRejected,
    AdminPromotionRejected,
    TotpDecryptionError,
    approve_federated_user,
    audit_admin_action,
    audit_email_hash,
    cancel_admin_promotion,
    get_user_by_email,
    list_admin_promotion_states,
    list_federated_reviews,
    list_users,
    request_admin_promotion,
    set_flash_if_exists,
    set_user_active,
    set_user_admin,
    stage_admin_email_change,
    update_access_tier,
)
from ...services.email_change import AdminEmailChangeReason
from ...services.totp_recover import (
    TOTP_RECOVERY_AUTHORIZATION_MAX_AGE_SECONDS,
    TotpRecoveryRejected,
    TotpRecoveryRejectionReason,
    TotpRecoveryTarget,
    authorize_totp_recovery,
    get_totp_recovery_target,
)
from ...template_setup import templates

logger = logging.getLogger(__name__)

router = SecureAPIRouter(access=RouteAccess.ADMIN, prefix="/admin")
routers = (router,)

_PAGE_SIZE_OPTIONS = (5, 10, 20, 50)
_DEFAULT_PAGE_SIZE = 20
_MAX_PAGE = 10_000
_ADMIN_LOOKUP_EMAIL_MAX_CHARS = max(LOCAL_EMAIL_MAX_CHARS, FEDERATED_EMAIL_MAX_CHARS)

_ADMIN_EMAIL_CHANGE_ERRORS = {
    "invalid_email": "Invalid email address.",
    "user_not_found": "User not found.",
    "federated_account": "Cannot change email for a federated account.",
    "inactive_account": "Activate the account before changing its email.",
    "self_change": "Use Change Email on your account page to change your own email.",
    "same_email": "That is already the user's email.",
    "email_in_use": "That email is already in use.",
}

_TOTP_RECOVERY_ERRORS = {
    "self_recovery": "A different administrator must authorize your recovery.",
    "user_not_found": "User not found.",
    "ineligible_account": ("Recovery is available only for active, verified local accounts."),
    "authenticator_not_configured": (
        "This account has no authenticator to recover. It must use normal setup."
    ),
    "recovery_codes_unavailable": (
        "This account has no unused saved recovery code. Use the controlled "
        "operator recovery procedure."
    ),
    "actor_ineligible": (
        "Recovery authorization requires a local administrator with an authenticator."
    ),
    "actor_session_invalid": "Your session expired. Sign in and start again.",
    "actor_step_up_exhausted": "Your session expired. Sign in and start again.",
    "actor_account_locked": ("Recovery authorization is temporarily unavailable. Try again later."),
    "invalid_admin_totp": (
        "Your administrator authentication code is invalid or was already used. "
        "Wait for the next code and try again."
    ),
}


require_reason_coverage(AdminEmailChangeReason, _ADMIN_EMAIL_CHANGE_ERRORS)
require_reason_coverage(TotpRecoveryRejectionReason, _TOTP_RECOVERY_ERRORS)


def _clamp_page_size(page_size: int) -> int:
    """Coerce a page size to the allowlist; anything else falls back to the default."""
    return page_size if page_size in _PAGE_SIZE_OPTIONS else _DEFAULT_PAGE_SIZE


def _admin_dashboard_url(*, page: int, page_size: int) -> str:
    """Return the canonical dashboard URL for one pagination position."""
    params: dict[str, int] = {}
    if page != 1:
        params["page"] = page
    if (size := _clamp_page_size(page_size)) != _DEFAULT_PAGE_SIZE:
        params["page_size"] = size
    return f"/admin?{urlencode(params)}" if params else "/admin"


async def _admin_redirect(
    pool: AsyncConnectionPool,
    session_id: str | None,
    msg: str,
    category: str = "error",
    *,
    page: int,
    page_size: int,
) -> Response:
    """Store best-effort flash when a token exists; return a 303 dashboard redirect."""
    if session_id:
        await set_flash_if_exists(pool, session_id, msg, category)
    return RedirectResponse(
        url=_admin_dashboard_url(page=page, page_size=page_size),
        status_code=303,
    )


def _normalize_admin_lookup_email(value: str) -> str:
    """Return stripped/lowercase SMTPUTF8-capable email, or empty text for blank input.

    Skip DNS checks; raise ValueError for invalid or over-320-character addresses.
    """
    value = value.strip()
    if not value:
        return ""
    try:
        normalized = validate_email(
            value, check_deliverability=False, allow_smtputf8=True
        ).normalized.lower()
    except EmailNotValidError as exc:
        raise ValueError("Enter a valid email address") from exc
    if len(normalized) > _ADMIN_LOOKUP_EMAIL_MAX_CHARS:
        raise ValueError("Enter a valid email address")
    return normalized


@router.get("", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    page: int = Query(default=1, ge=1, le=_MAX_PAGE),
    page_size: int = Query(default=_DEFAULT_PAGE_SIZE),
    email: Annotated[
        str,
        Query(max_length=_ADMIN_LOOKUP_EMAIL_MAX_CHARS),
        AfterValidator(_normalize_admin_lookup_email),
    ] = "",
) -> Response:
    """Render a bounded user list or one exact-email lookup with account actions.

    page_size accepts 5/10/20/50, otherwise 20. Exact lookups bypass the
    numbered window and use page 1; existing action redirects return to the
    ordinary list. Empty later list pages redirect within the supported window.
    """
    page_size = _clamp_page_size(page_size)
    pool = request.app.state.db_pool
    if email:
        target = await get_user_by_email(pool, email)
        users = [target] if target is not None else []
        total = len(users)
        page = 1
    else:
        users, total = await list_users(pool, page=page, page_size=page_size)

    actual_total_pages = max(1, (total + page_size - 1) // page_size)
    total_pages = min(actual_total_pages, _MAX_PAGE)
    if not users and page > 1:
        # The fallback count may observe new rows after the empty-page query.
        return_page = total_pages if total_pages < page else 1
        return RedirectResponse(url_for_query(request, page=return_page), status_code=303)

    promotion_states = await list_admin_promotion_states(
        pool,
        [user.id for user in users],
    )
    federated_reviews = (
        await list_federated_reviews(pool, user_ids=[user.id for user in users])
        if any(user.auth_method == "shibboleth" for user in users)
        else {}
    )
    response = templates.TemplateResponse(
        request,
        "admin.html",
        {
            "users": users,
            "total_users": total,
            "current_page": page,
            "total_pages": total_pages,
            "page_size": page_size,
            "page_size_options": _PAGE_SIZE_OPTIONS,
            "lookup_email": email,
            "email_max_chars": _ADMIN_LOOKUP_EMAIL_MAX_CHARS,
            "window_limited": actual_total_pages > _MAX_PAGE,
            "max_numbered_pages": _MAX_PAGE,
            "admin_promotion_states": promotion_states,
            "federated_reviews": federated_reviews,
        },
    )
    return _no_store(response)


def _no_store(response: Response) -> Response:
    """Keep responses uncached and limit referrers to the origin."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "strict-origin"
    return response


def _totp_recovery_target_error(
    target: TotpRecoveryTarget | None,
    *,
    actor_id: int,
) -> str | None:
    """Return target/self-recovery error text, or None for an eligible snapshot."""
    if target is None:
        return _TOTP_RECOVERY_ERRORS["user_not_found"]
    if target.user_id == actor_id:
        return _TOTP_RECOVERY_ERRORS["self_recovery"]
    if not target.eligible:
        if not target.recovery_codes_available:
            return _TOTP_RECOVERY_ERRORS["recovery_codes_unavailable"]
        if (
            target.auth_method == "local"
            and target.is_active
            and target.email_verified
            and not target.totp_configured
            and not target.recovery_required
        ):
            return _TOTP_RECOVERY_ERRORS["authenticator_not_configured"]
        return _TOTP_RECOVERY_ERRORS["ineligible_account"]
    return None


def _render_totp_recovery_form(
    request: Request,
    target: TotpRecoveryTarget,
    *,
    page: int,
    page_size: int,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    """Render the recovery form with normalized pagination and no-store headers."""
    response = templates.TemplateResponse(
        request,
        "admin_totp_recovery.html",
        {
            "target": target,
            "error": error,
            "current_page": page,
            "page_size": _clamp_page_size(page_size),
            "recovery_authorization_lifetime_minutes": (
                TOTP_RECOVERY_AUTHORIZATION_MAX_AGE_SECONDS // 60
            ),
            "admin_return_url": _admin_dashboard_url(
                page=page,
                page_size=page_size,
            ),
        },
        status_code=status_code,
    )
    return _no_store(response)


@router.get(
    "/users/{user_id}/totp-recovery",
    response_class=HTMLResponse,
)
@limiter.limit("10/minute;30/hour")
async def admin_totp_recovery_page(
    request: Request,
    user_id: int,
    page: int = Query(default=1, ge=1, le=_MAX_PAGE),
    page_size: int = Query(default=_DEFAULT_PAGE_SIZE),
) -> Response:
    """Render recovery confirmation for an eligible target/local actor.

    Rejected snapshots redirect to the dashboard with error flash; no recovery
    state changes, but flash storage may write to the session.
    """
    pool = request.app.state.db_pool
    session_id = request.state.session_id
    actor = request.state.user
    page_size = _clamp_page_size(page_size)

    if actor.auth_method != "local" or not actor.totp_configured:
        return await _admin_redirect(
            pool,
            session_id,
            _TOTP_RECOVERY_ERRORS["actor_ineligible"],
            page=page,
            page_size=page_size,
        )

    target = await get_totp_recovery_target(pool, user_id)
    if error := _totp_recovery_target_error(target, actor_id=actor.id):
        return await _admin_redirect(
            pool,
            session_id,
            error,
            page=page,
            page_size=page_size,
        )
    if target is None:  # narrowed by _totp_recovery_target_error
        raise RuntimeError("TOTP recovery target unexpectedly missing")

    return _render_totp_recovery_form(
        request,
        target,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/users/{user_id}/totp-recovery",
    response_class=HTMLResponse,
)
@limiter.limit("3/minute;10/hour")
async def admin_authorize_totp_recovery(
    request: Request,
    user_id: int,
    admin_totp_code: str = Form(..., max_length=TOTP_CODE_RAW_MAX_CHARS),
    confirm_reset: bool = Form(default=False),
    page: int = Form(default=1, ge=1, le=_MAX_PAGE),
    page_size: int = Form(default=_DEFAULT_PAGE_SIZE),
) -> Response:
    """Authorize recovery with confirm_reset and fresh administrator TOTP.

    No target plaintext code is produced. Missing consent/proof/target-policy
    refusals render 422; unreadable administrator TOTP renders 503. Invalid/
    exhausted authority clears cookies and redirects to login; preliminary
    ineligible/missing targets and account lockout redirect with dashboard flash.
    Success audits after reset/revocation commit and redirects 303 to dashboard.
    """
    pool = request.app.state.db_pool
    actor = request.state.user
    session_id = request.state.session_id
    page_size = _clamp_page_size(page_size)
    if session_id is None:
        raise RuntimeError("Admin route reached without a session ID")

    target = await get_totp_recovery_target(pool, user_id)
    if error := _totp_recovery_target_error(target, actor_id=actor.id):
        return await _admin_redirect(
            pool,
            session_id,
            error,
            page=page,
            page_size=page_size,
        )
    if target is None:  # narrowed by _totp_recovery_target_error
        raise RuntimeError("TOTP recovery target unexpectedly missing")

    if not confirm_reset:
        return _render_totp_recovery_form(
            request,
            target,
            page=page,
            page_size=page_size,
            error=(
                "Confirm that you understand this will immediately reset "
                "the account's authenticator."
            ),
            status_code=422,
        )

    try:
        authorization = await authorize_totp_recovery(
            pool,
            actor_id=actor.id,
            actor_session_id=session_id,
            target_user_id=user_id,
            admin_totp_code=admin_totp_code,
        )
    except AdminActionRejected:
        # Do not perform another privileged read after authority was revoked.
        audit_admin_action(
            level=logging.WARNING,
            request=request,
            event_type="admin_totp_recovery_authority_changed",
            target_user_id=user_id,
            reason="authority_or_session_changed",
        )
        response = RedirectResponse(url="/login?error=session_expired", status_code=303)
        clear_session_cookie(response)
        return response
    except TotpRecoveryRejected as exc:
        audit_admin_action(
            level=logging.WARNING,
            request=request,
            event_type="admin_totp_recovery_blocked",
            target_user_id=user_id,
            reason=exc.reason,
        )
        if exc.reason in {"actor_session_invalid", "actor_step_up_exhausted"}:
            response = RedirectResponse(url="/login?error=session_expired", status_code=303)
            clear_session_cookie(response)
            return response
        if exc.reason == "actor_account_locked":
            return await _admin_redirect(
                pool,
                session_id,
                _TOTP_RECOVERY_ERRORS[exc.reason],
                page=page,
                page_size=page_size,
            )
        latest_target = await get_totp_recovery_target(pool, user_id)
        if latest_target is None:
            return await _admin_redirect(
                pool,
                session_id,
                _TOTP_RECOVERY_ERRORS["user_not_found"],
                page=page,
                page_size=page_size,
            )
        return _render_totp_recovery_form(
            request,
            latest_target,
            page=page,
            page_size=page_size,
            error=_TOTP_RECOVERY_ERRORS[exc.reason],
            status_code=422,
        )
    except TotpDecryptionError:
        logger.exception(
            "Administrator TOTP could not be verified for recovery authorization",
            extra={
                "event_type": "admin_totp_recovery_credential_fault",
                "actor_admin_id": actor.id,
                "target_user_id": user_id,
            },
        )
        return _render_totp_recovery_form(
            request,
            target,
            page=page,
            page_size=page_size,
            error=(
                "Your administrator authenticator cannot be verified right now. "
                "Use the controlled operator recovery procedure."
            ),
            status_code=503,
        )

    audit_admin_action(
        level=logging.WARNING,
        request=request,
        event_type="admin_totp_recovery_authorized",
        target_user_id=authorization.target_user_id,
        reissued=authorization.reissued,
        expires_at=authorization.expires_at.isoformat(),
    )

    return await _admin_redirect(
        pool,
        session_id,
        (
            "Authenticator recovery authorized. The account owner must use "
            "their password and one saved recovery code before the authorization expires."
        ),
        "success",
        page=page,
        page_size=page_size,
    )


@router.post("/users/{user_id}/approve-federated")
@limiter.limit("5/minute;20/hour")
async def admin_approve_federated(
    request: Request,
    user_id: int,
    expected_issuer: str = Form(..., max_length=ISSUER_MAX_LENGTH),
    expected_subject_id: str = Form(..., max_length=SUBJECT_MAX_LENGTH),
    expected_review_revision: int = Form(..., ge=1, le=REVIEW_REVISION_MAX),
    access_tier: AccessTier = Form(...),
    page: int = Form(default=1, ge=1, le=_MAX_PAGE),
    page_size: int = Form(default=_DEFAULT_PAGE_SIZE),
) -> Response:
    """Approve the exact identity and proposal revision through approve_federated_user.

    Audit success and redirect with feedback; policy or missing-target errors
    also redirect without approval.
    """
    pool = request.app.state.db_pool
    session_id = request.state.session_id

    try:
        approved = await approve_federated_user(
            pool,
            user_id,
            expected_issuer=expected_issuer,
            expected_subject_id=expected_subject_id,
            expected_review_revision=expected_review_revision,
            access_tier=access_tier,
            actor_id=request.state.user.id,
            actor_session_id=session_id,
        )
    except AdminActionRejected as exc:
        return await _admin_redirect(
            pool,
            session_id,
            str(exc),
            page=page,
            page_size=page_size,
        )
    except UserNotFound:
        return await _admin_redirect(
            pool,
            session_id,
            "User not found.",
            page=page,
            page_size=page_size,
        )

    audit_admin_action(
        level=logging.INFO,
        request=request,
        event_type="admin_federated_user_approved",
        target_user_id=approved.user.id,
        old_value="pending",
        new_value="approved",
        access_tier=approved.user.access_tier,
        proposed_tier=approved.proposed_tier,
        proposed_rule=approved.proposed_rule,
    )
    return await _admin_redirect(
        pool,
        session_id,
        f"Federated identity approved at tier '{approved.user.access_tier}'.",
        "success",
        page=page,
        page_size=page_size,
    )


@router.post("/users/{user_id}/set-active")
async def admin_set_active(
    request: Request,
    user_id: int,
    is_active: bool = Form(...),
    page: int = Form(default=1, ge=1, le=_MAX_PAGE),
    page_size: int = Form(default=_DEFAULT_PAGE_SIZE),
) -> Response:
    """Apply set_user_active and redirect with feedback, including guarded rejections.

    Repeated activation unlocks and advances revision; repeated deactivation
    revokes sessions again. Audit distinguishes those cases from state changes.
    """
    pool = request.app.state.db_pool
    session_id = request.state.session_id

    if user_id == request.state.user.id and not is_active:
        return await _admin_redirect(
            pool,
            session_id,
            "You cannot deactivate your own account.",
            page=page,
            page_size=page_size,
        )

    try:
        result = await set_user_active(
            pool,
            user_id,
            is_active,
            actor_id=request.state.user.id,
            actor_session_id=session_id,
        )
    except AdminActionRejected as exc:
        return await _admin_redirect(
            pool,
            session_id,
            str(exc),
            page=page,
            page_size=page_size,
        )
    except UserNotFound:
        return await _admin_redirect(
            pool, session_id, "User not found.", page=page, page_size=page_size
        )

    if result.old_value == result.new_value:
        if not result.new_value:
            audit_admin_action(
                level=logging.INFO,
                request=request,
                event_type="admin_user_sessions_revoked",
                target_user_id=user_id,
                reason="already_inactive",
            )
            return await _admin_redirect(
                pool,
                session_id,
                "User remains inactive. All sessions revoked.",
                "success",
                page=page,
                page_size=page_size,
            )
        audit_admin_action(
            level=logging.INFO,
            request=request,
            event_type="admin_user_unlocked",
            target_user_id=user_id,
            lock_cleared=result.lock_cleared,
            authentication_state_invalidated=True,
        )
        return await _admin_redirect(
            pool,
            session_id,
            "Account recovery completed. Pending email changes must be requested again.",
            "success",
            page=page,
            page_size=page_size,
        )

    audit_admin_action(
        level=logging.INFO,
        request=request,
        event_type="admin_user_active_changed",
        target_user_id=user_id,
        old_value=result.old_value,
        new_value=result.new_value,
        lock_cleared=result.lock_cleared,
    )
    return await _admin_redirect(
        pool,
        session_id,
        f"User {'activated' if is_active else 'deactivated'}.",
        "success",
        page=page,
        page_size=page_size,
    )


@router.post("/users/{user_id}/set-tier")
async def admin_set_tier(
    request: Request,
    user_id: int,
    access_tier: AccessTier = Form(...),
    page: int = Form(default=1, ge=1, le=_MAX_PAGE),
    page_size: int = Form(default=_DEFAULT_PAGE_SIZE),
) -> Response:
    """Commit update_access_tier and redirect with feedback; audit actual tier changes."""
    pool = request.app.state.db_pool
    session_id = request.state.session_id

    try:
        old_value, new_value = await update_access_tier(
            pool,
            user_id,
            access_tier,
            actor_id=request.state.user.id,
            actor_session_id=session_id,
        )
    except AdminActionRejected as exc:
        return await _admin_redirect(
            pool,
            session_id,
            str(exc),
            page=page,
            page_size=page_size,
        )
    except UserNotFound:
        return await _admin_redirect(
            pool, session_id, "User not found.", page=page, page_size=page_size
        )

    if old_value == new_value:
        return await _admin_redirect(
            pool,
            session_id,
            f"User already has tier '{access_tier}'.",
            "info",
            page=page,
            page_size=page_size,
        )

    audit_admin_action(
        level=logging.INFO,
        request=request,
        event_type="admin_user_tier_changed",
        target_user_id=user_id,
        old_value=old_value,
        new_value=new_value,
    )
    return await _admin_redirect(
        pool,
        session_id,
        f"Tier changed: {old_value} → {new_value}.",
        "success",
        page=page,
        page_size=page_size,
    )


@router.post("/users/{user_id}/set-admin")
async def admin_set_admin(
    request: Request,
    user_id: int,
    is_admin: bool = Form(...),
    page: int = Form(default=1, ge=1, le=_MAX_PAGE),
    page_size: int = Form(default=_DEFAULT_PAGE_SIZE),
) -> Response:
    """Invite/reissue when is_admin is true; otherwise demote through guarded services.

    Self-demotion and expected service rejections redirect with feedback. Audit
    invitations and actual demotions; an invitation alone grants no authority.
    """
    pool = request.app.state.db_pool
    session_id = request.state.session_id

    if user_id == request.state.user.id and not is_admin:
        return await _admin_redirect(
            pool,
            session_id,
            "You cannot remove your own admin status.",
            page=page,
            page_size=page_size,
        )

    if is_admin:
        try:
            invitation = await request_admin_promotion(
                pool,
                actor_id=request.state.user.id,
                actor_session_id=session_id,
                target_user_id=user_id,
            )
        except (AdminActionRejected, AdminPromotionRejected) as exc:
            message = (
                str(exc)
                if isinstance(exc, AdminActionRejected)
                else {
                    "user_not_found": "User not found.",
                    "already_admin": "The user is already an administrator.",
                    "ineligible_account": (
                        "Only an active, verified local account with TOTP can be invited."
                    ),
                }.get(exc.reason, "The administrator invitation could not be created.")
            )
            return await _admin_redirect(
                pool,
                session_id,
                message,
                page=page,
                page_size=page_size,
            )

        audit_admin_action(
            level=logging.WARNING,
            request=request,
            event_type="admin_promotion_requested",
            target_user_id=invitation.user_id,
            reissued=invitation.reissued,
            expires_at=invitation.expires_at.isoformat(),
        )
        return await _admin_redirect(
            pool,
            session_id,
            (
                "Administrator invitation reissued."
                if invitation.reissued
                else "Administrator invitation created."
            ),
            "success",
            page=page,
            page_size=page_size,
        )

    try:
        old_value, new_value = await set_user_admin(
            pool,
            user_id,
            False,
            actor_id=request.state.user.id,
            actor_session_id=session_id,
        )
    except AdminActionRejected as exc:
        return await _admin_redirect(
            pool,
            session_id,
            str(exc),
            page=page,
            page_size=page_size,
        )
    except UserNotFound:
        return await _admin_redirect(
            pool, session_id, "User not found.", page=page, page_size=page_size
        )

    if old_value == new_value:
        return await _admin_redirect(
            pool,
            session_id,
            "No change — user already in that state.",
            "info",
            page=page,
            page_size=page_size,
        )

    audit_admin_action(
        level=logging.INFO,
        request=request,
        event_type="admin_user_admin_revoked",
        target_user_id=user_id,
        old_value=old_value,
        new_value=new_value,
    )
    return await _admin_redirect(
        pool,
        session_id,
        "Administrator access revoked.",
        "success",
        page=page,
        page_size=page_size,
    )


@router.post("/users/{user_id}/cancel-admin-promotion")
async def admin_cancel_admin_promotion(
    request: Request,
    user_id: int,
    page: int = Form(default=1, ge=1, le=_MAX_PAGE),
    page_size: int = Form(default=_DEFAULT_PAGE_SIZE),
) -> Response:
    """Cancel invitation/staged codes; redirect with feedback and audit actual cancellation."""
    pool = request.app.state.db_pool
    session_id = request.state.session_id
    try:
        cancelled = await cancel_admin_promotion(
            pool,
            actor_id=request.state.user.id,
            actor_session_id=session_id,
            target_user_id=user_id,
        )
    except AdminActionRejected as exc:
        return await _admin_redirect(
            pool,
            session_id,
            str(exc),
            page=page,
            page_size=page_size,
        )
    except AdminPromotionRejected:
        return await _admin_redirect(
            pool,
            session_id,
            "User not found.",
            page=page,
            page_size=page_size,
        )

    if cancelled:
        audit_admin_action(
            level=logging.INFO,
            request=request,
            event_type="admin_promotion_cancelled",
            target_user_id=user_id,
        )
    return await _admin_redirect(
        pool,
        session_id,
        "Administrator invitation cancelled." if cancelled else "No invitation was pending.",
        "success" if cancelled else "info",
        page=page,
        page_size=page_size,
    )


@router.post("/users/{user_id}/change-email")
async def admin_change_email(
    request: Request,
    user_id: int,
    new_email: str = Form(..., max_length=LOCAL_EMAIL_MAX_CHARS),
    page: int = Form(default=1, ge=1, le=_MAX_PAGE),
    page_size: int = Form(default=_DEFAULT_PAGE_SIZE),
) -> Response:
    """Stage an active local target's email change using current administrator authority.

    Self-change requires the separate password/TOTP-protected account flow.
    Queue confirmation to the new address and notice to the old one; only the
    confirmation POST changes email.
    Audit address hashes and redirect with feedback; expected actor/target
    rejections also redirect. A mistyped address is not proof of ownership.
    """
    pool = request.app.state.db_pool
    admin = request.state.user
    session_id = request.state.session_id

    try:
        result = await stage_admin_email_change(
            pool,
            actor_id=admin.id,
            actor_session_id=session_id,
            target_user_id=user_id,
            new_email=new_email,
        )
    except AdminActionRejected as exc:
        return await _admin_redirect(
            pool,
            session_id,
            str(exc),
            page=page,
            page_size=page_size,
        )
    except AdminEmailChangeRejected as exc:
        return await _admin_redirect(
            pool,
            session_id,
            _ADMIN_EMAIL_CHANGE_ERRORS[exc.reason],
            page=page,
            page_size=page_size,
        )

    old_email_hash = audit_email_hash(result.old_email)
    new_email_hash = audit_email_hash(result.new_email)
    audit_admin_action(
        level=logging.INFO,
        request=request,
        event_type="admin_email_change_requested",
        target_user_id=result.target_user_id,
        old_value_hash=old_email_hash,
        new_value_hash=new_email_hash,
    )
    logger.info(
        "Admin %s staged email change for %s → %s",
        admin.id,
        old_email_hash,
        new_email_hash,
    )

    return await _admin_redirect(
        pool,
        session_id,
        "A confirmation email will be sent shortly to the new address.",
        "success",
        page=page,
        page_size=page_size,
    )

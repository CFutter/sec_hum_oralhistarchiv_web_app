"""Administrator dataset controls without a metadata-access bypass."""

from fastapi import Form, HTTPException, Path, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from app.source_contract import SOURCE_NAME_MAX_CHARS, SOURCE_NAME_OPTIONAL_PATTERN
from app.sources import AccessTier, SourceMetadata

from ...jinja_helpers import path_for
from ...reason_contracts import require_reason_coverage
from ...request_utils import get_client_ip
from ...route_security import RouteAccess, SecureAPIRouter
from ...services import (
    ADMIN_DATASET_MAX_ID,
    ADMIN_DATASET_PAGE_SIZE,
    ADMIN_DATASET_UUID_MAX_CHARS,
    AdminActionRejected,
    DatasetAdminAction,
    DatasetAdminContext,
    DatasetAdminRejected,
    change_dataset_admin_state,
    get_admin_dataset_by_id,
    search_admin_datasets,
)
from ...services.dataset_admin import DatasetAdminReason
from ...template_setup import templates

router = SecureAPIRouter(access=RouteAccess.ADMIN, prefix="/admin/datasets")
routers = (router,)

_REJECTIONS = {
    "invalid_action": (422, "Choose a supported dataset action."),
    "invalid_tier": (422, "Choose a supported tier for this action."),
    "dataset_not_found": (404, "Dataset not found in the current catalogue."),
    "source_unavailable": (409, "Raising the tier requires a currently selected source policy."),
    "source_configuration": (409, "The selected source policy is ambiguous. Contact the operator."),
    "tier_below_floor": (409, "The requested tier is below the current minimum. Reload and retry."),
    "invalid_source_tier": (409, "The source record needs a valid classification before raising."),
}
_NOTICES = {
    "tier_raised": "The durable visibility floor was saved.",
    "hidden": "Dataset hidden from every catalogue viewer.",
    "restored": (
        "Administrator hiding removed with its visibility floor preserved. "
        "Any pending upstream correction still prevents publication."
    ),
    "unchanged": "No change was needed.",
}


require_reason_coverage(DatasetAdminReason, _REJECTIONS)


def _error(request: Request, status_code: int, message: str) -> Response:
    """Render a dataset-administration error with the supplied message/status."""
    return templates.TemplateResponse(
        request,
        "error.html",
        {"error_title": "Dataset administration", "error_message": message},
        status_code=status_code,
    )


@router.get("", response_class=HTMLResponse)
async def admin_datasets(
    request: Request,
    uuid: str = Query(default="", max_length=ADMIN_DATASET_UUID_MAX_CHARS, pattern=r"^[^\x00]*$"),
    source: str = Query(
        default="", max_length=SOURCE_NAME_MAX_CHARS, pattern=SOURCE_NAME_OPTIONAL_PATTERN
    ),
    after_id: int | None = Query(default=None, ge=1, le=ADMIN_DATASET_MAX_ID),
    before_id: int | None = Query(default=None, ge=1, le=ADMIN_DATASET_MAX_ID),
) -> Response:
    """List catalogue identities, including hidden/unselected sources, with ID pagination.

    An empty uuid/source leaves that filter unset. after_id/before_id are
    exclusive directions; supplying both raises HTTPException(422). No protected
    metadata-access bypass is granted.
    """
    if after_id is not None and before_id is not None:
        raise HTTPException(status_code=422, detail="Choose one pagination direction")
    selected: tuple[SourceMetadata, ...] = request.app.state.configured_sources
    result = await search_admin_datasets(
        request.app.state.db_pool,
        uuid=uuid,
        source=source,
        after_id=after_id,
        before_id=before_id,
        page_size=ADMIN_DATASET_PAGE_SIZE,
        configured_sources=selected,
    )
    return templates.TemplateResponse(
        request,
        "admin_datasets.html",
        {
            "records": result.records,
            "page_size": ADMIN_DATASET_PAGE_SIZE,
            "newer_id": result.newer_id,
            "older_id": result.older_id,
            "source": source,
            "uuid": uuid,
            "source_labels": {item.name: item.display.label for item in selected},
            "uuid_max_chars": ADMIN_DATASET_UUID_MAX_CHARS,
        },
    )


@router.get("/{dataset_id}", response_class=HTMLResponse)
async def admin_dataset_detail(
    request: Request,
    dataset_id: int = Path(gt=0),
    notice: str = Query(default="", max_length=32),
) -> Response:
    """Render identity/state and a nonhidden public title; return 404 if absent.

    Only allowlisted notice text is shown; protected metadata is omitted.
    """
    selected: tuple[SourceMetadata, ...] = request.app.state.configured_sources
    record = await get_admin_dataset_by_id(
        request.app.state.db_pool, dataset_id, configured_sources=selected
    )
    if record is None:
        return _error(request, *_REJECTIONS["dataset_not_found"])
    label = next(
        (item.display.label for item in selected if item.name == record.source), record.source
    )
    blocked = _REJECTIONS[record.raise_block_reason][1] if record.raise_block_reason else None
    return templates.TemplateResponse(
        request,
        "admin_dataset_detail.html",
        {
            "record": record,
            "source_label": label,
            "raise_blocked": blocked,
            "notice": _NOTICES.get(notice),
        },
    )


@router.post("/{dataset_id}/state")
async def admin_dataset_state(
    request: Request,
    dataset_id: int = Path(gt=0),
    action: DatasetAdminAction = Form(...),
    new_tier: AccessTier | None = Form(default=None),
) -> Response:
    """Apply raise_tier/hide/restore through the auditing transaction service.

    new_tier applies to raise_tier. Return a 303 to detail with a result notice;
    changed admin authority renders 403 and dataset refusals render their
    allowlisted 422/404/409 response.
    """
    selected: tuple[SourceMetadata, ...] = request.app.state.configured_sources
    try:
        change = await change_dataset_admin_state(
            request.app.state.db_pool,
            dataset_id,
            action,
            context=DatasetAdminContext(
                actor_id=request.state.user.id,
                actor_session_id=request.state.session_id,
                request_id=getattr(request.state, "request_id", None),
                client_ip=get_client_ip(request),
            ),
            new_tier=new_tier,
            configured_sources=selected,
        )
    except AdminActionRejected:
        return _error(request, 403, "Your administrator authority changed. Sign in again.")
    except DatasetAdminRejected as exc:
        return _error(request, *_REJECTIONS[exc.reason])
    notice = {"raise_tier": "tier_raised", "hide": "hidden", "restore": "restored"}[action]
    if not change.changed:
        notice = "unchanged"
    destination = path_for(request, "admin_dataset_detail", dataset_id=dataset_id)
    return RedirectResponse(f"{destination}?notice={notice}", status_code=303)

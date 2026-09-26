"""Page routes — home, search, detail, about."""

import logging
import math

from fastapi import Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from config import settings

from ..jinja_helpers import url_for_query
from ..route_security import RouteAccess, SecureAPIRouter
from ..services import (
    AccessTier,
    User,
    audit_user_event,
    can_view_full,
    get_dataset_by_id,
    get_facets,
    get_recent_datasets,
    search_datasets,
)
from ..services.datasets import get_home_metadata_counts
from ..services.parsed_record import FACET_LABEL_MAX_CHARS
from ..template_setup import templates

MAX_SEARCH_PAGE = 10000

router = SecureAPIRouter(access=RouteAccess.PUBLIC)


def _get_user_tier(request: Request) -> AccessTier:
    """Extract the user's access tier, defaulting to 'public' for guests."""
    user: User | None = request.state.user
    if user:
        return user.access_tier
    return "public"


@router.get("/")
async def home(request: Request) -> Response:
    """Render cached global totals, tier-scoped language/keyword counts, and recent records."""
    pool = request.app.state.db_pool
    catalogue_stats_cache = request.app.state.catalogue_stats_cache
    user_tier = _get_user_tier(request)

    recent = await get_recent_datasets(pool, user_tier)
    total_languages, total_keywords = await get_home_metadata_counts(pool, user_tier)
    global_stats = await catalogue_stats_cache.get_global_stats()

    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "total_datasets": global_stats.total_datasets,
            "total_languages": total_languages,
            "total_keywords": total_keywords,
            "recent": recent,
            "last_full_rebuild": global_stats.last_full_rebuild,
            "user_tier": user_tier,
        },
    )


@router.get("/search", response_class=HTMLResponse)
async def search_page(
    request: Request,
    query: str = Query(default="", alias="q", max_length=200, description="Free-text search"),
    keyword: str = Query("", max_length=FACET_LABEL_MAX_CHARS),
    language: str = Query("", max_length=FACET_LABEL_MAX_CHARS),
    access_level: str = Query("", max_length=FACET_LABEL_MAX_CHARS),
    page: int = Query(default=1, ge=1, le=MAX_SEARCH_PAGE, description="Page number"),
) -> Response:
    """Render tier-filtered search and sampled facets using PAGINATION_SIZE.

    Empty results beyond page one redirect 303 to the last accessible page;
    numbered pages stop at 10,000. Free text and exact filters follow
    services.datasets.search_datasets; hidden metadata never participates.
    """
    pool = request.app.state.db_pool
    user_tier = _get_user_tier(request)

    results, total_results = await search_datasets(
        pool,
        user_tier,
        query,
        keyword,
        language,
        access_level,
        page=page,
        page_size=settings.pagination_size,
    )

    if not results and page > 1:
        last_page = min(
            MAX_SEARCH_PAGE, max(1, math.ceil(total_results / settings.pagination_size))
        )
        return RedirectResponse(url_for_query(request, page=str(last_page)), status_code=303)

    total_pages = min(MAX_SEARCH_PAGE, max(1, math.ceil(total_results / settings.pagination_size)))
    current_page = page

    facets = await get_facets(pool, user_tier)

    return templates.TemplateResponse(
        request,
        "search.html",
        {
            "results": results,
            "query": query,
            "active_keyword": keyword or "",
            "active_language": language or "",
            "active_access_level": access_level or "",
            "all_access_levels": facets.get("access_levels", []),
            "all_keywords": facets.get("keywords", []),
            "all_languages": facets.get("languages", []),
            "result_count": total_results,
            "current_page": current_page,
            "total_pages": total_pages,
            "result_window_limited": total_results > MAX_SEARCH_PAGE * settings.pagination_size,
            "user_tier": user_tier,
        },
    )


@router.get("/dataset/{dataset_id}", response_class=HTMLResponse)
async def detail(request: Request, dataset_id: int) -> Response:
    """Render tier-redacted details, or a 404 page if the dataset is absent.

    Audit dataset_access for nonpublic visibility, including denied full views.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    user_tier = _get_user_tier(request)

    dataset = await get_dataset_by_id(pool, dataset_id, user_tier)

    if not dataset:
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Dataset not found",
                "error_message": "This dataset doesn't exist or has been removed.",
            },
            status_code=404,
        )

    if dataset.visibility_tier != "public":
        audit_user_event(
            level=logging.INFO,
            request=request,
            event_type="dataset_access",
            user_id=user.id if user else None,
            dataset_id=dataset.id,
            dataset_uuid=dataset.uuid,
            dataset_visibility_tier=dataset.visibility_tier,
            user_tier=user_tier,
            access_granted=can_view_full(dataset, user_tier),
        )

    return templates.TemplateResponse(
        request,
        "detail.html",
        {
            "dataset": dataset,
            "user_tier": user_tier,
        },
    )


@router.get("/about", response_class=HTMLResponse)
async def about(request: Request) -> Response:
    """Render the static about page."""
    return templates.TemplateResponse(request, "about.html")

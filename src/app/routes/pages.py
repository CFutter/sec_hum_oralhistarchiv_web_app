"""Page routes — home, search, detail, about."""

import math
from fastapi import APIRouter, Response, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from ..services import (
    AccessTier,
    search_datasets,
    get_recent_datasets,
    get_keyword_count,
    get_dataset_by_id,
    get_last_full_rebuild_date,
    can_view_full,
    audit_user_event
)
from config import settings
from ..template_setup import templates
from ..jinja_helpers import url_for_query

router = APIRouter()

def _get_user_tier(request: Request) -> AccessTier:
    """Extract the user's access tier, defaulting to 'public' for guests."""
    user = request.state.user
    if user:
        return user.access_tier
    return "public"


@router.get("/")
async def home(request: Request) -> Response:
    """Render the home page with collection stats and recent additions."""
    pool = request.app.state.db_pool

    user_tier = _get_user_tier(request)
    recent, total_datasets = await get_recent_datasets(pool, user_tier)
    full_rebuild_date = await get_last_full_rebuild_date(pool)

    facets = await request.app.state.facet_cache.get_cached_facets(user_tier)

    return templates.TemplateResponse(request, "home.html", {
        "total_datasets": total_datasets,
        "total_languages": len(facets.get("languages", [])),
        "total_keywords": await get_keyword_count(pool, user_tier),
        "recent": recent,
        "last_full_rebuild": full_rebuild_date,
        "user_tier": user_tier,
    })


@router.get("/search", response_class=HTMLResponse)
async def search_page(
    request: Request,
    query: str = Query(default="", alias="q", max_length=200, description="Free-text search"),
    keyword: str = Query("", max_length=100),
    language: str = Query("", max_length=100),
    access_level: str = Query("", max_length=100),
    page: int = Query(default=1, ge=1, le= 10000, description="Page number"),
) -> Response:
    """Render paginated search results with facet filtering.

    Supports free-text search across titles, descriptions, authors, and
    keywords, combined with optional exact-match filters for keyword,
    language, and access level.
    """
    pool = request.app.state.db_pool
    user_tier = _get_user_tier(request)

    results, total_results = await search_datasets(
        pool, user_tier, query, keyword, language, access_level,
        page=page, page_size=settings.pagination_size,
    )

    if not results and page > 1:
        _, total_results = await search_datasets(
            pool, user_tier, query, keyword, language, access_level,
            page=1, page_size=settings.pagination_size,
        )
        last_page = max(1, math.ceil(total_results / settings.pagination_size))
        return RedirectResponse(
            url_for_query(request, page=str(last_page)), status_code=303
        )

    total_pages = max(1, math.ceil(total_results / settings.pagination_size))
    current_page = page 

    facets = await request.app.state.facet_cache.get_cached_facets(user_tier)

    return templates.TemplateResponse(request, "search.html", {
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
        "user_tier": user_tier,
    })

@router.get("/dataset/{dataset_id}", response_class=HTMLResponse)
async def detail(request: Request, dataset_id: int) -> Response:
    """Render the detail page for a single dataset.
 
    Returns a 404 error page if the dataset does not exist. Restricted
    metadata is redacted based on the user's access tier (done via function 
    get_dataset_by_id). Access to restricted datasets is logged to the audit 
    channel for compliance review.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    user_tier = _get_user_tier(request)

    dataset = await get_dataset_by_id(pool, dataset_id, user_tier)
 
    if not dataset:
        return templates.TemplateResponse(request, "error.html", {
            "error_title": "Dataset not found",
            "error_message": "This dataset doesn't exist or has been removed.",
        }, status_code=404)
 

 
    if dataset.visibility_tier != "public":
        audit_user_event(
            request,
            "dataset_access",
            user_id=user.id if user else None,
            dataset_id=dataset.id,
            dataset_uuid=dataset.uuid,
            dataset_visibility_tier=dataset.visibility_tier,
            user_tier=user_tier,
            access_granted=can_view_full(dataset, user_tier),
        )
  
    return templates.TemplateResponse(request, "detail.html", {
        "dataset": dataset,
        "user_tier": user_tier,
    })

@router.get("/about", response_class=HTMLResponse)
async def about(request: Request) -> Response:
    """Render the static about page."""
    return templates.TemplateResponse(request, "about.html")
"""Page routes — home, search, detail, about."""

import hashlib
import logging
from dataclasses import dataclass
from typing import Annotated

from fastapi import HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import AfterValidator

from app.sources import AccessTier, SourceDisplay, SourceMetadata
from config import settings

from ..jinja_helpers import path_for, url_for_query
from ..route_security import RouteAccess, SecureAPIRouter
from ..services import (
    CataloguePolicy,
    Dataset,
    FacetDisclosure,
    User,
    audit_facet_disclosures,
    audit_metadata_disclosures,
    audit_user_event,
    can_access,
    can_view_full,
    get_dataset_by_id,
    get_facets,
    get_recent_datasets,
    get_source_statuses,
    search_catalogue_page,
)
from ..services.parsed_record import FACET_LABEL_MAX_CHARS
from ..services.search_cursor import (
    NUMBERED_SEARCH_PAGES,
    SEARCH_CURSOR_MAX_LENGTH,
    SearchCursorInvalid,
)
from ..services.search_query import validate_search_string
from ..template_setup import templates
from ..url_safety import is_safe_http_url

MAX_SEARCH_PAGE = NUMBERED_SEARCH_PAGES
_MAX_PROXY_INDEX_DIGITS = 10

SearchText = Annotated[str, AfterValidator(validate_search_string)]

router = SecureAPIRouter(access=RouteAccess.PUBLIC)


def _get_user_tier(request: Request) -> AccessTier:
    """Extract the user's access tier, defaulting to 'public' for guests."""
    user: User | None = request.state.user
    if user:
        return user.access_tier
    return "public"


def _get_catalogue_policy(request: Request) -> CataloguePolicy:
    """Read the snapshot published at lifespan or explicit source replacement."""
    policy: CataloguePolicy = request.app.state.catalogue_policy
    return policy


@dataclass(frozen=True, slots=True)
class _ResourceLink:
    """A safe stored proxy with its original array identity."""

    index: int
    kind: str
    url: str


def _resource_link(dataset: Dataset, index: int) -> _ResourceLink | None:
    """Return a safe Resource/LandingPage proxy at the zero-based index, or None."""
    proxies: object = dataset.resource_proxies
    if not isinstance(proxies, list) or not 0 <= index < len(proxies):
        return None
    proxy = proxies[index]
    if not isinstance(proxy, dict):
        return None
    kind, url = proxy.get("type"), proxy.get("ref")
    if (
        not isinstance(kind, str)
        or kind not in ("Resource", "LandingPage")
        or not isinstance(url, str)
    ):
        return None
    if url != url.strip() or not is_safe_http_url(url):
        return None
    return _ResourceLink(index=index, kind=kind, url=url)


def _preferred_resource_link(dataset: Dataset) -> _ResourceLink | None:
    """Return the first safe Resource, else first LandingPage, or None; retain original indices."""
    proxies: object = dataset.resource_proxies
    if not isinstance(proxies, list):
        return None
    for kind in ("Resource", "LandingPage"):
        for index in range(len(proxies)):
            link = _resource_link(dataset, index)
            if link is not None and link.kind == kind:
                return link
    return None


@router.get("/")
async def home(request: Request) -> Response:
    """Render live total, cached freshness and recent records; audit protected disclosures."""
    pool = request.app.state.db_pool
    catalogue_stats_cache = request.app.state.catalogue_stats_cache
    user_tier = _get_user_tier(request)
    configured_sources = _get_catalogue_policy(request)

    recent = await get_recent_datasets(pool, user_tier, configured_sources=configured_sources)
    global_stats = await catalogue_stats_cache.get_global_stats()

    response = templates.TemplateResponse(
        request,
        "home.html",
        {
            "total_datasets": global_stats.total_datasets,
            "recent": recent,
            "last_full_rebuild": global_stats.last_full_rebuild,
            "user_tier": user_tier,
            "configured_sources": configured_sources,
        },
    )
    audit_metadata_disclosures(
        request,
        recent,
        user_tier=user_tier,
        configured_sources=configured_sources,
        view="home",
    )
    return response


def _search_audience(request: Request) -> str:
    """Return anonymous for guests, else a SHA-256 audience bound to account/session IDs."""
    user: User | None = request.state.user
    if user is None:
        return "anonymous"
    session_id = getattr(request.state, "session_id", None) or ""
    return hashlib.sha256(
        f"oralhistarchiv-search-audience-v1\x00{user.id}\x00{session_id}".encode()
    ).hexdigest()


@router.get("/search", response_class=HTMLResponse)
async def search_page(
    request: Request,
    query: Annotated[
        SearchText,
        Query(alias="q", max_length=200, description="Free-text search"),
    ] = "",
    keyword: Annotated[
        SearchText,
        Query(max_length=FACET_LABEL_MAX_CHARS),
    ] = "",
    language: Annotated[
        SearchText,
        Query(max_length=FACET_LABEL_MAX_CHARS),
    ] = "",
    access_level: Annotated[
        SearchText,
        Query(max_length=FACET_LABEL_MAX_CHARS),
    ] = "",
    page: int = Query(
        default=1,
        ge=1,
        le=MAX_SEARCH_PAGE,
        description="Numbered page",
    ),
    cursor: Annotated[
        str | None,
        Query(max_length=SEARCH_CURSOR_MAX_LENGTH),
    ] = None,
    pagination: Annotated[
        str | None,
        Query(max_length=32),
    ] = None,
) -> Response:
    """Render bounded numbered pages/opaque continuation and audit metadata/facet disclosures.

    Blank query/facet values omit filters. cursor selects continuation; otherwise
    page selects a numbered page. Current tier/source/field policy applies on
    every request. Invalid cursors or empty numbered pages redirect 303 to page
    one; an eligible exhausted cursor yields an empty tail. pagination selects
    only allowlisted notice text. SearchWork bounds both result and facet reads;
    SearchUnavailable propagates to the retryable 503 handler.
    """
    user_tier = _get_user_tier(request)
    configured_sources = _get_catalogue_policy(request)
    cursor_pagination = cursor is not None
    facet_disclosures: list[FacetDisclosure] = []

    try:
        async with request.app.state.search_work.connection() as connection:
            result_page = await search_catalogue_page(
                connection,
                user_tier,
                query,
                keyword,
                language,
                access_level,
                page=page,
                page_size=settings.pagination_size,
                configured_sources=configured_sources,
                cursor=cursor,
                audience=_search_audience(request),
            )
            # Empty numbered pages redirect without rendering facets. Every
            # rendered page keeps both database reads inside the same budget.
            facets = (
                await get_facets(
                    connection,
                    user_tier,
                    configured_sources=configured_sources,
                    disclosures=facet_disclosures,
                )
                if result_page.datasets or page == 1 or cursor_pagination
                else {}
            )
    except SearchCursorInvalid:
        return RedirectResponse(
            url_for_query(
                request,
                page=1,
                cursor=None,
                pagination="restart",
            ),
            status_code=303,
        )

    results = result_page.datasets
    current_page = result_page.page

    if not results and page > 1 and not cursor_pagination:
        return RedirectResponse(
            url_for_query(
                request,
                page=1,
                cursor=None,
                pagination="empty",
            ),
            status_code=303,
        )

    next_page_url = previous_page_url = None

    if result_page.next_cursor is not None:
        next_page_url = url_for_query(
            request,
            page=None,
            cursor=result_page.next_cursor,
            pagination=None,
        )
    elif not cursor_pagination and current_page < MAX_SEARCH_PAGE and result_page.has_next:
        next_page_url = url_for_query(
            request,
            page=current_page + 1,
            cursor=None,
            pagination=None,
        )

    if result_page.previous_cursor is not None:
        previous_page_url = url_for_query(
            request,
            page=None,
            cursor=result_page.previous_cursor,
            pagination=None,
        )
    elif 1 < current_page <= MAX_SEARCH_PAGE:
        previous_page_url = url_for_query(
            request,
            page=current_page - 1,
            cursor=None,
            pagination=None,
        )

    notices = {
        "restart": ("This search bookmark has expired or no longer matches. Showing page 1."),
        "empty": "That search page is empty. Showing page 1.",
    }

    response = templates.TemplateResponse(
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
            "result_count": result_page.total_count,
            "current_page": current_page,
            "total_pages": None,
            "cursor_pagination": cursor_pagination,
            "next_page_url": next_page_url,
            "previous_page_url": previous_page_url,
            "pagination_notice": notices.get(pagination or ""),
            "search_start_url": (
                url_for_query(
                    request,
                    page=1,
                    cursor=None,
                    pagination=None,
                )
                if cursor_pagination
                else None
            ),
            "user_tier": user_tier,
            "configured_sources": configured_sources,
        },
    )
    audit_metadata_disclosures(
        request,
        results,
        user_tier=user_tier,
        configured_sources=configured_sources,
        view="search",
    )
    audit_facet_disclosures(request, facet_disclosures, user_tier=user_tier)
    return response


@router.get("/dataset/{dataset_id}", response_class=HTMLResponse)
async def detail(request: Request, dataset_id: int) -> Response:
    """Render tier-redacted details, or 404 when absent/hidden/quarantined.

    Audit protected metadata and nonpublic dataset access, including denied
    full views. Use a checked redirect for resource access when the source logs
    access; otherwise expose the safe stored URL directly.
    """
    pool = request.app.state.db_pool
    user = request.state.user
    user_tier = _get_user_tier(request)
    configured_sources = _get_catalogue_policy(request)

    dataset = await get_dataset_by_id(
        pool, dataset_id, user_tier, configured_sources=configured_sources
    )

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
            access_granted=can_view_full(dataset, user_tier, configured_sources=configured_sources),
        )

    configured_source = configured_sources.source_by_name.get(dataset.source)
    source_display = (
        configured_source.display if configured_source else SourceDisplay(label=dataset.source)
    )
    resource_link = (
        _preferred_resource_link(dataset)
        if can_view_full(dataset, user_tier, configured_sources=configured_sources)
        else None
    )
    resource_href = None
    if resource_link is not None:
        resource_href = (
            path_for(
                request,
                "resource_access",
                dataset_id=dataset.id,
                proxy_index=resource_link.index,
            )
            if configured_source is None or configured_source.log_resource_access
            else resource_link.url
        )

    response = templates.TemplateResponse(
        request,
        "detail.html",
        {
            "dataset": dataset,
            "user_tier": user_tier,
            "configured_sources": configured_sources,
            "record_visible": can_access(user_tier, dataset.visibility_tier),
            "source_display": source_display,
            "resource_href": resource_href,
            "resource_kind": resource_link.kind if resource_link else None,
        },
    )
    audit_metadata_disclosures(
        request,
        [dataset],
        user_tier=user_tier,
        configured_sources=configured_sources,
        view="detail",
        resource_exposed=resource_link is not None and resource_href == resource_link.url,
    )
    return response


@router.get("/dataset/{dataset_id}/resource/{proxy_index}")
async def resource_access(request: Request, dataset_id: int, proxy_index: str) -> Response:
    """Authorize/audit a safe stored resource and redirect 303 to its URL.

    proxy_index is a zero-based ASCII decimal string of at most ten digits.
    Raise HTTPException(404) for invalid indices, missing/hidden datasets,
    insufficient full-view access or unsafe/unrecognized proxies.
    """
    if not (
        len(proxy_index) <= _MAX_PROXY_INDEX_DIGITS
        and proxy_index.isascii()
        and proxy_index.isdecimal()
    ):
        raise HTTPException(status_code=404, detail="Not found")
    user_tier = _get_user_tier(request)
    configured_sources = _get_catalogue_policy(request)
    dataset = await get_dataset_by_id(
        request.app.state.db_pool, dataset_id, user_tier, configured_sources=configured_sources
    )
    if dataset is None or not can_view_full(
        dataset, user_tier, configured_sources=configured_sources
    ):
        raise HTTPException(status_code=404, detail="Not found")
    link = _resource_link(dataset, int(proxy_index))
    if link is None:
        raise HTTPException(status_code=404, detail="Not found")
    response = RedirectResponse(link.url, status_code=303)
    audit_metadata_disclosures(
        request,
        [dataset],
        user_tier=user_tier,
        configured_sources=configured_sources,
        view="resource",
        resource_exposed=True,
    )
    user = request.state.user
    audit_user_event(
        level=logging.INFO,
        request=request,
        event_type="resource_access",
        user_id=user.id if user else None,
        dataset_id=dataset.id,
        source=dataset.source,
        user_tier=user_tier,
        proxy_index=link.index,
    )
    return response


@router.get("/about", response_class=HTMLResponse)
async def about(request: Request) -> Response:
    """Render configured source labels and public synchronization status."""
    configured_sources: tuple[SourceMetadata, ...] = request.app.state.configured_sources
    source_statuses = await get_source_statuses(
        request.app.state.db_pool,
        configured_sources=configured_sources,
    )
    return templates.TemplateResponse(
        request,
        "about.html",
        {"source_statuses": source_statuses},
    )

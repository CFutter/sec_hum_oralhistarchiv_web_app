"""Query/redact serving catalogue metadata for the caller's tier.

Reads exclude administrator-hidden and quarantined identities and use the
stricter stored/administrator metadata tier. access_level describes upstream
resource access; it grants no authority. Database errors propagate.
"""

import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from datetime import UTC, datetime
from typing import Any, TypeGuard, get_args

from psycopg import sql
from psycopg.rows import tuple_row
from psycopg.sql import Composable
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.field_visibility import (
    FIELD_VISIBILITY,
    PUBLIC_DISCOVERY_FIELDS,
    PUBLIC_SEARCH_FIELDS,
    RESOURCE_URL_FIELDS,
)
from app.sources import AccessTier, SourceMetadata

from .access_tiers import can_access, tier_rank
from .catalogue_policy import CataloguePolicy, CataloguePolicyInput, compile_catalogue_policy
from .db import Database, get_catalogue_cursor, get_catalogue_search_cursor
from .parsed_record import FACET_LABEL_MAX_CHARS, ParsedRecord
from .schema import (
    DATASET_COMPUTED_FIELDS,
    DATASET_INSERT_COLUMNS,
    DATASET_SELECT_COLUMNS,
    DATASET_SELECT_SQL,
    PARSER_OWNED,
    build_record_params,
)
from .schema_invariants import assert_columns_match_dataclass, assert_unique_columns
from .search_cursor import (
    NUMBERED_SEARCH_PAGES,
    SearchCursor,
    SearchCursorInvalid,
    cursor_context_digest,
    issue_search_cursor,
    read_search_cursor,
)
from .search_projection import guard_catalogue_policy_cur
from .search_query import SearchQuery, parse_search_query, validate_search_string
from .sync_state import _validated_source_name, _validated_source_names

__all__ = [
    "FACET_OPTION_LIMIT",
    "FACET_SAMPLE_SIZE",
    "FIELD_VISIBILITY",
    "PUBLIC_DISCOVERY_FIELDS",
    "PUBLIC_SEARCH_FIELDS",
    "Author",
    "CataloguePolicy",
    "Dataset",
    "FacetDisclosure",
    "SearchPage",
    "assert_field_visibility_total",
    "build_catalogue_policy",
    "can_view_field",
    "can_view_full",
    "count_search_datasets",
    "field_required_tier",
    "filter_for_tier",
    "full_required_tier",
    "get_dataset_by_id",
    "get_facets",
    "get_global_catalogue_stats",
    "get_last_full_rebuild_date",
    "get_recent_datasets",
    "get_total_dataset_count",
    "search_catalogue_page",
    "search_datasets",
    "validate_dataset_insert_schema",
    "validate_dataset_schema",
]

logger = logging.getLogger(__name__)


_SEARCH_COUNT_TIMEOUT_MS = 2_000
_SEARCH_COUNT_TIMEOUT_MAX_MS = 30_000
_MAX_ORDERED_ROWS = 10_000

FACET_SAMPLE_SIZE = 200
FACET_OPTION_LIMIT = 50


@dataclass(frozen=True, slots=True)
class FacetDisclosure:
    """Identity and protected field names contributing to displayed suggestions."""

    dataset_id: int
    source: str
    uuid: str
    fields: tuple[str, ...]


@dataclass
class Author:
    """An author's display name."""

    name: str


@dataclass
class Dataset:
    """Catalogue metadata with independent resource and metadata access fields.

    access_level describes upstream resource restrictions for display and
    filtering; visibility_tier controls local metadata disclosure. The
    upstream service enforces resource access.
    """

    id: int
    uuid: str
    title: str
    project_title: str | None = None
    description: str | None = None
    resource_description: str | None = None
    languages: list[str] = field(default_factory=list)
    project_description: str | None = None
    authors: list[Author] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    resource_proxies: list[dict[str, Any]] = field(default_factory=list)
    resource_access_url: str | None = None
    landing_page_url: str | None = None
    license_val: str | None = None
    license_url: str | None = None
    access_level: str | None = None
    version: str | None = None
    doi: str | None = None
    resource_type: str | None = None
    bibliographical_citation: str | None = None
    source: str = field(kw_only=True)
    visibility_tier: AccessTier = "vetted"

    def __post_init__(self) -> None:
        """Require explicit canonical source ownership without normalization."""
        _validated_source_name(self.source)


@dataclass
class SearchPage:
    """One current catalogue page and opaque continuation bookmarks."""

    datasets: list[Dataset]
    total_count: int | None
    page: int
    next_cursor: str | None = None
    previous_cursor: str | None = None
    has_next: bool = False


def _parse_dataset(row: dict[str, Any]) -> Dataset:
    """Build a Dataset from every selected column.

    Missing columns raise KeyError. Invalid source identities raise ValueError;
    source ownership is never inferred or normalized. Normalize optional fields,
    skip malformed authors, and derive resource/landing URLs from proxies.
    """
    row_authors = row.get("authors") or []
    parsed_authors = []

    for a in row_authors:
        if isinstance(a, str):
            parsed_authors.append(Author(name=a))
        else:
            logger.warning("Skipping malformed author entry: %r", a)
            continue

    proxies = row.get("resource_proxies") or []
    resource_access_url = None
    landing_page_url = None
    if isinstance(proxies, list):
        for proxy in proxies:
            if isinstance(proxy, dict):
                proxy_type = proxy.get("type") or ""
                if proxy_type == "Resource" and not resource_access_url:
                    resource_access_url = proxy.get("ref")
                elif proxy_type == "LandingPage" and not landing_page_url:
                    landing_page_url = proxy.get("ref")

    # Derive forwarding from the SELECT contract: new selected fields cannot
    # disappear behind dataclass defaults, and incomplete rows fail here.
    values = {name: row[name] for name in DATASET_SELECT_COLUMNS}
    values.update(
        title=values["title"] or "(untitled)",
        authors=parsed_authors,
        languages=values["languages"] or [],
        keywords=values["keywords"] or [],
        resource_proxies=values["resource_proxies"] or [],
        access_level=values["access_level"] or "restricted",
        visibility_tier=values["visibility_tier"] or "vetted",
        resource_access_url=resource_access_url,
        landing_page_url=landing_page_url,
    )
    return Dataset(**values)


# Discovery remains public above the record tier; RLS restricts the joined
# metadata. Hidden/quarantined identities are excluded on both paths, and
# the bounded owner function resolves private timestamp ordering.
_CATALOGUE_COLUMNS_SQL = sql.SQL(", ").join(
    [
        *(
            sql.Identifier("discovery" if name in PUBLIC_DISCOVERY_FIELDS else "stored", name)
            for name in DATASET_SELECT_COLUMNS
        ),
        sql.SQL(
            "(COALESCE(discovery.title, '') || ' ' || COALESCE(discovery.access_level, '')) "
            "AS search_text_public"
        ),
    ]
)
_CATALOGUE_FROM_SQL = sql.SQL("""
    (
        SELECT {columns}
        FROM catalogue_discovery AS discovery
        LEFT JOIN oral_history_datasets AS stored ON stored.id = discovery.id
    ) AS catalogue
""").format(columns=_CATALOGUE_COLUMNS_SQL)


def build_catalogue_policy(
    configured_sources: Sequence[SourceMetadata],
    *,
    previous: CataloguePolicy | None = None,
) -> CataloguePolicy:
    """Compile a selection, or reuse its policy while immutable inputs are identical.

    Web startup prepares one policy. Request wiring also detects explicit source
    or code-matrix replacement, including replacement by tests. No global cache
    or record-level decision is involved.
    """
    if (
        previous is not None
        and previous.sources is configured_sources
        and previous.code_visibility is FIELD_VISIBILITY
        and previous.discovery_fields is PUBLIC_DISCOVERY_FIELDS
    ):
        return previous
    return compile_catalogue_policy(
        configured_sources,
        field_names=tuple(item.name for item in dataclass_fields(Dataset)),
        visibility=FIELD_VISIBILITY,
        discovery_fields=PUBLIC_DISCOVERY_FIELDS,
    )


def _catalogue_policy(configured_sources: CataloguePolicyInput) -> CataloguePolicy:
    """Preserve an already compiled policy across nested service/helper calls."""
    if isinstance(configured_sources, CataloguePolicy):
        return configured_sources
    return build_catalogue_policy(configured_sources)


def _search_policy_context(
    query: SearchQuery,
    rank: int,
    configured_sources: CataloguePolicyInput,
) -> dict[str, str]:
    """Bind precompiled document masks, including the unknown-source fallback."""
    policy = _catalogue_policy(configured_sources)
    policy.validate_rank(rank)
    return {
        "app.search_term": query.term,
        "app.search_pattern": query.pattern,
        "app.search_mode": query.mode,
        "app.search_field_masks": policy.document_masks_json[rank],
    }


def _search_predicate(query: SearchQuery, configured_sources: CataloguePolicyInput) -> Composable:
    """Match exclusively inside the current audience's physical projection."""
    del query, configured_sources
    return sql.SQL("(id IN (SELECT public.catalogue_match_ids(%(page_query)s)))")


def _search_where_clause(
    query: SearchQuery, configured_sources: CataloguePolicyInput
) -> Composable:
    """All text and exact filters use the same pre-redacted projection boundary."""
    return _search_predicate(query, configured_sources)


def _page_query_context(
    query: SearchQuery,
    rank: int,
    filters: Mapping[str, str],
    configured_sources: CataloguePolicyInput,
) -> Jsonb:
    """Bind precompiled versioned masks without exposing mutable policy mappings."""
    policy = _catalogue_policy(configured_sources)
    policy.validate_rank(rank)
    return Jsonb(
        {
            "mode": query.mode,
            "fingerprint": policy.fingerprint,
            "term": query.term,
            "pattern": query.pattern,
            **filters,
            "masks": dict(policy.page_masks[rank]),
        }
    )


def _ordered_catalogue_statement() -> sql.Composed:
    """Fetch only the bounded, already filtered IDs selected inside the owner boundary."""
    return sql.SQL("""
        SELECT {columns}
        FROM public.catalogue_page_ids(
            NULL::integer,
            public.catalogue_scan_ceiling(),
            false, %(limit)s, %(offset)s, %(page_query)s
        ) WITH ORDINALITY AS selected(id, position)
        JOIN {catalogue} ON catalogue.id = selected.id
        ORDER BY selected.position
    """).format(
        columns=sql.SQL(", ").join(
            sql.Identifier("catalogue", name) for name in DATASET_SELECT_COLUMNS
        ),
        catalogue=_CATALOGUE_FROM_SQL,
    )


async def count_search_datasets(
    pool: Database,
    user_tier: AccessTier,
    search_text: str = "",
    keyword: str = "",
    language: str = "",
    access_level: str = "",
    *,
    configured_sources: CataloguePolicyInput,
    timeout_ms: int = _SEARCH_COUNT_TIMEOUT_MS,
) -> int:
    """Count current authorized matches in a separate snapshot.

    timeout_ms must be an integer 1..30000 (default 2000); a shorter database
    timeout wins. Empty filters disable their exact match. Invalid timeout/text
    raises ValueError (non-string text raises TypeError). Restore the prior timeout
    on success; errors roll back transaction-local settings. The count may differ
    from a separately fetched page; ordinary navigation does not request it.
    """
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= _SEARCH_COUNT_TIMEOUT_MAX_MS:
        raise ValueError("Search count timeout is outside the supported range")

    sources = _catalogue_policy(configured_sources)
    query = parse_search_query(search_text)
    for value in (keyword, language, access_level):
        validate_search_string(value)

    rank = tier_rank(user_tier)
    params = {
        "page_query": _page_query_context(
            query,
            rank,
            {"keyword": keyword, "language": language, "access_level": access_level},
            sources,
        ),
    }

    scope = (
        get_catalogue_search_cursor(
            pool,
            user_tier,
            _search_policy_context(query, rank, sources),
            row_factory=tuple_row,
        )
        if query.term
        else get_catalogue_cursor(
            pool,
            user_tier,
            row_factory=tuple_row,
        )
    )

    async with scope as cur:
        await guard_catalogue_policy_cur(cur, sources)
        await cur.execute("SELECT current_setting('statement_timeout')")
        previous = await cur.fetchone()
        if previous is None:
            raise RuntimeError("Search count timeout query returned no row")

        # PostgreSQL uses zero to mean no timeout. Otherwise retain the
        # shorter of the current limit and this operation's requested limit.
        await cur.execute(
            """
            SELECT set_config(
                'statement_timeout',
                (
                    CASE
                        WHEN current_setting('statement_timeout')::interval
                             > interval '0'
                        THEN LEAST(
                            %s,
                            EXTRACT(
                                epoch FROM
                                current_setting('statement_timeout')::interval
                            ) * 1000
                        )
                        ELSE %s
                    END
                )::bigint::text || 'ms',
                true
            )
            """,
            (timeout_ms, timeout_ms),
        )

        await cur.execute(
            sql.SQL("SELECT COUNT(*) FROM public.catalogue_match_ids(%(page_query)s)"),
            params,
        )
        row = await cur.fetchone()
        if row is None:
            raise RuntimeError("Search count query returned no row")

        await cur.execute(
            "SELECT set_config('statement_timeout', %s, true)",
            (previous[0],),
        )

    return int(row[0])


async def search_datasets(  # noqa: PLR0913 - preserve the compatibility query API.
    pool: AsyncConnectionPool,
    user_tier: AccessTier,
    search_text: str = "",
    keyword: str = "",
    language: str = "",
    access_level: str = "",
    page: int = 1,
    page_size: int = 20,
    *,
    configured_sources: CataloguePolicyInput,
) -> tuple[list[Dataset], int]:
    """Return a page and exact count from separate statements.

    Require integer page 1..100 and page_size 0..100 or raise ValueError; zero
    returns ([], 0) without database access. Empty filters disable exact matching.
    Concurrent changes can make count and page differ; counting has a separate
    timeout. Ordinary navigation uses search_catalogue_page without counting.
    """
    if type(page) is not int or not 1 <= page <= NUMBERED_SEARCH_PAGES:
        raise ValueError("Numbered search page is outside the supported range")

    if type(page_size) is not int or not 0 <= page_size <= NUMBERED_SEARCH_PAGES:
        raise ValueError("Search page size is outside the supported range")

    sources = _catalogue_policy(configured_sources)
    query = parse_search_query(search_text)

    for value in (keyword, language, access_level):
        validate_search_string(value)

    if page_size == 0:
        return [], 0

    rank = tier_rank(user_tier)
    filters = {
        "keyword": keyword,
        "language": language,
        "access_level": access_level,
    }

    scope = (
        get_catalogue_search_cursor(
            pool,
            user_tier,
            _search_policy_context(query, rank, sources),
        )
        if query.term
        else get_catalogue_cursor(pool, user_tier)
    )

    async with scope as cur:
        await guard_catalogue_policy_cur(cur, sources)
        await cur.execute(
            _ordered_catalogue_statement(),
            {
                "limit": page_size,
                "offset": (page - 1) * page_size,
                "page_query": _page_query_context(
                    query,
                    rank,
                    filters,
                    sources,
                ),
            },
        )
        rows = await cur.fetchall()

    records = [
        filter_for_tier(
            _parse_dataset(row),
            user_tier,
            configured_sources=sources,
        )
        for row in rows
    ]

    total = await count_search_datasets(
        pool,
        user_tier,
        search_text,
        keyword,
        language,
        access_level,
        configured_sources=sources,
    )

    return records, total


def _search_bookmark_context(
    query: SearchQuery,
    user_tier: AccessTier,
    filters: Mapping[str, str],
    page_size: int,
    audience: str,
    configured_sources: CataloguePolicyInput,
) -> str:
    """Bind per-request bookmark values to the precomputed complete policy digest."""
    policy = _catalogue_policy(configured_sources)
    return cursor_context_digest(
        {
            "version": 3,
            "catalogue_policy": policy.fingerprint,
            "query": {"mode": query.mode, "term": query.term},
            "filters": dict(filters),
            "tier": user_tier,
            "page_size": page_size,
            "audience": audience,
        }
    )


def _catalogue_page_statement(
    where_clause: Composable,
    state: SearchCursor | None,
) -> sql.Composed:
    """Check the current anchor and select a limited page in one MVCC snapshot.

    The owner function keeps the timestamp private and seeks on the existing
    composite index. No global ordering window, eligible-set materialization or
    exact count is required. WITH ORDINALITY numbers only returned page IDs.
    """
    return sql.SQL("""
        WITH scan_ceiling AS MATERIALIZED (
            SELECT COALESCE(
                %(ceiling_id)s::integer,
                public.catalogue_scan_ceiling(),
                0
            ) AS ceiling_id
        ), bounds AS MATERIALIZED (
            SELECT ceiling_id,
                (%(anchor_id)s::integer IS NULL OR EXISTS (
                    SELECT 1 FROM {catalogue}
                    WHERE id = %(anchor_id)s
                      AND id <= scan_ceiling.ceiling_id
                      AND ({where})
                )) AS anchor_valid
            FROM scan_ceiling
        )
        SELECT catalogue.*, bounds.ceiling_id, bounds.anchor_valid
        FROM bounds
        LEFT JOIN LATERAL public.catalogue_page_ids(
            %(anchor_id)s,
            bounds.ceiling_id,
            {reverse},
            %(limit)s,
            {offset},
            %(page_query)s
        ) WITH ORDINALITY AS selected(id, position)
            ON bounds.anchor_valid
        LEFT JOIN {catalogue}
            ON catalogue.id = selected.id
        ORDER BY selected.position
    """).format(
        catalogue=_CATALOGUE_FROM_SQL,
        where=where_clause,
        reverse=sql.Literal(state is not None and state.direction == "previous"),
        offset=(sql.SQL("%(offset)s") if state is None else sql.Literal(0)),
    )


async def search_catalogue_page(  # noqa: PLR0913 - retain the public search API and explicit bookmark context.
    pool: Database,
    user_tier: AccessTier,
    search_text: str = "",
    keyword: str = "",
    language: str = "",
    access_level: str = "",
    page: int = 1,
    page_size: int = 20,
    *,
    configured_sources: CataloguePolicyInput,
    cursor: str | None = None,
    audience: str = "anonymous",
) -> SearchPage:
    """Return a redacted page with total_count=None and optional continuation bookmarks.

    Require integer page_size 1..100; without cursor, page must be 1..100 or
    ValueError is raised. A cursor overrides page and binds query, exact filters,
    tier, page size, audience and policy; audience is an opaque caller-defined
    bookmark scope, not authorization. Empty filters disable their exact match.
    Page 100 may issue one-hour bookmarks retaining the initial identity ceiling.
    Each request rechecks current eligibility/redaction in one statement snapshot.
    A removed/ineligible anchor raises SearchCursorInvalid; a valid empty end page
    is allowed. Missing/invalid query bounds raise RuntimeError.
    """
    if type(page_size) is not int or not 1 <= page_size <= NUMBERED_SEARCH_PAGES:
        raise ValueError("Search page size is outside the supported range")
    if cursor is None and (type(page) is not int or not 1 <= page <= NUMBERED_SEARCH_PAGES):
        raise ValueError("Numbered search page is outside the supported range")
    sources = _catalogue_policy(configured_sources)
    rank = tier_rank(user_tier)
    query = parse_search_query(search_text)
    for value in (keyword, language, access_level):
        validate_search_string(value)
    filters = {"keyword": keyword, "language": language, "access_level": access_level}
    context = _search_bookmark_context(query, user_tier, filters, page_size, audience, sources)
    state = read_search_cursor(cursor, context=context) if cursor is not None else None
    current_page = state.page if state is not None else page
    issued_at = state.issued_at if state is not None else int(time.time())
    params = {
        "rank": rank,
        "pattern": query.pattern,
        "term": query.term,
        **filters,
        "ceiling_id": state.ceiling_id if state is not None else None,
        "anchor_id": state.anchor_id if state is not None else None,
        "limit": page_size + 1,
        "page_query": _page_query_context(query, rank, filters, sources),
    }
    if state is None:
        params["offset"] = (page - 1) * page_size
    cursor_scope = (
        get_catalogue_search_cursor(pool, user_tier, _search_policy_context(query, rank, sources))
        if query.term
        else get_catalogue_cursor(pool, user_tier)
    )
    async with cursor_scope as cur:
        await guard_catalogue_policy_cur(cur, sources)
        await cur.execute(
            _catalogue_page_statement(_search_where_clause(query, sources), state), params
        )
        rows = await cur.fetchall()
    if not rows:
        raise RuntimeError("Catalogue page query returned no bounds row")
    bounds = rows[0]
    if bounds["anchor_valid"] is not True:
        if state is not None:
            raise SearchCursorInvalid("Search bookmark is no longer valid")
        raise RuntimeError("Catalogue page query returned invalid initial bounds")
    selected = [row for row in rows if row["id"] is not None]
    has_more = len(selected) > page_size
    selected = selected[:page_size]
    reverse = state is not None and state.direction == "previous"
    if reverse:
        selected.reverse()
    datasets = [
        filter_for_tier(_parse_dataset(row), user_tier, configured_sources=sources)
        for row in selected
    ]
    result = SearchPage(
        datasets=datasets,
        total_count=None,
        page=current_page,
        has_next=bool(datasets) and (reverse or has_more),
    )
    if not datasets:
        return result
    if current_page >= NUMBERED_SEARCH_PAGES and (reverse or has_more):
        result.next_cursor = issue_search_cursor(
            SearchCursor(
                datasets[-1].id, bounds["ceiling_id"], current_page + 1, "next", issued_at
            ),
            context=context,
        )
    if current_page > NUMBERED_SEARCH_PAGES and (not reverse or has_more):
        result.previous_cursor = issue_search_cursor(
            SearchCursor(
                datasets[0].id, bounds["ceiling_id"], current_page - 1, "previous", issued_at
            ),
            context=context,
        )
    return result


_REBUILD_FRESHNESS_SQL = sql.SQL("""
    SELECT CASE
        WHEN COUNT(state.last_full_rebuild_date) = COUNT(*)
        THEN MIN(state.last_full_rebuild_date)
        ELSE NULL
    END
    FROM unnest(%s::text[]) AS configured(source)
    LEFT JOIN sync_status AS state USING (source)
""")


async def get_global_catalogue_stats(
    pool: AsyncConnectionPool,
    *,
    source_names: Sequence[str],
) -> tuple[int, datetime | None]:
    """Return serving count and selected-source freshness from one SQL snapshot.

    Count includes unconfigured sources but excludes hidden/quarantined rows.
    Freshness is the oldest successful selected-source rebuild, or None if any
    selected source is absent/unrebuilt. Invalid scopes fail before I/O. Missing
    query rows raise RuntimeError; invalid result types raise TypeError.
    """
    names = _validated_source_names(source_names)
    async with get_catalogue_cursor(pool, "public", row_factory=tuple_row) as cur:
        await cur.execute(
            sql.SQL(
                """
                SELECT
                    (SELECT COUNT(*) FROM {catalogue}) AS total_datasets,
                    ({freshness}) AS last_full_rebuild
                """
            ).format(catalogue=_CATALOGUE_FROM_SQL, freshness=_REBUILD_FRESHNESS_SQL),
            (list(names),),
        )
        row = await cur.fetchone()

    if row is None:
        raise RuntimeError("Global catalogue-statistics query returned no row")

    total_datasets, last_full_rebuild = row

    if not isinstance(total_datasets, int):
        raise TypeError("Global catalogue-statistics count has an invalid type")
    if last_full_rebuild is not None and not isinstance(last_full_rebuild, datetime):
        raise TypeError("Global catalogue-statistics timestamp has an invalid type")

    return (
        total_datasets,
        last_full_rebuild.astimezone(UTC) if last_full_rebuild is not None else None,
    )


async def get_total_dataset_count(pool: Database) -> int:
    """Return the live nonhidden, nonquarantined count, or zero if no aggregate row arrives."""
    async with get_catalogue_cursor(pool, "public", row_factory=tuple_row) as cur:
        await cur.execute(
            sql.SQL("SELECT COUNT(*) FROM {catalogue}").format(catalogue=_CATALOGUE_FROM_SQL)
        )
        row = await cur.fetchone()
        return row[0] if row else 0


async def get_recent_datasets(
    pool: AsyncConnectionPool,
    user_tier: AccessTier,
    limit: int = 3,
    *,
    configured_sources: CataloguePolicyInput,
) -> list[Dataset]:
    """Return redacted rows by upstream timestamp/ID descending; NULL timestamps sort last.

    Require an integer limit 0..10000 or raise ValueError; zero skips database I/O.
    """
    configured_sources = _catalogue_policy(configured_sources)

    if type(limit) is not int or not 0 <= limit <= _MAX_ORDERED_ROWS:
        raise ValueError("Recent dataset limit is outside the supported range")

    if limit == 0:
        return []

    async with get_catalogue_cursor(pool, user_tier) as cur:
        await guard_catalogue_policy_cur(cur, configured_sources)
        await cur.execute(
            _ordered_catalogue_statement(),
            {
                "limit": limit,
                "offset": 0,
                "page_query": _page_query_context(
                    parse_search_query(""),
                    tier_rank(user_tier),
                    {
                        "keyword": "",
                        "language": "",
                        "access_level": "",
                    },
                    configured_sources,
                ),
            },
        )
        rows = await cur.fetchall()

    return [
        filter_for_tier(
            _parse_dataset(row),
            user_tier,
            configured_sources=configured_sources,
        )
        for row in rows
    ]


async def get_facets(
    pool: Database,
    user_tier: AccessTier,
    *,
    configured_sources: CataloguePolicyInput,
    disclosures: list[FacetDisclosure] | None = None,
) -> dict[str, list[str]]:
    """Return bounded keyword, language and access-level suggestions.

    Sample the newest 200 nonhidden rows and inspect at most the first
    100 keyword/language entries per row. Return at most 50 options per
    facet. If supplied, disclosures receives protected contributors to the
    returned options from the same SQL snapshot, without their metadata values.

    Keywords and languages retain their independent visibility gates.
    Keywords require at least two occurrences, including duplicates
    within one row. Exact search filters are not restricted to this sample.
    """
    configured_sources = _catalogue_policy(configured_sources)
    rank = tier_rank(user_tier)

    query = sql.SQL("""
        WITH sample_ids AS MATERIALIZED (
            SELECT sample.id
            FROM public.catalogue_page_ids(
                NULL::integer,
                public.catalogue_scan_ceiling(),
                false,
                %(sample_size)s,
                0,
                %(page_query)s
            ) AS sample(id)
        ), recent AS MATERIALIZED (
            SELECT
                id, source, uuid,
                keywords[1:100] AS keywords,
                languages[1:100] AS languages,
                access_level,
                visibility_tier
            FROM {catalogue}
            WHERE id IN (SELECT id FROM sample_ids)
        ), combined AS (
            SELECT
                'keyword' AS facet,
                unnest(keywords) AS value,
                id, source, uuid, visibility_tier
            FROM recent
            WHERE {keywords_visible}

            UNION ALL

            SELECT
                'language',
                unnest(languages),
                id, source, uuid, visibility_tier
            FROM recent
            WHERE {languages_visible}

            UNION ALL

            SELECT
                'access_level',
                access_level,
                id, source, uuid, visibility_tier
            FROM recent
        ), ranked AS (
            SELECT
                facet,
                value,
                ROW_NUMBER() OVER (
                    PARTITION BY facet
                    ORDER BY value
                ) AS position
            FROM combined
            WHERE value IS NOT NULL AND value != '' AND char_length(value) <= %(label_limit)s
            GROUP BY facet, value
            HAVING facet != 'keyword' OR COUNT(*) >= 2
        )
        SELECT facet, value, NULL::integer AS dataset_id,
               NULL::text AS source, NULL::text AS uuid, NULL::text AS visibility_tier
        FROM ranked
        WHERE position <= %(option_limit)s
        UNION ALL
        SELECT DISTINCT combined.facet, NULL::text, combined.id,
                        combined.source, combined.uuid, combined.visibility_tier
        FROM combined JOIN ranked USING (facet, value)
        WHERE ranked.position <= %(option_limit)s
          AND combined.facet IN ('keyword', 'language')
        ORDER BY facet, value, dataset_id
    """).format(
        catalogue=_CATALOGUE_FROM_SQL,
        keywords_visible=_field_visible_sql(
            "keywords",
            configured_sources,
        ),
        languages_visible=_field_visible_sql(
            "languages",
            configured_sources,
        ),
    )

    facets: dict[str, list[str]] = {
        "keywords": [],
        "languages": [],
        "access_levels": [],
    }

    async with get_catalogue_cursor(
        pool,
        user_tier,
        row_factory=tuple_row,
    ) as cur:
        await guard_catalogue_policy_cur(cur, configured_sources)
        await cur.execute(
            query,
            {
                "rank": rank,
                "sample_size": FACET_SAMPLE_SIZE,
                "option_limit": FACET_OPTION_LIMIT,
                "label_limit": FACET_LABEL_MAX_CHARS,
                "page_query": _page_query_context(
                    parse_search_query(""),
                    rank,
                    {
                        "keyword": "",
                        "language": "",
                        "access_level": "",
                    },
                    configured_sources,
                ),
            },
        )

        contributors: dict[int, tuple[str, str, set[str]]] = {}
        for facet, value, dataset_id, source, uuid, record_tier in await cur.fetchall():
            if dataset_id is not None:
                name = {"keyword": "keywords", "language": "languages"}[facet]
                minimum = max(
                    (record_tier, configured_sources.minimum(name, source)), key=tier_rank
                )
                if disclosures is not None and minimum != "public":
                    contributors.setdefault(dataset_id, (source, uuid, set()))[2].add(name)
                continue
            if facet == "keyword":
                facets["keywords"].append(value)
            elif facet == "language":
                facets["languages"].append(value)
            elif facet == "access_level":
                facets["access_levels"].append(value)

        if disclosures is not None:
            disclosures.extend(
                FacetDisclosure(identity, source, uuid, tuple(sorted(fields)))
                for identity, (source, uuid, fields) in sorted(contributors.items())
            )

    return facets


async def get_dataset_by_id(
    pool: AsyncConnectionPool,
    dataset_id: int,
    user_tier: AccessTier,
    *,
    configured_sources: CataloguePolicyInput,
) -> Dataset | None:
    """Return a redacted dataset, or None if absent, administrator-hidden or quarantined."""
    configured_sources = _catalogue_policy(configured_sources)
    async with get_catalogue_cursor(pool, user_tier) as cur:
        await guard_catalogue_policy_cur(cur, configured_sources)
        await cur.execute(
            sql.SQL("SELECT {} FROM {catalogue} WHERE id = %s").format(
                DATASET_SELECT_SQL, catalogue=_CATALOGUE_FROM_SQL
            ),
            (dataset_id,),
        )
        row = await cur.fetchone()
        if not row:
            return None
        return filter_for_tier(
            _parse_dataset(row), user_tier, configured_sources=configured_sources
        )


async def get_last_full_rebuild_date(
    pool: Database,
    *,
    source_names: Sequence[str],
) -> datetime | None:
    """Return selected sources' oldest UTC rebuild, or None for absent/unrebuilt sources.

    Invalid source scopes fail before I/O; an unexpected timestamp type raises
    TypeError.
    """
    names = _validated_source_names(source_names)
    async with get_catalogue_cursor(pool, "public", row_factory=tuple_row) as cur:
        await cur.execute(_REBUILD_FRESHNESS_SQL, (list(names),))
        row = await cur.fetchone()
        if not row:
            return None
        rebuilt_at = row[0]
        if rebuilt_at is not None and not isinstance(rebuilt_at, datetime):
            raise TypeError("Last-full-rebuild timestamp has an invalid type")
        return rebuilt_at.astimezone(UTC) if rebuilt_at is not None else None


def validate_dataset_schema() -> None:
    """Raise AssertionError if Dataset fields differ from the select/computed contract."""
    assert_columns_match_dataclass(
        Dataset,
        DATASET_SELECT_COLUMNS,
        DATASET_COMPUTED_FIELDS,
        columns_label="DATASET_SELECT_COLUMNS",
        dataclass_label="Dataset",
    )


def validate_dataset_insert_schema() -> None:
    """Reject duplicate insert columns and parser/parameter drift using one synthetic record."""
    assert_unique_columns(DATASET_INSERT_COLUMNS, columns_label="DATASET_INSERT_COLUMNS")
    if set(ParsedRecord.model_fields) - {"visibility_tier"} != PARSER_OWNED:
        raise AssertionError("ParsedRecord and parser-owned SQL columns differ")
    synthetic: dict[str, Any] = dict.fromkeys(PARSER_OWNED)
    synthetic.update(uuid="startup-check", title="Schema check")
    for name in (
        "languages",
        "authors",
        "keywords",
        "institutions",
        "main_disciplines",
        "resource_proxies",
    ):
        synthetic[name] = []
    params = build_record_params(
        synthetic,
        access_level="public",
        source="startup-check",
        visibility_tier="public",
    )
    if len(params) != len(DATASET_INSERT_COLUMNS):
        raise AssertionError(
            f"build_record_params emitted {len(params)} values for "
            f"{len(DATASET_INSERT_COLUMNS)} insert columns — record→tuple drift."
        )


def full_required_tier(
    dataset: Dataset,
    *,
    configured_sources: CataloguePolicyInput,
) -> AccessTier:
    """Combine the precompiled full-field minimum with the current record floor."""
    policy = _catalogue_policy(configured_sources)
    minimum = policy.full_minima.get(dataset.source, policy.full_minima[None])
    return max((minimum, dataset.visibility_tier), key=tier_rank)


def can_view_full(
    dataset: Dataset,
    user_tier: AccessTier,
    *,
    configured_sources: CataloguePolicyInput,
) -> bool:
    """Require all metadata fields, including for resource redirects."""
    return can_access(user_tier, full_required_tier(dataset, configured_sources=configured_sources))


def _is_field_minimum(value: object) -> TypeGuard[AccessTier]:
    """Require an exact canonical string tier in the runtime policy."""
    return type(value) is str and value in get_args(AccessTier)


def _field_visible_sql(field_name: str, configured_sources: CataloguePolicyInput) -> Composable:
    """Reuse static SQL cases that continue checking each row's effective record tier."""
    policy = _catalogue_policy(configured_sources)
    policy.validate_field(field_name)
    return policy.field_sql[field_name]


def field_required_tier(
    dataset: Dataset,
    field_name: str,
    *,
    configured_sources: CataloguePolicyInput,
) -> AccessTier:
    """Return the stricter code, source and effective stored/administrator tier.

    The approved public discovery envelope remains exempt from the record floor.
    Callers must provide their selected source snapshot. An empty selection
    keeps non-discovery metadata from unselected sources at the vetted tier.
    """
    policy = _catalogue_policy(configured_sources)
    minimum = policy.minimum(field_name, dataset.source)
    record_rank = tier_rank(dataset.visibility_tier)
    if field_name in policy.discovery_fields:
        return minimum
    return dataset.visibility_tier if record_rank >= tier_rank(minimum) else minimum


def can_view_field(
    dataset: Dataset,
    user_tier: AccessTier,
    field_name: str,
    *,
    configured_sources: CataloguePolicyInput,
) -> bool:
    """Return whether the viewer meets a field's effective metadata minimum."""
    return can_access(
        user_tier,
        field_required_tier(dataset, field_name, configured_sources=configured_sources),
    )


def _redacted_values() -> dict[str, Any]:
    """Return redaction defaults with fresh lists; keys define the redacted-field policy."""
    return {
        "project_title": None,
        "description": None,
        "resource_description": None,
        "languages": [],
        "project_description": None,
        "authors": [],
        "keywords": [],
        "resource_proxies": [],
        "resource_access_url": None,
        "landing_page_url": None,
        "license_val": None,
        "license_url": None,
        "doi": None,
        "resource_type": None,
        "bibliographical_citation": None,
    }


def filter_for_tier(
    dataset: Dataset,
    user_tier: AccessTier,
    *,
    configured_sources: CataloguePolicyInput,
) -> Dataset:
    """Return dataset itself when every field is allowed, otherwise a redacted copy.

    Evaluate each field independently. Hidden fields receive their declared
    scalar/list defaults, with fresh lists on every redacted copy. The input
    and its visible values are not mutated.
    """
    policy = _catalogue_policy(configured_sources)
    hidden = {
        name
        for name in policy.field_names
        if not can_view_field(dataset, user_tier, name, configured_sources=policy)
    }
    if not hidden:
        return dataset
    defaults = _redacted_values()
    values = {
        name: defaults[name] if name in hidden else getattr(dataset, name)
        for name in policy.field_names
    }
    return Dataset(**values)


def assert_field_visibility_total() -> None:
    """Require a total valid field matrix and a safe, complete redaction partition.

    Public discovery/search minima remain public. All representations of the
    same resource/landing targets require equal minima, so a derived URL cannot
    bypass a stricter proxy policy. This assertion runs during process startup.
    """
    classified = PUBLIC_DISCOVERY_FIELDS | _redacted_values().keys()
    all_fields = {f.name for f in dataclass_fields(Dataset)}
    missing = all_fields - classified
    overlap = PUBLIC_DISCOVERY_FIELDS & _redacted_values().keys()
    unknown = classified - all_fields
    unapproved_search = PUBLIC_SEARCH_FIELDS - PUBLIC_DISCOVERY_FIELDS
    if not isinstance(FIELD_VISIBILITY, Mapping):
        # Startup policy invariants consistently use AssertionError.
        raise AssertionError("FIELD_VISIBILITY must be a field-to-tier mapping")  # noqa: TRY004
    matrix_fields = set(FIELD_VISIBILITY)
    missing_matrix = all_fields - matrix_fields
    unknown_matrix = matrix_fields - all_fields
    invalid_names = {name for name in matrix_fields if type(name) is not str}
    invalid_tiers = {
        name for name, minimum in FIELD_VISIBILITY.items() if not _is_field_minimum(minimum)
    }
    nonpublic_discovery = {
        name
        for name in PUBLIC_DISCOVERY_FIELDS & matrix_fields
        if FIELD_VISIBILITY[name] != "public"
    }
    nonpublic_search = {
        name for name in PUBLIC_SEARCH_FIELDS & matrix_fields if FIELD_VISIBILITY[name] != "public"
    }
    resource_minima = {
        FIELD_VISIBILITY[name]
        for name in RESOURCE_URL_FIELDS & matrix_fields
        if name not in invalid_tiers
    }
    resource_mismatch = len(resource_minima) > 1
    if (
        missing
        or overlap
        or unknown
        or unapproved_search
        or missing_matrix
        or unknown_matrix
        or invalid_names
        or invalid_tiers
        or nonpublic_discovery
        or nonpublic_search
        or resource_mismatch
    ):
        raise AssertionError(
            f"Field visibility classification incomplete — "
            f"unclassified fields: {sorted(missing)}; in both sets: {sorted(overlap)}; "
            f"not Dataset fields: {sorted(unknown)}; "
            f"publicly searchable but not public-discovery fields: "
            f"{sorted(unapproved_search)}; "
            f"matrix missing fields: {sorted(missing_matrix)}; "
            f"matrix unknown fields: {sorted(unknown_matrix, key=repr)}; "
            f"invalid matrix field names: {sorted(invalid_names, key=repr)}; "
            f"invalid matrix tiers: {sorted(invalid_tiers, key=repr)}; "
            f"nonpublic discovery minima: {sorted(nonpublic_discovery)}; "
            f"nonpublic search minima: {sorted(nonpublic_search)}; "
            f"resource URL minimum mismatch: {resource_mismatch}"
        )

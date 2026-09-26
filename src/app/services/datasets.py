"""Query PostgreSQL catalogue metadata and redact it for the caller's tier.

Database errors propagate. Public query helpers apply metadata visibility;
access_level describes upstream resource access and does not authorize it.
"""

import logging
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from datetime import UTC, datetime
from typing import Any

from psycopg import sql
from psycopg.rows import tuple_row
from psycopg.sql import Composable
from psycopg_pool import AsyncConnectionPool

from .access_tiers import TIER_CASE_SQL, AccessTier, can_access, tier_rank
from .db import get_db_cursor
from .parsed_record import ParsedRecord
from .schema import (
    DATASET_COMPUTED_FIELDS,
    DATASET_INSERT_COLUMNS,
    DATASET_SELECT_COLUMNS,
    DATASET_SELECT_SQL,
    PARSER_OWNED,
    build_record_params,
)
from .schema_invariants import assert_columns_match_dataclass

logger = logging.getLogger(__name__)


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
    source: str = "swissubase"
    visibility_tier: AccessTier = "vetted"


def _parse_dataset(row: dict[str, Any]) -> Dataset:
    """Build a Dataset from every DATASET_SELECT_COLUMNS key; missing keys raise KeyError.

    Normalize empty fields, log and skip malformed authors, and derive access
    and landing URLs from the first truthy matching resource-proxy references.
    """
    row_authors = row.get("authors") or []
    parsed_authors = []

    for a in row_authors:
        if isinstance(a, str):
            parsed_authors.append(Author(name=a))
        elif isinstance(a, dict) and "name" in a:
            parsed_authors.append(Author(name=a["name"]))
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
        source=values["source"] or "swissubase",
        visibility_tier=values["visibility_tier"] or "vetted",
        resource_access_url=resource_access_url,
        landing_page_url=landing_page_url,
    )
    return Dataset(**values)


_DATASET_ORDER_SQL = sql.SQL("upstream_modified_at DESC NULLS LAST, id DESC")


async def search_datasets(
    pool: AsyncConnectionPool,
    user_tier: AccessTier,
    search_text: str = "",
    keyword: str = "",
    language: str = "",
    access_level: str = "",
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Dataset], int]:
    """Return a redacted page and matching count, newest upstream timestamp first.

    search_text is a trimmed, case-insensitive literal substring: title and
    access level always match, other indexed metadata only at an allowed
    tier. Nonempty keyword/language filters require exact array membership
    and allowed visibility; access_level is an exact, ungated match. Empty
    filters impose no restriction. page is one-based; callers must provide
    a positive page and page_size. Ties sort by descending ID, NULL dates last.

    An empty later page triggers a separate count query that can observe
    concurrent changes. page_size=0 on page 1 returns zero without counting.
    """
    offset = (page - 1) * page_size
    rank = tier_rank(user_tier)
    fts_clause: Composable

    visible_to_user = sql.SQL("""{tier_case} <= %(rank)s""").format(tier_case=TIER_CASE_SQL)

    term = search_text.strip()
    if term:
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        fts_clause = sql.SQL(
            "(search_text_public ILIKE %(pattern)s"
            " OR (search_text_full ILIKE %(pattern)s AND {visible}))"
        ).format(visible=visible_to_user)
    else:
        pattern = None
        fts_clause = sql.SQL("TRUE")

    where_clause = sql.SQL("""
            {fts}
            AND (%(keyword)s = ''  OR (keywords  @> ARRAY[%(keyword)s]  AND {visible}))
            AND (%(language)s = '' OR (languages @> ARRAY[%(language)s] AND {visible}))
            AND (%(access_level)s = '' OR access_level = %(access_level)s)
    """).format(fts=fts_clause, visible=visible_to_user)

    sql_query = sql.SQL("""
        SELECT {columns}, COUNT(*) OVER() AS total_count
        FROM oral_history_datasets
        WHERE {where}
        ORDER BY {order}
        LIMIT %(limit)s OFFSET %(offset)s
    """).format(columns=DATASET_SELECT_SQL, where=where_clause, order=_DATASET_ORDER_SQL)

    params = {
        "rank": rank,
        "pattern": pattern,
        "keyword": keyword,
        "language": language,
        "access_level": access_level,
        "limit": page_size,
        "offset": offset,
    }

    async with get_db_cursor(pool) as cur:
        await cur.execute(sql_query, params)
        rows = await cur.fetchall()

    if not rows:
        if offset == 0:
            return [], 0
        count_query = sql.SQL("SELECT COUNT(*) FROM oral_history_datasets WHERE {where}").format(
            where=where_clause
        )
        async with get_db_cursor(pool, row_factory=tuple_row) as cur:
            await cur.execute(count_query, params)
            row = await cur.fetchone()
        return [], (row[0] if row else 0)

    total_count = rows[0]["total_count"]
    datasets = [filter_for_tier(_parse_dataset(row), user_tier) for row in rows]
    return datasets, total_count


async def get_global_catalogue_stats(
    pool: AsyncConnectionPool,
) -> tuple[int, datetime | None]:
    """Return (dataset count, UTC rebuild time or None) from one statement snapshot.

    Raises RuntimeError if no row is returned and TypeError for unexpected
    count or timestamp types.
    """
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM oral_history_datasets) AS total_datasets,
                (
                    SELECT last_full_rebuild_date
                    FROM sync_status
                    WHERE id = 1
                ) AS last_full_rebuild
            """
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


async def get_total_dataset_count(pool: AsyncConnectionPool) -> int:
    """Return the tier-independent dataset count, or zero if no aggregate row arrives."""
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute("SELECT COUNT(*) FROM oral_history_datasets")
        row = await cur.fetchone()
        return row[0] if row else 0


async def get_recent_datasets(
    pool: AsyncConnectionPool, user_tier: AccessTier, limit: int = 3
) -> list[Dataset]:
    """Return up to nonnegative limit redacted rows, newest upstream timestamp first.

    NULL dates sort last; ties sort by descending ID.
    """

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("""
            SELECT {}
                FROM oral_history_datasets
                ORDER BY {} LIMIT %s
            """).format(DATASET_SELECT_SQL, _DATASET_ORDER_SQL),
            (limit,),
        )
        rows = await cur.fetchall()

    return [filter_for_tier(_parse_dataset(row), user_tier) for row in rows]


async def get_keyword_count(pool: AsyncConnectionPool, user_tier: AccessTier) -> int:
    """Count distinct nonempty keywords in datasets visible to user_tier."""
    rank = tier_rank(user_tier)
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute(
            sql.SQL("""
            SELECT COUNT(DISTINCT kw) FROM (
                SELECT unnest(keywords) AS kw
                FROM oral_history_datasets
                WHERE {tier_case} <= %(rank)s
            ) t
            WHERE kw IS NOT NULL AND kw <> ''
            """).format(tier_case=TIER_CASE_SQL),
            {"rank": rank},
        )
        row = await cur.fetchone()
        return row[0] if row else 0


async def get_home_metadata_counts(
    pool: AsyncConnectionPool,
    user_tier: AccessTier,
) -> tuple[int, int]:
    """Return (distinct nonempty languages, keywords) for visible datasets.

    Raises RuntimeError if the aggregate returns no row.
    """
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute(
            sql.SQL("""
                WITH visible AS MATERIALIZED (
                    SELECT languages, keywords FROM oral_history_datasets
                    WHERE {tier_case} <= %(rank)s
                )
                SELECT
                    (SELECT COUNT(DISTINCT value) FROM visible,
                     LATERAL unnest(languages) AS value WHERE value <> ''),
                    (SELECT COUNT(DISTINCT value) FROM visible,
                     LATERAL unnest(keywords) AS value WHERE value <> '')
            """).format(tier_case=TIER_CASE_SQL),
            {"rank": tier_rank(user_tier)},
        )
        row = await cur.fetchone()
    if row is None:
        raise RuntimeError("Home metadata aggregate returned no row")
    return int(row[0]), int(row[1])


FACET_SAMPLE_SIZE = 200
FACET_OPTION_LIMIT = 50


async def get_facets(pool: AsyncConnectionPool, user_tier: AccessTier) -> dict[str, list[str]]:
    """Return sorted keywords, languages, and access_levels suggestions.

    Use the newest 200 rows and first 100 keyword/language entries per row,
    then keep at most 50 values per facet. Keyword/language values require
    allowed visibility; access levels do not. Keywords require at least two
    occurrences, including duplicates within one row. Exact search filters
    are not limited to this sample.
    """
    rank = tier_rank(user_tier)
    query = sql.SQL("""
        WITH recent AS MATERIALIZED (
            SELECT keywords[1:100] AS keywords, languages[1:100] AS languages,
                   access_level, visibility_tier
            FROM oral_history_datasets
            ORDER BY upstream_modified_at DESC NULLS LAST, id DESC
            LIMIT %(sample_size)s
        ), combined AS (
            SELECT 'keyword' AS facet, unnest(keywords) AS value
                FROM recent WHERE {tier_case} <= %(rank)s
            UNION ALL
            SELECT 'language', unnest(languages)
                FROM recent WHERE {tier_case} <= %(rank)s
            UNION ALL
            SELECT 'access_level', access_level FROM recent
        ), ranked AS (
            SELECT facet, value,
                   ROW_NUMBER() OVER (PARTITION BY facet ORDER BY value) AS position
            FROM combined WHERE value IS NOT NULL AND value != ''
            GROUP BY facet, value
            HAVING facet != 'keyword' OR COUNT(*) >= 2
        )
        SELECT facet, value FROM ranked WHERE position <= %(option_limit)s
        ORDER BY facet, value
        """).format(tier_case=TIER_CASE_SQL)

    facets: dict[str, list[str]] = {
        "keywords": [],
        "languages": [],
        "access_levels": [],
    }

    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute(
            query,
            {"rank": rank, "sample_size": FACET_SAMPLE_SIZE, "option_limit": FACET_OPTION_LIMIT},
        )
        for facet, value in await cur.fetchall():
            if facet == "keyword":
                facets["keywords"].append(value)
            elif facet == "language":
                facets["languages"].append(value)
            elif facet == "access_level":
                facets["access_levels"].append(value)

    return facets


async def get_dataset_by_id(
    pool: AsyncConnectionPool, dataset_id: int, user_tier: AccessTier
) -> Dataset | None:
    """Return the tier-redacted dataset, or None when its ID is absent."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("SELECT {} FROM oral_history_datasets WHERE id = %s").format(
                DATASET_SELECT_SQL
            ),
            (dataset_id,),
        )
        row = await cur.fetchone()
        if not row:
            return None
        return filter_for_tier(_parse_dataset(row), user_tier)


async def get_last_full_rebuild_date(pool: AsyncConnectionPool) -> datetime | None:
    """Return the stored last-full-rebuild timestamp in UTC, or None if absent."""
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute("SELECT last_full_rebuild_date FROM sync_status WHERE id = 1")
        row = await cur.fetchone()
        if not row:
            return None
        rebuilt_at: datetime | None = row[0]
        if rebuilt_at is None:
            return None
        return rebuilt_at.astimezone(UTC)


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
    """Raise AssertionError on parser/insert-column drift using one synthetic record."""
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


def can_view_full(dataset: Dataset, user_tier: AccessTier) -> bool:
    """Return whether user_tier permits dataset.visibility_tier."""
    return can_access(user_tier, dataset.visibility_tier)


# Security boundary: every value in these fields is deliberately disclosed to
# anonymous users for every dataset, including records whose full metadata
# requires the registered or vetted tier. Sources must guarantee that the
# values are safe for unrestricted publication both individually and in
# combination. Changing this set is a policy decision, not a presentation tweak.
PUBLIC_DISCOVERY_FIELDS = frozenset(
    {
        "id",
        "uuid",
        "title",
        "access_level",
        "version",
        "source",
        "visibility_tier",
    }
)

# Only this subset participates in ungated free-text search for above-tier
# records. The database trigger that builds search_text_public is pinned to
# this exact set by the tier tests and by the runtime schema contract.
PUBLIC_SEARCH_FIELDS = frozenset({"title", "access_level"})


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


def filter_for_tier(dataset: Dataset, user_tier: AccessTier) -> Dataset:
    """Return dataset itself when allowed, otherwise a new redacted Dataset.

    The copy retains PUBLIC_DISCOVERY_FIELDS and resets every other field
    using _redacted_values(), including fresh lists.
    """
    if can_view_full(dataset, user_tier):
        return dataset
    visible = {name: getattr(dataset, name) for name in PUBLIC_DISCOVERY_FIELDS}
    return Dataset(**visible, **_redacted_values())


def assert_redaction_total() -> None:
    """Raise AssertionError unless every Dataset field has exactly one disclosure policy.

    Reject unknown policy fields and PUBLIC_SEARCH_FIELDS outside
    PUBLIC_DISCOVERY_FIELDS.
    """
    classified = PUBLIC_DISCOVERY_FIELDS | _redacted_values().keys()
    all_fields = {f.name for f in dataclass_fields(Dataset)}
    missing = all_fields - classified
    overlap = PUBLIC_DISCOVERY_FIELDS & _redacted_values().keys()
    unknown = classified - all_fields
    unapproved_search = PUBLIC_SEARCH_FIELDS - PUBLIC_DISCOVERY_FIELDS
    if missing or overlap or unknown or unapproved_search:
        raise AssertionError(
            f"filter_for_tier classification incomplete — "
            f"unclassified fields: {sorted(missing)}; in both sets: {sorted(overlap)}; "
            f"not Dataset fields: {sorted(unknown)}; "
            f"publicly searchable but not public-discovery fields: "
            f"{sorted(unapproved_search)}"
        )

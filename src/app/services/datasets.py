"""Dataset data service — abstraction layer between routes and data.

Reads from the PostgreSQL oral_history_datasets table. The public API
functions (search_datasets, get_facets, etc.) are used by routes; internal
helpers (prefixed _) should not be accessed directly.
"""
import logging
from datetime import timezone

from dataclasses import dataclass, field, fields as dataclass_fields
from psycopg import sql
from psycopg_pool import AsyncConnectionPool
from psycopg.rows import tuple_row
from psycopg.sql import Composable
from typing import Any


from .access_tiers import AccessTier, can_access, tier_rank
from .db import get_db_cursor
from .schema import (
    DATASET_SELECT_SQL, 
    DATASET_SELECT_COLUMNS, 
    DATASET_COMPUTED_FIELDS, 
    DATASET_INSERT_COLUMNS, 
    DATASET_COLUMNS
)

logger = logging.getLogger(__name__)

# =============================================================================
# Data models
# =============================================================================

@dataclass
class Author:
    """A dataset author (single name field)."""
    name: str

@dataclass
class Dataset:
    """A single oral history dataset record.

    Authorization uses two independent fields:

    - access_level: Download restriction from the upstream source
      (e.g., "public", "restricted"). Set automatically during sync
      based on the OAI-PMH license field. Controls whether a user
      can access the actual resource (recordings, transcripts).

    - visibility_tier: Metadata visibility level ("public",
      "registered", "vetted"). Set per-dataset by administrators.
      Controls which metadata fields are shown to a given user —
      users below the required tier see a redacted view
      (title and access_level only, via filter_for_tier).

    These are intentionally orthogonal: a dataset can be publicly
    visible (metadata browsable by anyone) but restricted for
    download, or vice versa.
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
    download_url: str | None = None
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
    

# =============================================================================
# Internal: load and parse
# =============================================================================

def _parse_dataset(row: dict[str, Any]) -> Dataset:
    """Parse a DB row (dict) into a Dataset dataclass."""
    row_authors = row.get("authors") or []
    parsed_authors = []
    license_val = row.get("license_val") or ""

    for a in row_authors:
        if isinstance(a, str):
            parsed_authors.append(Author(name=a))
        elif isinstance(a, dict) and "name" in a:
            parsed_authors.append(Author(name=a["name"]))
        else:
            logger.warning("Skipping malformed author entry: %r", a) 
            continue

    proxies = row.get("resource_proxies") or []
    download_url = None
    landing_page_url = None
    if isinstance(proxies, list):
        for proxy in proxies:
            if isinstance(proxy, dict):
                proxy_type = proxy.get("type") or ""
                if proxy_type == "Resource" and not download_url:
                    download_url = proxy.get("ref")
                elif proxy_type == "LandingPage" and not landing_page_url:
                    landing_page_url = proxy.get("ref")

    return Dataset(
        id=row["id"],
        uuid=row["uuid"],
        title=row["title"] or "(untitled)",
        project_title=row.get("project_title"),
        description=row.get("description"),
        resource_description=row.get("resource_description"),
        languages=row.get("languages") or [],
        project_description=row.get("project_description"),
        authors=parsed_authors,
        keywords=row.get("keywords") or [],
        resource_proxies=row.get("resource_proxies") or [],
        download_url=download_url,
        landing_page_url=landing_page_url,
        license_val=license_val,
        license_url=row.get("license_url"),
        access_level=row.get("access_level") or "restricted",
        version=row.get("version"),
        doi=row.get("doi"),
        resource_type=row.get("resource_type"),
        bibliographical_citation=row.get("bibliographical_citation"),
        source=row.get("source") or "swissubase",
        visibility_tier=row.get("visibility_tier") or "vetted",
    )

# =============================================================================
# Public API
# =============================================================================

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
    """Search datasets with substring matching and exact-match filters.

    Every filter is tier-aware: a user only matches metadata on a dataset
    whose ``visibility_tier`` their tier permits. The sole exception is the
    always-public blob (title + access level), matchable on every dataset
    so the catalogue stays browsable.

    - Free-text search matches the public blob (title + access level) on
      every dataset, and the full blob (description, project fields,
      keywords, authors) only on datasets the user may fully see.
    - The ``keyword`` and ``language`` filters match ONLY on datasets the
      user may fully see. Those fields are redacted by ``filter_for_tier``
      for below-tier users, so an un-gated filter would leak their values
      as a presence/absence oracle (a below-tier user could confirm a
      hidden dataset carries a guessed keyword/language). Gating them here
      closes that oracle while leaving redacted browse-by-title intact.
    - The ``access_level`` filter is deliberately NOT tier-gated: access
      level is shown on every dataset (including redacted ones), so
      filtering on it reveals nothing the user cannot already see.

    This function governs which rows *match* — the part that determines what
    the result set and its ``total_count`` disclose. Restricted fields on the
    returned rows are redacted via ``filter_for_tier``.
    """
    offset = (page - 1) * page_size
    rank = tier_rank(user_tier)  
    fts_clause: Composable

    visible_to_user = sql.SQL(
        """(CASE visibility_tier
                WHEN 'public'     THEN 0
                WHEN 'registered' THEN 1
                WHEN 'vetted'     THEN 2
                ELSE 99
            END) <= %(rank)s"""
    )
    
    if search_text.strip():
        escaped = (
            search_text
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        pattern = f"%{escaped}%"
        fts_clause = sql.SQL(
            "(search_text_public ILIKE %(pattern)s"
            " OR (search_text_full ILIKE %(pattern)s AND {visible}))"
        ).format(visible=visible_to_user)
    else:
        pattern = None
        fts_clause = sql.SQL("TRUE")

    # PERF TODO (LOW, pre-Phase-2): this ends `ORDER BY last_modified DESC LIMIT`,
    # which is a full-table sort — unindexed today. Add in the next migration:
    #   CREATE INDEX ix_datasets_last_modified ON oral_history_datasets (last_modified DESC);   
    # Additionally `%s = ANY(keywords)` is a seq-scan per filter, and a
    # plain GIN index does NOT serve `= ANY` (only @> / <@ / && / =). To index this, BOTH:
    #   (1) migration: CREATE INDEX ... USING GIN (keywords);  (and languages)
    #   (2) rewrite this to `keywords @> ARRAY[%s]` (semantically identical for single
    #       values, and @> is GIN-served). The index alone does nothing without the rewrite.
    # Fine at current catalogue size; a cost cliff at Source-B scale.

    sql_query = sql.SQL("""
        SELECT {columns}, COUNT(*) OVER() AS total_count
        FROM oral_history_datasets
        WHERE
            {fts}
            -- keyword/language: only match rows the user may fully see, so the
            -- filter can't probe redacted facet values (see docstring).
            AND (%(keyword)s = ''  OR (%(keyword)s = ANY(keywords)  AND {visible}))
            AND (%(language)s = '' OR (%(language)s = ANY(languages) AND {visible}))
            -- access_level is visible on redacted rows; no tier gate needed.
            AND (%(access_level)s = '' OR access_level = %(access_level)s)
        ORDER BY last_modified DESC
        LIMIT %(limit)s OFFSET %(offset)s
    """).format(
        columns=DATASET_SELECT_SQL,
        fts=fts_clause,
        visible=visible_to_user,
    )

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
        return [], 0

    total_count = rows[0]["total_count"]
    datasets = [filter_for_tier(_parse_dataset(row), user_tier) for row in rows]
    return datasets, total_count


async def get_collection_datasets(
    pool: AsyncConnectionPool, 
    user_tier: AccessTier, 
    limit: int = 50
) -> list[Dataset]:
    """Return tier-visible datasets that share a keyword with at least one other.

    Currently unused: no route calls this function and it is not exported
    from app.services. Results are limited to datasets whose
    visibility_tier the given user_tier permits, redacted via
    filter_for_tier.

    TODO: Support filtering by predefined collection IDs. Currently the
    implicit "shared keywords" collection (keywords appearing in at least
    two visible records) is the only grouping. Planned for a next step.
    """
    rank = tier_rank(user_tier)
    query = sql.SQL("""
        WITH visible AS (
            SELECT * FROM oral_history_datasets
            WHERE (CASE visibility_tier WHEN 'public' THEN 0
                WHEN 'registered' THEN 1 WHEN 'vetted' THEN 2 ELSE 99 END) <= %(rank)s
        ),
        shared_keywords AS (
            SELECT kw FROM (SELECT DISTINCT id, unnest(keywords) AS kw FROM visible) t
            GROUP BY kw HAVING count(*) >= 2
        )
        SELECT {fields} FROM visible
        WHERE keywords && (SELECT coalesce(array_agg(kw), '{{}}') FROM shared_keywords)
        ORDER BY last_modified DESC
        LIMIT %(limit)s
    """).format(fields=DATASET_SELECT_SQL)

    async with get_db_cursor(pool) as cur:
        await cur.execute(query, {"rank": rank, "limit": limit})
        return [filter_for_tier(_parse_dataset(row), user_tier) for row in await cur.fetchall()]


async def get_recent_datasets(pool: AsyncConnectionPool, user_tier: AccessTier, limit: int = 3) -> tuple[list[Dataset], int]:
    """Returns (recent_datasets, total_count) without loading the full table."""
    async with get_db_cursor(pool) as cur:
        await cur.execute("SELECT COUNT(*) AS cnt FROM oral_history_datasets")
        row = await cur.fetchone()
        total = row["cnt"] if row else 0

        await cur.execute(
            sql.SQL("SELECT {} FROM oral_history_datasets ORDER BY last_modified DESC LIMIT %s")
            .format(DATASET_SELECT_SQL),
            (limit,),
        )
        datasets = [filter_for_tier(_parse_dataset(row), user_tier) for row in await cur.fetchall()]

    return datasets, total

async def get_keyword_count(pool: AsyncConnectionPool, user_tier: AccessTier) -> int:
    """True count of distinct keywords visible at this tier.

    Unlike get_facets (which drops singletons to de-noise the sidebar), this
    counts every distinct keyword — for the home-page stat. Still tier-scoped,
    so it never reveals keywords from datasets above the user's tier.
    """
    rank = tier_rank(user_tier)
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute(
            """
            SELECT COUNT(DISTINCT kw) FROM (
                SELECT unnest(keywords) AS kw
                FROM oral_history_datasets
                WHERE (CASE visibility_tier WHEN 'public' THEN 0
                       WHEN 'registered' THEN 1 WHEN 'vetted' THEN 2
                       ELSE 99 END) <= %(rank)s
            ) t
            WHERE kw IS NOT NULL AND kw <> ''
            """,
            {"rank": rank},
        )
        row = await cur.fetchone()
        return row[0] if row else 0

async def get_facets(pool: AsyncConnectionPool, user_tier: AccessTier ) -> dict[str, list[str]]:
    """Fetch unique keywords, languages, and access levels in one round-trip.

    Tier-scoped: only datasets at or below the user's visibility tier
    contribute facet values, so the sidebar can't enumerate keywords or
    languages that occur only in datasets the user can't see.

    Keywords are filtered to those appearing in at least two datasets
    to reduce noise in the search sidebar. This threshold can be adjusted
    in the HAVING clause below.
    """
    rank = tier_rank(user_tier)
    query = """
        SELECT facet, value FROM (
            SELECT 'keyword' AS facet, unnest(keywords) AS value
                FROM oral_history_datasets
                WHERE (CASE visibility_tier WHEN 'public' THEN 0
                    WHEN 'registered' THEN 1 WHEN 'vetted' THEN 2
                    ELSE 99 END) <= %(rank)s
            UNION ALL
            SELECT 'language', unnest(languages) 
                FROM oral_history_datasets
                WHERE (CASE visibility_tier WHEN 'public' THEN 0
                        WHEN 'registered' THEN 1 WHEN 'vetted' THEN 2
                        ELSE 99 END) <= %(rank)s
            UNION ALL
            SELECT 'access_level', access_level 
                FROM oral_history_datasets
                WHERE (CASE visibility_tier WHEN 'public' THEN 0
                       WHEN 'registered' THEN 1 WHEN 'vetted' THEN 2
                       ELSE 99 END) <= %(rank)s
        ) AS combined_facets
        WHERE value IS NOT NULL AND value != ''
        GROUP BY facet, value
        HAVING facet != 'keyword' OR COUNT(*) >= 2
        ORDER BY facet, value
    """
    
    facets: dict[str, list[str]] = {
        "keywords": [],
        "languages": [],
        "access_levels": [],
    }
    
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute(query, {"rank": rank})
        for facet, value in await cur.fetchall():
            if facet == 'keyword':
                facets["keywords"].append(value)
            elif facet == 'language':
                facets["languages"].append(value)
            elif facet == 'access_level':
                facets["access_levels"].append(value)
                    
    return facets


async def get_dataset_by_id(pool: AsyncConnectionPool, dataset_id: int, user_tier: AccessTier) -> Dataset | None:
    """Fetch a dataset by id, already redacted for `user_tier`.

    Returns a tier-filtered Dataset (below-tier callers get title + access_level
    only) or None if no row exists. Redaction is applied here so no caller can
    render an unredacted row. `visibility_tier` is preserved on the result, so
    callers can still audit the access decision via can_view_full().
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("SELECT {} FROM oral_history_datasets WHERE id = %s").format(DATASET_SELECT_SQL),
            (dataset_id,),
        )
        row = await cur.fetchone()
        if not row:
            return None
        return filter_for_tier(_parse_dataset(row), user_tier)


async def get_last_full_rebuild_date(pool: AsyncConnectionPool) -> str | None:
    """Get the last *full rebuild* date, formatted for display.

    This is when the dataset table was last fully reconciled against the 
    upstream source (stale versions removed), so it is the meaningful
    "data complete and consistent as of" marker. Incremental syncs run
    more often but cannot detect in-place upstream updates, so they are
    tracked separately as sync_status.last_harvest_date.

    Returns None if a full rebuild has not completed yet.
    """
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute("SELECT last_full_rebuild_date FROM sync_status WHERE id = 1")
        row = await cur.fetchone()
        if not row or not row[0]:
            return None
        return row[0].astimezone(timezone.utc).strftime('%d %B %Y, %H:%M UTC')

def validate_dataset_schema() -> None:
    """Verify that DATASET_SELECT_COLUMNS and Dataset fields are in sync.

    Catches drift between the SQL column list and the Python dataclass.
    Raises AssertionError with a clear message if they diverge.
    """
    dataclass_field_names = {
        f.name for f in dataclass_fields(Dataset)
    } - DATASET_COMPUTED_FIELDS

    select_columns = set(DATASET_SELECT_COLUMNS)

    missing_from_dataclass = select_columns - dataclass_field_names
    missing_from_select = dataclass_field_names - select_columns

    errors = []
    if missing_from_dataclass:
        errors.append(
            f"Columns in SELECT but not on Dataset: {missing_from_dataclass}"
        )
    if missing_from_select:
        errors.append(
            f"Fields on Dataset but not in SELECT: {missing_from_select}"
        )

    if errors:
        raise AssertionError(
            "DATASET_SELECT_COLUMNS / Dataset mismatch: "
            + "; ".join(errors)
        )

def validate_dataset_insert_schema() -> None:
    """Verify INSERT column list matches what _build_record_params emits.

    Catches drift between DATASET_INSERT_COLUMNS and the record-to-tuple
    construction in sync.py. Runs at startup so ordering bugs fail loudly.
    """
    expected_trailing = ["data", "last_modified"]
    if DATASET_INSERT_COLUMNS[:len(DATASET_COLUMNS)] != DATASET_COLUMNS:
        raise AssertionError(
            "DATASET_INSERT_COLUMNS must start with DATASET_COLUMNS in order."
        )
    if DATASET_INSERT_COLUMNS[len(DATASET_COLUMNS):] != expected_trailing:
        raise AssertionError(
            f"DATASET_INSERT_COLUMNS must end with {expected_trailing}, "
            f"got {DATASET_INSERT_COLUMNS[len(DATASET_COLUMNS):]}"
        )

# =============================================================================
# Access-tier visibility
# =============================================================================

def can_view_full(dataset: Dataset, user_tier: AccessTier) -> bool:
    """Check if a user's access tier allows full metadata visibility.

    Compares the user's tier against the dataset's visibility_tier.
    The visibility_tier is set per-dataset in the database, allowing
    fine-grained control independent of access_level (download restrictions).
    """
    return can_access(user_tier, dataset.visibility_tier)


_TIER_VISIBLE_FIELDS = frozenset({
    "id", "uuid", "title", "access_level", "version", "source", "visibility_tier",
})

def _redacted_values() -> dict:
    """Return the redacted value for every non-visible Dataset field.

    A function rather than a module constant so each redacted Dataset gets
    its own fresh list objects — a shared [] would be aliased across every
    redacted dataset, so an in-place mutation on one would leak onto all.
    Keys are the authoritative set of redacted fields (see assert_redaction_total).
    """
    return {
        "project_title": None, 
        "description": None, 
        "resource_description": None,
        "languages": [], 
        "project_description": None, 
        "authors": [], 
        "keywords": [],
        "resource_proxies": [], 
        "download_url": None, 
        "landing_page_url": None,
        "license_val": None, 
        "license_url": None, 
        "doi": None,
        "resource_type": None, 
        "bibliographical_citation": None,
    }

def filter_for_tier(dataset: Dataset, user_tier: AccessTier) -> Dataset:
    """Return a copy of the dataset with restricted fields redacted.

    If the user's tier is sufficient, the dataset is returned unchanged.
    Otherwise a new Dataset is built from two sources: the tier-visible
    fields (_TIER_VISIBLE_FIELDS) copied from the original, and every other
    field reset to its redacted value (_redacted_values()). A below-tier viewer
    keeps only id, uuid, title, access_level, version, source and
    visibility_tier.

    Every Dataset field must appear in exactly one of those two sets;
    assert_redaction_total() enforces this at startup, so a newly added field
    fails fast rather than silently leaking or vanishing.
    """
    if can_view_full(dataset, user_tier):
        return dataset
    visible = {name: getattr(dataset, name) for name in _TIER_VISIBLE_FIELDS}
    return Dataset(**visible, **_redacted_values())


def assert_redaction_total() -> None:
    """Verify every Dataset field is classified as visible or redacted, exactly once.

    Builds the classified set from _TIER_VISIBLE_FIELDS and the keys of
    _redacted_values() and compares it against the Dataset dataclass
    fields. A field in neither set would silently leak (or vanish) after
    redaction; a field in both signals a contradictory classification. Runs
    at startup so a newly added field fails fast.

    Raises:
        AssertionError: If any field is unclassified or appears in both sets.
    """
    classified = _TIER_VISIBLE_FIELDS | _redacted_values().keys()
    all_fields = {f.name for f in dataclass_fields(Dataset)}
    missing = all_fields - classified
    overlap = _TIER_VISIBLE_FIELDS & _redacted_values().keys()
    if missing or overlap:
        raise AssertionError(
            f"filter_for_tier classification incomplete — "
            f"unclassified fields: {sorted(missing)}; in both sets: {sorted(overlap)}"
        )
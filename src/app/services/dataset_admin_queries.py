"""Read identity and restriction state for routes protected by administrator policy.

These helpers do not authorize callers. They include hidden/quarantined catalogue
rows and retained unselected sources. Only serving rows receive a public catalogue title;
protected metadata is never read. Durable state without a current catalogue row
remains stored and is not an actionable result.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, get_args

from psycopg import sql
from psycopg_pool import AsyncConnectionPool

from app.sources import AccessTier, SourceMetadata

from .access_tiers import tier_rank
from .dataset_admin import (
    DatasetAdminReason,
    DatasetAdminRejected,
    DatasetAdminState,
    _required_tier,
)
from .db import get_db_cursor
from .sync_state import _validated_source_name

ADMIN_DATASET_UUID_MAX_CHARS = 2048
ADMIN_DATASET_MAX_ID = 2_147_483_647
ADMIN_DATASET_PAGE_SIZE = 20
_MAX_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class DatasetAdminRecord:
    """Identity, serving public title, restrictions and permitted administrator actions."""

    dataset_id: int
    source: str
    uuid: str
    state: DatasetAdminState
    required_tier: AccessTier | None
    raise_block_reason: DatasetAdminReason | None
    public_title: str | None
    quarantined_at: datetime | None = None
    quarantine_reason: str | None = None

    @property
    def allowed_raise_tiers(self) -> tuple[AccessTier, ...]:
        """Return permitted choices, or none when source classification is unavailable."""
        minimum = self.required_tier
        if minimum is None or self.raise_block_reason is not None:
            return ()
        return tuple(tier for tier in get_args(AccessTier) if tier_rank(tier) >= tier_rank(minimum))


@dataclass(frozen=True, slots=True)
class DatasetAdminPage:
    """A bounded identity page; boundaries preserve filters but grant no access."""

    records: list[DatasetAdminRecord]
    newer_id: int | None = None
    older_id: int | None = None


_COLUMNS_SQL = sql.SQL("""
    stored.id, stored.source, stored.uuid, stored.stored_tier,
    admin_state.visibility_tier AS admin_tier, admin_state.hidden_at,
    stored.record_tier, discovery.title AS public_title,
    quarantine.quarantined_at, quarantine.reason AS quarantine_reason
""")
_FROM_SQL = sql.SQL("""
    dataset_admin_catalogue AS stored
    LEFT JOIN dataset_admin_state AS admin_state
      ON admin_state.source = stored.source AND admin_state.uuid = stored.uuid
    LEFT JOIN catalogue_discovery AS discovery ON discovery.id = stored.id
    LEFT JOIN ingestion_quarantine AS quarantine
      ON quarantine.source = stored.source AND quarantine.uuid = stored.uuid
""")
_FILTER_SQL = sql.SQL("""
    (%(uuid)s = '' OR stored.uuid = %(uuid)s)
    AND (%(source)s = '' OR stored.source = %(source)s)
""")


def _parse_record(
    row: dict[str, Any], configured_sources: Sequence[SourceMetadata]
) -> DatasetAdminRecord:
    """Build an administrator record, retaining a source-policy rejection as its reason."""
    state = DatasetAdminState(row["stored_tier"], row["admin_tier"], row["hidden_at"])
    minimum: AccessTier | None
    reason: DatasetAdminReason | None
    try:
        source_floor = _required_tier(
            {"source": row["source"], "data": {"visibility_tier": row["record_tier"]}},
            configured_sources,
        )
    except DatasetAdminRejected as exc:
        minimum = None
        reason = exc.reason
    else:
        resolved_minimum = max((state.effective_tier, source_floor), key=tier_rank)
        minimum = resolved_minimum
        reason = None
    return DatasetAdminRecord(
        row["id"],
        row["source"],
        row["uuid"],
        state,
        minimum,
        reason,
        row["public_title"],
        row["quarantined_at"],
        row["quarantine_reason"],
    )


def _validate_search(
    uuid: str, source: str, after_id: int | None, before_id: int | None, page_size: int
) -> None:
    """Validate bounded UUID/source filters, one positive-ID direction and page size.

    Raise TypeError for a non-string source; other invalid inputs raise ValueError.
    """
    if not isinstance(uuid, str) or len(uuid) > ADMIN_DATASET_UUID_MAX_CHARS or "\x00" in uuid:
        raise ValueError("Invalid dataset UUID filter")
    if not isinstance(source, str):
        raise TypeError("Invalid dataset source filter")
    if source:
        _validated_source_name(source)
    for boundary in (after_id, before_id):
        if boundary is not None and (
            type(boundary) is not int or not 1 <= boundary <= ADMIN_DATASET_MAX_ID
        ):
            raise ValueError("Invalid administrator dataset boundary")
    if after_id is not None and before_id is not None:
        raise ValueError("Choose one administrator dataset direction")
    if type(page_size) is not int or not 1 <= page_size <= _MAX_PAGE_SIZE:
        raise ValueError("Invalid administrator dataset page size")


async def search_admin_datasets(
    pool: AsyncConnectionPool,
    *,
    uuid: str = "",
    source: str = "",
    after_id: int | None = None,
    before_id: int | None = None,
    page_size: int = ADMIN_DATASET_PAGE_SIZE,
    configured_sources: Sequence[SourceMetadata],
) -> DatasetAdminPage:
    """Read at most page_size + 1 identities, including withheld/unselected sources.

    Descending ID keysets avoid global counts and growing offsets. after_id
    requests older identities, before_id newer ones; pass at most one boundary.
    UUID/source filters remain exact and must be retained when following links.
    The discovery view supplies public titles only for serving identities.
    Ingestion/deletion can change results between requests; no snapshot is held.
    configured_sources is required; () marks every source unselected.
    """
    _validate_search(uuid, source, after_id, before_id, page_size)
    selected = tuple(configured_sources)
    boundary = before_id if before_id is not None else after_id
    comparison = sql.SQL(">") if before_id is not None else sql.SQL("<")
    order = sql.SQL("ASC") if before_id is not None else sql.SQL("DESC")
    boundary_sql = (
        sql.SQL("AND stored.id {comparison} %(boundary)s").format(comparison=comparison)
        if boundary is not None
        else sql.SQL("")
    )
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("""
                SELECT {columns} FROM {relation}
                WHERE {predicate} {boundary}
                ORDER BY stored.id {order} LIMIT %(limit)s
            """).format(
                columns=_COLUMNS_SQL,
                relation=_FROM_SQL,
                predicate=_FILTER_SQL,
                boundary=boundary_sql,
                order=order,
            ),
            {"uuid": uuid, "source": source, "limit": page_size + 1, "boundary": boundary},
        )
        rows = await cur.fetchall()
    extra = len(rows) > page_size
    rows = rows[:page_size]
    if before_id is not None:
        rows.reverse()
    records = [_parse_record(row, selected) for row in rows]
    if not records:
        return DatasetAdminPage([])
    has_newer = extra if before_id is not None else after_id is not None
    has_older = before_id is not None or extra
    return DatasetAdminPage(
        records,
        newer_id=records[0].dataset_id if has_newer else None,
        older_id=records[-1].dataset_id if has_older else None,
    )


async def get_admin_dataset_by_id(
    pool: AsyncConnectionPool,
    dataset_id: int,
    *,
    configured_sources: Sequence[SourceMetadata],
) -> DatasetAdminRecord | None:
    """Return controls for a current catalogue ID, even when hidden, or None if absent.

    configured_sources is required; () explicitly disables source-dependent raise
    choices while retaining identity and hide/restore state.
    """
    if type(dataset_id) is not int or dataset_id <= 0:
        raise ValueError("Invalid dataset ID")
    selected = tuple(configured_sources)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("SELECT {columns} FROM {relation} WHERE stored.id = %s").format(
                columns=_COLUMNS_SQL, relation=_FROM_SQL
            ),
            (dataset_id,),
        )
        row = await cur.fetchone()
    return _parse_record(row, selected) if row is not None else None

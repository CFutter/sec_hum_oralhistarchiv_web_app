"""Project configured source state into safe public About-page summaries."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from app.sources import SourceMetadata

from .db import Database, get_db_cursor
from .sync_state import _validated_source_names

_SourceState = Literal["active", "pending", "degraded"]
_STALE_INTERVAL_MULTIPLIER = 2


@dataclass(frozen=True, slots=True)
class SourceStatus:
    """Public presentation fields and a finite status, without source diagnostics."""

    name: str
    label: str
    sensitivity_badge: str | None
    status: _SourceState


def _source_status(
    source: SourceMetadata,
    row: Mapping[str, Any] | None,
    now: datetime,
) -> _SourceState:
    """Classify missing/incomplete runs as pending and failed or overdue runs as degraded."""
    if row is None:
        return "pending"

    harvested_at = row["last_harvest_date"]
    rebuilt_at = row["last_full_rebuild_date"]
    stale = any(
        completed_at is not None
        and (now - completed_at).total_seconds() > _STALE_INTERVAL_MULTIPLIER * interval
        for completed_at, interval in (
            (harvested_at, source.schedule.incremental_interval_seconds),
            (rebuilt_at, source.schedule.rebuild_interval_seconds),
        )
    )
    if row["sync_failed"] or row["rebuild_failed"] or stale:
        return "degraded"
    if harvested_at is None or rebuilt_at is None:
        return "pending"
    return "active"


async def get_source_statuses(
    pool: Database,
    *,
    configured_sources: Sequence[SourceMetadata],
) -> tuple[SourceStatus, ...]:
    """Read public source summaries in configuration order from one SQL snapshot.

    Require nonempty, uniquely named sources before database access. Active
    requires successful harvest/rebuild timestamps no older than twice their
    respective source intervals, with neither error channel set. Missing or
    incomplete clean history is pending; an error or stale completed operation
    is degraded. Database errors propagate to application error handling.

    Query only configured identities and project display text and status;
    endpoint URLs, credentials, timestamps and diagnostic messages stay private.
    """
    sources = tuple(configured_sources)
    names = _validated_source_names(tuple(source.name for source in sources))
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT source, last_harvest_date, last_full_rebuild_date,
                      COALESCE(last_sync_error <> '', FALSE) AS sync_failed,
                      COALESCE(last_rebuild_error <> '', FALSE) AS rebuild_failed
               FROM sync_status
               WHERE source = ANY(%s::text[])""",
            (list(names),),
        )
        by_name = {row["source"]: row for row in await cur.fetchall()}

    now = datetime.now(UTC)
    return tuple(
        SourceStatus(
            name=source.name,
            label=source.display.label,
            sensitivity_badge=source.display.sensitivity_badge,
            status=_source_status(source, by_name.get(source.name), now),
        )
        for source in sources
    )

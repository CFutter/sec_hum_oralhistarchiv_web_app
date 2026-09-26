"""Harvest SWISSUbase and reconcile source-owned PostgreSQL catalogue rows.

run_sync/run_full_rebuild serialize on one event loop and a PostgreSQL
session advisory lock. All ingestion writes must use that session;
*_cur helpers use its current transaction. Fetches use an isolated
worker via a threadpool. Settings control the OAI endpoint, institution
filter, visibility ceiling, and SYNC_WRITE_TIMEOUT_SECONDS.

Fetch/policy failures may return failed SyncOutcome; write, connection,
and cancellation failures can propagate. Incremental batches remain
committed when later work fails. No Source B ingestion is implemented.
"""

import asyncio
import logging
import re
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from psycopg import AsyncConnection, AsyncCursor, DataError, IntegrityError, sql
from psycopg.errors import UniqueViolation
from psycopg_pool import AsyncConnectionPool
from starlette.concurrency import run_in_threadpool

from app.doi import canonicalize_doi
from config import settings

from .access_tiers import SourcePolicy, resolve_tier, tier_case_sql
from .db import Database, get_db_cursor
from .oai_client import HarvestResult, fetch_updates_isolated
from .schema import (
    DATASET_INSERT_COLUMNS,
    DATASET_INSERT_PLACEHOLDERS,
    DATASET_INSERT_SQL,
    build_record_params,
)
from .stored_harvest import (
    StoredHarvestRecoveryRequired,
    build_source_fingerprint,
    decode_stored_harvest,
    encode_stored_harvest_parts,
)

logger = logging.getLogger(__name__)

# Incremental sync and full rebuild mutate the same catalogue and resumable
# state. One stable key therefore serializes both operations across processes.
_SYNC_ADVISORY_LOCK_KEY = 0x4F484153  # "OHAS"

# Avoid occupying multiple pool connections while local jobs wait for the
# cross-process advisory lock.
_sync_mutex = asyncio.Lock()


@asynccontextmanager
async def _cross_process_sync_lock(
    pool: AsyncConnectionPool,
) -> AsyncIterator[AsyncConnection]:
    """Wait for the ingestion advisory lock and yield its autocommit connection.

    Every mutation must use this session so connection loss fences writes.
    On exit unlock and restore transaction mode within five seconds; close
    the connection and propagate failures/cancellation if cleanup fails.
    """
    async with pool.connection() as lock_conn:
        await lock_conn.set_autocommit(True)
        try:
            await lock_conn.execute(
                "SELECT pg_advisory_lock(%s)",
                (_SYNC_ADVISORY_LOCK_KEY,),
            )
            yield lock_conn
        finally:
            # Never return a possibly locked session to the pool. Cancellation
            # or protocol failure during cleanup discards the connection.
            try:
                async with asyncio.timeout(5):
                    await lock_conn.execute(
                        "SELECT pg_advisory_unlock(%s)",
                        (_SYNC_ADVISORY_LOCK_KEY,),
                    )
                    await lock_conn.set_autocommit(False)
            except BaseException:
                await lock_conn.close()
                raise


def _classify_swissubase_access(license_val: str | None) -> str:
    """Return restricted only for a case-insensitive “restricted access” prefix; otherwise public.

    None and leading whitespace do not match. This labels resource access,
    not metadata authorization.
    """
    if (license_val or "").lower().startswith("restricted access"):
        return "restricted"
    return "public"


_SWISSUBASE_POLICY = SourcePolicy(
    name="swissubase",
    max_visibility=settings.swissubase_max_visibility,
    classify_access=_classify_swissubase_access,
)


_DATASET_UPDATE_CLAUSE = sql.SQL(", ").join(
    [
        sql.SQL("{} = EXCLUDED.{}").format(sql.Identifier(c), sql.Identifier(c))
        for c in DATASET_INSERT_COLUMNS
        if c != "visibility_tier"
    ]
    + [
        sql.SQL("""visibility_tier = CASE
            WHEN {stored_rank} >= {incoming_rank}
            THEN oral_history_datasets.visibility_tier
            ELSE EXCLUDED.visibility_tier
        END""").format(
            stored_rank=tier_case_sql("oral_history_datasets"),
            incoming_rank=tier_case_sql("excluded"),
        )
    ]
)

SyncErrorChannel = Literal["incremental", "rebuild"]


class _FullReharvestRequired(RuntimeError):
    """The staged harvest or committed source binding requires a rebuild."""


@dataclass(frozen=True, slots=True)
class SyncOutcome:
    """Catalogue outcome; failed does not necessarily mean no changes committed.

    Incremental affected_count counts successful upserts and actual deleted
    rows, including resumed batches. Rebuilds count successful upserts;
    an empty-match rebuild instead counts requested explicit withdrawals.
    failed_count counts unresolved records, and requires_full_rebuild asks
    the caller to perform authoritative recovery. Fields are not validated.
    """

    status: Literal["success", "partial", "failed"]
    affected_count: int = 0
    failed_count: int = 0
    reason: str | None = None
    requires_full_rebuild: bool = False


_SYNC_ERROR_COLUMNS: dict[SyncErrorChannel, tuple[sql.Identifier, sql.Identifier]] = {
    "incremental": (
        sql.Identifier("last_sync_error"),
        sql.Identifier("last_sync_error_at"),
    ),
    "rebuild": (
        sql.Identifier("last_rebuild_error"),
        sql.Identifier("last_rebuild_error_at"),
    ),
}

_MAX_DISPLAY_ERRORS = 20
_REBUILD_MIN_SUCCESS_DENOM = 2
# A terminal OAI response cannot independently prove that an upstream
# catalogue was complete.  Keep deletions inferred from absence conservative;
# explicit deleted/nonmatching identities are handled separately below.
_REBUILD_MAX_INFERRED_DELETE_COUNT = 100
_REBUILD_MAX_INFERRED_DELETE_RATIO_PERCENT = 25

# Bound incremental transactions by both work and wall time. Per-record
# savepoints retain fault isolation, while one outer commit and progress write
# per batch avoid a durability flush for every harvested identity. These are
# deliberately implementation constants: changing them alters only replay and
# lock-duration bounds, not an operator-facing product policy.
_INCREMENTAL_COMMIT_BATCH_SIZE = 50
_INCREMENTAL_COMMIT_BATCH_MAX_SECONDS = 2.0


class _RebuildAborted(Exception):
    """Signal rollback of a rebuild transaction while retaining existing data."""

    def __init__(self, success_count: int, offered: int) -> None:
        """Store successful/offered record counts and describe the below-half rollback."""
        self.success_count = success_count
        self.offered = offered
        super().__init__(
            f"Full rebuild aborted — only {success_count}/{offered} records "
            "inserted (below threshold); stale-delete rolled back, existing data kept."
        )


class _RebuildContractionAborted(Exception):
    """Signal rollback when absence-based deletion looks like truncation."""

    def __init__(self, existing_count: int, inferred_delete_count: int) -> None:
        """Store remaining-row/deletion counts and describe the contraction rollback."""
        self.existing_count = existing_count
        self.inferred_delete_count = inferred_delete_count
        super().__init__(
            "Full rebuild aborted — upstream would remove "
            f"{inferred_delete_count}/{existing_count} records by absence "
            "(limit: at most "
            f"{_REBUILD_MAX_INFERRED_DELETE_COUNT} records and "
            f"{_REBUILD_MAX_INFERRED_DELETE_RATIO_PERCENT}%); "
            "existing data kept."
        )


def _sanitize_error_message(error_msg: str, max_length: int = 500) -> str:
    """Replace Python-path/traceback patterns and truncate to max_length characters plus an ellipsis.

    Callers supply a nonnegative limit. This is not a general secret or
    filesystem-path scrubber.
    """
    error_msg = re.sub(
        r"(?:[A-Za-z]:)?[\\/]?[\w./\\-]+\.py",
        "<file>",
        error_msg,
    )
    error_msg = re.sub(r'\s+File "[^"]+"[^\n]*\n', " ", error_msg)

    if len(error_msg) > max_length:
        error_msg = error_msg[:max_length] + "..."

    return error_msg


def _source_a_fingerprint() -> str:
    """Hash the current SWISSUbase source name, OAI endpoint, and institution filter."""
    return build_source_fingerprint(
        source=_SWISSUBASE_POLICY.name,
        oai_url=settings.swissubase_oai_pmh_url,
        institution_filter=settings.oai_institution_filter,
    )


async def _clear_staged_harvest_if_unchanged(
    pool: Database,
    expected_payload: bytes,
) -> None:
    """Transactionally clear staged payload/start/progress only if bytes still match; otherwise raise RuntimeError."""
    async with get_db_cursor(pool) as cur:
        await _clear_staged_harvest_if_unchanged_cur(
            cur,
            expected_payload,
        )


async def _clear_staged_harvest_if_unchanged_cur(
    cur: AsyncCursor[Any],
    expected_payload: bytes,
) -> None:
    """Clear matching staged payload/start/progress in the caller's transaction; no matching singleton raises RuntimeError."""
    await cur.execute(
        """
        UPDATE sync_status
        SET incremental_harvest = NULL,
            incremental_started_at = NULL,
            incremental_position = 0,
            incremental_affected = 0
        WHERE id = 1
          AND incremental_harvest = %s
        RETURNING id
        """,
        (expected_payload,),
    )

    if await cur.fetchone() is None:
        raise RuntimeError("staged harvest changed while held under the ingestion lock")


async def upsert_dataset(
    cur: AsyncCursor[Any],
    params: tuple[Any, ...],
) -> None:
    """Upsert source metadata without loosening stored visibility.

    On a (source, uuid) conflict, retain the stricter of the stored and
    incoming tiers. PostgreSQL compares them inside the atomic upsert, so
    administrative restrictions survive incremental sync and full rebuilds.

    Args:
        cur: Cursor in the caller's transaction.
        params: Values ordered by DATASET_INSERT_COLUMNS.
    """
    await cur.execute(
        sql.SQL("""
            INSERT INTO oral_history_datasets ({columns})
            VALUES ({placeholders})
            ON CONFLICT (source, uuid) DO UPDATE SET {updates}
        """).format(
            columns=DATASET_INSERT_SQL,
            placeholders=DATASET_INSERT_PLACEHOLDERS,
            updates=_DATASET_UPDATE_CLAUSE,
        ),
        params,
    )


async def _upsert_public_catalogue_record(
    cur: AsyncCursor[Any], record: dict[str, Any], policy: SourcePolicy
) -> None:
    """Classify resource access, resolve metadata visibility, validate, and upsert under policy.name.

    Use the caller's transaction; missing uuid raises ValueError and record,
    policy, or database errors propagate.
    """
    uuid = record.get("uuid")
    if not uuid:
        raise ValueError(
            "Cannot upsert a catalogue record without a uuid — uuid is the "
            "conflict key; a NULL-uuid row can never be updated and would "
            "accumulate duplicates on every sync."
        )

    access_level = policy.classify_access(record.get("license_val"))
    visibility_tier = resolve_tier(record.get("visibility_tier"), policy)
    params = build_record_params(
        record, access_level, source=policy.name, visibility_tier=visibility_tier
    )

    await upsert_dataset(cur, params)


async def _delete_stale_source_records(
    cur: AsyncCursor[Any], source: str, offered_uuids: list[str]
) -> None:
    """Delete source rows absent from offered_uuids after enforcing contraction limits.

    The caller must hold the ingestion lock and have applied explicit
    withdrawals in this transaction. More than 100 inferred deletions or
    25% of remaining source rows raises _RebuildContractionAborted before
    deletion; a missing count row raises RuntimeError.
    """
    await cur.execute(
        """
        SELECT count(*) AS existing_count,
               count(*) FILTER (WHERE NOT (uuid = ANY(%s))) AS inferred_delete_count
        FROM oral_history_datasets
        WHERE source = %s
        """,
        (offered_uuids, source),
    )
    row = await cur.fetchone()
    if row is None:
        raise RuntimeError("Could not count existing Source A rows before stale deletion")

    existing_count = int(row["existing_count"])
    inferred_delete_count = int(row["inferred_delete_count"])
    if (
        inferred_delete_count > _REBUILD_MAX_INFERRED_DELETE_COUNT
        or inferred_delete_count * 100 > existing_count * _REBUILD_MAX_INFERRED_DELETE_RATIO_PERCENT
    ):
        raise _RebuildContractionAborted(existing_count, inferred_delete_count)

    await cur.execute(
        "DELETE FROM oral_history_datasets WHERE source = %s AND NOT (uuid = ANY(%s))",
        (source, offered_uuids),
    )


async def _delete_explicit_source_records(
    cur: AsyncCursor[Any],
    source: str,
    uuids: list[str],
) -> None:
    """Delete source rows with the supplied UUIDs in the caller's transaction; skip empty input."""
    if not uuids:
        return

    await cur.execute(
        """
        DELETE FROM oral_history_datasets
        WHERE source = %s
          AND uuid = ANY(%s)
        """,
        (source, uuids),
    )


async def _update_sync_timestamp(
    cur: AsyncCursor[Any],
    harvest_started_at: datetime,
    *,
    source_cursor: datetime | None,
) -> None:
    """Store local harvest start time; update the upstream cursor only when source_cursor is not None."""
    await cur.execute(
        """UPDATE sync_status SET last_harvest_date = %s,
           source_cursor = COALESCE(%s, source_cursor) WHERE id = 1""",
        (harvest_started_at, source_cursor),
    )


async def _upsert_ingestion_failures_cur(
    cur: AsyncCursor[Any],
    source: str,
    failures: dict[str, str],
) -> None:
    """Persist a batch of failures without rewriting unchanged rows."""
    if not failures:
        return

    uuids = list(failures)
    messages = [failures[uuid] for uuid in uuids]

    await cur.execute(
        """
        INSERT INTO ingestion_failures AS existing
            (source, uuid, message)
        SELECT %s, incoming.uuid, incoming.message
        FROM unnest(%s::text[], %s::text[])
             AS incoming(uuid, message)
        ON CONFLICT (source, uuid)
        DO UPDATE SET
            message = EXCLUDED.message,
            updated_at = CURRENT_TIMESTAMP
        WHERE existing.message IS DISTINCT FROM EXCLUDED.message
        """,
        (source, uuids, messages),
    )


async def _set_ingestion_failure_cur(
    cur: AsyncCursor[Any],
    source: str,
    uuid: str,
    message: str,
) -> None:
    """Upsert one source/UUID diagnostic in the caller's transaction; unchanged text keeps its timestamp."""
    await cur.execute(
        """
        INSERT INTO ingestion_failures AS existing
            (source, uuid, message)
        VALUES (%s, %s, %s)
        ON CONFLICT (source, uuid)
        DO UPDATE SET
            message = EXCLUDED.message,
            updated_at = CURRENT_TIMESTAMP
        WHERE existing.message IS DISTINCT FROM EXCLUDED.message
        """,
        (source, uuid, message),
    )


async def _delete_ingestion_failure_cur(
    cur: AsyncCursor[Any],
    source: str,
    uuid: str,
) -> None:
    """Delete a source/UUID diagnostic in the caller's transaction; absence is harmless."""
    await cur.execute(
        """
        DELETE FROM ingestion_failures
        WHERE source = %s AND uuid = %s
        """,
        (source, uuid),
    )


async def _list_ingestion_failures_cur(
    cur: AsyncCursor[Any],
    source: str,
) -> list[tuple[str, str]]:
    """Return (uuid, message) diagnostics for source, ordered by UUID, using the caller's cursor."""
    await cur.execute(
        """
        SELECT uuid, message
        FROM ingestion_failures
        WHERE source = %s
        ORDER BY uuid
        """,
        (source,),
    )
    return [(row["uuid"], row["message"]) for row in await cur.fetchall()]


async def _replace_ingestion_failures_cur(
    cur: AsyncCursor[Any],
    source: str,
    failures: list[tuple[str, str]],
) -> None:
    """Replace one source's complete failure set in the current transaction."""
    await cur.execute(
        "DELETE FROM ingestion_failures WHERE source = %s",
        (source,),
    )
    await _upsert_ingestion_failures_cur(cur, source, dict(failures))


async def _update_full_rebuild_timestamp(
    cur: AsyncCursor[Any],
    harvest_started_at: datetime,
    *,
    failed_records: list[tuple[str, str]],
    source_cursor: datetime,
    source_fingerprint: str,
) -> None:
    """Publish a rebuild's recovery state in the caller's catalogue transaction.

    Failures replace the source failure set and incremental diagnostic
    without advancing timestamps, cursor, or binding. With no failures,
    clear failures, advance both timestamps/cursor/binding, and clear the
    incremental error if failures previously existed.
    """
    source = _SWISSUBASE_POLICY.name

    if failed_records:
        await _replace_ingestion_failures_cur(
            cur,
            source,
            failed_records,
        )
        await _record_record_errors(
            cur,
            failed_records,
            "Unresolved catalogue records",
            channel="incremental",
        )
        return

    await cur.execute(
        """SELECT EXISTS (
               SELECT 1 FROM ingestion_failures WHERE source = %s
           ) AS had_failures""",
        (source,),
    )
    row = await cur.fetchone()
    had_failures = bool(row and row["had_failures"])

    await cur.execute(
        "DELETE FROM ingestion_failures WHERE source = %s",
        (source,),
    )
    await cur.execute(
        """UPDATE sync_status
           SET last_harvest_date = %s,
               last_full_rebuild_date = %s,
               source_cursor = %s,
               source_fingerprint = %s
           WHERE id = 1""",
        (harvest_started_at, harvest_started_at, source_cursor, source_fingerprint),
    )
    if had_failures:
        await _clear_sync_error(cur, channel="incremental")


async def _record_sync_error(
    cur: AsyncCursor[Any], error_msg: str, *, channel: SyncErrorChannel
) -> None:
    """Store error text unchanged and UTC now for channel; log and suppress execute Exceptions.

    The caller owns the transaction; a caught database failure may leave it
    aborted. Invalid channel lookup and cancellation still propagate.
    """
    col, col_at = _SYNC_ERROR_COLUMNS[channel]
    try:
        await cur.execute(
            sql.SQL("UPDATE sync_status SET {col} = %s, {col_at} = %s WHERE id = 1").format(
                col=col, col_at=col_at
            ),
            (error_msg, datetime.now(UTC)),
        )
    except Exception:
        logger.exception(
            "Failed to record sync error to DB (channel=%s). Original error: %s",
            channel,
            error_msg,
        )


async def _clear_sync_error(cur: AsyncCursor[Any], *, channel: SyncErrorChannel) -> None:
    """Clear the selected channel's diagnostic and timestamp in the caller's transaction."""
    col, col_at = _SYNC_ERROR_COLUMNS[channel]
    await cur.execute(
        sql.SQL("UPDATE sync_status SET {col} = NULL, {col_at} = NULL WHERE id = 1").format(
            col=col, col_at=col_at
        ),
    )


async def _record_record_errors(
    cur: AsyncCursor[Any],
    errors: list[tuple[str, str]],
    context: str,
    *,
    channel: SyncErrorChannel,
) -> None:
    """Store context, total failure count, and at most 20 UUID/message pairs for channel.

    Stamp UTC now in the caller's transaction; input diagnostics are not sanitized here.
    """
    formatted = "\n".join(f"  {uuid}: {msg}" for uuid, msg in errors[:_MAX_DISPLAY_ERRORS])
    if len(errors) > _MAX_DISPLAY_ERRORS:
        formatted += f"\n  ... and {len(errors) - _MAX_DISPLAY_ERRORS} more"

    error_text = f"{context}: {len(errors)} record(s) failed\n{formatted}"

    col, col_at = _SYNC_ERROR_COLUMNS[channel]
    await cur.execute(
        sql.SQL("UPDATE sync_status SET {col} = %s, {col_at} = %s WHERE id = 1").format(
            col=col, col_at=col_at
        ),
        (error_text, datetime.now(UTC)),
    )


async def _sync_source_a(pool: Database) -> SyncOutcome:
    """Resume staged work or fetch and durably stage an incremental SWISSUbase harvest.

    Require the ingestion-lock connection and source binding. Refetch
    compatible-format changes; unsupported binding/state raises
    _FullReharvestRequired. Fetch from two UTC dates before source_cursor,
    or 1900-01-01 if absent. Fetch errors return failed outcomes; staging/
    write errors are reported and re-raised. Missing sync_status raises
    RuntimeError. Staging and replay have separate configured write timeouts.
    """
    harvest_started_at = datetime.now(UTC)
    current_source_fingerprint = _source_a_fingerprint()

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "SELECT source_cursor, source_fingerprint, incremental_harvest, "
            "incremental_started_at "
            "FROM sync_status WHERE id = 1"
        )
        row = await cur.fetchone()
        if row is None:
            raise RuntimeError("sync_status table is empty — run migrations first")
        last_sync = row["source_cursor"]
        committed_source_fingerprint = row.get("source_fingerprint")

    if committed_source_fingerprint != current_source_fingerprint:
        if committed_source_fingerprint is None:
            detail = "the committed catalogue has no source configuration binding"
        else:
            detail = "the configured source differs from the committed catalogue"
        raise _FullReharvestRequired(f"{detail}; authoritative full rebuild required")

    pending_payload = row["incremental_harvest"]
    if pending_payload is not None:
        try:
            harvest = decode_stored_harvest(
                pending_payload,
                expected_source_fingerprint=current_source_fingerprint,
            )
        except StoredHarvestRecoveryRequired as exc:
            if exc.recovery_action == "full_reharvest":
                raise _FullReharvestRequired(str(exc)) from exc

            await _clear_staged_harvest_if_unchanged(
                pool,
                pending_payload,
            )
            logger.warning(
                "Reset incompatible staged Source A harvest; recovery=%s",
                exc.recovery_action,
                extra={
                    "event_type": "stored_harvest_reset",
                    "recovery_action": exc.recovery_action,
                },
            )
        else:
            started_at = row["incremental_started_at"]
            if started_at is None:
                raise _FullReharvestRequired("staged harvest exists without incremental_started_at")
            return await _write_incremental(
                pool,
                harvest,
                started_at,
            )

    since = (
        (last_sync.astimezone(UTC) - timedelta(days=2)).strftime("%Y-%m-%d")
        if last_sync is not None
        else "1900-01-01"
    )
    try:
        harvest = await run_in_threadpool(
            fetch_updates_isolated,
            oai_url=settings.swissubase_oai_pmh_url,
            since=since,
            institution_filter=settings.oai_institution_filter,
        )
        harvest.validate()
    except Exception as exc:
        sanitized = _sanitize_error_message(f"{type(exc).__name__}: {exc}")
        logger.exception("Source A incremental sync failed during fetch")
        async with get_db_cursor(pool) as cur:
            await _record_sync_error(
                cur,
                f"Incremental sync (fetch): {sanitized}",
                channel="incremental",
            )
        return SyncOutcome("failed", reason=sanitized)

    try:
        async with asyncio.timeout(settings.sync_write_timeout_seconds):
            stored_harvest = encode_stored_harvest_parts(
                harvest,
                source_fingerprint=current_source_fingerprint,
            )
            async with get_db_cursor(pool) as cur:
                await cur.execute(
                    """UPDATE sync_status
                       SET incremental_harvest =
                               %s::bytea || %s::bytea || %s::bytea,
                       incremental_started_at = %s, incremental_position = 0,
                       incremental_affected = 0 WHERE id = 1""",
                    (
                        stored_harvest.prefix,
                        stored_harvest.harvest,
                        stored_harvest.suffix,
                        harvest_started_at,
                    ),
                )
            del stored_harvest
    except Exception as exc:
        await _report_write_failure(pool, "incremental", exc)
        raise

    return await _write_incremental(pool, harvest, harvest_started_at)


async def _report_write_failure(pool: Database, channel: SyncErrorChannel, exc: Exception) -> None:
    """Attempt a sanitized channel diagnostic within five seconds; log and suppress reporting Exceptions."""
    try:
        async with asyncio.timeout(5), get_db_cursor(pool) as cur:
            await _record_sync_error(
                cur,
                f"{channel} write: {_sanitize_error_message(type(exc).__name__ + ': ' + str(exc))}",
                channel=channel,
            )
    except Exception:
        logger.exception("Could not persist %s write failure", channel)


async def _write_incremental(
    pool: Database,
    harvest: HarvestResult,
    started_at: datetime,
) -> SyncOutcome:
    """Apply staged work within SYNC_WRITE_TIMEOUT_SECONDS; report and re-raise write errors.

    Propagate _FullReharvestRequired without reporting here. Completed
    batches remain committed after later failure or timeout.
    """
    try:
        async with asyncio.timeout(settings.sync_write_timeout_seconds):
            return await _apply_incremental_harvest(
                pool,
                harvest,
                started_at,
            )
    except _FullReharvestRequired:
        raise
    except Exception as exc:
        await _report_write_failure(pool, "incremental", exc)
        raise


def _validated_incremental_progress(
    progress: Mapping[str, object],
    *,
    work_items: int,
) -> tuple[int, int]:
    """Return (position, affected), requiring each to be a non-boolean integer in 0..work_items.

    Raise _FullReharvestRequired otherwise; no relation between the two
    counts or payload identity is checked.
    """
    position = progress.get("incremental_position")
    affected = progress.get("incremental_affected")
    if (
        not isinstance(position, int)
        or isinstance(position, bool)
        or not 0 <= position <= work_items
    ):
        raise _FullReharvestRequired(
            "incremental_position is outside the staged harvest "
            f"(position={position!r}, work_items={work_items})"
        )
    if (
        not isinstance(affected, int)
        or isinstance(affected, bool)
        or not 0 <= affected <= work_items
    ):
        raise _FullReharvestRequired(
            "incremental_affected is outside the staged harvest "
            f"(affected={affected!r}, work_items={work_items})"
        )
    return position, affected


async def _finalize_incremental_harvest(
    pool: Database,
    *,
    source: str,
    harvest_started_at: datetime,
    source_cursor: datetime | None,
    had_work: bool,
) -> list[tuple[str, str]]:
    """Clear staged payload/progress and return unresolved (uuid, message) pairs atomically.

    Failures preserve timestamps/cursor and set the incremental diagnostic.
    Otherwise stamp harvest_started_at, clear the error, and update the
    source cursor only when had_work is true and the cursor is supplied.
    """
    async with get_db_cursor(pool) as cur:
        failed_records = await _list_ingestion_failures_cur(cur, source)
        await cur.execute(
            """UPDATE sync_status SET incremental_harvest = NULL,
               incremental_started_at = NULL,
               incremental_position = 0, incremental_affected = 0 WHERE id = 1""",
        )

        if failed_records:
            await _record_record_errors(
                cur,
                failed_records,
                "Incremental sync",
                channel="incremental",
            )
        else:
            await _update_sync_timestamp(
                cur,
                harvest_started_at,
                source_cursor=source_cursor if had_work else None,
            )
            await _clear_sync_error(cur, channel="incremental")

    return failed_records


async def _apply_incremental_harvest(
    pool: Database,
    harvest: HarvestResult,
    harvest_started_at: datetime,
) -> SyncOutcome:
    """Replay validated staged work on the ingestion-lock connection from durable progress.

    Process sorted withdrawals before matching records; commit at 50 items
    or after a per-item elapsed check reaches two seconds. This is not a
    strict two-second transaction limit. Savepoints isolate DataError,
    IntegrityError, and ValueError; persist their diagnostics and continue.
    Other errors propagate, preserving earlier batches. Quarantine uncertain
    IDs, clear successful IDs failures, and finalize to success/partial.
    Missing status raises RuntimeError; corrupt progress requires a rebuild.
    """
    source = _SWISSUBASE_POLICY.name

    withdrawals = sorted(harvest.nonmatching_uuids | harvest.deleted_uuids)
    work: list[tuple[str, dict[str, Any] | None]] = [(uuid, None) for uuid in withdrawals] + [
        (record["uuid"], record) for record in harvest.matching_records
    ]

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "SELECT incremental_position, incremental_affected FROM sync_status WHERE id = 1"
        )
        progress = await cur.fetchone()
        if progress is None:
            raise RuntimeError("sync_status table is empty")
        # Validate the durable cursor before recording any harvest-specific
        # failures. A corrupt cursor is recoverable by a full rebuild, so this
        # transaction must not publish partial replay state first.
        position, success_count = _validated_incremental_progress(
            progress,
            work_items=len(work),
        )
        await _upsert_ingestion_failures_cur(
            cur,
            source,
            harvest.uncertain_records,
        )

    resumed_at = position
    committed_batches = 0
    max_batch_seconds = 0.0
    total_commit_seconds = 0.0
    max_commit_seconds = 0.0
    loop = asyncio.get_running_loop()
    write_started = loop.time()

    while position < len(work):
        # Keep tentative counters separate from the last committed counters.
        # If processing, the progress UPDATE, or COMMIT fails, get_db_cursor()
        # rolls the batch back and these values are deliberately not published
        # to the outer loop.
        next_position = position
        next_success_count = success_count
        batch_items = 0
        batch_started = loop.time()

        async with get_db_cursor(pool) as cur:
            while next_position < len(work):
                uuid, record = work[next_position]
                try:
                    # get_db_cursor() owns the outer batch transaction. This
                    # nested transaction is a savepoint, so a recoverable bad
                    # record does not poison the batch's PostgreSQL transaction.
                    async with cur.connection.transaction():
                        if record is None:
                            await _delete_explicit_source_records(cur, source, [uuid])
                            changed = cur.rowcount
                        else:
                            await _upsert_public_catalogue_record(
                                cur,
                                record,
                                _SWISSUBASE_POLICY,
                            )
                            changed = 1

                        await _delete_ingestion_failure_cur(cur, source, uuid)
                except (DataError, IntegrityError, ValueError) as exc:
                    failure_message = (
                        "DOI collision within Source A: upstream minted a new UUID "
                        f"but reused an existing DOI (uuid={uuid})."
                        if isinstance(exc, UniqueViolation)
                        and exc.diag.constraint_name == "datasets_source_doi_key"
                        else _sanitize_error_message(f"{type(exc).__name__}: {exc}")
                    )
                    await _set_ingestion_failure_cur(
                        cur,
                        source,
                        uuid,
                        failure_message,
                    )
                    logger.warning(
                        "Source A record %s failed; skipping",
                        uuid,
                        exc_info=True,
                    )
                else:
                    next_success_count += changed

                next_position += 1
                batch_items += 1

                if (
                    batch_items >= _INCREMENTAL_COMMIT_BATCH_SIZE
                    or loop.time() - batch_started >= _INCREMENTAL_COMMIT_BATCH_MAX_SECONDS
                ):
                    break

            await cur.execute(
                """UPDATE sync_status SET incremental_position = %s,
                   incremental_affected = %s WHERE id = 1""",
                (next_position, next_success_count),
            )
            commit_started = loop.time()

        # The context exited only after the outer transaction committed.
        # Advancing the durable counters here keeps memory and PostgreSQL in
        # agreement if a statement, cancellation, or COMMIT fails.
        batch_committed = loop.time()
        commit_seconds = batch_committed - commit_started
        position = next_position
        success_count = next_success_count
        committed_batches += 1
        total_commit_seconds += commit_seconds
        max_commit_seconds = max(max_commit_seconds, commit_seconds)
        max_batch_seconds = max(max_batch_seconds, batch_committed - batch_started)

    failed_records = await _finalize_incremental_harvest(
        pool,
        source=source,
        harvest_started_at=harvest_started_at,
        source_cursor=harvest.source_cursor,
        had_work=bool(work),
    )

    elapsed_seconds = loop.time() - write_started
    processed_items = position - resumed_at
    logger.info(
        "Incremental Source A write committed %d item(s) in %d batch(es)",
        processed_items,
        committed_batches,
        extra={
            "event_type": "incremental_write_batches",
            "source": source,
            "work_items": len(work),
            "resumed_at": resumed_at,
            "processed_items": processed_items,
            "committed_batches": committed_batches,
            "batch_size_limit": _INCREMENTAL_COMMIT_BATCH_SIZE,
            "batch_seconds_limit": _INCREMENTAL_COMMIT_BATCH_MAX_SECONDS,
            "max_batch_seconds": round(max_batch_seconds, 6),
            "total_commit_seconds": round(total_commit_seconds, 6),
            "max_commit_seconds": round(max_commit_seconds, 6),
            "mean_commit_seconds": (
                round(total_commit_seconds / committed_batches, 6) if committed_batches else None
            ),
            "elapsed_seconds": round(elapsed_seconds, 6),
            "records_per_second": (
                round(processed_items / elapsed_seconds, 3)
                if processed_items and elapsed_seconds > 0
                else None
            ),
        },
    )

    return SyncOutcome(
        "partial" if failed_records else "success",
        affected_count=success_count,
        failed_count=len(failed_records),
        reason="unresolved catalogue records" if failed_records else None,
    )


async def _full_rebuild_source_a(pool: Database) -> SyncOutcome:
    """Replay pending work when possible, then fetch from 1900-01-01 and reconcile SWISSUbase.

    Require the ingestion-lock connection. Keep unreplayable staged bytes
    until the rebuild transaction commits. Fetch failures return failed
    outcomes; replay/write failures are reported and re-raised. Rebuild
    application uses SYNC_WRITE_TIMEOUT_SECONDS.
    """
    staged_payload_to_clear: bytes | None = None
    source_fingerprint = _source_a_fingerprint()

    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute("SELECT incremental_harvest FROM sync_status WHERE id = 1")
            pending = await cur.fetchone()

        if pending and pending["incremental_harvest"] is not None:
            pending_payload = pending["incremental_harvest"]
            try:
                await _sync_source_a(pool)
            except _FullReharvestRequired as exc:
                staged_payload_to_clear = pending_payload
                logger.warning(
                    "Pending harvest cannot be safely replayed; "
                    "retaining it until the full reharvest commits",
                    extra={
                        "event_type": "stored_harvest_full_recovery",
                        "recovery_action": "full_reharvest",
                        "reason": str(exc),
                    },
                )
    except Exception as exc:
        await _report_write_failure(pool, "rebuild", exc)
        raise

    harvest_started_at = datetime.now(UTC)

    try:
        harvest = await run_in_threadpool(
            fetch_updates_isolated,
            oai_url=settings.swissubase_oai_pmh_url,
            since="1900-01-01",
            institution_filter=settings.oai_institution_filter,
        )
        harvest.discard_serialized_worker_payload()
        harvest.validate()
    except Exception as exc:
        sanitized = _sanitize_error_message(f"{type(exc).__name__}: {exc}")
        logger.exception("Full rebuild aborted — fetch failed")
        async with get_db_cursor(pool) as cur:
            await _record_sync_error(
                cur,
                f"Full rebuild: {sanitized}",
                channel="rebuild",
            )
        return SyncOutcome("failed", reason=sanitized)

    try:
        async with asyncio.timeout(settings.sync_write_timeout_seconds):
            return await _apply_full_harvest(
                pool,
                harvest,
                harvest_started_at,
                staged_payload_to_clear=staged_payload_to_clear,
                source_fingerprint=source_fingerprint,
            )
    except Exception as exc:
        await _report_write_failure(pool, "rebuild", exc)
        raise


def _doi_correction_groups(
    records: list[dict[str, Any]], current: dict[str, str]
) -> list[list[dict[str, Any]]]:
    """Return connected record groups whose canonical DOI assignments share old/new owners.

    current maps canonical DOI to existing UUID. Inputs should have unique
    UUIDs; duplicate UUIDs overwrite earlier records. Singletons are included;
    records are returned by reference without mutation.
    """
    offered = {record["uuid"]: record for record in records}
    neighbors: dict[str, set[str]] = {uuid: set() for uuid in offered}
    proposed: dict[str, str] = {}

    for uuid, record in offered.items():
        raw = record.get("doi")
        doi = canonicalize_doi(raw) if isinstance(raw, str) else None
        if doi is None:
            continue
        for owner in (current.get(doi), proposed.get(doi)):
            if owner is not None and owner in offered and owner != uuid:
                neighbors[uuid].add(owner)
                neighbors[owner].add(uuid)
        proposed[doi] = uuid

    groups = []
    seen: set[str] = set()
    for uuid in offered:
        if uuid in seen:
            continue
        pending = [uuid]
        group = []
        while pending:
            member = pending.pop()
            if member in seen:
                continue
            seen.add(member)
            group.append(offered[member])
            pending.extend(sorted(neighbors[member] - seen))
        groups.append(group)

    return groups


async def _reconcile_rebuild_records(
    cur: AsyncCursor[Any], records: list[dict[str, Any]]
) -> tuple[int, list[tuple[str, str]]]:
    """Upsert DOI-connected groups in savepoints; return (successes, UUID/error pairs).

    The caller owns the outer transaction. Temporarily clear existing DOIs
    for multirecord groups to permit swaps. Duplicate final DOIs and
    DataError/IntegrityError/ValueError/KeyError roll back the group and
    become diagnostics; other errors propagate.
    """
    await cur.execute(
        "SELECT uuid, doi FROM oral_history_datasets WHERE source = %s AND doi IS NOT NULL",
        (_SWISSUBASE_POLICY.name,),
    )
    current = {row["doi"]: row["uuid"] for row in await cur.fetchall()}
    successes = 0
    failures: list[tuple[str, str]] = []

    for group in _doi_correction_groups(records, current):
        try:
            canonical = [canonicalize_doi(r["doi"]) for r in group if r.get("doi")]
            nonempty = [doi for doi in canonical if doi is not None]
            if len(nonempty) != len(set(nonempty)):
                raise ValueError(  # noqa: TRY301 - deliberate transaction rollback signal
                    "Duplicate final DOI assignments in rebuild group"
                )

            async with cur.connection.transaction():
                if len(group) > 1:
                    await cur.execute(
                        "UPDATE oral_history_datasets SET doi = NULL "
                        "WHERE source = %s AND uuid = ANY(%s)",
                        (_SWISSUBASE_POLICY.name, [r["uuid"] for r in group]),
                    )
                for record in group:
                    await _upsert_public_catalogue_record(cur, record, _SWISSUBASE_POLICY)

            successes += len(group)
        except (DataError, IntegrityError, ValueError, KeyError) as exc:
            logger.warning("Full rebuild correction group failed", exc_info=True)
            error = _sanitize_error_message(f"{type(exc).__name__}: {exc}")
            failures.extend((record["uuid"], error) for record in group)

    return successes, failures


async def _apply_full_harvest(
    pool: Database,
    harvest: HarvestResult,
    harvest_started_at: datetime,
    *,
    staged_payload_to_clear: bytes | None = None,
    source_fingerprint: str | None = None,
) -> SyncOutcome:
    """Reconcile a validated full harvest on the ingestion-lock connection.

    With no matches, commit explicit withdrawals only and return failed.
    Otherwise delete explicit/guarded-absent rows and upsert matches in one
    transaction, protecting uncertain IDs. Roll back if contraction exceeds
    100 rows or 25%, or fewer than half the offered records write; return
    a failed outcome. Partial success can commit deletions/upserts but
    does not advance rebuild timestamps, source cursor, or binding.

    None source_fingerprint uses current settings. A supplied staged payload
    is cleared only if unchanged, else RuntimeError. Validation/database
    errors propagate; successful reconciliation returns success or partial.
    """
    source_cursor = harvest.validate()
    if source_fingerprint is None:
        source_fingerprint = _source_a_fingerprint()
    live_records = harvest.matching_records
    failed_records = list(harvest.uncertain_records.items())
    explicit_removals = sorted(harvest.deleted_uuids | harvest.nonmatching_uuids)

    if not live_records:
        logger.warning(
            "Full rebuild aborted — no matching records returned; "
            "applying %d explicit removal(s) and keeping all other existing data. "
            "Deleted=%d, nonmatching=%d, uncertain=%d",
            len(explicit_removals),
            len(harvest.deleted_uuids),
            len(harvest.nonmatching_uuids),
            len(harvest.uncertain_records),
        )

        if explicit_removals:
            async with get_db_cursor(pool) as cur:
                await _delete_explicit_source_records(
                    cur,
                    _SWISSUBASE_POLICY.name,
                    explicit_removals,
                )

        async with get_db_cursor(pool) as cur:
            await _record_sync_error(
                cur,
                "Full rebuild: upstream returned 0 matching records for "
                f"institution filter {settings.oai_institution_filter!r}; "
                f"{len(explicit_removals)} explicit source removal(s) applied; "
                f"{len(harvest.uncertain_records)} record(s) had uncertain "
                "institution metadata; all other existing data kept.",
                channel="rebuild",
            )

        return SyncOutcome(
            "failed",
            affected_count=len(explicit_removals),
            failed_count=len(failed_records),
            reason="no matching records; only explicit withdrawals applied",
        )

    success_count = 0
    protected_uuids = {record["uuid"] for record in live_records}
    protected_uuids.update(harvest.uncertain_records.keys())

    try:
        async with get_db_cursor(pool) as cur:
            # Explicit upstream withdrawals are authoritative and must not be
            # confused with rows inferred absent because a harvest was short.
            # Both statements remain in this transaction, so either all
            # removals commit or the contraction guard rolls them all back.
            await _delete_explicit_source_records(
                cur,
                _SWISSUBASE_POLICY.name,
                explicit_removals,
            )
            await _delete_stale_source_records(
                cur, _SWISSUBASE_POLICY.name, sorted(protected_uuids)
            )
            success_count, write_failures = await _reconcile_rebuild_records(cur, live_records)
            failed_records.extend(write_failures)

            offered_count = len(live_records)
            if success_count * _REBUILD_MIN_SUCCESS_DENOM < offered_count:
                raise _RebuildAborted(  # noqa: TRY301 - deliberate transaction rollback signal
                    success_count, offered_count
                )

            if staged_payload_to_clear is not None:
                await _clear_staged_harvest_if_unchanged_cur(
                    cur,
                    staged_payload_to_clear,
                )

            await _update_full_rebuild_timestamp(
                cur,
                harvest_started_at,
                failed_records=failed_records,
                source_cursor=source_cursor,
                source_fingerprint=source_fingerprint,
            )
            if failed_records:
                await _record_record_errors(cur, failed_records, "Full rebuild", channel="rebuild")
            else:
                await _clear_sync_error(cur, channel="rebuild")
                await _clear_sync_error(cur, channel="incremental")
    except _RebuildContractionAborted as exc:
        logger.error(  # noqa: TRY400 - expected controlled rebuild abort
            "%s",
            exc,
            extra={
                "event_type": "sync_rebuild_contraction_aborted",
                "existing_count": exc.existing_count,
                "inferred_delete_count": exc.inferred_delete_count,
            },
        )
        async with get_db_cursor(pool) as status_cur:
            await _record_sync_error(status_cur, str(exc), channel="rebuild")
        return SyncOutcome(
            "failed",
            failed_count=len(failed_records),
            reason=str(exc),
        )
    except _RebuildAborted as exc:
        logger.error(  # noqa: TRY400 - expected controlled rebuild abort
            "%s",
            exc,
            extra={
                "event_type": "sync_rebuild_aborted",
                "success_count": exc.success_count,
                "offered": exc.offered,
            },
        )
        async with get_db_cursor(pool) as status_cur:
            await _record_record_errors(
                status_cur,
                failed_records,
                f"Full rebuild ABORTED — {exc.success_count}/{exc.offered} "
                "inserted, stale-delete rolled back, existing data kept",
                channel="rebuild",
            )
        return SyncOutcome(
            "failed",
            failed_count=len(failed_records),
            reason=str(exc),
        )

    return SyncOutcome(
        "partial" if failed_records else "success",
        affected_count=success_count,
        failed_count=len(failed_records),
        reason="unresolved catalogue records" if failed_records else None,
    )


async def _run_sync_on_locked_connection(
    connection: AsyncConnection,
) -> SyncOutcome:
    """Run incremental work on the locked session, translating required rebuilds to a failed recovery outcome."""
    try:
        return await _sync_source_a(connection)
    except _FullReharvestRequired as exc:
        async with get_db_cursor(connection) as cur:
            await _record_sync_error(
                cur,
                f"Incremental sync requires a full rebuild: {exc}",
                channel="incremental",
            )
        return SyncOutcome(
            "failed",
            reason="full rebuild required",
            requires_full_rebuild=True,
        )


async def run_sync(pool: AsyncConnectionPool) -> SyncOutcome:
    """Serialize incremental ingestion locally and across processes; return its SyncOutcome.

    Use one event loop per process. Reserve a pool connection while fetching
    and writing; write/connection failures and cancellation can propagate.
    Callers must handle requires_full_rebuild and invalidate catalogue caches.
    """
    async with _sync_mutex, _cross_process_sync_lock(pool) as connection:
        return await _run_sync_on_locked_connection(connection)


async def _run_full_rebuild_on_locked_connection(
    connection: AsyncConnection,
) -> SyncOutcome:
    """Run a full rebuild on the session that owns the ingestion lock."""
    return await _full_rebuild_source_a(connection)


async def run_full_rebuild(pool: AsyncConnectionPool) -> SyncOutcome:
    """Serialize full reconciliation locally and across processes; return its SyncOutcome.

    Use one event loop per process. Reserve a pool connection while fetching
    and writing; write/connection failures and cancellation can propagate.
    A partial/failed result may include committed changes; callers invalidate caches.
    """
    async with _sync_mutex, _cross_process_sync_lock(pool) as connection:
        return await _run_full_rebuild_on_locked_connection(connection)

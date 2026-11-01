"""Harvest configured sources and reconcile source-owned catalogue rows.

run_sync/run_full_rebuild serialize on one event loop and a PostgreSQL
session advisory lock. All ingestion writes use that session;
*_cur helpers use its current transaction. Blocking adapter fetches run
through a threadpool; transport isolation remains the adapter's responsibility.

The selected ConfiguredSource supplies the adapter, write policy, persistent
identity and write timeout throughout each run and its recovery.

Fetch/policy failures may return failed SyncOutcome; write, connection,
and cancellation failures can propagate. Incremental batches remain
committed when later work fails.
"""

import asyncio
import logging
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from psycopg import AsyncConnection, AsyncCursor, DataError, IntegrityError, sql
from psycopg.errors import ProgramLimitExceeded, UniqueViolation
from psycopg_pool import AsyncConnectionPool

from app.doi import canonicalize_doi
from app.log_text import escape_log_controls
from app.sources import ConfiguredSource, JsonFeedConfig, SourcePolicy, normalize_harvest_since

from .access_tiers import (
    resolve_required_source_tier,
    resolve_tier,
    tier_case_sql,
)
from .catalogue_lock import INGESTION_RUN_LOCK_KEY, acquire_catalogue_write_lock_cur
from .db import Database, get_db_cursor
from .db_schema_contract import DATASET_COLUMN_CONTRACT
from .harvest import HarvestResult
from .ingestion_audit import (
    DatasetWriteState,
    IngestionAudit,
    audit_savepoint,
    read_tier_state_cur,
)
from .schema import (
    DATASET_INSERT_COLUMNS,
    DATASET_INSERT_SQL,
    build_record_params,
)
from .source_fetch import run_source_fetch
from .stored_harvest import (
    StoredHarvestRecoveryRequired,
    decode_stored_harvest,
    encode_stored_harvest_parts,
)

logger = logging.getLogger(__name__)

# Avoid occupying multiple pool connections while local jobs wait for the
# cross-process advisory lock.
_sync_mutex = asyncio.Lock()


@asynccontextmanager
async def _cross_process_sync_lock(
    pool: AsyncConnectionPool,
) -> AsyncIterator[AsyncConnection]:
    """Wait for whole-run ingestion ownership and yield its autocommit connection.

    Every mutation must use this session so connection loss fences writes.
    This run lock does not block administrator catalogue changes during fetch.
    On exit unlock and restore transaction mode within five seconds; close
    the connection and propagate failures/cancellation if cleanup fails.
    """
    async with pool.connection() as lock_conn:
        await lock_conn.set_autocommit(True)
        try:
            await lock_conn.execute(
                "SELECT pg_advisory_lock(%s)",
                (INGESTION_RUN_LOCK_KEY,),
            )
            yield lock_conn
        finally:
            # Never return a possibly locked session to the pool. Cancellation
            # or protocol failure during cleanup discards the connection.
            try:
                async with asyncio.timeout(5):
                    await lock_conn.execute(
                        "SELECT pg_advisory_unlock(%s)",
                        (INGESTION_RUN_LOCK_KEY,),
                    )
                    await lock_conn.set_autocommit(False)
            except BaseException:
                await lock_conn.close()
                raise


def _dataset_upsert_statement() -> sql.Composed:
    """Build one change-aware write from the validated column/type contract."""
    effective_tier = sql.SQL("""CASE
        WHEN incoming.data->>'visibility_tier' IN ('public', 'registered', 'vetted')
        THEN incoming.visibility_tier
        WHEN {stored_rank} >= {incoming_rank} THEN stored.visibility_tier
        ELSE incoming.visibility_tier END""").format(
        stored_rank=tier_case_sql("stored"), incoming_rank=tier_case_sql("incoming")
    )
    incoming_values = {
        name: effective_tier if name == "visibility_tier" else sql.Identifier("incoming", name)
        for name in DATASET_INSERT_COLUMNS
    }
    # A concurrent first insert needs conflict handling; existing rows avoid sequence churn.
    conflict_tier = sql.SQL("""CASE
        WHEN EXCLUDED.data->>'visibility_tier' IN ('public', 'registered', 'vetted')
        THEN EXCLUDED.visibility_tier
        WHEN {stored_rank} >= {incoming_rank} THEN oral_history_datasets.visibility_tier
        ELSE EXCLUDED.visibility_tier END""").format(
        stored_rank=tier_case_sql("oral_history_datasets"), incoming_rank=tier_case_sql("excluded")
    )
    compared_columns = [name for name in DATASET_INSERT_COLUMNS if name != "synced_at"]
    conflict_changed = sql.SQL("ROW({stored}) IS DISTINCT FROM ROW({incoming})").format(
        stored=sql.SQL(", ").join(
            sql.Identifier("oral_history_datasets", name) for name in compared_columns
        ),
        incoming=sql.SQL(", ").join(
            conflict_tier if name == "visibility_tier" else sql.Identifier("excluded", name)
            for name in compared_columns
        ),
    )
    conflict_values = {
        name: conflict_tier if name == "visibility_tier" else sql.Identifier("excluded", name)
        for name in DATASET_INSERT_COLUMNS
    }
    conflict_values["synced_at"] = sql.SQL(
        "CASE WHEN {} THEN EXCLUDED.synced_at ELSE oral_history_datasets.synced_at END"
    ).format(conflict_changed)
    return sql.SQL("""
        WITH incoming AS MATERIALIZED (
            SELECT {parameters}
        ), existing AS MATERIALIZED (
            SELECT stored.id, stored.source, stored.uuid, stored.visibility_tier,
                   ROW({stored_values}) IS DISTINCT FROM ROW({incoming_values}) AS changed
            FROM oral_history_datasets AS stored
            JOIN incoming USING (source, uuid)
            FOR UPDATE OF stored
        ), updated AS (
            UPDATE oral_history_datasets AS stored
            SET {updates}
            FROM incoming, existing
            WHERE stored.id = existing.id AND existing.changed
            RETURNING stored.id, stored.source, stored.uuid, stored.visibility_tier
        ), inserted AS (
            INSERT INTO oral_history_datasets ({columns})
            SELECT {insert_values} FROM incoming
            WHERE NOT EXISTS (SELECT 1 FROM existing)
            ON CONFLICT (source, uuid) DO UPDATE SET {conflict_updates}
            RETURNING id, source, uuid, visibility_tier
        )
        SELECT * FROM updated
        UNION ALL SELECT * FROM inserted
        UNION ALL
        SELECT id, source, uuid, visibility_tier FROM existing WHERE NOT changed
    """).format(
        parameters=sql.SQL(", ").join(
            sql.SQL("%s::{type} AS {name}").format(
                type=sql.SQL(DATASET_COLUMN_CONTRACT[name].pg_type), name=sql.Identifier(name)
            )
            for name in DATASET_INSERT_COLUMNS
        ),
        stored_values=sql.SQL(", ").join(
            sql.Identifier("stored", name) for name in compared_columns
        ),
        incoming_values=sql.SQL(", ").join(incoming_values[name] for name in compared_columns),
        updates=sql.SQL(", ").join(
            sql.SQL("{} = {}").format(sql.Identifier(name), value)
            for name, value in incoming_values.items()
        ),
        conflict_updates=sql.SQL(", ").join(
            sql.SQL("{} = {}").format(sql.Identifier(name), value)
            for name, value in conflict_values.items()
        ),
        columns=DATASET_INSERT_SQL,
        insert_values=sql.SQL(", ").join(
            sql.Identifier("incoming", name) for name in DATASET_INSERT_COLUMNS
        ),
    )


_DATASET_UPSERT_SQL = _dataset_upsert_statement()

SyncErrorChannel = Literal["incremental", "rebuild"]


class _FullReharvestRequired(RuntimeError):
    """The staged harvest or committed source binding requires a rebuild."""


class _SourceBindingAcknowledgementRequired(_FullReharvestRequired):
    """A changed source identity must be acknowledged before any new fetch or replay."""


@dataclass(frozen=True, slots=True)
class SyncOutcome:
    """Catalogue outcome; failed does not necessarily mean no changes committed.

    Incremental affected_count counts successful upserts and actual deleted
    rows, including resumed batches. Rebuilds count successful upserts;
    an empty-match rebuild instead counts actual deleted rows. These counts
    describe committed work, not requested withdrawals or a net row delta.
    failed_count counts unresolved records, and requires_full_rebuild asks
    the caller to perform authoritative recovery. Fields are not validated.
    """

    status: Literal["success", "partial", "failed"]
    affected_count: int = 0
    failed_count: int = 0
    reason: str | None = None
    requires_full_rebuild: bool = False
    requires_source_acknowledgement: bool = False


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
_JSON_FEED_CUTOFF_ERROR = "JSON feed snapshot predates the committed source cursor"
_JSON_FEED_FAILURE_REASONS = frozenset(
    {
        "duplicate_record_key",
        "record_shape",
        "record_tier",
        "record_timestamp",
        "record_metadata",
        "record_rejected",
        "record_write_failed",
        "record_group_failed",
    }
)
_REBUILD_MIN_SUCCESS_DENOM = 2
# A completed harvest cannot independently prove that the upstream catalogue
# was complete. Keep deletions inferred from absence conservative;
# authoritative tombstones delete immediately; local filter exclusions are
# withheld and count toward the full-rebuild contraction budget.
# Both write paths roll these data-dependent failures back to their existing
# item/group savepoint. Escaping instances require authoritative recovery.
# Application invariants (AssertionError/ProgrammingError) and transient
# connection/timeout errors must remain visible to the caller.
_RECORD_WRITE_ERRORS = (
    DataError,
    IntegrityError,
    ProgramLimitExceeded,
    ValueError,
    KeyError,
    TypeError,
)

# Batch commits limit lock duration and durability flushes while savepoints
# isolate records; the elapsed check occurs only after each item.
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
            "inserted (below threshold); stale-delete rolled back, other existing data kept. "
            "Committed authoritative withdrawals remain applied."
        )


class _RebuildContractionAborted(Exception):
    """Signal rollback when inferred deletion or local exclusions look like truncation."""

    def __init__(
        self,
        existing_count: int,
        inferred_delete_count: int,
        *,
        max_inferred_delete_count: int,
        max_inferred_delete_ratio_percent: int,
        includes_filter_exclusions: bool = False,
    ) -> None:
        """Store remaining-row/deletion counts and describe the contraction rollback."""
        self.existing_count = existing_count
        self.inferred_delete_count = inferred_delete_count
        reason = "absence or filter exclusion" if includes_filter_exclusions else "absence"
        super().__init__(
            "Full rebuild aborted — upstream would remove "
            f"{inferred_delete_count}/{existing_count} records by {reason} "
            "(limit: at most "
            f"{max_inferred_delete_count} records and "
            f"{max_inferred_delete_ratio_percent}%); "
            "other existing data kept. Committed authoritative withdrawals remain applied."
        )


def _sanitize_error_message(error_msg: str, max_length: int = 500) -> str:
    """Redact URLs/Python paths/traceback lines, escape controls and cap diagnostic text.

    Truncate after redaction/escaping to max_length characters plus an ellipsis.
    Callers supply a nonnegative limit. This is not a general secret or path scrubber.
    """
    error_msg = re.sub(r'(?:^|\s+)File "[^"\r\n]+"[^\r\n]*(?:\r?\n|$)', " ", error_msg)
    # URL paths may end in .py; redact the entire token before matching file paths.
    error_msg = re.sub(r"\b[A-Za-z][A-Za-z0-9+.-]*://\S+", "<url>", error_msg)
    error_msg = re.sub(
        r"(?:[A-Za-z]:)?[\\/]?[\w./\\-]+\.py",
        "<file>",
        error_msg,
    )
    error_msg = escape_log_controls(error_msg)

    if len(error_msg) > max_length:
        error_msg = error_msg[:max_length] + "..."

    return error_msg


def _private_errors(configured_source: ConfiguredSource) -> dict[str, bool]:
    """Always supply an explicit diagnostic policy, including for public sources."""
    return {"private_errors": isinstance(configured_source.config, JsonFeedConfig)}


def _audit_options(audit: IngestionAudit | None) -> dict[str, IngestionAudit]:
    """Pass a collector only when audit collection is enabled."""
    return {"audit": audit} if audit is not None else {}


def _safe_cutoff_error(exc: Exception) -> bool:
    """Recognize only the exact public JSON-feed cutoff ValueError."""
    return type(exc) is ValueError and exc.args == (_JSON_FEED_CUTOFF_ERROR,)


def _ingestion_error(exc: Exception, *, private_errors: bool, phase: str) -> str:
    """Return a sanitized error, or only phase for private errors except the allowed cutoff."""
    if not private_errors:
        return _sanitize_error_message(f"{type(exc).__name__}: {exc}")
    return "ValueError: " + _JSON_FEED_CUTOFF_ERROR if _safe_cutoff_error(exc) else phase


def _private_write_error(exc: Exception, *, private_errors: bool) -> None:
    """Raise a fixed RuntimeError for private write errors except the allowed cutoff error."""
    if private_errors and not _safe_cutoff_error(exc):
        raise RuntimeError("JSON feed ingestion write failed") from None


def _log_private_error(message: str, *args: object) -> None:
    """Log fixed operational context without attaching a private exception."""
    logger.error(message, *args)


def _feed_failures(failures: Mapping[str, str]) -> dict[str, str]:
    """Retain fixed native/write reasons; persisted arbitrary messages are not trusted."""
    return {
        uuid: reason
        if isinstance(reason, str) and reason in _JSON_FEED_FAILURE_REASONS
        else "record_rejected"
        for uuid, reason in failures.items()
    }


def _incremental_failure(exc: Exception, source: str, uuid: str, *, private: bool) -> str:
    """Return a private failure code or sanitized error, explaining same-source DOI collisions."""
    if private:
        return "record_write_failed"
    if isinstance(exc, UniqueViolation) and exc.diag.constraint_name == "datasets_source_doi_key":
        return (
            f"DOI collision within source {source!r}: upstream minted a new UUID "
            f"but reused an existing DOI (uuid={uuid})."
        )
    return _sanitize_error_message(f"{type(exc).__name__}: {exc}")


async def _clear_staged_harvest_if_unchanged(
    pool: Database,
    expected_payload: bytes,
    *,
    source: str,
) -> None:
    """Transactionally clear staged payload/start/progress only if bytes still match; otherwise raise RuntimeError."""
    async with get_db_cursor(pool) as cur:
        await _clear_staged_harvest_if_unchanged_cur(
            cur,
            expected_payload,
            source=source,
        )


async def _clear_staged_harvest_if_unchanged_cur(
    cur: AsyncCursor[Any],
    expected_payload: bytes,
    *,
    source: str,
) -> None:
    """Clear matching staged payload/start/progress in the caller's transaction; no matching source row raises RuntimeError."""
    await cur.execute(
        """
        UPDATE sync_status
        SET incremental_harvest = NULL,
            incremental_started_at = NULL,
            incremental_position = 0,
            incremental_affected = 0
        WHERE source = %s
          AND incremental_harvest = %s
        RETURNING source
        """,
        (source, expected_payload),
    )

    if await cur.fetchone() is None:
        raise RuntimeError("staged harvest changed while held under the ingestion lock")


async def upsert_dataset(
    cur: AsyncCursor[Any],
    params: tuple[Any, ...],
) -> DatasetWriteState:
    """Upsert changed catalogue content and return its persisted identity/tier.

    cur uses dictionary rows in the caller's transaction; params follows
    DATASET_INSERT_COLUMNS. Ingestion callers hold the catalogue write lock. An
    explicit upstream tier replaces the stored tier; omission keeps the stricter
    stored/incoming tier. Unchanged rows skip UPDATE/search-trigger work and retain
    synced_at. Existing rows do not allocate identities except a concurrent-insert
    conflict. A missing returned row raises RuntimeError.
    """
    await cur.execute(_DATASET_UPSERT_SQL, params)

    row = await cur.fetchone()
    if row is None:
        raise RuntimeError("Catalogue upsert returned no persisted state")

    return DatasetWriteState(
        dataset_id=row["id"],
        source=row["source"],
        uuid=row["uuid"],
        stored_tier=row["visibility_tier"],
    )


async def _upsert_public_catalogue_record(
    cur: AsyncCursor[Any],
    record: dict[str, Any],
    policy: SourcePolicy,
) -> DatasetWriteState:
    """Validate and upsert a record under the selected source policy.

    Use the caller's transaction. Policy, validation and database failures
    propagate. Return the actual persisted identity and stored tier.
    """
    uuid = record.get("uuid")
    if not uuid:
        raise ValueError(
            "Cannot upsert a catalogue record without a uuid — uuid is the "
            "conflict key; a NULL-uuid row can never be updated and would "
            "accumulate duplicates on every sync."
        )

    visibility_tier = (
        resolve_required_source_tier(
            record.get("visibility_tier"),
            policy,
        )
        if policy.requires_record_tier
        else resolve_tier(
            record.get("visibility_tier"),
            policy,
        )
    )

    access_level = policy.classify_access(record.get("license_val"))
    params = build_record_params(
        record,
        access_level,
        source=policy.name,
        visibility_tier=visibility_tier,
    )

    return await upsert_dataset(cur, params)


async def _upsert_audited_record(
    cur: AsyncCursor[Any],
    record: dict[str, Any],
    policy: SourcePolicy,
    audit: IngestionAudit | None,
) -> None:
    """Capture before state and consume the upsert's persisted result.

    The caller holds the common catalogue transaction lock and owns the
    current transaction/savepoint.
    """
    before = (
        await read_tier_state_cur(
            cur,
            source=policy.name,
            uuid=record["uuid"],
        )
        if audit is not None
        else None
    )

    after = await _upsert_public_catalogue_record(
        cur,
        record,
        policy,
    )

    if audit is not None:
        audit.record_tier_change(before, after)


async def _delete_stale_source_records(
    cur: AsyncCursor[Any],
    source: str,
    offered_uuids: list[str],
    *,
    max_inferred_delete_count: int,
    max_inferred_delete_ratio_percent: int,
    quarantined_uuids: Sequence[str] = (),
    audit: IngestionAudit | None = None,
) -> None:
    """Delete source rows absent from offered_uuids after enforcing contraction limits.

    The caller must hold the ingestion lock and have applied authoritative
    withdrawals independently. Quarantined filter exclusions count toward the
    same budget but are never deleted here. Limits come from the validated source
    schedule; exceeding either raises _RebuildContractionAborted before
    deletion. A missing count row raises RuntimeError.
    """
    await cur.execute(
        """
        SELECT count(*) AS existing_count,
               count(*) FILTER (
                   WHERE NOT (uuid = ANY(%s)) OR uuid = ANY(%s)
               ) AS inferred_delete_count
        FROM oral_history_datasets WHERE source = %s
        """
        if quarantined_uuids
        else """
        SELECT count(*) AS existing_count,
               count(*) FILTER (WHERE NOT (uuid = ANY(%s))) AS inferred_delete_count
        FROM oral_history_datasets
        WHERE source = %s
        """,
        (offered_uuids, list(quarantined_uuids), source)
        if quarantined_uuids
        else (offered_uuids, source),
    )
    row = await cur.fetchone()
    if row is None:
        raise RuntimeError(
            f"Could not count existing rows for source {source!r} before stale deletion"
        )

    existing_count = int(row["existing_count"])
    inferred_delete_count = int(row["inferred_delete_count"])
    if (
        inferred_delete_count > max_inferred_delete_count
        or inferred_delete_count * 100 > existing_count * max_inferred_delete_ratio_percent
    ):
        raise _RebuildContractionAborted(
            existing_count,
            inferred_delete_count,
            max_inferred_delete_count=max_inferred_delete_count,
            max_inferred_delete_ratio_percent=max_inferred_delete_ratio_percent,
            includes_filter_exclusions=bool(quarantined_uuids),
        )

    await cur.execute(
        (
            "DELETE FROM oral_history_datasets WHERE source = %s AND NOT (uuid = ANY(%s))"
            if audit is None
            else "DELETE FROM oral_history_datasets WHERE source = %s AND NOT (uuid = ANY(%s)) RETURNING id, uuid"
        ),
        (source, offered_uuids),
    )
    if audit is not None:
        audit.record_withdrawals(await cur.fetchall(), source=source, reason="inferred")


async def _delete_explicit_source_records(
    cur: AsyncCursor[Any],
    source: str,
    uuids: list[str],
    *,
    audit: IngestionAudit | None = None,
) -> int:
    """Delete supplied source identities and return actual rows deleted in this transaction.

    Only existing rows count; repeated identities do not inflate the result.
    Empty input runs no query.
    The caller must commit before publishing this count or buffered audit events.
    """
    if not uuids:
        return 0

    await cur.execute(
        """
        DELETE FROM oral_history_datasets
        WHERE source = %s
          AND uuid = ANY(%s)
        """
        if audit is None
        else """
        DELETE FROM oral_history_datasets
        WHERE source = %s
          AND uuid = ANY(%s)
        RETURNING id, uuid
        """,
        (source, uuids),
    )
    if audit is not None:
        deleted_rows = await cur.fetchall()
        audit.record_withdrawals(deleted_rows, source=source, reason="explicit")
        return len(deleted_rows)
    return cur.rowcount


async def _publish_fetch_progress_cur(
    cur: AsyncCursor[Any],
    *,
    source: str,
    source_cursor: datetime,
    source_fingerprint: str,
) -> None:
    """Write consumed-snapshot progress in the caller's transaction without resolving quarantine.

    Full rebuilds retry quarantined identities even when upstream timestamps
    have not changed.
    """
    await cur.execute(
        """UPDATE sync_status
           SET source_fetch_cursor = %s, source_fetch_fingerprint = %s
           WHERE source = %s""",
        (source_cursor, source_fingerprint, source),
    )


async def _apply_authoritative_withdrawals(
    pool: Database, source: str, uuids: list[str], *, requires_record_tier: bool
) -> int:
    """Commit genuine privacy withdrawals independently of later rebuild safeguards."""
    if not uuids:
        return 0
    audit = IngestionAudit() if requires_record_tier else None
    async with get_db_cursor(pool) as cur:
        await acquire_catalogue_write_lock_cur(cur)
        deleted = await _delete_explicit_source_records(cur, source, uuids, **_audit_options(audit))
        await _delete_ingestion_failures_cur(cur, source, uuids)
        if audit is not None:
            await audit.persist_cur(cur)
    if audit is not None:
        audit.emit()
    return deleted


async def _update_sync_timestamp(
    cur: AsyncCursor[Any],
    harvest_started_at: datetime,
    *,
    source: str,
    source_cursor: datetime | None,
) -> None:
    """Publish clean incremental progress only for the already-clean binding.

    A newer consumed interpretation remains incomplete until a full rebuild
    succeeds. None preserves the prior clean cursor for empty polls.
    """
    await cur.execute(
        """UPDATE sync_status SET last_harvest_date = %s,
           source_cursor = COALESCE(%s, source_cursor)
           WHERE source = %s AND (
               source_fetch_fingerprint IS NULL
               OR source_fingerprint = source_fetch_fingerprint
           )""",
        (harvest_started_at, source_cursor, source),
    )


async def _quarantine_known_records_cur(
    cur: AsyncCursor[Any],
    source: str,
    uuids: Sequence[str],
    harvest_started_at: datetime,
    source_cursor: datetime,
    *,
    reason: Literal[
        "record_rejected", "record_write_failed", "filter_mismatch"
    ] = "record_rejected",
) -> None:
    """Withhold retained records independently of diagnostic cleanup and deletion.

    No metadata or unvalidated restriction is copied from the rejected record.
    The identity remains quarantined until a valid upstream upsert commits.
    The catalogue lock serializes this change with administrator state and
    projection rebuilding; first failure time is retained on repeated rejection.
    """
    if not uuids:
        return
    await acquire_catalogue_write_lock_cur(cur)
    await cur.execute(
        """INSERT INTO ingestion_quarantine AS existing
            (source, uuid, reason, failed_harvest_at, failed_source_cursor)
        SELECT source, uuid, %s, %s, %s FROM oral_history_datasets
        WHERE source = %s AND uuid = ANY(%s::text[])
        ON CONFLICT (source, uuid) DO UPDATE SET
            reason = EXCLUDED.reason,
            failed_harvest_at = GREATEST(existing.failed_harvest_at, EXCLUDED.failed_harvest_at),
            failed_source_cursor = GREATEST(existing.failed_source_cursor, EXCLUDED.failed_source_cursor)
        WHERE existing.failed_harvest_at < EXCLUDED.failed_harvest_at
           OR existing.failed_source_cursor < EXCLUDED.failed_source_cursor""",
        (reason, harvest_started_at, source_cursor, source, list(uuids)),
    )


async def _restore_valid_record_cur(
    cur: AsyncCursor[Any],
    source: str,
    uuid: str,
    harvest_started_at: datetime,
    source_cursor: datetime,
) -> None:
    """Restore only after a later fresh harvest's validated upsert succeeds.

    Share its transaction/savepoint so a rollback cannot publish the old copy.
    Replaying input staged before or during rejection cannot clear quarantine.
    """
    await cur.execute(
        "DELETE FROM ingestion_quarantine WHERE source = %s AND uuid = %s "
        "AND failed_harvest_at < %s AND failed_source_cursor <= %s",
        (source, uuid, harvest_started_at, source_cursor),
    )


async def _quarantine_filter_exclusions_cur(
    cur: AsyncCursor[Any],
    source: str,
    uuids: Sequence[str],
    harvest_started_at: datetime,
    source_cursor: datetime,
) -> list[tuple[str, str]]:
    """Withhold only known local exclusions; unknown upstream identities create no state."""
    if not uuids:
        return []
    await _quarantine_known_records_cur(
        cur, source, uuids, harvest_started_at, source_cursor, reason="filter_mismatch"
    )
    await cur.execute(
        """WITH known AS MATERIALIZED (
            SELECT source, uuid FROM oral_history_datasets
            WHERE source = %s AND uuid = ANY(%s::text[])
        ), recorded AS (
            INSERT INTO ingestion_failures AS existing (source, uuid, message)
            SELECT source, uuid, 'filter_mismatch' FROM known WHERE true
            ON CONFLICT (source, uuid) DO UPDATE SET message = EXCLUDED.message,
                updated_at = CURRENT_TIMESTAMP
            WHERE existing.message IS DISTINCT FROM EXCLUDED.message
        ) SELECT uuid FROM known""",
        (source, list(uuids)),
    )
    return [(row["uuid"], "filter_mismatch") for row in await cur.fetchall()]


async def _persist_write_quarantine(
    pool: Database,
    source: str,
    uuids: set[str],
    harvest_started_at: datetime,
    source_cursor: datetime,
) -> None:
    """Commit identified write failures after their catalogue transaction ends.

    A failed batch/rebuild must not roll back its serving restriction. Drain
    this final transaction despite cancellation; database failures still surface
    to the scheduler rather than claiming that a quarantine was persisted.
    """
    if not uuids:
        return

    async def persist() -> None:
        """Persist sorted known-record quarantines in a separate database transaction."""
        async with get_db_cursor(pool) as cur:
            await _quarantine_known_records_cur(
                cur,
                source,
                sorted(uuids),
                harvest_started_at,
                source_cursor,
                reason="record_write_failed",
            )

    pending = asyncio.create_task(persist())
    cancelled = False
    while not pending.done():
        try:
            await asyncio.shield(pending)
        except asyncio.CancelledError:
            cancelled = True
    pending.result()
    if cancelled:
        raise asyncio.CancelledError


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


async def _delete_ingestion_failures_cur(
    cur: AsyncCursor[Any],
    source: str,
    uuids: Sequence[str],
) -> None:
    """Clear accepted/withdrawn diagnostics, retaining any current serving quarantine."""
    if not uuids:
        return

    await cur.execute(
        """
        DELETE FROM ingestion_failures AS failure
        WHERE source = %s AND uuid = ANY(%s::text[])
          AND NOT EXISTS (
              SELECT 1 FROM ingestion_quarantine AS quarantine
              JOIN oral_history_datasets AS stored
                ON stored.source = quarantine.source AND stored.uuid = quarantine.uuid
              WHERE quarantine.source = failure.source AND quarantine.uuid = failure.uuid
          )
        """,
        (source, list(uuids)),
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
    source: str,
    failed_records: list[tuple[str, str]],
    source_cursor: datetime,
    source_fingerprint: str,
) -> None:
    """Publish a rebuild's recovery state in the caller's catalogue transaction.

    Publish consumed-snapshot progress even when quarantined identities remain.
    Failures replace the source failure set and incremental diagnostic without
    advancing clean timestamps, cursor, or binding. With no failures,
    clear failures, advance both timestamps/cursor/binding, and clear the
    incremental error if failures previously existed.
    """
    await _publish_fetch_progress_cur(
        cur,
        source=source,
        source_cursor=source_cursor,
        source_fingerprint=source_fingerprint,
    )
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
            source=source,
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
           WHERE source = %s""",
        (harvest_started_at, harvest_started_at, source_cursor, source_fingerprint, source),
    )
    if had_failures:
        await _clear_sync_error(cur, source=source, channel="incremental")


async def _record_sync_error(
    cur: AsyncCursor[Any],
    error_msg: str,
    *,
    source: str,
    channel: SyncErrorChannel,
    private_errors: bool,
) -> None:
    """Store error text unchanged and UTC now for channel; log and suppress execute Exceptions.

    Isolate the UPDATE in a transaction/savepoint so a caught statement
    failure does not abort other caller writes. Invalid channel lookup and
    cancellation still propagate; connection loss cannot preserve writes.
    """
    col, col_at = _SYNC_ERROR_COLUMNS[channel]
    try:
        async with cur.connection.transaction():
            await cur.execute(
                sql.SQL(
                    "UPDATE sync_status SET {col} = %s, {col_at} = %s WHERE source = %s"
                ).format(col=col, col_at=col_at),
                (error_msg, datetime.now(UTC), source),
            )
    except Exception:
        if private_errors:
            _log_private_error("Failed to record feed sync diagnostic (channel=%s)", channel)
        else:
            logger.exception(
                "Failed to record sync error to DB (channel=%s). Original error: %s",
                channel,
                error_msg,
            )


async def _clear_sync_error(
    cur: AsyncCursor[Any],
    *,
    source: str,
    channel: SyncErrorChannel,
) -> None:
    """Clear the selected channel's diagnostic and timestamp in the caller's transaction."""
    col, col_at = _SYNC_ERROR_COLUMNS[channel]
    await cur.execute(
        sql.SQL("UPDATE sync_status SET {col} = NULL, {col_at} = NULL WHERE source = %s").format(
            col=col, col_at=col_at
        ),
        (source,),
    )


async def _record_record_errors(
    cur: AsyncCursor[Any],
    errors: list[tuple[str, str]],
    context: str,
    *,
    source: str,
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
        sql.SQL("UPDATE sync_status SET {col} = %s, {col_at} = %s WHERE source = %s").format(
            col=col, col_at=col_at
        ),
        (error_text, datetime.now(UTC), source),
    )


def _require_source_status_row(
    row: Mapping[str, Any] | None,
    *,
    source: str,
) -> Mapping[str, Any]:
    """Return the existing row or reject missing source state."""
    if row is None:
        raise RuntimeError(
            f"sync_status row is missing for source {source!r}; start the scheduler to provision it"
        )
    return row


def _latest_source_cursor(row: Mapping[str, Any]) -> object:
    """Choose the latest valid cutoff, preserving invalid input for rejection.

    The fetch and replay boundaries own diagnostic sanitization. Return an
    invalid stored value unchanged so those existing boundaries reject it;
    never ignore corrupt auxiliary progress in favor of a clean cursor.
    """
    cursors = []
    for name in ("source_cursor", "source_fetch_cursor"):
        value = row.get(name)
        try:
            cursor = normalize_harvest_since(value)
        except (TypeError, ValueError):
            return value
        if cursor is not None:
            cursors.append(cursor)
    return max(cursors, default=None)


def _require_json_feed_cutoff(
    configured_source: ConfiguredSource,
    candidate_cursor: object,
    committed_cursor: object,
) -> None:
    """Reject rollback or invalid JSON-feed cursors without exposing source metadata.

    Call while holding the ingestion lock, before staging or any replay/rebuild
    mutation. Existing source protocols retain their own cursor semantics.
    """
    if not isinstance(configured_source.config, JsonFeedConfig):
        return
    message = _JSON_FEED_CUTOFF_ERROR
    try:
        candidate = normalize_harvest_since(candidate_cursor)
        committed = normalize_harvest_since(committed_cursor)
    except (TypeError, ValueError):
        raise ValueError(message) from None
    if candidate is None or (committed is not None and candidate < committed):
        raise ValueError(message)


async def _require_source_binding_acknowledgement_cur(
    cur: AsyncCursor[Any],
    *,
    source: str,
    previous_fingerprint: str | None,
    new_fingerprint: str,
) -> None:
    """Raise _SourceBindingAcknowledgementRequired for a changed, unacknowledged binding.

    An absent or unchanged previous fingerprint requires no query.
    """
    if previous_fingerprint is None or previous_fingerprint == new_fingerprint:
        return
    await cur.execute(
        "SELECT 1 AS acknowledged FROM source_binding_acknowledgements "
        "WHERE source = %s AND previous_fingerprint = %s AND source_fingerprint = %s",
        (source, previous_fingerprint, new_fingerprint),
    )
    row = await cur.fetchone()
    if row is None or row.get("acknowledged") != 1:
        logger.error(
            "Source binding changed; review the configuration before acknowledging it",
            extra={
                "event_type": "source_binding_review_required",
                "source": source,
                "previous_fingerprint": previous_fingerprint,
                "target_fingerprint": new_fingerprint,
            },
        )
        raise _SourceBindingAcknowledgementRequired(
            "source configuration changed; operator acknowledgement required "
            f"(previous={previous_fingerprint}, target={new_fingerprint})"
        )


async def _sync_source(
    pool: Database,
    *,
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Resume staged work or fetch and durably stage an incremental harvest.

    Require the ingestion-lock connection and matching source binding.
    Refetch compatible-format changes; unsupported binding/state raises
    _FullReharvestRequired. Fetch from the UTC cursor minus two days,
    or request full input when the cursor is absent. Fetch errors return
    failed outcomes; staging/write errors are reported and re-raised.
    Missing sync_status raises RuntimeError. Staging and replay have
    separate selected-source write timeouts.
    """
    harvest_started_at = datetime.now(UTC)
    source, adapter = configured_source.name, configured_source.adapter
    private = isinstance(configured_source.config, JsonFeedConfig)
    current_source_fingerprint = adapter.config_fingerprint()

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "SELECT source_cursor, source_fingerprint, source_fetch_cursor, "
            "source_fetch_fingerprint, incremental_harvest, incremental_started_at "
            "FROM sync_status WHERE source = %s",
            (source,),
        )
        row = _require_source_status_row(
            await cur.fetchone(),
            source=source,
        )
        last_sync = (
            _latest_source_cursor(row)
            if private
            else row.get("source_fetch_cursor") or row["source_cursor"]
        )
        committed_source_fingerprint = row.get("source_fetch_fingerprint") or row.get(
            "source_fingerprint"
        )
        await _require_source_binding_acknowledgement_cur(
            cur,
            source=source,
            previous_fingerprint=committed_source_fingerprint,
            new_fingerprint=current_source_fingerprint,
        )

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
                if private:
                    raise _FullReharvestRequired(
                        "JSON feed staged harvest requires full rebuild"
                    ) from None
                raise _FullReharvestRequired(str(exc)) from exc

            await _clear_staged_harvest_if_unchanged(
                pool,
                pending_payload,
                source=source,
            )
            logger.warning(
                "Reset incompatible staged harvest; recovery=%s",
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
            try:
                _require_json_feed_cutoff(configured_source, harvest.source_cursor, last_sync)
            except ValueError:
                raise _FullReharvestRequired(_JSON_FEED_CUTOFF_ERROR) from None
            return await _write_incremental(
                pool,
                harvest,
                started_at,
                configured_source=configured_source,
            )
    try:
        normalized_cursor = normalize_harvest_since(last_sync)
        since = normalized_cursor - timedelta(days=2) if normalized_cursor is not None else None
        harvest = await run_source_fetch(
            adapter.fetch,
            since=since,
        )
        harvest.validate()
        _require_json_feed_cutoff(configured_source, harvest.source_cursor, last_sync)
    except Exception as exc:
        sanitized = _ingestion_error(exc, private_errors=private, phase="feed_fetch_failed")
        if private:
            _log_private_error("Incremental sync failed during feed fetch")
        else:
            logger.exception("Incremental sync failed during fetch")
        async with get_db_cursor(pool) as cur:
            await _record_sync_error(
                cur,
                f"Incremental sync (fetch): {sanitized}",
                source=source,
                channel="incremental",
                **_private_errors(configured_source),
            )
        return SyncOutcome("failed", reason=sanitized)

    try:
        async with asyncio.timeout(configured_source.schedule.write_timeout_seconds):
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
                       incremental_affected = 0 WHERE source = %s""",
                    (
                        stored_harvest.prefix,
                        stored_harvest.harvest,
                        stored_harvest.suffix,
                        harvest_started_at,
                        source,
                    ),
                )
            del stored_harvest
    except Exception as exc:
        await _report_write_failure(
            pool, "incremental", exc, source=source, **_private_errors(configured_source)
        )
        _private_write_error(exc, private_errors=private)
        raise

    return await _write_incremental(
        pool, harvest, harvest_started_at, configured_source=configured_source
    )


async def _report_write_failure(
    pool: Database,
    channel: SyncErrorChannel,
    exc: Exception,
    *,
    source: str,
    private_errors: bool,
) -> None:
    """Attempt a sanitized channel diagnostic within five seconds; log and suppress reporting Exceptions."""
    try:
        async with asyncio.timeout(5), get_db_cursor(pool) as cur:
            await _record_sync_error(
                cur,
                f"{channel} write: {_ingestion_error(exc, private_errors=private_errors, phase='feed_write_failed')}",
                source=source,
                channel=channel,
                private_errors=private_errors,
            )
    except Exception:
        if private_errors:
            _log_private_error("Could not persist %s feed write failure", channel)
        else:
            logger.exception("Could not persist %s write failure", channel)


async def _write_incremental(
    pool: Database,
    harvest: HarvestResult,
    started_at: datetime,
    *,
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Apply staged work within its timeout and request recovery for bad data.

    Propagate _FullReharvestRequired without reporting here. Completed
    batches remain committed after later failure or timeout. Escaping record
    data failures request a full rebuild; transient/application errors propagate.
    """
    try:
        async with asyncio.timeout(configured_source.schedule.write_timeout_seconds):
            return await _apply_incremental_harvest(
                pool,
                harvest,
                started_at,
                configured_source=configured_source,
            )
    except _FullReharvestRequired:
        raise
    except Exception as exc:
        await _report_write_failure(
            pool,
            "incremental",
            exc,
            source=configured_source.name,
            **_private_errors(configured_source),
        )
        if isinstance(exc, _RECORD_WRITE_ERRORS):
            raise _FullReharvestRequired("staged harvest cannot be replayed") from None
        _private_write_error(
            exc, private_errors=isinstance(configured_source.config, JsonFeedConfig)
        )
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


async def _read_incremental_progress_cur(
    cur: AsyncCursor[Any],
    configured_source: ConfiguredSource,
    candidate_cursor: datetime | None,
) -> Mapping[str, Any]:
    """Read progress and fence a JSON-feed replay before publishing any changes."""
    json_feed = isinstance(configured_source.config, JsonFeedConfig)
    query = (
        "SELECT incremental_position, incremental_affected, source_cursor, source_fetch_cursor "
        "FROM sync_status WHERE source = %s"
        if json_feed
        else "SELECT incremental_position, incremental_affected FROM sync_status WHERE source = %s"
    )
    await cur.execute(
        query,
        (configured_source.name,),
    )
    progress = _require_source_status_row(await cur.fetchone(), source=configured_source.name)
    if json_feed:
        try:
            _require_json_feed_cutoff(
                configured_source,
                candidate_cursor,
                _latest_source_cursor(progress),
            )
        except ValueError:
            raise _FullReharvestRequired(_JSON_FEED_CUTOFF_ERROR) from None
    return progress


async def _finalize_incremental_harvest(
    pool: Database,
    *,
    source: str,
    harvest_started_at: datetime,
    source_cursor: datetime,
    source_fingerprint: str,
    had_work: bool,
    private_errors: bool,
) -> list[tuple[str, str]]:
    """Clear staged payload/progress and return unresolved (uuid, message) pairs atomically.

    Always advance consumed-snapshot progress; failures preserve clean state
    and remain durable until a successful identity update or authoritative retry.
    Otherwise stamp clean incremental progress only for an already clean
    binding. A changed binding becomes clean only after a successful full rebuild.
    A clean source cursor advances only when had_work is true.
    """
    async with get_db_cursor(pool) as cur:
        await _publish_fetch_progress_cur(
            cur,
            source=source,
            source_cursor=source_cursor,
            source_fingerprint=source_fingerprint,
        )
        failed_records = await _list_ingestion_failures_cur(cur, source)
        if private_errors:
            safe_failures = _feed_failures(dict(failed_records))
            if safe_failures != dict(failed_records):
                await _upsert_ingestion_failures_cur(cur, source, safe_failures)
            failed_records = list(safe_failures.items())
        await cur.execute(
            """UPDATE sync_status SET incremental_harvest = NULL,
               incremental_started_at = NULL,
               incremental_position = 0, incremental_affected = 0 WHERE source = %s""",
            (source,),
        )
        if failed_records:
            await _record_record_errors(
                cur,
                failed_records,
                "Incremental sync",
                source=source,
                channel="incremental",
            )
        else:
            await _update_sync_timestamp(
                cur,
                harvest_started_at,
                source=source,
                source_cursor=source_cursor if had_work else None,
            )
            await _clear_sync_error(cur, source=source, channel="incremental")

    return failed_records


async def _apply_incremental_item_cur(
    cur: AsyncCursor[Any],
    uuid: str,
    record: dict[str, Any] | None,
    policy: SourcePolicy,
    audit: IngestionAudit | None,
) -> int:
    """Apply one savepoint and merge audit changes only after success."""
    with audit_savepoint(audit) as item_audit:
        async with cur.connection.transaction():
            if record is None:
                changed = await _delete_explicit_source_records(
                    cur,
                    policy.name,
                    [uuid],
                    **_audit_options(item_audit),
                )
            else:
                await _upsert_audited_record(
                    cur,
                    record,
                    policy,
                    item_audit,
                )
                changed = 1

    return changed


async def _apply_incremental_harvest(
    pool: Database,
    harvest: HarvestResult,
    harvest_started_at: datetime,
    *,
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Apply staged work and retain serving quarantine after a failed transaction."""
    source_cursor = harvest.validate()
    write_failures: set[str] = set()
    try:
        return await _apply_incremental_harvest_work(
            pool,
            harvest,
            harvest_started_at,
            configured_source=configured_source,
            write_failures=write_failures,
        )
    finally:
        await _persist_write_quarantine(
            pool, configured_source.name, write_failures, harvest_started_at, source_cursor
        )


async def _apply_incremental_item_with_recovery_cur(
    cur: AsyncCursor[Any],
    uuid: str,
    record: dict[str, Any] | None,
    configured_source: ConfiguredSource,
    audit: IngestionAudit | None,
    *,
    harvest_started_at: datetime,
    write_failures: set[str],
    source_cursor: datetime,
) -> int | None:
    """Apply one savepoint and retain failed identities for post-rollback quarantine."""
    source = configured_source.name
    policy = configured_source.policy
    private = isinstance(configured_source.config, JsonFeedConfig)
    try:
        changed = await _apply_incremental_item_cur(cur, uuid, record, policy, audit)
    except _RECORD_WRITE_ERRORS as exc:
        if record is not None:
            write_failures.add(uuid)
        message = _incremental_failure(exc, source, uuid, private=private)
        await _set_ingestion_failure_cur(cur, source, uuid, message)
        if record is not None:
            await _quarantine_known_records_cur(
                cur, source, [uuid], harvest_started_at, source_cursor, reason="record_write_failed"
            )
        logger.warning("Source %s record %s failed; skipping", source, uuid, exc_info=not private)
        return None
    if record is not None:
        await _restore_valid_record_cur(cur, source, uuid, harvest_started_at, source_cursor)
    return changed


async def _apply_incremental_harvest_work(
    pool: Database,
    harvest: HarvestResult,
    harvest_started_at: datetime,
    *,
    configured_source: ConfiguredSource,
    write_failures: set[str],
) -> SyncOutcome:
    """Replay validated staged work on the ingestion-lock connection from durable progress.

    Process sorted withdrawals before matching records; commit at 50 items
    or after a per-item elapsed check reaches two seconds. This is not a
    strict two-second transaction limit. Savepoints isolate the shared
    record-write errors; persist their diagnostics and continue.
    Other errors propagate, preserving earlier batches. Quarantine uncertain
    IDs, clear successful IDs failures, and finalize to success/partial.
    Missing status raises RuntimeError; corrupt progress requires a rebuild.

    Successful identities' failures are cleared once per batch.
    A cleanup failure rolls back the current batch, including its progress
    and buffered audit; earlier committed batches remain durable.
    """
    source = configured_source.name
    policy = configured_source.policy
    private = isinstance(configured_source.config, JsonFeedConfig)

    source_cursor = harvest.validate()
    withdrawals = sorted(harvest.deleted_uuids)
    work: list[tuple[str, dict[str, Any] | None]] = [(uuid, None) for uuid in withdrawals] + [
        (record["uuid"], record) for record in harvest.matching_records
    ]

    async with get_db_cursor(pool) as cur:
        progress = await _read_incremental_progress_cur(
            cur, configured_source, harvest.source_cursor
        )
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
            _feed_failures(harvest.uncertain_records) if private else harvest.uncertain_records,
        )
        await _quarantine_known_records_cur(
            cur, source, list(harvest.uncertain_records), harvest_started_at, source_cursor
        )
        await _quarantine_filter_exclusions_cur(
            cur,
            source,
            sorted(harvest.nonmatching_uuids),
            harvest_started_at,
            source_cursor,
        )

    resumed_at = position
    committed_batches = 0
    max_batch_seconds = 0.0
    total_commit_seconds = 0.0
    max_commit_seconds = 0.0
    loop = asyncio.get_running_loop()
    write_started = loop.time()

    while position < len(work):
        # Publish counters only after commit so rollback leaves durable progress unchanged.
        next_position = position
        next_success_count = success_count
        batch_items = 0
        batch_started = loop.time()
        batch_audit = IngestionAudit() if policy.requires_record_tier else None
        successful_uuids: list[str] = []

        async with get_db_cursor(pool) as cur:
            await acquire_catalogue_write_lock_cur(cur)

            while next_position < len(work):
                uuid, record = work[next_position]

                changed = await _apply_incremental_item_with_recovery_cur(
                    cur,
                    uuid,
                    record,
                    configured_source,
                    batch_audit,
                    harvest_started_at=harvest_started_at,
                    write_failures=write_failures,
                    source_cursor=source_cursor,
                )
                if changed is not None:
                    next_success_count += changed
                    successful_uuids.append(uuid)

                next_position += 1
                batch_items += 1

                if (
                    batch_items >= _INCREMENTAL_COMMIT_BATCH_SIZE
                    or loop.time() - batch_started >= _INCREMENTAL_COMMIT_BATCH_MAX_SECONDS
                ):
                    break

            await _delete_ingestion_failures_cur(
                cur,
                source,
                successful_uuids,
            )

            await cur.execute(
                """UPDATE sync_status SET incremental_position = %s,
                   incremental_affected = %s WHERE source = %s""",
                (next_position, next_success_count, source),
            )
            if batch_audit is not None:
                await batch_audit.persist_cur(cur)
            commit_started = loop.time()

        batch_committed = loop.time()
        if batch_audit is not None:
            batch_audit.emit()
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
        source_cursor=harvest.validate(),
        source_fingerprint=configured_source.adapter.config_fingerprint(),
        had_work=bool(work or harvest.nonmatching_uuids),
        **_private_errors(configured_source),
    )

    elapsed_seconds = loop.time() - write_started
    processed_items = position - resumed_at
    logger.info(
        "Incremental write committed %d item(s) in %d batch(es)",
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


async def _full_rebuild_source(
    pool: Database,
    *,
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Replay pending work when possible, then fetch full input and reconcile.

    Require the ingestion-lock connection. Keep unreplayable staged bytes
    until the rebuild transaction commits. Fetch failures return failed
    outcomes; replay/write failures are reported and re-raised.
    Reconciliation uses the selected source's write timeout.
    """
    staged_payload_to_clear: bytes | None = None
    source = configured_source.name
    adapter = configured_source.adapter
    source_fingerprint = adapter.config_fingerprint()
    private = isinstance(configured_source.config, JsonFeedConfig)

    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                "SELECT incremental_harvest, source_fingerprint, source_fetch_fingerprint "
                "FROM sync_status WHERE source = %s",
                (source,),
            )
            pending = _require_source_status_row(
                await cur.fetchone(),
                source=source,
            )
            await _require_source_binding_acknowledgement_cur(
                cur,
                source=source,
                previous_fingerprint=(
                    pending.get("source_fetch_fingerprint") or pending.get("source_fingerprint")
                ),
                new_fingerprint=source_fingerprint,
            )

        if pending["incremental_harvest"] is not None:
            pending_payload = pending["incremental_harvest"]
            try:
                await _sync_source(pool, configured_source=configured_source)
            except _FullReharvestRequired as exc:
                staged_payload_to_clear = pending_payload
                logger.warning(
                    "Pending harvest cannot be safely replayed; "
                    "retaining it until the full reharvest commits",
                    extra={
                        "event_type": "stored_harvest_full_recovery",
                        "recovery_action": "full_reharvest",
                        "reason": "full_reharvest_required" if private else str(exc),
                    },
                )
    except Exception as exc:
        await _report_write_failure(
            pool, "rebuild", exc, source=source, **_private_errors(configured_source)
        )
        _private_write_error(exc, private_errors=private)
        raise

    harvest_started_at = datetime.now(UTC)

    try:
        harvest = await run_source_fetch(
            adapter.fetch,
            since=None,
        )
        harvest.validate()
    except Exception as exc:
        sanitized = _ingestion_error(exc, private_errors=private, phase="feed_fetch_failed")
        if private:
            _log_private_error("Full rebuild aborted — feed fetch failed")
        else:
            logger.exception("Full rebuild aborted — fetch failed")
        async with get_db_cursor(pool) as cur:
            await _record_sync_error(
                cur,
                f"Full rebuild: {sanitized}",
                source=source,
                channel="rebuild",
                **_private_errors(configured_source),
            )
        return SyncOutcome("failed", reason=sanitized)

    try:
        async with asyncio.timeout(configured_source.schedule.write_timeout_seconds):
            return await _apply_full_harvest(
                pool,
                harvest,
                harvest_started_at,
                configured_source=configured_source,
                source_fingerprint=source_fingerprint,
                staged_payload_to_clear=staged_payload_to_clear,
            )
    except Exception as exc:
        await _report_write_failure(
            pool, "rebuild", exc, source=source, **_private_errors(configured_source)
        )
        _private_write_error(exc, private_errors=private)
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


async def _write_rebuild_group_cur(
    cur: AsyncCursor[Any],
    group: list[dict[str, Any]],
    policy: SourcePolicy,
    audit: IngestionAudit | None,
    harvest_started_at: datetime | None = None,
    source_cursor: datetime | None = None,
) -> None:
    """Write a DOI-connected group and merge audit changes only after its savepoint succeeds.

    Clear existing DOIs for multirecord swaps; clear quarantine only when both
    harvest timestamps are supplied. The caller owns the outer transaction.
    """
    with audit_savepoint(audit) as group_audit:
        async with cur.connection.transaction():
            if len(group) > 1:
                await cur.execute(
                    "UPDATE oral_history_datasets SET doi = NULL "
                    "WHERE source = %s AND uuid = ANY(%s)",
                    (policy.name, [record["uuid"] for record in group]),
                )
            for record in group:
                await _upsert_audited_record(cur, record, policy, group_audit)
                if harvest_started_at is not None and source_cursor is not None:
                    await _restore_valid_record_cur(
                        cur, policy.name, record["uuid"], harvest_started_at, source_cursor
                    )


async def _reconcile_rebuild_records(
    cur: AsyncCursor[Any],
    records: list[dict[str, Any]],
    *,
    policy: SourcePolicy,
    private_errors: bool,
    audit: IngestionAudit | None = None,
    write_failures: set[str] | None = None,
    harvest_started_at: datetime | None = None,
    source_cursor: datetime | None = None,
) -> tuple[int, list[tuple[str, str]]]:
    """Upsert DOI-connected groups in savepoints; return successful count and UUID/error pairs.

    The caller owns the transaction. Multirecord groups temporarily clear DOIs
    for swaps. Duplicate final DOIs and _RECORD_WRITE_ERRORS roll back the group
    and become diagnostics; other errors propagate. If supplied, write_failures
    accumulates failed UUIDs for post-rollback quarantine.
    """
    await cur.execute(
        "SELECT uuid, doi FROM oral_history_datasets WHERE source = %s AND doi IS NOT NULL",
        (policy.name,),
    )
    current = {row["doi"]: row["uuid"] for row in await cur.fetchall()}
    successes = 0
    failures: list[tuple[str, str]] = []

    for group in _doi_correction_groups(records, current):
        try:
            canonical = [canonicalize_doi(r["doi"]) for r in group if r.get("doi")]
            nonempty = [doi for doi in canonical if doi is not None]
            if len(nonempty) != len(set(nonempty)):
                raise ValueError("Duplicate final DOI assignments in rebuild group")

            await _write_rebuild_group_cur(
                cur, group, policy, audit, harvest_started_at, source_cursor
            )
            successes += len(group)
        except _RECORD_WRITE_ERRORS as exc:
            if write_failures is not None:
                write_failures.update(record["uuid"] for record in group)
            logger.warning("Full rebuild correction group failed", exc_info=not private_errors)
            error = (
                "record_group_failed"
                if private_errors
                else _sanitize_error_message(f"{type(exc).__name__}: {exc}")
            )
            failures.extend((record["uuid"], error) for record in group)

    return successes, failures


async def _apply_empty_full_harvest(
    pool: Database,
    harvest: HarvestResult,
    *,
    configured_source: ConfiguredSource,
    source_fingerprint: str,
    staged_payload_to_clear: bytes | None,
) -> SyncOutcome:
    """Retain ambiguous absences and return the durable unresolved failure count."""
    source = configured_source.name
    private = isinstance(configured_source.config, JsonFeedConfig)
    failures = _feed_failures(harvest.uncertain_records) if private else harvest.uncertain_records
    explicit_removals = sorted(harvest.deleted_uuids)
    source_cursor = harvest.validate()
    deleted_count = await _apply_authoritative_withdrawals(
        pool,
        source,
        explicit_removals,
        requires_record_tier=configured_source.policy.requires_record_tier,
    )

    logger.warning(
        "Full rebuild aborted — no matching records returned; "
        "applied %d explicit removal(s) from %d requested and kept all other existing data. "
        "Deleted=%d, nonmatching=%d, uncertain=%d",
        deleted_count,
        len(explicit_removals),
        len(harvest.deleted_uuids),
        len(harvest.nonmatching_uuids),
        len(harvest.uncertain_records),
    )

    async with get_db_cursor(pool) as cur:
        await _upsert_ingestion_failures_cur(cur, source, failures)
        # All-uncertain snapshots still have a durable retry set. An
        # entirely empty response remains ambiguous and cannot bind a
        # changed source or advance recovery past its retained catalogue.
        if failures:
            if staged_payload_to_clear is not None:
                await _clear_staged_harvest_if_unchanged_cur(
                    cur, staged_payload_to_clear, source=source
                )
            await _publish_fetch_progress_cur(
                cur,
                source=source,
                source_cursor=source_cursor,
                source_fingerprint=source_fingerprint,
            )
        await _record_sync_error(
            cur,
            f"Full rebuild: source {source!r} returned 0 matching records; "
            f"{deleted_count} explicit source removal(s) applied; "
            f"{len(harvest.uncertain_records)} record(s) had uncertain "
            "source metadata; all other existing data kept.",
            source=source,
            channel="rebuild",
            **_private_errors(configured_source),
        )

        await cur.execute(
            "SELECT count(*) AS failed_count FROM ingestion_failures WHERE source = %s",
            (source,),
        )
        count_row = await cur.fetchone()
        if count_row is None:
            raise RuntimeError("Ingestion failure count query returned no row")
        failed_count = count_row["failed_count"]

    return SyncOutcome(
        "failed",
        affected_count=deleted_count,
        failed_count=failed_count,
        reason="no matching records; only explicit withdrawals applied",
    )


async def _apply_full_harvest(
    pool: Database,
    harvest: HarvestResult,
    harvest_started_at: datetime,
    *,
    configured_source: ConfiguredSource,
    source_fingerprint: str,
    staged_payload_to_clear: bytes | None = None,
) -> SyncOutcome:
    """Reconcile a snapshot while retaining restrictions after a failed rebuild."""
    source_cursor = harvest.validate()
    write_failures: set[str] = set()
    try:
        return await _apply_full_harvest_work(
            pool,
            harvest,
            harvest_started_at,
            configured_source=configured_source,
            source_fingerprint=source_fingerprint,
            staged_payload_to_clear=staged_payload_to_clear,
            write_failures=write_failures,
        )
    finally:
        await _persist_write_quarantine(
            pool, configured_source.name, write_failures, harvest_started_at, source_cursor
        )


async def _apply_full_harvest_work(
    pool: Database,
    harvest: HarvestResult,
    harvest_started_at: datetime,
    *,
    configured_source: ConfiguredSource,
    source_fingerprint: str,
    staged_payload_to_clear: bytes | None,
    write_failures: set[str],
) -> SyncOutcome:
    """Reconcile a validated full harvest on the ingestion-lock connection.

    With no matches, apply authoritative withdrawals and return failed.
    Otherwise commit authoritative withdrawals independently, then delete
    guarded-absent rows and upsert matches in one transaction, protecting
    uncertain and locally excluded IDs. Roll back the latter if contraction exceeds
    the selected source limits, or fewer than half the offered records write; return
    a failed outcome. Partial success can commit deletions/upserts but
    does not advance rebuild timestamps, source cursor, or binding.

    source_fingerprint is captured from the adapter that fetched this harvest.
    A supplied staged payload is cleared only if unchanged, else RuntimeError.
    Validation/database errors propagate; successful reconciliation returns
    success or partial.
    """
    source = configured_source.name
    policy = configured_source.policy
    source_cursor = harvest.validate()
    if isinstance(configured_source.config, JsonFeedConfig):
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                "SELECT source_cursor, source_fetch_cursor FROM sync_status WHERE source = %s",
                (source,),
            )
            status = _require_source_status_row(await cur.fetchone(), source=source)
            _require_json_feed_cutoff(
                configured_source,
                source_cursor,
                _latest_source_cursor(status),
            )

    private = isinstance(configured_source.config, JsonFeedConfig)
    audit = IngestionAudit() if policy.requires_record_tier else None
    live_records = harvest.matching_records
    failures = _feed_failures(harvest.uncertain_records) if private else harvest.uncertain_records
    failed_records = list(failures.items())
    explicit_removals = sorted(harvest.deleted_uuids)

    # Restrictive handling of authenticated, identifiable invalid records must
    # survive an unrelated contraction guard or rebuild transaction rollback.
    if failures:
        async with get_db_cursor(pool) as cur:
            await _quarantine_known_records_cur(
                cur, source, list(failures), harvest_started_at, source_cursor
            )
    if harvest.nonmatching_uuids:
        async with get_db_cursor(pool) as cur:
            excluded = await _quarantine_filter_exclusions_cur(
                cur,
                source,
                sorted(harvest.nonmatching_uuids),
                harvest_started_at,
                source_cursor,
            )
            failed_records.extend(excluded)

    if not live_records:
        return await _apply_empty_full_harvest(
            pool,
            harvest,
            configured_source=configured_source,
            source_fingerprint=source_fingerprint,
            staged_payload_to_clear=staged_payload_to_clear,
        )

    success_count = 0
    protected_uuids = {record["uuid"] for record in live_records}
    protected_uuids.update(harvest.uncertain_records.keys())
    protected_uuids.update(harvest.nonmatching_uuids)

    # An authoritative privacy withdrawal must not wait for an unrelated
    # absence/filter safeguard or a later accepted-record write to succeed.
    await _apply_authoritative_withdrawals(
        pool, source, explicit_removals, requires_record_tier=policy.requires_record_tier
    )

    try:
        async with get_db_cursor(pool) as cur:
            await acquire_catalogue_write_lock_cur(cur)
            await _delete_stale_source_records(
                cur,
                source,
                sorted(protected_uuids),
                max_inferred_delete_count=configured_source.schedule.rebuild_max_inferred_delete_count,
                max_inferred_delete_ratio_percent=(
                    configured_source.schedule.rebuild_max_inferred_delete_ratio_percent
                ),
                quarantined_uuids=sorted(harvest.nonmatching_uuids),
                **_audit_options(audit),
            )
            success_count, record_write_failures = await _reconcile_rebuild_records(
                cur,
                live_records,
                policy=policy,
                private_errors=private,
                write_failures=write_failures,
                harvest_started_at=harvest_started_at,
                source_cursor=source_cursor,
                **_audit_options(audit),
            )
            failed_records.extend(record_write_failures)

            offered_count = len(live_records)
            if success_count * _REBUILD_MIN_SUCCESS_DENOM < offered_count:
                raise _RebuildAborted(  # noqa: TRY301 - deliberate transaction rollback signal
                    success_count, offered_count
                )

            if staged_payload_to_clear is not None:
                await _clear_staged_harvest_if_unchanged_cur(
                    cur,
                    staged_payload_to_clear,
                    source=source,
                )

            await _update_full_rebuild_timestamp(
                cur,
                harvest_started_at,
                source=source,
                failed_records=failed_records,
                source_cursor=source_cursor,
                source_fingerprint=source_fingerprint,
            )
            if failed_records:
                await _record_record_errors(
                    cur,
                    failed_records,
                    "Full rebuild",
                    source=source,
                    channel="rebuild",
                )
            else:
                await _clear_sync_error(cur, source=source, channel="rebuild")
                await _clear_sync_error(cur, source=source, channel="incremental")
            if audit is not None:
                await audit.persist_cur(cur)
        if audit is not None:
            audit.emit()
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
            await _record_sync_error(
                status_cur,
                str(exc),
                source=source,
                channel="rebuild",
                **_private_errors(configured_source),
            )
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
                source=source,
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
    *,
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Run incremental work on the locked session and translate rebuild signals."""
    try:
        return await _sync_source(
            connection,
            configured_source=configured_source,
        )
    except _FullReharvestRequired as exc:
        acknowledgement_required = isinstance(exc, _SourceBindingAcknowledgementRequired)
        async with get_db_cursor(connection) as cur:
            detail = (
                "full_reharvest_required"
                if isinstance(configured_source.config, JsonFeedConfig)
                else str(exc)
            )
            await _record_sync_error(
                cur,
                f"Incremental sync requires a full rebuild: {detail}",
                source=configured_source.name,
                channel="incremental",
                **_private_errors(configured_source),
            )
        return SyncOutcome(
            "failed",
            reason=(
                "source configuration acknowledgement required"
                if acknowledgement_required
                else "full rebuild required"
            ),
            requires_full_rebuild=not acknowledgement_required,
            requires_source_acknowledgement=acknowledgement_required,
        )


async def run_sync(
    pool: AsyncConnectionPool,
    *,
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Serialize incremental ingestion locally and across processes.

    Reserve one pool connection for fetching and writing. Write/connection
    failures and cancellation can propagate. Callers handle
    requires_full_rebuild and invalidate catalogue caches.
    """
    try:
        async with _sync_mutex, _cross_process_sync_lock(pool) as connection:
            return await _run_sync_on_locked_connection(
                connection,
                configured_source=configured_source,
            )
    except Exception as exc:
        _private_write_error(
            exc, private_errors=isinstance(configured_source.config, JsonFeedConfig)
        )
        raise


async def _run_full_rebuild_on_locked_connection(
    connection: AsyncConnection,
    *,
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Run a full rebuild on the session that owns the ingestion lock."""
    try:
        return await _full_rebuild_source(connection, configured_source=configured_source)
    except _SourceBindingAcknowledgementRequired:
        return SyncOutcome(
            "failed",
            reason="source configuration acknowledgement required",
            requires_source_acknowledgement=True,
        )


async def run_full_rebuild(
    pool: AsyncConnectionPool,
    *,
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Serialize full reconciliation locally and across processes.

    Reserve one pool connection for fetching and writing. Write/connection
    failures and cancellation can propagate. Partial/failed results may
    include committed changes; callers invalidate catalogue caches.
    """
    try:
        async with _sync_mutex, _cross_process_sync_lock(pool) as connection:
            return await _run_full_rebuild_on_locked_connection(
                connection,
                configured_source=configured_source,
            )
    except Exception as exc:
        _private_write_error(
            exc, private_errors=isinstance(configured_source.config, JsonFeedConfig)
        )
        raise

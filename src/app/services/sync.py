"""Sync orchestrator — coordinates fetching from all sources and writing to DB.

Currently supports:
- Source A: SWISSUbase via OAI-PMH (oai_client.py)
- Source B: Placeholder for Phase 2
"""

from datetime import datetime, timezone
import json
import logging
import re

from psycopg import sql, AsyncCursor
from psycopg_pool import AsyncConnectionPool
from psycopg.errors import UniqueViolation
from starlette.concurrency import run_in_threadpool

from .db import get_db_cursor
from .schema import (
    DATASET_INSERT_SQL, 
    DATASET_INSERT_PLACEHOLDERS, 
    DATASET_COLUMNS,
    DATASET_INSERT_COLUMNS
    )
from .oai_client import fetch_updates
from .access_tiers import SourcePolicy, resolve_tier
from .access_tiers import AccessTier

from config import settings

logger = logging.getLogger(__name__)

_SWISSUBASE_POLICY = SourcePolicy(
    name="swissubase",
    max_visibility=settings.swissubase_max_visibility,
)

_DATASET_UPDATE_CLAUSE = sql.SQL(", ").join(
    sql.SQL("{} = EXCLUDED.{}").format(sql.Identifier(c), sql.Identifier(c))
    for c in DATASET_INSERT_COLUMNS
)

_PARSER_OWNED = set(DATASET_COLUMNS) - {"access_level", "source", "visibility_tier"}
_ARRAY_COLUMNS = ("languages", "authors", "keywords", "institutions", "main_disciplines")

def _sanitize_error_message(error_msg: str, max_length: int = 500) -> str:
    """Strip file paths and truncate error messages before storing.
    
    Removes:
    - Absolute file paths (e.g., /opt/.../file.py)
    - Python stack frames (e.g., "  File ...")
    - Truncates to max_length characters
    """
    # Strip file paths in messages
    error_msg = re.sub(r"/[\w./\-]+\.py", "<file>", error_msg)
    
    # Strip stack frames if any leaked into the message
    error_msg = re.sub(r"\s+File \"[^\"]+\"[^\n]*\n", " ", error_msg)
    
    # Truncate
    if len(error_msg) > max_length:
        error_msg = error_msg[:max_length] + "..."
    
    return error_msg


# =============================================================================
# DB helpers
# =============================================================================

def _build_record_params(
    record: dict,
    access_level: str,
    source: str,
    visibility_tier: AccessTier
) -> tuple:
    """Build a params tuple from a record dict, ordered by DATASET_INSERT_COLUMNS.

    The tuple is emitted by iterating DATASET_INSERT_COLUMNS, so value order
    can never drift from the column list or the placeholder list (both built
    the same way in schema.py). Adding or reordering a column there updates
    this automatically.

    Field-presence is validated against _PARSER_OWNED: every key that
    parse_cmdi_to_dict is contracted to emit must be present in `record`. A
    missing key signals a parser/CMDI-profile drift (a renamed or dropped
    field) and raises KeyError, so the drift surfaces as a skipped-and-recorded
    record (last_sync_error / /health/detail) instead of silently nulling
    columns across the catalogue. Note this checks key *presence*, not value:
    an optional field the parser emits as None/[] is present and valid, and
    becomes a NULL column as expected.

    Raises:
        KeyError: If `record` is missing a key that parse_cmdi_to_dict emits
            (parser contract / profile drift).

    Args:
        record: The raw record data (typically from OAI-PMH).
        access_level: Derived from license_val via _classify_access_level.
        source: Application-set source identifier ("swissubase", "mock",
                "leomed", etc.). Caller controls this, not upstream.
        visibility_tier: Application-set initial visibility ("public",
                        "registered", or "vetted"). Required — there is no
                        default, so the caller must make an explicit choice
                        (sync derives it via resolve_tier and the source's
                        policy ceiling). Administrators can override per
                        record after insert (directly in the database
                        today).
    """
    missing_keys = _PARSER_OWNED - record.keys()
    if missing_keys:
        raise KeyError(
            f"record missing parser-emitted keys (CMDI profile drift?): {sorted(missing_keys)}"
        )

    values = {
        "access_level": access_level,
        "resource_proxies": json.dumps(record.get("resource_proxies", [])),
        "source": source,
        "visibility_tier": visibility_tier,
        "data": json.dumps(record),
        "last_modified": datetime.now(timezone.utc),
    }
    for col in DATASET_COLUMNS:
        if col in values:
            continue
        values[col] = record.get(col, []) if col in _ARRAY_COLUMNS else record.get(col)

    # DATASET_INSERT_COLUMNS ⊆ values.keys() is already guaranteed 
    # (every column is assigned above) and the column-set alignment
    # is validated at startup by validate_dataset_insert_schema(). 
    # Unreachable in practice; kept as a defensive invariant.
    missing = [c for c in DATASET_INSERT_COLUMNS if c not in values]
    if missing:
        raise AssertionError(f"_build_record_params has no value for columns: {missing}")
    
    return tuple(values[col] for col in DATASET_INSERT_COLUMNS)


def _classify_access_level(license_val: str | None, source: str) -> str:
    """Derive access level from the OAI-PMH license field.

    SWISSUbase uses free-text license values. Records with licenses
    starting with "restricted access" (case-insensitive) are classified
    as restricted; everything else is public.

    If SWISSUbase changes their license labelling, this function
    is the single place to update. Classifier left fail-open by choice
    for Source A because upstream omits restricted download links; any
    non-swissubase source must set access_level explicitly.
    """
    if source != "swissubase":
        raise NotImplementedError(
            f"_classify_access_level is fail-open and only validated for "
            f"SWISSUbase. Source {source!r} must set access_level explicitly "
            f"via its own gating."
        )
    if (license_val or "").lower().startswith("restricted access"):
        return "restricted"
    return "public"


async def _upsert_dataset(cur: AsyncCursor, params: tuple) -> None:
    """Upsert one dataset row by uuid. Single source of the INSERT/ON CONFLICT SQL."""
    await cur.execute(sql.SQL("""
        INSERT INTO oral_history_datasets ({columns})
        VALUES ({placeholders})
        ON CONFLICT (uuid) DO UPDATE SET {updates}
    """).format(
        columns=DATASET_INSERT_SQL,
        placeholders=DATASET_INSERT_PLACEHOLDERS,
        updates=_DATASET_UPDATE_CLAUSE,
    ), params)


async def _upsert_public_catalogue_record(cur: AsyncCursor, record: dict, policy: SourcePolicy) -> None:
    """Insert or update one record from a PUBLIC metadata catalogue (Source A).

    Visibility is resolved through the source POLICY, never hardcoded: a record
    can't be published more permissively than policy.max_visibility. A public
    catalogue publishes at "public"; pointing this at a restricted catalogue
    (policy ceiling "vetted") clamps every record to "vetted".
    """
    uuid = record.get("uuid")
    if not uuid:
        raise ValueError(
            "Cannot upsert a catalogue record without a uuid — uuid is the "
            "conflict key; a NULL-uuid row can never be updated and would "
            "accumulate duplicates on every sync."
        )

    access_level = _classify_access_level(record.get("license_val"), source=policy.name)
    visibility_tier = resolve_tier(record.get("visibility_tier"), policy) 
    params = _build_record_params(
        record, access_level, 
        source=policy.name, 
        visibility_tier=visibility_tier
    )

    await _upsert_dataset(cur, params)

async def _delete_source_records(cur: AsyncCursor, source: str) -> None:
    """Delete all records from a specific source.

    Scoped by the source column so that rebuilding Source A
    does not affect Source B or mock data.
    """
    await cur.execute("DELETE FROM oral_history_datasets WHERE source = %s", (source,))


async def _update_sync_timestamp(cur: AsyncCursor, harvest_started_at: datetime) -> None:
    """Update the incremental harvest watermark (the OAI 'from' cursor)."""
    await cur.execute("UPDATE sync_status SET last_harvest_date = %s WHERE id = 1",
                (harvest_started_at,))


async def _update_full_rebuild_timestamp(cur: AsyncCursor, harvest_started_at: datetime) -> None:
    """Mark a completed full rebuild.

    A full rebuild has fetched everything up to "now", so the incremental
    cursor (last_harvest_date) is reset to now as well — the next incremental
    sync starts from this point. last_full_rebuild_date is the marker shown
    to users as "data complete and consistent as of", since only a full
    rebuild can remove stale dataset versions (incremental syncs cannot
    detect in-place upstream updates).
    """
    await cur.execute(
        """UPDATE sync_status
           SET last_harvest_date = %s,
               last_full_rebuild_date = %s
           WHERE id = 1""",
        (harvest_started_at, harvest_started_at),
    )


async def _record_sync_error(cur: AsyncCursor, error_msg: str) -> None:
    """Record a sync failure in the sync_status table.
    
    If the DB write itself fails (DB down, locks, etc.), logs to application
    logger as last resort so the original error isn't lost.
    """
    try:
        await cur.execute(
            """UPDATE sync_status
               SET last_sync_error = %s,
                   last_sync_error_at = %s
               WHERE id = 1""",
            (error_msg, datetime.now(timezone.utc)),
        )
    except Exception:
        logger.exception(
            "Failed to record sync error to DB. Original error: %s",
            error_msg,
        )

async def _clear_sync_error(cur: AsyncCursor) -> None:
    """Clear the sync error after a successful sync."""
    await cur.execute(
        """UPDATE sync_status
           SET last_sync_error = NULL,
               last_sync_error_at = NULL
           WHERE id = 1""",
    )


async def _record_record_errors(cur: AsyncCursor, errors: list[tuple[str, str]], context: str) -> None:
    """Record record-level errors from a partially-successful sync."""
    formatted = "\n".join(
        f"  {uuid}: {msg}"
        for uuid, msg in errors[:20]
    )
    if len(errors) > 20:
        formatted += f"\n  ... and {len(errors) - 20} more"
    
    error_text = f"{context}: {len(errors)} record(s) failed\n{formatted}"
    
    try:
        await cur.execute(
            """UPDATE sync_status
               SET last_sync_error = %s,
                   last_sync_error_at = %s
               WHERE id = 1""",
            (error_text, datetime.now(timezone.utc)),
        )
    except Exception:
        logger.exception(
            "Failed to record record-level errors to DB. Errors: %s",
            error_text,
        )


# =============================================================================
# Sync operations
# =============================================================================
async def run_sync(pool: AsyncConnectionPool) -> None:
    """Run incremental sync from all sources."""
    await _sync_source_a(pool)
    # _sync_source_b(pool)  # TODO: Phase 2
    logger.info("Sync complete.")


async def run_full_rebuild(pool: AsyncConnectionPool) -> None:
    """Run full rebuild of all sources."""
    await _full_rebuild_source_a(pool)
    # _full_rebuild_source_b(pool)  # TODO: Phase 2


async def _sync_source_a(pool: AsyncConnectionPool) -> None:
    """Incremental sync — fetches only new/updated records since last harvest.
    
    Each record is processed in its own transaction. A failure on one
    record (malformed data, schema violation) is logged and the sync
    continues with the next record. The watermark advances to the harvest start time 
    (captured before the fetch, so records modified mid-harvest are re-fetched next run — 
    idempotent by uuid), regardless of per-record failures — the regular full rebuild will
    refetch any records that have since been corrected upstream.
    """
    harvest_started_at = datetime.now(timezone.utc)
    
    async with get_db_cursor(pool) as cur:
        await cur.execute("SELECT last_harvest_date FROM sync_status WHERE id = 1")
        row = await cur.fetchone()
        if not row:
            raise RuntimeError("sync_status table is empty — run migrations first")
        last_sync = row["last_harvest_date"]

    since = last_sync.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    try:
        records = await run_in_threadpool(
            fetch_updates,
            oai_url=settings.swissubase_oai_pmh_url,
            since=since,
            institution_filter=settings.oai_institution_filter,
        )
    except Exception as e:
        sanitized = _sanitize_error_message(f"{type(e).__name__}: {e}")
        logger.exception("Source A incremental sync failed during fetch")
        async with get_db_cursor(pool) as cur:
            await _record_sync_error(cur, f"Incremental sync (fetch): {sanitized}")
        return

    success_count = 0
    failed_records: list[tuple[str, str]] = []

    for record in records:
        uuid = record.get("uuid")
        if not uuid:
            logger.warning(
                "Source A record has no UUID; skipping. Title: %r",
                record.get("title", "")[:100],
            )
            failed_records.append(("<no-uuid>", "missing UUID"))
            continue

        try:
            async with get_db_cursor(pool) as cur:
                if record.get("_deleted"):
                    await cur.execute(
                        "DELETE FROM oral_history_datasets WHERE uuid = %s",
                        (uuid,),
                    )
                else:
                    await _upsert_public_catalogue_record(cur, record, _SWISSUBASE_POLICY)
            success_count += 1
        except UniqueViolation as e:
            if e.diag.constraint_name == "oral_history_datasets_doi_key":  
                sanitized = (
                    f"DOI collision: upstream minted a new uuid but reused an existing "
                    f"doi (uuid={uuid}). The doi UNIQUE constraint blocked this version; "
                    f"it stays invisible until the next full rebuild removes its predecessor. "
                    f"If this recurs, the doi UNIQUE constraint needs revisiting."
                )
            else:
                sanitized = _sanitize_error_message(f"{type(e).__name__}: {e}")
            logger.warning("Source A record %s failed (unique violation); skipping", uuid, exc_info=True)
            failed_records.append((uuid, sanitized))
        except Exception as e:
            logger.warning("Source A record %s failed; skipping", uuid, exc_info=True)
            sanitized = _sanitize_error_message(f"{type(e).__name__}: {e}")
            failed_records.append((uuid, sanitized))

    async with get_db_cursor(pool) as cur: 
        await _update_sync_timestamp(cur, harvest_started_at)
        if failed_records:
            await _record_record_errors(cur, failed_records, "Incremental sync")
        else:
            await _clear_sync_error(cur)

    if failed_records:
        logger.warning(
            "Source A sync complete — %d records processed, %d failed.",
            success_count, len(failed_records),
        )
    else:
        logger.info(
            "Source A sync complete — %d records processed.",
            success_count,
        )


async def _full_rebuild_source_a(pool: AsyncConnectionPool) -> None:
    """Full re-harvest — replaces all Source A records.

    Fetches all records BEFORE deleting anything. If the fetch fails
    or returns empty, existing data is preserved.

    Necessary because updated dataset versions get new UUIDs and DOIs
    in OAI-PMH, with no link to the previous version and no reliable
    upstream "modified" signal — periodic full rebuilds are how stale
    versions get removed.

    Per-record resilience: the delete and all inserts run in a single
    transaction (so the table is never observed empty), but each record
    is upserted inside a SAVEPOINT. A single malformed record rolls back
    only its own savepoint and is recorded in sync_status; the rest of
    the rebuild still commits. This mirrors the incremental sync's
    skip-and-record behaviour, and makes failures visible via
    last_sync_error (surfaced on /health/detail) rather than silently
    aborting the whole rebuild.
    """
    harvest_started_at = datetime.now(timezone.utc)
    try:
        records = await run_in_threadpool(
            fetch_updates,
            oai_url=settings.swissubase_oai_pmh_url,
            since="1900-01-01T00:00:00Z",
            institution_filter=settings.oai_institution_filter,
        )
    except Exception as e:
        sanitized = _sanitize_error_message(f"{type(e).__name__}: {e}")
        logger.exception("Full rebuild aborted — fetch failed")
        async with get_db_cursor(pool) as cur:
            await _record_sync_error(cur, f"Full rebuild: {sanitized}")
        return

    live_records = [r for r in records if not r.get("_deleted")]
    if not live_records:
        logger.warning("Full rebuild aborted — no records returned, keeping existing data.")
        return

    success_count = 0
    failed_records: list[tuple[str, str]] = []

    async with get_db_cursor(pool) as cur:
        await _delete_source_records(cur, _SWISSUBASE_POLICY.name)
        for record in live_records:
            uuid = record.get("uuid")
            if not uuid:
                logger.warning(
                    "Full rebuild: record has no UUID; skipping. Title: %r", 
                    (record.get("title") or "")[:100]
                )
                failed_records.append(("<no-uuid>", "missing UUID"))
                continue
            try:
                async with cur.connection.transaction():
                    await _upsert_public_catalogue_record(cur, record, _SWISSUBASE_POLICY)
                success_count += 1
            except Exception as e:
                logger.warning(
                    "Full rebuild: record %s failed; skipping", uuid, exc_info=True
                )
                sanitized = _sanitize_error_message(f"{type(e).__name__}: {e}")
                failed_records.append((uuid, sanitized))

        await _update_full_rebuild_timestamp(cur, harvest_started_at)
        if failed_records:
            await _record_record_errors(cur, failed_records, "Full rebuild")
        else:
            await _clear_sync_error(cur)

    if failed_records:
        logger.warning(
            "Full rebuild complete — %d records inserted, %d failed.",
            success_count, len(failed_records),
        )
    else:
        logger.info("Full rebuild complete — %d records inserted.", success_count)

# async def _sync_source_b(pool: AsyncConnectionPool) -> None:
#     """Sync datasets from Source B.
#     
#     TODO: Phase 2 — implement when Source B access is available.
#     Expected: separate client module (source_b_client.py),
#     same pattern as Source A (fetch → filter → upsert).
#     """
#     pass
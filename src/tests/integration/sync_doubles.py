"""Shared doubles for the synchronisation modules of the integration tier.

Several modules drive ``app.services.sync`` against the real database with a
patched harvest (``FETCH``) and records shaped exactly like the parser's
output (``make_record``). They lived in one sync module and were imported
from there; they sit here so that no test module imports another.
"""

from datetime import UTC, datetime
from typing import Any

from app.services.oai_client import HarvestResult
from tests.oai_fixtures import SOURCE_CURSOR

# The patch target that replaces the isolated harvest in the sync loop.
FETCH = "app.services.sync.fetch_updates_isolated"


def harvest_result(
    matching_records=(),
    *,
    deleted_uuids=(),
    nonmatching_uuids=(),
    uncertain_records=None,
) -> HarvestResult:
    """Build the structured result returned by ``fetch_updates``."""
    return HarvestResult(
        source_cursor=SOURCE_CURSOR,
        matching_records=list(matching_records),
        deleted_uuids=set(deleted_uuids),
        nonmatching_uuids=set(nonmatching_uuids),
        uncertain_records=dict(uncertain_records or {}),
    )


def make_record(uuid, title="Oral History Interviews", **over):
    """A record dict with EVERY key in datasets.PARSER_OWNED, mirroring the
    exact output shape of _parse_cmdi_to_dict (lists for the array fields,
    None-able strings elsewhere, resource_proxies as a list of dicts).

    institutions carries a real filter-matching value ('Universität Kassel')
    even though sync itself never filters — fetch_updates does — so these
    records look exactly like what the sync loop receives in production.
    """
    rec = {
        "uuid": uuid,
        "title": title,
        "project_title": None,
        "description": "Interviews with eyewitnesses about postwar reconstruction.",
        "resource_description": None,
        "languages": ["German"],
        "project_description": None,
        "authors": ["Anna Steinberg", "Ivan Kovačević"],
        "keywords": ["oral history", "postwar"],
        "resource_proxies": [{"type": "LandingPage", "ref": "https://example.org/ds/1"}],
        "license_val": None,
        "license_url": None,
        "version": "1.0",
        "doi": None,
        "resource_type": "Audio",
        "main_disciplines": ["History"],
        "institutions": ["Universität Kassel"],
        "bibliographical_citation": None,
        "upstream_modified_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    rec.update(over)
    return rec


def count_datasets(conn, **where) -> int:
    """Number of catalogue rows, optionally filtered by equality on columns."""
    if where:
        clauses = " AND ".join(f"{k} = %s" for k in where)
        row = conn.execute(
            f"SELECT COUNT(*) FROM oral_history_datasets WHERE {clauses}",
            list(where.values()),
        ).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) FROM oral_history_datasets").fetchone()
    return row[0]


def sync_status_row(conn) -> dict[str, Any]:
    """The singleton ``sync_status`` row's timestamps and last-error columns."""
    row = conn.execute(
        """SELECT last_harvest_date, last_full_rebuild_date,
                  last_sync_error, last_sync_error_at,
                  last_rebuild_error, last_rebuild_error_at
           FROM sync_status WHERE id = 1"""
    ).fetchone()
    return {
        "last_harvest_date": row[0],
        "last_full_rebuild_date": row[1],
        "last_sync_error": row[2],
        "last_sync_error_at": row[3],
        "last_rebuild_error": row[4],
        "last_rebuild_error_at": row[5],
    }


def ingestion_failure_uuids(conn, *, source: str = "swissubase") -> set[str]:
    """Unresolved identities for a source, read from ``ingestion_failures``.

    ``sync_status.incremental_failures`` is never written by production
    (sync.py:360-503); the durable failure set lives in this table
    (source, uuid, message, updated_at) and is replaced wholesale per run.
    """
    rows = conn.execute(
        "SELECT uuid FROM ingestion_failures WHERE source = %s", (source,)
    ).fetchall()
    return {r[0] for r in rows}

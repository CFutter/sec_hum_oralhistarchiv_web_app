"""Integration tests for the sync orchestrator against real PostgreSQL.

Covers backlog §3.8 (no-uuid boundary raise), the DOI-collision
self-diagnosis branch, the real harvest watermark, full-rebuild
single-transaction + SAVEPOINT semantics, the migration-owned search-text
trigger, and the two datasets.py bugfix pins (get_last_full_rebuild_date
timezone NameError; get_collection_datasets executed with no params).

fetch_updates is a plain sync function called via run_in_threadpool, so a
Mock patched at 'app.services.sync.fetch_updates' that returns a list (or
raises) drives every path. Everything downstream — upserts, savepoints,
triggers, sync_status writes — runs against the real database.
"""
import logging
import re
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from app.services import sync
from app.services.datasets import get_collection_datasets, get_last_full_rebuild_date
from app.services.db import get_db_cursor
from app.services.sync import (
    _SWISSUBASE_POLICY,
    _sync_source_a,
    _upsert_public_catalogue_record,
    run_full_rebuild,
)
from config import settings

FETCH = "app.services.sync.fetch_updates"


def make_record(uuid, title="Oral History Interviews", **over):
    """A record dict with EVERY key in sync._PARSER_OWNED, mirroring the
    exact output shape of parse_cmdi_to_dict (lists for the array fields,
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
    }
    rec.update(over)
    return rec


def test_make_record_matches_parser_contract():
    """Harness self-check: make_record emits exactly sync._PARSER_OWNED.

    If DATASET_COLUMNS / _PARSER_OWNED drift, this fails first with a clear
    diff instead of every sync test failing on an opaque KeyError.
    """
    assert set(make_record("u")) == sync._PARSER_OWNED


def _count_datasets(conn, **where) -> int:
    if where:
        clauses = " AND ".join(f"{k} = %s" for k in where)
        row = conn.execute(
            f"SELECT COUNT(*) FROM oral_history_datasets WHERE {clauses}",  # noqa: S608
            list(where.values()),
        ).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) FROM oral_history_datasets").fetchone()
    return row[0]


def _sync_status(conn) -> dict:
    row = conn.execute(
        """SELECT last_harvest_date, last_full_rebuild_date,
                  last_sync_error, last_sync_error_at
           FROM sync_status WHERE id = 1"""
    ).fetchone()
    return {
        "last_harvest_date": row[0],
        "last_full_rebuild_date": row[1],
        "last_sync_error": row[2],
        "last_sync_error_at": row[3],
    }


# =============================================================================
# §3.8 — _upsert_public_catalogue_record refuses a falsy uuid at the boundary
# =============================================================================

async def test_upsert_raises_on_none_uuid_before_touching_table(db_pool, sync_conn):
    """§3.8: uuid=None raises ValueError BEFORE any INSERT — a NULL-uuid row
    can never conflict-match and would duplicate on every sync."""
    with pytest.raises(ValueError, match="uuid"):
        async with get_db_cursor(db_pool) as cur:
            await _upsert_public_catalogue_record(
                cur, make_record(uuid=None), _SWISSUBASE_POLICY
            )
    assert _count_datasets(sync_conn) == 0


async def test_upsert_raises_on_empty_uuid(db_pool, sync_conn):
    """§3.8: empty-string uuid is just as falsy — same ValueError, no row."""
    with pytest.raises(ValueError):
        async with get_db_cursor(db_pool) as cur:
            await _upsert_public_catalogue_record(
                cur, make_record(uuid=""), _SWISSUBASE_POLICY
            )
    assert _count_datasets(sync_conn) == 0


async def test_sync_loop_records_missing_uuid_as_failed_record(db_pool, sync_conn):
    """§3.8 through the loop: a no-uuid record is skipped-and-recorded — the
    sync COMPLETES and last_sync_error carries the '<no-uuid>' marker instead
    of the whole run aborting or duplicates accumulating."""
    with patch(FETCH, return_value=[make_record(uuid=None)]):
        await _sync_source_a(db_pool)

    status = _sync_status(sync_conn)
    assert status["last_sync_error"] is not None
    assert "<no-uuid>" in status["last_sync_error"]
    assert "missing UUID" in status["last_sync_error"]
    assert _count_datasets(sync_conn) == 0


# =============================================================================
# Incremental sync happy path — policy tier, access classification,
# migration-owned search trigger, watermark timing
# =============================================================================

async def test_incremental_sync_happy_path(db_pool, sync_conn):
    """Two records land with source='swissubase'; visibility resolves through
    the source POLICY ceiling (settings.swissubase_max_visibility — records
    carry no tier of their own); access_level derives from the license text;
    the SEARCH TRIGGER (defined only in the migration — schema source of
    truth) fills search_text_full with the description but keeps it OUT of
    search_text_public; the watermark lands between call start and fetch
    return (captured BEFORE the fetch, backlog §3.1); error state clears."""
    fetch_returned_at = {}

    def fake_fetch(**kwargs):
        # Capture t1 INSIDE the fake: the watermark must be <= this instant.
        fetch_returned_at["t1"] = datetime.now(timezone.utc)
        return [
            make_record(
                uuid="oai:swissubase:aaa-1",
                title="Restricted Interviews",
                description="Testimony about the unmistakableword flood of 1962.",
                license_val="Restricted access (special agreement)",
                doi="10.1/aaa-1",
            ),
            make_record(
                uuid="oai:swissubase:bbb-2",
                title="Open Interviews",
                license_val="CC BY 4.0",
                doi="10.1/bbb-2",
            ),
        ]

    t0 = datetime.now(timezone.utc)
    with patch(FETCH, side_effect=fake_fetch):
        await _sync_source_a(db_pool)

    rows = sync_conn.execute(
        """SELECT uuid, source, visibility_tier, access_level,
                  search_text_public, search_text_full
           FROM oral_history_datasets ORDER BY uuid"""
    ).fetchall()
    assert len(rows) == 2
    by_uuid = {r[0]: r for r in rows}

    for r in rows:
        assert r[1] == "swissubase"
        # Records carry visibility_tier=None -> resolve_tier returns the
        # policy ceiling, which is settings.swissubase_max_visibility
        # ('vetted' in the default test env).
        assert r[2] == settings.swissubase_max_visibility

    # License classification: 'Restricted access …' -> restricted; CC -> public.
    assert by_uuid["oai:swissubase:aaa-1"][3] == "restricted"
    assert by_uuid["oai:swissubase:bbb-2"][3] == "public"

    # Search trigger: full blob has the distinctive description word;
    # public blob has the title but NOT the description.
    _, _, _, _, pub, full = by_uuid["oai:swissubase:aaa-1"]
    assert "unmistakableword" in full
    assert "Restricted Interviews" in pub
    assert "unmistakableword" not in pub

    status = _sync_status(sync_conn)
    assert status["last_sync_error"] is None
    # Watermark: captured before the fetch, so t0 <= watermark <= t1.
    assert t0 <= status["last_harvest_date"] <= fetch_returned_at["t1"]


async def test_sync_same_uuid_twice_updates_not_duplicates(db_pool, sync_conn):
    """ON CONFLICT (uuid) DO UPDATE: re-syncing the same uuid with a changed
    title updates the single existing row instead of inserting a second."""
    with patch(FETCH, return_value=[make_record("oai:x:dup-1", title="Old Title")]):
        await _sync_source_a(db_pool)
    with patch(FETCH, return_value=[make_record("oai:x:dup-1", title="New Title")]):
        await _sync_source_a(db_pool)

    rows = sync_conn.execute(
        "SELECT title FROM oral_history_datasets WHERE uuid = %s", ("oai:x:dup-1",)
    ).fetchall()
    assert rows == [("New Title",)]
    assert _count_datasets(sync_conn) == 1


async def test_tombstone_record_deletes_row(db_pool, sync_conn):
    """A {'_deleted': True} OAI tombstone removes the corresponding row."""
    with patch(FETCH, return_value=[make_record("oai:x:tomb-1")]):
        await _sync_source_a(db_pool)
    assert _count_datasets(sync_conn, uuid="oai:x:tomb-1") == 1

    with patch(FETCH, return_value=[{"_deleted": True, "uuid": "oai:x:tomb-1"}]):
        await _sync_source_a(db_pool)
    assert _count_datasets(sync_conn, uuid="oai:x:tomb-1") == 0
    assert _sync_status(sync_conn)["last_sync_error"] is None


async def test_tombstone_for_never_seen_uuid_is_a_clean_noop(db_pool, sync_conn):
    """TEST-052: OAI replays tombstones, so a delete for a uuid this instance
    never held must be a clean no-op — 0 rows deleted, no error recorded, the
    watermark still advances. A strictness regression (raising on 0-row
    DELETE) would turn routine replayed tombstones into a perpetual
    last_sync_error."""
    before = _sync_status(sync_conn)["last_harvest_date"]
    with patch(FETCH, return_value=[
        {"_deleted": True, "uuid": "oai:x:never-existed"},
    ]):
        await _sync_source_a(db_pool)

    assert _sync_status(sync_conn)["last_sync_error"] is None
    assert _sync_status(sync_conn)["last_harvest_date"] > before


# =============================================================================
# DOI collision — the self-diagnosing UniqueViolation branch
# =============================================================================

async def test_doi_collision_skips_record_with_diagnostic_message(db_pool, sync_conn):
    """Upstream minted a new uuid but reused an existing doi: the doi UNIQUE
    constraint blocks the new version; the sync records the self-diagnosing
    'DOI collision' message naming the new uuid, keeps the original row, and
    still lands the other record of the same batch (per-record isolation)."""
    with patch(FETCH, return_value=[
        make_record("oai:x:orig-1", title="Original Version", doi="10.1/dup"),
    ]):
        await _sync_source_a(db_pool)
    assert _count_datasets(sync_conn, uuid="oai:x:orig-1") == 1

    with patch(FETCH, return_value=[
        # colliding record FIRST — proves the follow-up record still lands
        make_record("oai:x:newver-2", title="New Version", doi="10.1/dup"),
        make_record("oai:x:innocent-3", title="Innocent Bystander", doi="10.1/other"),
    ]):
        await _sync_source_a(db_pool)

    # Colliding record skipped; original intact; batch-mate landed.
    assert _count_datasets(sync_conn, uuid="oai:x:newver-2") == 0
    assert sync_conn.execute(
        "SELECT title FROM oral_history_datasets WHERE uuid = %s", ("oai:x:orig-1",)
    ).fetchone() == ("Original Version",)
    assert _count_datasets(sync_conn, uuid="oai:x:innocent-3") == 1

    err = _sync_status(sync_conn)["last_sync_error"]
    assert err is not None
    assert "DOI collision" in err
    assert "reused an existing" in err
    assert "oai:x:newver-2" in err


# =============================================================================
# Per-record resilience in the incremental loop
# =============================================================================

async def test_incremental_sync_survives_one_broken_record(db_pool, sync_conn):
    """A record missing a _PARSER_OWNED key (parser-contract drift ->
    KeyError) is skipped-and-recorded; both healthy neighbours still land."""
    broken = make_record("oai:x:broken-2")
    del broken["description"]  # key ABSENT (drift), not merely None

    with patch(FETCH, return_value=[
        make_record("oai:x:good-1"),
        broken,
        make_record("oai:x:good-3"),
    ]):
        await _sync_source_a(db_pool)

    assert _count_datasets(sync_conn, uuid="oai:x:good-1") == 1
    assert _count_datasets(sync_conn, uuid="oai:x:good-3") == 1
    assert _count_datasets(sync_conn, uuid="oai:x:broken-2") == 0

    err = _sync_status(sync_conn)["last_sync_error"]
    assert err is not None
    assert "oai:x:broken-2" in err


async def test_watermark_advances_despite_per_record_failures(db_pool, sync_conn):
    """TEST-053: the watermark (last_harvest_date) advances to the harvest
    start EVEN WHEN some records fail — only a FETCH-phase failure holds it
    back. A 'safety' edit that skips the watermark advance whenever any record
    failed would create an ever-growing re-fetch window (every sync re-harvests
    from the last fully-clean run). Pins the advance explicitly, alongside the
    recorded error."""
    broken = make_record("oai:x:broken")
    del broken["languages"]  # KeyError in _build_record_params
    before = _sync_status(sync_conn)["last_harvest_date"]

    with patch(FETCH, return_value=[make_record("oai:x:ok"), broken]):
        await _sync_source_a(db_pool)

    status = _sync_status(sync_conn)
    assert _count_datasets(sync_conn, uuid="oai:x:ok") == 1  # good record landed
    assert status["last_sync_error"] is not None             # failure recorded
    assert status["last_harvest_date"] > before              # watermark STILL moved


async def test_non_oai_body_advances_watermark_and_clears_error(db_pool, sync_conn):
    """TEST-036 (sync side): a well-formed non-OAI 200 body (captive portal /
    maintenance page) parses to zero records, so the sync advances the
    watermark AND clears last_sync_error — presenting a silently-lost harvest
    window as a perfectly healthy sync. Characterises the current behaviour so
    a future 'treat empty harvest as suspicious' change is a deliberate,
    test-visible decision rather than an accident.

    Patches the HTTP layer (not fetch_updates) so the real
    _oai_list_records/fetch_updates empty-body path runs end to end."""
    from tests.unit.test_oai_client import _FakeResponse  # reuse the fake

    # Seed a prior error so 'cleared' is observable.
    async with get_db_cursor(db_pool) as cur:
        await cur.execute(
            "UPDATE sync_status SET last_sync_error = %s WHERE id = 1",
            ("stale error from a previous run",),
        )
    before = _sync_status(sync_conn)["last_harvest_date"]

    body = b'<html><body>maintenance</body></html>'
    with patch("app.services.oai_client._session.get",
               return_value=_FakeResponse(body)):
        await _sync_source_a(db_pool)

    status = _sync_status(sync_conn)
    assert status["last_sync_error"] is None       # error CLEARED (the trap)
    assert status["last_harvest_date"] > before    # watermark advanced


# =============================================================================
# Full rebuild — single transaction, source-scoped delete, savepoints
# =============================================================================

async def test_full_rebuild_replaces_source_scoped_and_advances_timestamps(
    db_pool, sync_conn, dataset_factory
):
    """Full rebuild deletes ONLY swissubase rows (mock-source row preserved),
    inserts the fresh fetch, and _update_full_rebuild_timestamp advances BOTH
    last_full_rebuild_date and last_harvest_date (the incremental cursor
    resets to the rebuild instant)."""
    with patch(FETCH, return_value=[make_record("oai:x:old-X", title="Stale X")]):
        await _sync_source_a(db_pool)
    dataset_factory(uuid="oai:mock:keep-me", source="mock")

    before = _sync_status(sync_conn)
    assert before["last_full_rebuild_date"] is None

    rebuild_t0 = datetime.now(timezone.utc)
    with patch(FETCH, return_value=[make_record("oai:x:new-Y", title="Fresh Y")]):
        await run_full_rebuild(db_pool)

    assert _count_datasets(sync_conn, uuid="oai:x:old-X") == 0       # stale gone
    assert _count_datasets(sync_conn, uuid="oai:x:new-Y") == 1       # fresh in
    assert _count_datasets(sync_conn, uuid="oai:mock:keep-me") == 1  # other source kept

    after = _sync_status(sync_conn)
    assert after["last_full_rebuild_date"] is not None
    assert after["last_full_rebuild_date"] >= rebuild_t0
    assert after["last_harvest_date"] >= rebuild_t0
    assert after["last_harvest_date"] > before["last_harvest_date"]
    # Both stamped from the same harvest_started_at instant.
    assert after["last_harvest_date"] == after["last_full_rebuild_date"]


async def test_full_rebuild_aborts_on_empty_fetch_keeping_data(
    db_pool, sync_conn, dataset_factory, caplog
):
    """An empty harvest must never wipe the catalogue: existing rows are
    kept, a warning is logged, and neither timestamp advances."""
    dataset_factory(uuid="oai:x:precious-1", source="swissubase")
    before = _sync_status(sync_conn)

    with caplog.at_level(logging.WARNING, logger="app.services.sync"):
        with patch(FETCH, return_value=[]):
            await run_full_rebuild(db_pool)

    assert _count_datasets(sync_conn, uuid="oai:x:precious-1") == 1
    assert any("Full rebuild aborted" in r.message for r in caplog.records)

    after = _sync_status(sync_conn)
    assert after["last_harvest_date"] == before["last_harvest_date"]
    assert after["last_full_rebuild_date"] is None


async def test_full_rebuild_savepoint_isolates_broken_record(db_pool, dataset_factory):
    """One malformed record rolls back only its own SAVEPOINT: both healthy
    records are present AND COMMITTED (visible from a brand-new connection),
    the old row is gone, and the failure is recorded in last_sync_error."""
    import psycopg

    from .conftest import TEST_DATABASE_URL

    dataset_factory(uuid="oai:x:pre-rebuild", source="swissubase")

    broken = make_record("oai:x:sp-broken")
    del broken["authors"]  # KeyError inside the savepoint

    with patch(FETCH, return_value=[
        make_record("oai:x:sp-good-1"),
        broken,
        make_record("oai:x:sp-good-2"),
    ]):
        await run_full_rebuild(db_pool)

    # A NEW connection proves the transaction committed (not just visible
    # from an in-flight snapshot).
    with psycopg.connect(TEST_DATABASE_URL) as fresh:
        uuids = {
            r[0] for r in fresh.execute(
                "SELECT uuid FROM oral_history_datasets WHERE source = 'swissubase'"
            ).fetchall()
        }
        err = fresh.execute(
            "SELECT last_sync_error FROM sync_status WHERE id = 1"
        ).fetchone()[0]

    assert uuids == {"oai:x:sp-good-1", "oai:x:sp-good-2"}
    assert err is not None
    assert "oai:x:sp-broken" in err


async def test_full_rebuild_fetch_failure_keeps_data(db_pool, sync_conn, dataset_factory):
    """If the harvest itself raises, nothing is deleted and the error is
    recorded with the 'Full rebuild:' prefix."""
    dataset_factory(uuid="oai:x:survivor-1", source="swissubase")

    with patch(FETCH, side_effect=RuntimeError("upstream exploded")):
        await run_full_rebuild(db_pool)

    assert _count_datasets(sync_conn, uuid="oai:x:survivor-1") == 1
    err = _sync_status(sync_conn)["last_sync_error"]
    assert err is not None
    assert err.startswith("Full rebuild:")
    assert "upstream exploded" in err


# =============================================================================
# BUGFIX PIN — get_last_full_rebuild_date (NameError: timezone unimported)
# =============================================================================

async def test_get_last_full_rebuild_date_none_before_any_rebuild(db_pool):
    """Fresh sync_status (last_full_rebuild_date NULL) -> None, no crash."""
    assert await get_last_full_rebuild_date(db_pool) is None


async def test_get_last_full_rebuild_date_formats_after_rebuild(db_pool):
    """BUGFIX PIN: this function once raised NameError ('timezone' was never
    imported in datasets.py), 500-ing the home page as soon as any full
    rebuild had ever completed. After a successful rebuild it must return the
    display string 'DD Month YYYY, HH:MM UTC'."""
    with patch(FETCH, return_value=[make_record("oai:x:rebuilt-1")]):
        await run_full_rebuild(db_pool)

    formatted = await get_last_full_rebuild_date(db_pool)
    assert formatted is not None
    assert re.fullmatch(r"\d{2} \w+ \d{4}, \d{2}:\d{2} UTC", formatted)


# =============================================================================
# BUGFIX PIN — get_collection_datasets (query executed with NO params)
# =============================================================================

async def test_get_collection_datasets_returns_keyword_sharers(db_pool, dataset_factory):
    """BUGFIX PIN: the shared-keywords query was once executed WITHOUT its
    params dict -> every call crashed. Now: of three datasets, exactly the
    two sharing 'shared-kw' are returned; the singleton-keyword one is not."""
    dataset_factory(uuid="oai:x:share-1", keywords=["shared-kw", "extra"])
    dataset_factory(uuid="oai:x:share-2", keywords=["shared-kw"])
    dataset_factory(uuid="oai:x:loner-3", keywords=["singleton-kw"])

    result = await get_collection_datasets(db_pool, "vetted")
    assert {d.uuid for d in result} == {"oai:x:share-1", "oai:x:share-2"}


async def test_get_collection_datasets_tier_scopes_visibility(db_pool, dataset_factory):
    """Tier scoping: a vetted-only sharer is invisible at user_tier='public' —
    both excluded from the results and excluded from the shared-keyword count
    (the CTE counts only rows the user may see)."""
    dataset_factory(uuid="oai:x:pub-1", visibility_tier="public", keywords=["shared-kw"])
    dataset_factory(uuid="oai:x:pub-2", visibility_tier="public", keywords=["shared-kw"])
    dataset_factory(uuid="oai:x:vet-3", visibility_tier="vetted", keywords=["shared-kw"])

    vetted_view = await get_collection_datasets(db_pool, "vetted")
    assert {d.uuid for d in vetted_view} == {"oai:x:pub-1", "oai:x:pub-2", "oai:x:vet-3"}

    public_view = await get_collection_datasets(db_pool, "public")
    assert {d.uuid for d in public_view} == {"oai:x:pub-1", "oai:x:pub-2"}

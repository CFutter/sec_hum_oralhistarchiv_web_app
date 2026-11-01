"""Existing catalogue identities avoid sequence allocation and redundant row writes."""

import asyncio
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg.rows import dict_row

from app.services import ensure_source_status_rows
from app.services.db import get_db_cursor
from app.services.ingestion import _reconcile_rebuild_records, run_full_rebuild, upsert_dataset
from app.services.schema import DATASET_INSERT_COLUMNS, build_record_params
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.sync_doubles import make_record
from tests.source_fixtures import fixture_source, legacy_source

_SOURCE = "change_aware"
_FIRST_WRITE = datetime(2026, 1, 1, tzinfo=UTC)
_NEXT_WRITE = _FIRST_WRITE + timedelta(days=1)


def _params(record, *, tier="public", stamp=_FIRST_WRITE, source=_SOURCE):
    """Build dataset insert parameters with an explicit sync timestamp."""
    values = list(build_record_params(record, "public", source, tier))
    values[DATASET_INSERT_COLUMNS.index("synced_at")] = stamp
    return tuple(values)


async def _write(pool, record, **options):
    """Upsert a test record with explicit insert-parameter overrides."""
    async with get_db_cursor(pool) as cur:
        return await upsert_dataset(cur, _params(record, **options))


def _snapshot(conn, uuid="stable"):
    """Return row identity/storage metadata and sequence state, then commit the observer
    transaction.
    """
    row = conn.execute(
        "SELECT id, xmin::text, ctid::text, synced_at, visibility_tier, "
        "title, search_vector_full::text FROM oral_history_datasets "
        "WHERE source = %s AND uuid = %s",
        (_SOURCE, uuid),
    ).fetchone()
    sequence = conn.execute(
        "SELECT last_value, is_called FROM oral_history_datasets_id_seq"
    ).fetchone()
    conn.commit()
    return row, sequence


async def test_unchanged_replay_preserves_physical_row_timestamp_and_sequence(db_pool, sync_conn):
    """Verify unchanged replay preserves physical row timestamp and sequence."""
    record = make_record("stable", visibility_tier="public")
    first = await _write(db_pool, record)
    before = _snapshot(sync_conn)
    # JSON object key order must not manufacture a content change.
    reordered = dict(reversed(tuple(record.items())))
    replay = await _write(db_pool, reordered, stamp=_NEXT_WRITE)
    assert replay == first
    assert _snapshot(sync_conn) == before


async def test_real_change_updates_search_and_timestamp_without_consuming_identity(
    db_pool, sync_conn
):
    """Verify real change updates search and timestamp without consuming identity."""
    record = make_record("stable", visibility_tier="public")
    first = await _write(db_pool, record)
    before_row, sequence = _snapshot(sync_conn)
    changed = await _write(
        db_pool, {**record, "title": "Distinctive revised title"}, stamp=_NEXT_WRITE
    )
    row, after_sequence = _snapshot(sync_conn)
    assert changed.dataset_id == first.dataset_id
    assert after_sequence == sequence
    assert row[1:3] != before_row[1:3]
    assert row[3] == _NEXT_WRITE and row[5] == "Distinctive revised title"
    assert "distinctive" in row[6]


@pytest.mark.parametrize(
    "stored,incoming,expected",
    [("vetted", "public", "vetted"), ("public", "registered", "registered")],
)
async def test_change_detection_compares_the_preserved_effective_tier(
    db_pool, sync_conn, stored, incoming, expected
):
    """Verify change detection compares the preserved effective tier."""
    record = make_record("stable")
    first = await _write(db_pool, record, tier=stored)
    before_row, sequence = _snapshot(sync_conn)
    result = await _write(db_pool, record, tier=incoming, stamp=_NEXT_WRITE)
    row, after_sequence = _snapshot(sync_conn)
    assert result.dataset_id == first.dataset_id and result.stored_tier == expected
    assert after_sequence == sequence
    if expected == stored:
        assert row == before_row
    else:
        assert row[3] == _NEXT_WRITE and row[4] == expected


async def test_new_identity_allocates_once_and_other_sources_remain_independent(db_pool, sync_conn):
    """Verify new identity allocates once and other sources remain independent."""
    record = make_record("stable")
    first = await _write(db_pool, record)
    _, sequence = _snapshot(sync_conn)
    other = await _write(db_pool, record, source="another_source")
    assert other.dataset_id == first.dataset_id + 1
    assert _snapshot(sync_conn)[1][0] == sequence[0] + 1


async def test_doi_swap_remains_atomic_and_preserves_existing_ids(db_pool, sync_conn):
    """Verify doi swap remains atomic and preserves existing IDs."""
    first = make_record("first", doi="10.1234/first")
    second = make_record("second", doi="10.1234/second")
    first_state = await _write(db_pool, first)
    second_state = await _write(db_pool, second)
    _, sequence = _snapshot(sync_conn, "first")
    async with get_db_cursor(db_pool) as cur:
        successes, failures = await _reconcile_rebuild_records(
            cur,
            [{**first, "doi": second["doi"]}, {**second, "doi": first["doi"]}],
            policy=legacy_source(name=_SOURCE, max_visibility="public").policy,
            private_errors=False,
        )
    assert successes == 2 and failures == []
    rows = sync_conn.execute(
        "SELECT id, uuid, doi FROM oral_history_datasets WHERE source = %s ORDER BY uuid",
        (_SOURCE,),
    ).fetchall()
    sync_conn.commit()
    assert rows == [
        (first_state.dataset_id, "first", second["doi"]),
        (second_state.dataset_id, "second", first["doi"]),
    ]
    assert _snapshot(sync_conn, "first")[1] == sequence


async def test_direct_concurrent_first_writes_keep_atomic_conflict_and_stricter_tier(sync_conn):
    # Hold the first insert uncommitted so the other statement's snapshot has
    # no existing row. This exercises the ON CONFLICT fallback, not normal replay.
    """Verify direct concurrent first writes keep atomic conflict and stricter tier."""
    async with (
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL, row_factory=dict_row) as first,
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL, row_factory=dict_row) as second,
    ):
        async with first.cursor() as cur:
            initial = await upsert_dataset(cur, _params(make_record("stable"), tier="vetted"))
        async with second.cursor() as cur:
            pending = asyncio.create_task(
                upsert_dataset(
                    cur, _params(make_record("stable"), tier="public", stamp=_NEXT_WRITE)
                )
            )
            async with asyncio.timeout(5):
                while True:
                    blocked = sync_conn.execute(
                        "SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = %s",
                        (second.info.backend_pid,),
                    ).fetchone()
                    sync_conn.commit()
                    if blocked is not None and blocked[0]:
                        break
                    await asyncio.sleep(0.01)
            await first.commit()
            result = await pending
        await second.commit()
    assert result.dataset_id == initial.dataset_id and result.stored_tier == "vetted"
    row, _sequence = _snapshot(sync_conn)
    assert row[4] == "vetted" and row[3] == _FIRST_WRITE


async def test_unchanged_rebuild_advances_source_freshness_without_touching_rows(
    db_pool, sync_conn
):
    """Verify unchanged rebuild advances source freshness without touching rows."""
    source = fixture_source(name=_SOURCE, max_visibility="public")
    await ensure_source_status_rows(db_pool, (source.name,))
    assert (await run_full_rebuild(db_pool, configured_source=source)).status == "success"
    before = sync_conn.execute(
        "SELECT id, xmin::text, ctid::text, synced_at FROM oral_history_datasets ORDER BY id"
    ).fetchall()
    sync_conn.execute(
        "UPDATE sync_status SET last_harvest_date = %s, last_full_rebuild_date = %s WHERE source = %s",
        (_FIRST_WRITE, _FIRST_WRITE, source.name),
    )
    sync_conn.commit()
    result = await run_full_rebuild(db_pool, configured_source=source)
    assert result.status == "success" and result.affected_count == len(before)
    assert (
        sync_conn.execute(
            "SELECT id, xmin::text, ctid::text, synced_at FROM oral_history_datasets ORDER BY id"
        ).fetchall()
        == before
    )
    observed, rebuilt = sync_conn.execute(
        "SELECT last_harvest_date, last_full_rebuild_date FROM sync_status WHERE source = %s",
        (source.name,),
    ).fetchone()
    sync_conn.commit()
    assert observed > _FIRST_WRITE and rebuilt > _FIRST_WRITE

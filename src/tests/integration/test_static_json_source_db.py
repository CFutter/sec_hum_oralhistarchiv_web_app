"""Prove a registered native JSON adapter uses ordinary source-keyed ingestion."""

from datetime import UTC, datetime
from unittest.mock import create_autospec

from app.paths import PROJECT_ROOT
from app.services import ensure_source_status_rows
from app.services.cache import CatalogueStatsCache
from app.services.ingestion import SyncOutcome
from app.services.scheduler import sync_and_invalidate
from app.sources import load_sources_for_startup
from tests.source_fixtures import TEST_SOURCE_NAME

PROOF_CONFIG = PROJECT_ROOT / "deploy/environment/sources.proof.toml"
SOURCE_CURSOR = datetime(2020, 1, 4, tzinfo=UTC)
RETAINED_SOURCE = "retained_proof"
SHARED_UUID = "static_json:public"
EXPECTED_ROWS = {
    "fixture_demo": (
        ("fixture:public", "public"),
        ("fixture:registered", "registered"),
        ("fixture:vetted", "vetted"),
    ),
    "static_json_demo": (
        ("static_json:public", "public"),
        ("static_json:registered", "registered"),
        ("static_json:vetted", "vetted"),
    ),
}


def _snapshot(conn, source):
    """Snapshot every persisted field, then finish the test-side transaction."""
    state = conn.execute(
        "SELECT to_jsonb(state) FROM sync_status AS state WHERE source = %s",
        (source,),
    ).fetchone()
    rows = conn.execute(
        "SELECT to_jsonb(dataset) FROM oral_history_datasets AS dataset "
        "WHERE source = %s ORDER BY uuid",
        (source,),
    ).fetchall()
    failures = conn.execute(
        "SELECT to_jsonb(failure) FROM ingestion_failures AS failure "
        "WHERE source = %s ORDER BY uuid",
        (source,),
    ).fetchall()
    conn.commit()
    return state, rows, failures


def _seed_retained_source(conn, dataset_factory):
    """Populate an unselected source with catalogue, progress and diagnostic sentinels."""
    dataset_factory(
        source=RETAINED_SOURCE,
        uuid=SHARED_UUID,
        title="Retained source catalogue sentinel",
        description="Retained source private metadata sentinel",
        visibility_tier="vetted",
    )
    conn.execute(
        """UPDATE sync_status
           SET source_cursor = TIMESTAMPTZ '2020-01-04 00:00:00+00',
               source_fingerprint = %s,
               incremental_harvest = %s,
               incremental_started_at = TIMESTAMPTZ '2020-01-05 00:00:00+00',
               incremental_position = 1,
               incremental_affected = 1,
               last_harvest_date = TIMESTAMPTZ '2020-01-06 00:00:00+00',
               last_full_rebuild_date = TIMESTAMPTZ '2020-01-07 00:00:00+00',
               last_sync_error = 'Retained incremental error sentinel',
               last_sync_error_at = TIMESTAMPTZ '2020-01-08 00:00:00+00',
               last_rebuild_error = 'Retained rebuild error sentinel',
               last_rebuild_error_at = TIMESTAMPTZ '2020-01-09 00:00:00+00'
           WHERE source = %s""",
        ("f" * 64, b"Retained staged payload must not be replayed", RETAINED_SOURCE),
    )
    conn.execute(
        """INSERT INTO ingestion_failures (source, uuid, message, updated_at)
           VALUES (%s, %s, %s, TIMESTAMPTZ '2020-01-10 00:00:00+00')""",
        (RETAINED_SOURCE, SHARED_UUID, "Retained unresolved-record sentinel"),
    )
    conn.commit()


def _assert_selected_source(conn, source, started_at, finished_at):
    """Check selected-source records, progress and binding match the native harvest."""
    rows = conn.execute(
        "SELECT id, source, uuid, visibility_tier FROM oral_history_datasets "
        "WHERE source = %s ORDER BY uuid",
        (source.name,),
    ).fetchall()
    assert tuple((row[2], row[3]) for row in rows) == EXPECTED_ROWS[source.name]
    assert all(row[1] == source.name for row in rows)
    assert len({row[0] for row in rows}) == 3
    state = conn.execute(
        """SELECT source_cursor, source_fingerprint,
                  incremental_harvest, incremental_started_at,
                  incremental_position, incremental_affected,
                  last_harvest_date, last_full_rebuild_date,
                  last_sync_error, last_sync_error_at,
                  last_rebuild_error, last_rebuild_error_at
           FROM sync_status WHERE source = %s""",
        (source.name,),
    ).fetchone()
    assert state is not None
    assert state[:6] == (
        SOURCE_CURSOR,
        source.adapter.config_fingerprint(),
        None,
        None,
        0,
        0,
    )
    last_harvest, last_rebuild = state[6:8]
    assert isinstance(last_harvest, datetime) and last_harvest.utcoffset() is not None
    assert isinstance(last_rebuild, datetime) and last_rebuild.utcoffset() is not None
    assert started_at <= last_harvest <= finished_at
    assert last_rebuild <= last_harvest
    assert state[8:] == (None, None, None, None)
    assert conn.execute(
        "SELECT count(*) FROM ingestion_failures WHERE source = %s",
        (source.name,),
    ).fetchone() == (0,)
    conn.commit()
    return {row[2]: row[0] for row in rows}, last_harvest, last_rebuild


async def test_selected_static_json_and_fixture_use_normal_ingestion(
    bind_catalogue_policy, db_pool, sync_conn, dataset_factory, monkeypatch
):
    """Verify selected static JSON and fixture use normal ingestion."""
    sources = load_sources_for_startup(PROOF_CONFIG, environment="dev")
    policy = bind_catalogue_policy(sources)
    assert tuple((source.name, source.config.adapter) for source in sources) == (
        ("fixture_demo", "fixture"),
        ("static_json_demo", "static_json"),
    )
    assert all(source.policy.max_visibility == "public" for source in sources)
    assert all(source.policy.requires_record_tier for source in sources)
    names = tuple(source.name for source in sources)
    await ensure_source_status_rows(db_pool, (*names, RETAINED_SOURCE))
    for source in sources:
        assert sync_conn.execute(
            "SELECT source_cursor, source_fingerprint, incremental_harvest "
            "FROM sync_status WHERE source = %s",
            (source.name,),
        ).fetchone() == (None, None, None)
    sync_conn.commit()
    _seed_retained_source(sync_conn, dataset_factory)
    retained_before = _snapshot(sync_conn, RETAINED_SOURCE)
    baseline_before = _snapshot(sync_conn, TEST_SOURCE_NAME)
    assert retained_before[0] is not None
    assert len(retained_before[1]) == len(retained_before[2]) == 1
    assert baseline_before[0] is not None

    cache = CatalogueStatsCache(
        db_pool, source_names=names, policy_fingerprint=policy.fingerprint, subscribe=False
    )
    original_invalidate = cache.invalidate_cache
    invalidate = create_autospec(original_invalidate, spec_set=True, return_value=None)
    monkeypatch.setattr(cache, "invalidate_cache", invalidate)
    initial_ids = {}
    rebuild_times = {}
    invalidations = 0
    try:
        for affected in (3, 2):
            for source in sources:
                other_name = next(name for name in names if name != source.name)
                other_before = _snapshot(sync_conn, other_name)
                started_at = datetime.now(UTC)
                outcome = await sync_and_invalidate(db_pool, cache, source)
                finished_at = datetime.now(UTC)
                assert isinstance(outcome, SyncOutcome)
                assert (outcome.status, outcome.affected_count, outcome.failed_count) == (
                    "success",
                    affected,
                    0,
                )
                assert outcome.reason is None and outcome.requires_full_rebuild is False
                ids, last_harvest, last_rebuild = _assert_selected_source(
                    sync_conn, source, started_at, finished_at
                )
                if affected == 3:
                    initial_ids[source.name] = ids
                    rebuild_times[source.name] = last_rebuild
                    assert last_harvest == last_rebuild
                else:
                    assert ids == initial_ids[source.name]
                    assert last_rebuild == rebuild_times[source.name]
                assert _snapshot(sync_conn, other_name) == other_before
                assert _snapshot(sync_conn, RETAINED_SOURCE) == retained_before
                assert _snapshot(sync_conn, TEST_SOURCE_NAME) == baseline_before
                invalidations += 1
                assert invalidate.call_count == invalidations
        assert invalidate.call_count == 4
    finally:
        cache.stop()

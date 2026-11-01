"""Source-keyed durable state before multi-source runtime activation."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import create_autospec, patch

import pytest

from app.paths import PROJECT_ROOT
from app.services import (
    CatalogueStatsCache,
    ensure_source_status_rows,
    get_global_catalogue_stats,
    get_last_full_rebuild_date,
    ingestion,
    runtime_sources,
)
from app.services.db import get_db_cursor
from app.services.scheduler import sync_and_invalidate
from app.services.stored_harvest import encode_stored_harvest
from app.sources import (
    ConfiguredSource,
    FixtureAdapter,
    FixtureConfig,
    SourceDisplay,
    configure_sources,
)
from tests.integration.sync_doubles import FETCH, harvest_result, make_record
from tests.source_fixtures import TEST_SOURCE_NAME, legacy_source

FOREIGN_SOURCE = "fixture_other"
SHARED_UUID = "fixture:shared_identity"
SHARED_DOI = "10.1234/state_shared"


def _state_document(conn, source):
    """Read the required source-status row as a JSON object."""
    row = conn.execute(
        "SELECT to_jsonb(state) FROM sync_status AS state WHERE source = %s",
        (source,),
    ).fetchone()
    assert row is not None
    return row[0]


def _set_state_sentinel(conn, source):
    """Give every mutable state field a nondefault value."""
    conn.execute(
        """
        UPDATE sync_status
        SET source_cursor = TIMESTAMPTZ '2020-01-04 00:00:00+00',
            source_fingerprint = %s,
            last_harvest_date = TIMESTAMPTZ '2020-01-05 00:00:00+00',
            last_full_rebuild_date = TIMESTAMPTZ '2020-01-06 00:00:00+00',
            last_sync_error = 'Foreign incremental sentinel',
            last_sync_error_at = TIMESTAMPTZ '2020-01-07 00:00:00+00',
            last_rebuild_error = 'Foreign rebuild sentinel',
            last_rebuild_error_at = TIMESTAMPTZ '2020-01-08 00:00:00+00',
            incremental_harvest = %s,
            incremental_started_at = TIMESTAMPTZ '2020-01-09 00:00:00+00',
            incremental_position = 2,
            incremental_affected = 1
        WHERE source = %s
        """,
        ("b" * 64, b"Foreign staged bytes must not be consumed", source),
    )
    conn.commit()


@pytest.mark.parametrize("operation", ["incremental", "rebuild", "fetch-failure"])
async def test_current_source_operations_preserve_foreign_state_and_rows(
    db_pool, sync_conn, dataset_factory, operation
):
    """Verify current source operations preserve foreign state and rows."""
    await ensure_source_status_rows(db_pool, (FOREIGN_SOURCE,))
    _set_state_sentinel(sync_conn, FOREIGN_SOURCE)
    dataset_factory(
        uuid=SHARED_UUID,
        doi=SHARED_DOI,
        source=FOREIGN_SOURCE,
        title="Foreign catalogue sentinel",
        visibility_tier="vetted",
    )
    sync_conn.execute(
        "INSERT INTO ingestion_failures (source, uuid, message) VALUES (%s, %s, %s)",
        (FOREIGN_SOURCE, SHARED_UUID, "Foreign unresolved sentinel"),
    )
    sync_conn.commit()

    before_state = _state_document(sync_conn, FOREIGN_SOURCE)
    before_dataset = sync_conn.execute(
        "SELECT to_jsonb(dataset) FROM oral_history_datasets AS dataset "
        "WHERE source = %s AND uuid = %s",
        (FOREIGN_SOURCE, SHARED_UUID),
    ).fetchone()
    before_failure = sync_conn.execute(
        "SELECT uuid, message, updated_at FROM ingestion_failures WHERE source = %s",
        (FOREIGN_SOURCE,),
    ).fetchall()
    before_current = _state_document(sync_conn, TEST_SOURCE_NAME)

    runner = ingestion.run_full_rebuild if operation == "rebuild" else ingestion.run_sync
    failure = RuntimeError("Current fetch sentinel") if operation == "fetch-failure" else None
    harvest = harvest_result(
        [make_record(SHARED_UUID, title="Current catalogue record", doi=SHARED_DOI)]
    )
    with patch(
        FETCH,
        autospec=True,
        return_value=harvest,
        side_effect=failure,
    ) as fetch:
        outcome = await runner(db_pool, configured_source=legacy_source())

    fetch.assert_called_once()
    assert _state_document(sync_conn, FOREIGN_SOURCE) == before_state
    assert (
        sync_conn.execute(
            "SELECT to_jsonb(dataset) FROM oral_history_datasets AS dataset "
            "WHERE source = %s AND uuid = %s",
            (FOREIGN_SOURCE, SHARED_UUID),
        ).fetchone()
        == before_dataset
    )
    assert (
        sync_conn.execute(
            "SELECT uuid, message, updated_at FROM ingestion_failures WHERE source = %s",
            (FOREIGN_SOURCE,),
        ).fetchall()
        == before_failure
    )

    after_current = _state_document(sync_conn, TEST_SOURCE_NAME)
    if operation == "fetch-failure":
        assert outcome.status == "failed"
        assert "Current fetch sentinel" in after_current["last_sync_error"]
        assert after_current["source_cursor"] == before_current["source_cursor"]
        assert after_current["source_fingerprint"] == before_current["source_fingerprint"]
        assert sync_conn.execute(
            "SELECT count(*) FROM oral_history_datasets WHERE source = %s",
            (TEST_SOURCE_NAME,),
        ).fetchone() == (0,)
    else:
        assert outcome.status == "success"
        assert after_current["source_cursor"] is not None
        assert sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE source = %s AND uuid = %s",
            (TEST_SOURCE_NAME, SHARED_UUID),
        ).fetchone() == ("Current catalogue record",)


async def test_provisioning_creates_defaults_and_preserves_existing_full_state(db_pool, sync_conn):
    """Verify provisioning creates defaults and preserves existing full state."""
    before_current = _state_document(sync_conn, TEST_SOURCE_NAME)
    await ensure_source_status_rows(db_pool, (TEST_SOURCE_NAME, FOREIGN_SOURCE))

    assert _state_document(sync_conn, FOREIGN_SOURCE) == {
        "source": FOREIGN_SOURCE,
        "source_cursor": None,
        "source_fingerprint": None,
        "source_fetch_cursor": None,
        "source_fetch_fingerprint": None,
        "last_harvest_date": None,
        "last_full_rebuild_date": None,
        "last_sync_error": None,
        "last_sync_error_at": None,
        "last_rebuild_error": None,
        "last_rebuild_error_at": None,
        "incremental_harvest": None,
        "incremental_started_at": None,
        "incremental_position": 0,
        "incremental_affected": 0,
    }

    _set_state_sentinel(sync_conn, FOREIGN_SOURCE)
    before_foreign = _state_document(sync_conn, FOREIGN_SOURCE)
    await ensure_source_status_rows(db_pool, (TEST_SOURCE_NAME, FOREIGN_SOURCE))
    await ensure_source_status_rows(db_pool, (TEST_SOURCE_NAME, FOREIGN_SOURCE))

    assert _state_document(sync_conn, FOREIGN_SOURCE) == before_foreign
    assert _state_document(sync_conn, TEST_SOURCE_NAME) == before_current
    assert sync_conn.execute(
        "SELECT count(*) FROM sync_status WHERE source = %s",
        (FOREIGN_SOURCE,),
    ).fetchone() == (1,)


@pytest.mark.parametrize(
    "runner",
    [
        pytest.param(ingestion.run_sync, id="incremental"),
        pytest.param(ingestion.run_full_rebuild, id="full-rebuild"),
    ],
)
async def test_missing_requested_state_fails_before_fetch_with_other_source_present(
    db_pool, sync_conn, runner
):
    """Verify missing requested state fails before fetch with other source present."""
    await ensure_source_status_rows(db_pool, (FOREIGN_SOURCE,))
    _set_state_sentinel(sync_conn, FOREIGN_SOURCE)
    before_foreign = _state_document(sync_conn, FOREIGN_SOURCE)
    sync_conn.execute(
        "DELETE FROM sync_status WHERE source = %s",
        (TEST_SOURCE_NAME,),
    )
    sync_conn.commit()

    with (
        patch(FETCH, autospec=True) as fetch,
        pytest.raises(
            RuntimeError,
            match="sync_status row is missing for source",
        ) as exc_info,
    ):
        await runner(db_pool, configured_source=legacy_source())

    assert repr(TEST_SOURCE_NAME) in str(exc_info.value)
    fetch.assert_not_called()
    assert _state_document(sync_conn, FOREIGN_SOURCE) == before_foreign
    assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone() == (0,)
    assert sync_conn.execute(
        "SELECT count(*) FROM sync_status WHERE source = %s",
        (TEST_SOURCE_NAME,),
    ).fetchone() == (0,)
    assert (
        await get_last_full_rebuild_date(
            db_pool,
            source_names=(TEST_SOURCE_NAME,),
        )
        is None
    )
    assert await get_global_catalogue_stats(
        db_pool,
        source_names=(TEST_SOURCE_NAME,),
    ) == (0, None)


async def _helper_state_baseline(db_pool, sync_conn):
    """Populate both rows so unintended writes remain observable."""
    await ensure_source_status_rows(db_pool, (FOREIGN_SOURCE,))
    _set_state_sentinel(sync_conn, TEST_SOURCE_NAME)
    _set_state_sentinel(sync_conn, FOREIGN_SOURCE)
    return (
        _state_document(sync_conn, TEST_SOURCE_NAME),
        _state_document(sync_conn, FOREIGN_SOURCE),
    )


@pytest.mark.parametrize("matching_payload", [True, False], ids=["matching", "stale"])
async def test_guarded_stage_clear_selects_the_requested_source(
    db_pool, sync_conn, matching_payload
):
    """Verify guarded stage clear selects the requested source."""
    before_current, before_selected = await _helper_state_baseline(db_pool, sync_conn)
    row = sync_conn.execute(
        "SELECT incremental_harvest FROM sync_status WHERE source = %s",
        (FOREIGN_SOURCE,),
    ).fetchone()
    assert row is not None
    payload = row[0] if matching_payload else b"stale expected payload"

    if matching_payload:
        await ingestion._clear_staged_harvest_if_unchanged(
            db_pool,
            payload,
            source=FOREIGN_SOURCE,
        )
        expected_selected = {
            **before_selected,
            "incremental_harvest": None,
            "incremental_started_at": None,
            "incremental_position": 0,
            "incremental_affected": 0,
        }
    else:
        with pytest.raises(RuntimeError, match="staged harvest changed"):
            await ingestion._clear_staged_harvest_if_unchanged(
                db_pool,
                payload,
                source=FOREIGN_SOURCE,
            )
        expected_selected = before_selected

    assert _state_document(sync_conn, FOREIGN_SOURCE) == expected_selected
    assert _state_document(sync_conn, TEST_SOURCE_NAME) == before_current


@pytest.mark.parametrize(
    "source_cursor",
    [None, datetime(2030, 1, 2, tzinfo=UTC)],
    ids=["preserve-cursor", "advance-cursor"],
)
async def test_timestamp_helper_selects_the_requested_source(db_pool, sync_conn, source_cursor):
    """Verify timestamp helper selects the requested source."""
    before_current, before_selected = await _helper_state_baseline(db_pool, sync_conn)
    started_at = datetime(2030, 1, 3, tzinfo=UTC)

    async with get_db_cursor(db_pool) as cur:
        await ingestion._update_sync_timestamp(
            cur,
            started_at,
            source=FOREIGN_SOURCE,
            source_cursor=source_cursor,
        )

    row = sync_conn.execute(
        "SELECT last_harvest_date, source_cursor FROM sync_status WHERE source = %s",
        (FOREIGN_SOURCE,),
    ).fetchone()
    expected_cursor = (
        source_cursor if source_cursor is not None else datetime(2020, 1, 4, tzinfo=UTC)
    )
    assert row == (started_at, expected_cursor)
    after_selected = _state_document(sync_conn, FOREIGN_SOURCE)
    changed_columns = {"last_harvest_date", "source_cursor"}
    assert {
        name: value for name, value in after_selected.items() if name not in changed_columns
    } == {name: value for name, value in before_selected.items() if name not in changed_columns}
    assert _state_document(sync_conn, TEST_SOURCE_NAME) == before_current


@pytest.mark.parametrize("channel", ["incremental", "rebuild"])
async def test_diagnostic_helpers_select_the_requested_source(
    db_pool, sync_conn, channel: ingestion.SyncErrorChannel
):
    """Verify diagnostic helpers select the requested source."""
    before_current, before_selected = await _helper_state_baseline(db_pool, sync_conn)
    prefix = "sync" if channel == "incremental" else "rebuild"
    error_column = f"last_{prefix}_error"
    timestamp_column = f"last_{prefix}_error_at"
    changed_columns = {error_column, timestamp_column}

    for operation in ("record", "records", "write", "clear"):
        if operation == "write":
            await ingestion._report_write_failure(
                db_pool,
                channel,
                ValueError("Selected write sentinel"),
                source=FOREIGN_SOURCE,
                private_errors=False,
            )
        else:
            async with get_db_cursor(db_pool) as cur:
                if operation == "record":
                    await ingestion._record_sync_error(
                        cur,
                        "Selected diagnostic sentinel",
                        source=FOREIGN_SOURCE,
                        channel=channel,
                        private_errors=False,
                    )
                elif operation == "records":
                    await ingestion._record_record_errors(
                        cur,
                        [("fixture:problem", "Selected record sentinel")],
                        "Selected records",
                        source=FOREIGN_SOURCE,
                        channel=channel,
                    )
                else:
                    await ingestion._clear_sync_error(
                        cur,
                        source=FOREIGN_SOURCE,
                        channel=channel,
                    )

        after_selected = _state_document(sync_conn, FOREIGN_SOURCE)
        if operation == "clear":
            assert after_selected[error_column] is None
            assert after_selected[timestamp_column] is None
        else:
            expected_message = {
                "record": "Selected diagnostic sentinel",
                "records": (
                    "Selected records: 1 record(s) failed\n"
                    "  fixture:problem: Selected record sentinel"
                ),
                "write": f"{channel} write: ValueError: Selected write sentinel",
            }[operation]
            assert after_selected[error_column] == expected_message
            assert after_selected[timestamp_column] is not None
            assert after_selected[timestamp_column] != before_selected[timestamp_column]

        assert {
            name: value for name, value in after_selected.items() if name not in changed_columns
        } == {name: value for name, value in before_selected.items() if name not in changed_columns}
        assert _state_document(sync_conn, TEST_SOURCE_NAME) == before_current


@pytest.mark.parametrize("with_failures", [False, True], ids=["clean", "unresolved"])
async def test_rebuild_publication_selects_the_requested_source(db_pool, sync_conn, with_failures):
    """Verify rebuild publication selects the requested source."""
    before_current, before_selected = await _helper_state_baseline(db_pool, sync_conn)
    for source in (TEST_SOURCE_NAME, FOREIGN_SOURCE):
        sync_conn.execute(
            "INSERT INTO ingestion_failures (source, uuid, message) VALUES (%s, %s, %s)",
            (source, "fixture:old", "Previous unresolved sentinel"),
        )
    sync_conn.commit()
    before_current_failures = sync_conn.execute(
        "SELECT uuid, message, updated_at FROM ingestion_failures WHERE source = %s ORDER BY uuid",
        (TEST_SOURCE_NAME,),
    ).fetchall()

    started_at = datetime(2030, 1, 3, tzinfo=UTC)
    source_cursor = datetime(2030, 1, 2, tzinfo=UTC)
    failed_records = [("fixture:problem", "Selected rebuild sentinel")] if with_failures else []
    async with get_db_cursor(db_pool) as cur:
        await ingestion._update_full_rebuild_timestamp(
            cur,
            started_at,
            source=FOREIGN_SOURCE,
            failed_records=failed_records,
            source_cursor=source_cursor,
            source_fingerprint="c" * 64,
        )

    after_selected = _state_document(sync_conn, FOREIGN_SOURCE)
    selected_failures = sync_conn.execute(
        "SELECT uuid, message FROM ingestion_failures WHERE source = %s ORDER BY uuid",
        (FOREIGN_SOURCE,),
    ).fetchall()
    assert selected_failures == failed_records

    if with_failures:
        changed_columns = {"last_sync_error", "last_sync_error_at"}
        assert "Selected rebuild sentinel" in after_selected["last_sync_error"]
        assert after_selected["last_sync_error_at"] is not None
    else:
        changed_columns = {
            "last_harvest_date",
            "last_full_rebuild_date",
            "source_cursor",
            "source_fingerprint",
            "last_sync_error",
            "last_sync_error_at",
        }
        row = sync_conn.execute(
            "SELECT last_harvest_date, last_full_rebuild_date, source_cursor, "
            "source_fingerprint, last_sync_error, last_sync_error_at "
            "FROM sync_status WHERE source = %s",
            (FOREIGN_SOURCE,),
        ).fetchone()
        assert row == (started_at, started_at, source_cursor, "c" * 64, None, None)

    changed_columns.update({"source_fetch_cursor", "source_fetch_fingerprint"})
    assert datetime.fromisoformat(after_selected["source_fetch_cursor"]) == source_cursor
    assert after_selected["source_fetch_fingerprint"] == "c" * 64
    assert {
        name: value for name, value in after_selected.items() if name not in changed_columns
    } == {name: value for name, value in before_selected.items() if name not in changed_columns}
    assert _state_document(sync_conn, TEST_SOURCE_NAME) == before_current
    assert (
        sync_conn.execute(
            "SELECT uuid, message, updated_at FROM ingestion_failures "
            "WHERE source = %s ORDER BY uuid",
            (TEST_SOURCE_NAME,),
        ).fetchall()
        == before_current_failures
    )


def _configured_fixture(name: str) -> ConfiguredSource:
    """Build a named public-floor fixture source."""
    return configure_sources(
        (
            FixtureConfig(
                name=name,
                display=SourceDisplay(label=f"Fixture {name}"),
                max_visibility="public",
            ),
        )
    )[0]


@pytest.mark.parametrize("source_name", ["fixture_one", "fixture_two"])
async def test_fixture_rebuild_and_incremental_use_only_their_own_state(
    db_pool, sync_conn, dataset_factory, source_name
):
    """Verify fixture rebuild and incremental use only their own state."""
    configured_source = _configured_fixture(source_name)
    other_name = "fixture_two" if source_name == "fixture_one" else "fixture_one"
    await ensure_source_status_rows(db_pool, (source_name, other_name))
    _set_state_sentinel(sync_conn, other_name)
    dataset_factory(
        source=other_name,
        uuid="fixture:public",
        title="Other fixture catalogue sentinel",
        visibility_tier="vetted",
    )
    sync_conn.execute(
        "INSERT INTO ingestion_failures (source, uuid, message) VALUES (%s, %s, %s)",
        (other_name, "fixture:public", "Other fixture unresolved sentinel"),
    )
    sync_conn.commit()
    before_current = _state_document(sync_conn, TEST_SOURCE_NAME)
    before_other = _state_document(sync_conn, other_name)
    before_dataset = sync_conn.execute(
        "SELECT to_jsonb(dataset) FROM oral_history_datasets AS dataset WHERE source = %s",
        (other_name,),
    ).fetchall()
    before_failures = sync_conn.execute(
        "SELECT uuid, message, updated_at FROM ingestion_failures WHERE source = %s",
        (other_name,),
    ).fetchall()
    sync_conn.commit()

    with patch(FETCH, autospec=True) as oai_fetch:
        rebuilt = await ingestion.run_full_rebuild(
            db_pool,
            configured_source=configured_source,
        )
        incremental = await ingestion.run_sync(
            db_pool,
            configured_source=configured_source,
        )

    oai_fetch.assert_not_called()
    assert (rebuilt.status, rebuilt.affected_count) == ("success", 3)
    assert (incremental.status, incremental.affected_count) == ("success", 2)
    assert sync_conn.execute(
        "SELECT uuid, visibility_tier FROM oral_history_datasets WHERE source = %s ORDER BY uuid",
        (source_name,),
    ).fetchall() == [
        ("fixture:public", "public"),
        ("fixture:registered", "registered"),
        ("fixture:vetted", "vetted"),
    ]
    row = sync_conn.execute(
        "SELECT source_cursor, source_fingerprint, incremental_harvest, "
        "incremental_position, incremental_affected FROM sync_status WHERE source = %s",
        (source_name,),
    ).fetchone()
    assert row == (
        datetime(2020, 1, 4, tzinfo=UTC),
        configured_source.adapter.config_fingerprint(),
        None,
        0,
        0,
    )
    assert _state_document(sync_conn, other_name) == before_other
    assert _state_document(sync_conn, TEST_SOURCE_NAME) == before_current
    assert (
        sync_conn.execute(
            "SELECT to_jsonb(dataset) FROM oral_history_datasets AS dataset WHERE source = %s",
            (other_name,),
        ).fetchall()
        == before_dataset
    )
    assert (
        sync_conn.execute(
            "SELECT uuid, message, updated_at FROM ingestion_failures WHERE source = %s",
            (other_name,),
        ).fetchall()
        == before_failures
    )


async def test_fixture_staged_replay_does_not_fetch_or_consume_another_source(db_pool, sync_conn):
    """Verify fixture staged replay does not fetch or consume another source."""
    configured_source = _configured_fixture("fixture_one")
    await ensure_source_status_rows(db_pool, (configured_source.name, FOREIGN_SOURCE))
    _set_state_sentinel(sync_conn, FOREIGN_SOURCE)
    before_other = _state_document(sync_conn, FOREIGN_SOURCE)
    before_current = _state_document(sync_conn, TEST_SOURCE_NAME)
    rebuilt = await ingestion.run_full_rebuild(db_pool, configured_source=configured_source)
    assert rebuilt.status == "success"
    harvest = configured_source.adapter.fetch(since=None)
    harvest.matching_records[0]["title"] = "Replayed fixture title"
    payload = encode_stored_harvest(
        harvest,
        source_fingerprint=configured_source.adapter.config_fingerprint(),
    )
    sync_conn.execute(
        "UPDATE sync_status SET incremental_harvest = %s, incremental_started_at = %s, "
        "incremental_position = 0, incremental_affected = 0 WHERE source = %s",
        (payload, datetime(2030, 1, 1, tzinfo=UTC), configured_source.name),
    )
    sync_conn.commit()

    with patch.object(
        FixtureAdapter,
        "fetch",
        autospec=True,
        side_effect=AssertionError("Staged fixture replay must not fetch"),
    ) as fetch:
        outcome = await ingestion.run_sync(db_pool, configured_source=configured_source)

    fetch.assert_not_called()
    assert (outcome.status, outcome.affected_count) == ("success", 3)
    assert sync_conn.execute(
        "SELECT title FROM oral_history_datasets WHERE source = %s AND uuid = %s",
        (configured_source.name, "fixture:public"),
    ).fetchone() == ("Replayed fixture title",)
    assert sync_conn.execute(
        "SELECT incremental_harvest, incremental_started_at, incremental_position, "
        "incremental_affected FROM sync_status WHERE source = %s",
        (configured_source.name,),
    ).fetchone() == (None, None, 0, 0)
    assert _state_document(sync_conn, FOREIGN_SOURCE) == before_other
    assert _state_document(sync_conn, TEST_SOURCE_NAME) == before_current


async def test_unbound_fixture_incremental_requires_a_rebuild_before_fetch(db_pool, sync_conn):
    """Verify unbound fixture incremental requires a rebuild before fetch."""
    configured_source = _configured_fixture("fixture_one")
    await ensure_source_status_rows(db_pool, (configured_source.name, FOREIGN_SOURCE))
    _set_state_sentinel(sync_conn, FOREIGN_SOURCE)
    before_other = _state_document(sync_conn, FOREIGN_SOURCE)
    before_current = _state_document(sync_conn, TEST_SOURCE_NAME)

    with patch("app.services.ingestion.run_source_fetch", autospec=True) as fetch:
        outcome = await ingestion.run_sync(db_pool, configured_source=configured_source)

    fetch.assert_not_awaited()
    assert outcome == ingestion.SyncOutcome(
        "failed",
        reason="full rebuild required",
        requires_full_rebuild=True,
    )
    row = sync_conn.execute(
        "SELECT source_cursor, source_fingerprint, incremental_harvest, last_sync_error "
        "FROM sync_status WHERE source = %s",
        (configured_source.name,),
    ).fetchone()
    assert row is not None
    assert row[:3] == (None, None, None)
    assert "full rebuild" in row[3]
    assert sync_conn.execute(
        "SELECT count(*) FROM oral_history_datasets WHERE source = %s",
        (configured_source.name,),
    ).fetchone() == (0,)
    assert _state_document(sync_conn, FOREIGN_SOURCE) == before_other
    assert _state_document(sync_conn, TEST_SOURCE_NAME) == before_current


async def test_development_fixture_recovers_through_the_first_scheduler_tick(
    db_pool, sync_conn, dataset_factory, monkeypatch
):
    """Verify development fixture recovers through the first scheduler tick."""
    monkeypatch.setattr(
        runtime_sources,
        "settings",
        SimpleNamespace(
            sources_config_file=str(PROJECT_ROOT / "deploy/environment/sources.dev.toml"),
            env_state="dev",
            allow_fixture_source=False,
        ),
    )
    sources = runtime_sources.load_runtime_sources()
    assert tuple(source.name for source in sources) == ("fixture_demo",)
    source = sources[0]
    assert isinstance(source.adapter, FixtureAdapter)
    before_legacy = _state_document(sync_conn, TEST_SOURCE_NAME)
    retained_id = dataset_factory(
        source=TEST_SOURCE_NAME,
        uuid="fixture:public",
        title="Retained unselected record",
    )
    retained = sync_conn.execute(
        "SELECT to_jsonb(dataset) FROM oral_history_datasets AS dataset WHERE id = %s",
        (retained_id,),
    ).fetchone()
    sync_conn.commit()
    await ensure_source_status_rows(db_pool, (source.name,))
    initial = _state_document(sync_conn, source.name)
    assert initial["source_cursor"] is initial["source_fingerprint"] is None
    sync_conn.commit()

    cache = create_autospec(CatalogueStatsCache, instance=True, spec_set=True)
    fixture_fetch = create_autospec(FixtureAdapter.fetch, side_effect=FixtureAdapter.fetch)
    monkeypatch.setattr(FixtureAdapter, "fetch", fixture_fetch)
    with patch(
        FETCH, autospec=True, side_effect=AssertionError("Offline ingestion used OAI")
    ) as oai_fetch:
        first = await sync_and_invalidate(db_pool, cache, source)
        assert first == ingestion.SyncOutcome("success", affected_count=3)
        first_state = _state_document(sync_conn, source.name)
        cursor = datetime(2020, 1, 4, tzinfo=UTC)
        assert datetime.fromisoformat(first_state["source_cursor"]) == cursor
        assert first_state["source_fingerprint"] == source.adapter.config_fingerprint()
        assert first_state["last_harvest_date"] is not None
        assert first_state["last_full_rebuild_date"] == first_state["last_harvest_date"]
        rows = sync_conn.execute(
            "SELECT id, uuid, access_level, visibility_tier FROM oral_history_datasets "
            "WHERE source = %s ORDER BY uuid",
            (source.name,),
        ).fetchall()
        assert [row[1:] for row in rows] == [
            ("fixture:public", "public", "public"),
            ("fixture:registered", "restricted", "registered"),
            ("fixture:vetted", "restricted", "vetted"),
        ]
        sync_conn.commit()

        second = await sync_and_invalidate(db_pool, cache, source)
        assert second == ingestion.SyncOutcome("success", affected_count=2)
    oai_fetch.assert_not_called()
    assert [entry.kwargs["since"] for entry in fixture_fetch.call_args_list] == [
        None,
        cursor - timedelta(days=2),
    ]
    assert all(
        set(entry.kwargs) == {"since", "cancel_event"} and not entry.kwargs["cancel_event"].is_set()
        for entry in fixture_fetch.call_args_list
    )
    assert all(entry.args[0] is source.adapter for entry in fixture_fetch.call_args_list)
    assert cache.invalidate_cache.call_count == 2
    final = _state_document(sync_conn, source.name)
    assert final["source_cursor"] == first_state["source_cursor"]
    assert final["source_fingerprint"] == first_state["source_fingerprint"]
    assert final["last_full_rebuild_date"] == first_state["last_full_rebuild_date"]
    assert all(
        final[field] is None
        for field in (
            "last_sync_error",
            "last_sync_error_at",
            "last_rebuild_error",
            "last_rebuild_error_at",
            "incremental_harvest",
            "incremental_started_at",
        )
    )
    assert final["incremental_position"] == final["incremental_affected"] == 0
    assert (
        sync_conn.execute(
            "SELECT id, uuid, access_level, visibility_tier FROM oral_history_datasets "
            "WHERE source = %s ORDER BY uuid",
            (source.name,),
        ).fetchall()
        == rows
    )
    assert sync_conn.execute(
        "SELECT count(*) FROM ingestion_failures WHERE source = %s",
        (source.name,),
    ).fetchone() == (0,)
    assert _state_document(sync_conn, TEST_SOURCE_NAME) == before_legacy
    assert (
        sync_conn.execute(
            "SELECT to_jsonb(dataset) FROM oral_history_datasets AS dataset WHERE id = %s",
            (retained_id,),
        ).fetchone()
        == retained
    )

"""Compose recorded OAI and fixture ingestion with registered jobs and HTTP health."""

from unittest.mock import MagicMock, create_autospec

import requests
from pydantic import SecretStr

from app.services import ensure_source_status_rows
from app.services.ingestion import SyncOutcome
from app.services.scheduler import (
    RunningJobTracker,
    create_scheduler,
    rebuild_and_invalidate,
    sync_and_invalidate,
)
from app.sources import configure_sources, oai_client
from config import settings
from tests.source_fixtures import TEST_SOURCE_NAME
from tests.sources.cases.oai_pmh_cmdi import ENDPOINT, make_case

OAI_SOURCE = "recorded_acceptance"
FIXTURE_SOURCE = "fixture_acceptance"
RETAINED_SOURCE = "retained_acceptance"
OUTAGE = "Recorded OAI endpoint unavailable"
TOKEN = "selected-source-health-acceptance-token"
SOURCE_DOCUMENT = f"""[[sources]]
name = "{OAI_SOURCE}"
adapter = "oai_pmh_cmdi"
label = "Recorded OAI archive"
endpoint = "{ENDPOINT}"
institution_filter = "Beispielstadt"
max_pages = 7
max_visibility = "registered"
requires_record_tier = false
incremental_interval_seconds = 7200
rebuild_interval_seconds = 172800
write_timeout_seconds = 119

[[sources]]
name = "{FIXTURE_SOURCE}"
adapter = "fixture"
label = "Offline fixture archive"
max_visibility = "public"
requires_record_tier = true
incremental_interval_seconds = 3600
rebuild_interval_seconds = 86400
write_timeout_seconds = 113
"""


def _snapshot(conn, source):
    """Read every persisted field and release the test connection's transaction."""
    state = conn.execute(
        "SELECT to_jsonb(state) FROM sync_status AS state WHERE source = %s", (source,)
    ).fetchone()
    assert state is not None
    datasets = conn.execute(
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
    return state[0], datasets, failures


def _seed_retained(conn, dataset_factory, shared_uuid):
    """Populate an unselected source with catalogue, progress and diagnostic sentinels."""
    dataset_factory(
        source=RETAINED_SOURCE,
        uuid=shared_uuid,
        title="Retained catalogue sentinel",
        visibility_tier="vetted",
    )
    conn.execute(
        """UPDATE sync_status SET source_fingerprint = %s,
                  incremental_harvest = %s, incremental_position = 1,
                  incremental_affected = 1,
                  incremental_started_at = TIMESTAMPTZ '2020-01-05 00:00:00+00',
                  last_sync_error = 'Unselected retained diagnostic'
           WHERE source = %s""",
        ("e" * 64, b"Unselected staged work must remain untouched", RETAINED_SOURCE),
    )
    conn.execute(
        "INSERT INTO ingestion_failures (source, uuid, message) VALUES (%s, %s, %s)",
        (RETAINED_SOURCE, shared_uuid, "Unselected unresolved record"),
    )
    conn.commit()


def _assert_bound(conn, source, cursor, expected_rows):
    """Check selected-source rows, cursor, binding and completed staging state."""
    rows = conn.execute(
        "SELECT id, uuid, visibility_tier, source FROM oral_history_datasets "
        "WHERE source = %s ORDER BY uuid",
        (source.name,),
    ).fetchall()
    assert tuple((row[1], row[2]) for row in rows) == expected_rows
    assert all(row[3] == source.name for row in rows)
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
    assert state[:6] == (cursor, source.adapter.config_fingerprint(), None, None, 0, 0)
    assert state[6] is not None and state[7] is not None
    assert state[7] <= state[6]
    assert state[8:] == (None, None, None, None)
    assert conn.execute(
        "SELECT count(*) FROM ingestion_failures WHERE source = %s", (source.name,)
    ).fetchone() == (0,)
    conn.commit()
    return {row[1]: row[0] for row in rows}, state[7]


async def _run_registered_job(
    scheduler, tracker, source, *, operation="incremental_sync"
) -> SyncOutcome:
    """Run the selected scheduler job and require its tracker to finish idle."""
    job = scheduler.get_job(f"{operation}:{source.name}")
    assert job is not None
    assert job.args[-1] is source
    outcome = await job.func(*job.args, **job.kwargs)
    assert isinstance(outcome, SyncOutcome)
    assert tracker.active_job_ids == ()
    return outcome


def _assert_registered_schedules(scheduler, sources):
    """Check each source has its configured incremental and rebuild jobs."""
    for source in sources:
        for operation, seconds, callback in (
            (
                "incremental_sync",
                source.schedule.incremental_interval_seconds,
                sync_and_invalidate,
            ),
            ("full_rebuild", source.schedule.rebuild_interval_seconds, rebuild_and_invalidate),
        ):
            job = scheduler.get_job(f"{operation}:{source.name}")
            assert job is not None
            assert job.args[1] is callback
            assert job.args[-1] is source
            assert job.trigger.interval.total_seconds() == seconds
            assert job.max_instances == 1


def _assert_health(client, names, *, failed_source=None):
    """Check detailed health reports only the selected sources and expected failure."""
    response = client.get("/health/detail", headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == ("degraded" if failed_source else "healthy")
    assert body["checks"]["database"] == "ok"
    sources = body["checks"]["sources"]
    assert tuple(sources) == names
    assert RETAINED_SOURCE not in response.text
    assert TEST_SOURCE_NAME not in sources
    for name in names:
        checks = sources[name]
        assert checks["status"] == ("degraded" if name == failed_source else "healthy")
        assert "sync_stale" not in checks and "full_rebuild_stale" not in checks
        assert "rebuild_error" not in checks
        if name == failed_source:
            assert OUTAGE in checks["sync_error"]
        else:
            assert "sync_error" not in checks


def _assert_retained(conn, expected):
    """Check each unselected source still matches its earlier snapshot."""
    for name, before in expected.items():
        assert _snapshot(conn, name) == before


def _selected_client(tmp_path, monkeypatch, client_factory):
    """Create a live client using this test's explicit selected-source configuration."""
    source_file = tmp_path / "sources.toml"
    source_file.write_text(SOURCE_DOCUMENT, encoding="utf-8")
    monkeypatch.setattr(settings, "sources_config_file", str(source_file))
    monkeypatch.setattr(settings, "env_state", "dev")
    monkeypatch.setattr(settings, "allow_fixture_source", False)
    monkeypatch.setattr(settings, "fastapi_debug", False)
    monkeypatch.setattr(settings, "health_detail_token", SecretStr(TOKEN))
    client = client_factory("127.0.0.61")
    sources = client.app.state.configured_sources
    assert tuple(source.name for source in sources) == (OAI_SOURCE, FIXTURE_SOURCE)
    assert tuple(source.policy.max_visibility for source in sources) == ("registered", "public")
    assert tuple(
        (
            source.schedule.incremental_interval_seconds,
            source.schedule.rebuild_interval_seconds,
            source.schedule.write_timeout_seconds,
        )
        for source in sources
    ) == ((7200, 172800, 119), (3600, 86400, 113))
    assert all(not hasattr(source, "adapter") for source in sources)
    return client, configure_sources(tuple(source.config for source in sources))


def _assert_failed_fetch(conn, source, before):
    """Check only failure diagnostics changed and return the new snapshot."""
    after = _snapshot(conn, source)
    assert after[1:] == before[1:]
    assert OUTAGE in after[0]["last_sync_error"]
    assert after[0]["last_sync_error_at"] is not None
    unchanged = set(before[0]) - {"last_sync_error", "last_sync_error_at"}
    assert {key: after[0][key] for key in unchanged} == {key: before[0][key] for key in unchanged}
    return after


def _recorded_transport(monkeypatch):
    """Capture true signatures, then install replay and a strict HTTP blocker."""
    session_spec = requests.Session()
    original_get, original_close = session_spec.get, session_spec.close
    original_close()
    original_factory = oai_client._build_session
    original_request = requests.sessions.Session.request
    case = make_case(monkeypatch)
    request_blocker = create_autospec(
        original_request, side_effect=AssertionError("Acceptance test attempted real HTTP")
    )
    monkeypatch.setattr(requests.sessions.Session, "request", request_blocker)
    outage_session = MagicMock(spec_set=session_spec)
    outage_get = create_autospec(original_get, side_effect=requests.ConnectionError(OUTAGE))
    outage_close = create_autospec(original_close, return_value=None)
    outage_session.get = outage_get
    outage_session.close = outage_close
    outage_factory = create_autospec(original_factory, return_value=outage_session)
    return case, outage_factory, outage_get, outage_close, request_blocker


def _assert_native_boundaries(calls):
    """Check OAI requests used the expected rebuild and incremental dates."""
    boundaries = []
    for call in calls:
        params = call["params"]
        assert isinstance(params, dict)
        if "from" in params:
            boundaries.append(params["from"])
    assert boundaries == ["1900-01-01", "2020-01-02"]


async def test_recorded_oai_failure_does_not_block_the_selected_fixture_or_its_health(
    db_pool, sync_conn, dataset_factory, e2e_client_from_address, tmp_path, monkeypatch
):
    """Verify recorded OAI failure does not block the selected fixture or its health."""
    case, outage_factory, outage_get, outage_close, request_blocker = _recorded_transport(
        monkeypatch
    )

    client, sources = _selected_client(tmp_path, monkeypatch, e2e_client_from_address)
    names = tuple(source.name for source in sources)
    await ensure_source_status_rows(db_pool, (*names, RETAINED_SOURCE))
    _seed_retained(sync_conn, dataset_factory, case.full_ids[0])
    retained = {name: _snapshot(sync_conn, name) for name in (RETAINED_SOURCE, TEST_SOURCE_NAME)}
    await ensure_source_status_rows(db_pool, names)
    _assert_retained(sync_conn, retained)

    cache = client.app.state.catalogue_stats_cache
    invalidate = create_autospec(cache.invalidate_cache, spec_set=True, return_value=None)
    monkeypatch.setattr(cache, "invalidate_cache", invalidate)
    tracker = RunningJobTracker()
    scheduler = create_scheduler(db_pool, cache, tracker, sources)
    _assert_registered_schedules(scheduler, sources)
    expected_rows = {
        OAI_SOURCE: tuple((identifier, "registered") for identifier in case.full_ids),
        FIXTURE_SOURCE: (
            ("fixture:public", "public"),
            ("fixture:registered", "registered"),
            ("fixture:vetted", "vetted"),
        ),
    }
    initial = {}
    for source in sources:
        outcome = await _run_registered_job(scheduler, tracker, source, operation="full_rebuild")
        assert (outcome.status, outcome.affected_count, outcome.failed_count) == ("success", 3, 0)
        initial[source.name] = _assert_bound(
            sync_conn, source, case.cursor, expected_rows[source.name]
        )
    _assert_health(client, names)
    oai_before, fixture_before = (_snapshot(sync_conn, source.name) for source in sources)

    with monkeypatch.context() as outage_patch:
        outage_patch.setattr(oai_client, "_build_session", outage_factory)
        failed = await _run_registered_job(scheduler, tracker, sources[0])
    assert (failed.status, failed.affected_count, failed.failed_count) == ("failed", 0, 0)
    assert failed.requires_full_rebuild is False
    assert failed.reason is not None and OUTAGE in failed.reason
    outage_factory.assert_called_once_with()
    outage_get.assert_called_once()
    assert outage_get.call_args.kwargs["params"]["from"] == "2020-01-02"
    outage_close.assert_called_once_with()
    oai_failed = _assert_failed_fetch(sync_conn, OAI_SOURCE, oai_before)
    assert _snapshot(sync_conn, FIXTURE_SOURCE) == fixture_before
    _assert_health(client, names, failed_source=OAI_SOURCE)

    fixture_outcome = await _run_registered_job(scheduler, tracker, sources[1])
    assert (fixture_outcome.status, fixture_outcome.affected_count) == ("success", 2)
    assert (
        _assert_bound(sync_conn, sources[1], case.cursor, expected_rows[FIXTURE_SOURCE])
        == initial[FIXTURE_SOURCE]
    )
    fixture_after = _snapshot(sync_conn, FIXTURE_SOURCE)
    assert _snapshot(sync_conn, OAI_SOURCE) == oai_failed
    _assert_health(client, names, failed_source=OAI_SOURCE)

    retried = await _run_registered_job(scheduler, tracker, sources[0])
    assert (retried.status, retried.affected_count, retried.failed_count) == ("success", 2, 0)
    assert (
        _assert_bound(sync_conn, sources[0], case.cursor, expected_rows[OAI_SOURCE])
        == initial[OAI_SOURCE]
    )
    assert _snapshot(sync_conn, FIXTURE_SOURCE) == fixture_after
    _assert_retained(sync_conn, retained)
    _assert_health(client, names)
    assert invalidate.call_count == 5
    _assert_native_boundaries(case.io_calls)
    request_blocker.assert_not_called()

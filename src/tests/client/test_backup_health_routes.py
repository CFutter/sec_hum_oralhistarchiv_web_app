"""Backup age is protected, bounded and independent of existing readiness policy."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from queue import Queue
from unittest.mock import patch

import pytest
import time_machine
from psycopg import OperationalError
from psycopg.errors import QueryCanceled

from app.thread_work import ThreadWorkAdmissionTimeout
from app.thread_work import run_thread_work as real_run_thread_work
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor
from tests.source_fixtures import TEST_SOURCE_NAME

_NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
_UNKNOWN = {"status": "unknown", "age_seconds": None}
_DETAIL = "/health/detail"


def _bearer():
    """Build a bearer header from the configured health-detail secret."""
    assert settings.health_detail_token is not None
    return {"Authorization": f"Bearer {settings.health_detail_token.get_secret_value()}"}


def _sync_row():
    """Build recent successful harvest and rebuild timestamps without errors."""
    return {
        "last_harvest_date": _NOW - timedelta(minutes=5),
        "last_full_rebuild_date": _NOW - timedelta(hours=1),
        "last_sync_error": None,
        "last_sync_error_at": None,
        "last_rebuild_error": None,
        "last_rebuild_error_at": None,
    }


def _outbox_row(**changes):
    """Build an idle outbox status row with caller overrides."""
    return {
        "pending_count": 0,
        "sending_count": 0,
        "dead_count": 0,
        "recent_failure_count": 0,
        "pending_age": None,
        "sending_age": None,
        "retention_overdue_count": 0,
        **changes,
    }


def _clean_context(*_args, **_kwargs):
    """Return a cursor context with healthy source and outbox rows."""
    return FakeCursorCtx(
        make_async_cursor(
            fetchall=[{**_sync_row(), "source": TEST_SOURCE_NAME}], fetchone=[_outbox_row()]
        )
    )


def _marker(tmp_path, monkeypatch, *, age_seconds=60):
    """Write a timestamped backup marker and select it in settings; age is seconds."""
    path = tmp_path / "last-success"
    path.write_text(f"OHA_BACKUP_SUCCESS_V1 {int(_NOW.timestamp()) - age_seconds}\n")
    path.chmod(0o640)
    monkeypatch.setattr(settings, "backup_status_file", str(path))
    return path


def test_authorized_detail_reports_actual_marker_age_without_changing_readiness(
    guest_client, tmp_path, monkeypatch
):
    """Check authorized detail reports actual marker age without changing readiness (HTTP 200)."""
    _marker(tmp_path, monkeypatch)
    with (
        time_machine.travel(_NOW, tick=False),
        patch("app.routes.health.get_db_cursor", autospec=True, side_effect=_clean_context),
    ):
        response = guest_client.get(_DETAIL, headers=_bearer())

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["checks"]["backup"] == {"status": "ok", "age_seconds": 60}
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["outbox"]["pending_count"] == 0
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("problem", ["missing", "malformed", "future", "old"])
def test_unavailable_or_old_backup_evidence_does_not_redefine_database_readiness(
    guest_client, tmp_path, monkeypatch, problem
):
    """Check unavailable or old backup evidence does not redefine database readiness (HTTP 200)."""
    path = _marker(tmp_path, monkeypatch, age_seconds=30 * 86400 if problem == "old" else 60)
    if problem == "missing":
        path.unlink()
    elif problem == "malformed":
        path.write_text("private archive or error text must not reach JSON\n")
    elif problem == "future":
        path.write_text(f"OHA_BACKUP_SUCCESS_V1 {int(_NOW.timestamp()) + 1}\n")
    with (
        time_machine.travel(_NOW, tick=False),
        patch("app.routes.health.get_db_cursor", autospec=True, side_effect=_clean_context),
    ):
        response = guest_client.get(_DETAIL, headers=_bearer())

    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "healthy"
    assert body["checks"]["backup"] == (
        {"status": "ok", "age_seconds": 30 * 86400} if problem == "old" else _UNKNOWN
    )
    assert str(path) not in response.text
    assert "private archive" not in response.text


def test_unconfigured_backup_status_does_not_admit_thread_work(guest_client, monkeypatch):
    """Check unconfigured backup status does not admit thread work (HTTP 200)."""
    monkeypatch.setattr(settings, "backup_status_file", None)
    with (
        time_machine.travel(_NOW, tick=False),
        patch("app.routes.health.get_db_cursor", autospec=True, side_effect=_clean_context),
        patch("app.routes.health.run_thread_work", autospec=True) as work,
        patch("app.routes.health.read_backup_status", autospec=True) as reader,
    ):
        response = guest_client.get(_DETAIL, headers=_bearer())

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["checks"]["backup"] == _UNKNOWN
    work.assert_not_awaited()
    reader.assert_not_called()


@pytest.mark.parametrize(
    "header", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic anything"}]
)
def test_denied_detail_reads_neither_backup_nor_database(guest_client, monkeypatch, header):
    """Check denied detail reads neither backup nor database (HTTP 404)."""
    monkeypatch.setattr(settings, "backup_status_file", "/private/last-success")
    monkeypatch.setattr(settings, "fastapi_debug", False)
    with (
        patch("app.routes.health.read_backup_status", autospec=True) as reader,
        patch("app.routes.health.run_thread_work", autospec=True) as work,
        patch("app.routes.health.get_db_cursor", autospec=True) as database,
    ):
        response = guest_client.get(_DETAIL, headers=header)

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}
    reader.assert_not_called()
    work.assert_not_awaited()
    database.assert_not_called()


def test_liveness_reads_no_backup_even_when_a_marker_is_configured(guest_client, monkeypatch):
    """Check liveness reads no backup even when a marker is configured (HTTP 200)."""
    monkeypatch.setattr(settings, "backup_status_file", "/private/last-success")
    with (
        patch("app.routes.health.read_backup_status", autospec=True) as reader,
        patch("app.routes.health.run_thread_work", autospec=True) as work,
        patch("app.routes.health.get_db_cursor", autospec=True) as database,
    ):
        response = guest_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    reader.assert_not_called()
    work.assert_not_awaited()
    database.assert_not_called()


def test_backup_age_remains_available_during_database_failure(guest_client, tmp_path, monkeypatch):
    """Check backup age remains available during database failure (HTTP 503)."""
    _marker(tmp_path, monkeypatch)
    with (
        time_machine.travel(_NOW, tick=False),
        patch(
            "app.routes.health.get_db_cursor", autospec=True, side_effect=OperationalError("lost")
        ),
    ):
        response = guest_client.get(_DETAIL, headers=_bearer())

    assert response.status_code == 503
    assert response.json()["status"] == "unhealthy"
    assert response.json()["checks"]["database"] == "disconnected"
    assert response.json()["checks"]["backup"] == {"status": "ok", "age_seconds": 60}


@pytest.mark.parametrize("stage", ["source", "outbox", "stalled-outbox"])
def test_backup_age_does_not_mask_existing_degraded_causes(
    guest_client, tmp_path, monkeypatch, stage
):
    """Check backup age does not mask existing degraded causes (HTTP 200)."""
    _marker(tmp_path, monkeypatch)
    cursor = make_async_cursor(
        fetchall=[{**_sync_row(), "source": TEST_SOURCE_NAME}], fetchone=[_outbox_row()]
    )
    if stage == "source":
        cursor.execute.side_effect = [None, QueryCanceled("statement timeout")]
    elif stage == "outbox":
        cursor.fetchone.side_effect = [RuntimeError("outbox read failed")]
    else:
        cursor.fetchone.side_effect = [
            _outbox_row(pending_count=1, pending_age=settings.outbox_stale_after_seconds),
        ]
    with (
        time_machine.travel(_NOW, tick=False),
        patch("app.routes.health.get_db_cursor", autospec=True, return_value=FakeCursorCtx(cursor)),
    ):
        response = guest_client.get(_DETAIL, headers=_bearer())

    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "degraded"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["backup"] == {"status": "ok", "age_seconds": 60}
    if stage == "outbox":
        assert body["checks"]["outbox_error"] == "Outbox diagnostics unavailable"
    elif stage == "stalled-outbox":
        assert body["checks"]["outbox_degraded"] is True
    else:
        source = guest_client.app.state.configured_sources[0]
        assert body["checks"]["sources"][source.name]["sync"] == "error"


def test_marker_reader_runs_on_a_worker_thread_with_its_own_capacity(guest_client, monkeypatch):
    """Check marker reader runs on a worker thread with its own capacity."""
    monkeypatch.setattr(settings, "backup_status_file", "/local/last-success")
    observed = {}

    def reader(path):
        """Record the reader thread and return a healthy marker status."""
        observed["worker"] = threading.get_ident()
        assert path == "/local/last-success"
        return {"status": "ok", "age_seconds": 9}

    async def work(function, capacity, *, admission_timeout_seconds):
        """Record admission settings and delegate to the real thread-work runner."""
        observed["event_loop"] = threading.get_ident()
        observed["capacity"] = capacity.total_tokens
        observed["budget"] = admission_timeout_seconds
        return await real_run_thread_work(
            function, capacity, admission_timeout_seconds=admission_timeout_seconds
        )

    with (
        time_machine.travel(_NOW, tick=False),
        patch("app.routes.health.read_backup_status", autospec=True, side_effect=reader),
        patch("app.routes.health.run_thread_work", autospec=True, side_effect=work),
        patch("app.routes.health.get_db_cursor", autospec=True, side_effect=_clean_context),
    ):
        response = guest_client.get(_DETAIL, headers=_bearer())

    assert response.json()["checks"]["backup"] == {"status": "ok", "age_seconds": 9}
    assert observed["worker"] != observed["event_loop"]
    assert observed["capacity"] == 2
    assert observed["budget"] == 0.2


def test_marker_capacity_timeout_is_unknown_without_reading_the_file(guest_client, monkeypatch):
    """Check marker capacity timeout is unknown without reading the file (HTTP 200)."""
    monkeypatch.setattr(settings, "backup_status_file", "/local/last-success")
    with (
        time_machine.travel(_NOW, tick=False),
        patch("app.routes.health.get_db_cursor", autospec=True, side_effect=_clean_context),
        patch("app.routes.health.read_backup_status", autospec=True) as reader,
        patch(
            "app.routes.health.run_thread_work",
            autospec=True,
            side_effect=ThreadWorkAdmissionTimeout(0.2),
        ),
    ):
        response = guest_client.get(_DETAIL, headers=_bearer())

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["checks"]["backup"] == _UNKNOWN
    reader.assert_not_called()


def test_two_busy_marker_readers_bound_a_third_request_without_blocking_the_event_loop(
    guest_client, monkeypatch
):
    """Check two busy marker readers bound a third request without blocking the event loop (HTTP 200)."""
    monkeypatch.setattr(settings, "backup_status_file", "/local/last-success")
    entered = Queue()
    release = threading.Event()

    def reader(_path):
        """Record entry, wait up to ten seconds for release, and return a healthy status."""
        entered.put(threading.get_ident())
        assert release.wait(timeout=10), "The test did not release the marker readers"
        return {"status": "ok", "age_seconds": 1}

    with (
        time_machine.travel(_NOW, tick=False),
        patch("app.routes.health.read_backup_status", autospec=True, side_effect=reader) as read,
        patch("app.routes.health.get_db_cursor", autospec=True, side_effect=_clean_context),
        ThreadPoolExecutor(max_workers=3) as callers,
    ):
        first = callers.submit(guest_client.get, _DETAIL, headers=_bearer())
        second = callers.submit(guest_client.get, _DETAIL, headers=_bearer())
        try:
            entered.get(timeout=10)
            entered.get(timeout=10)
            third = callers.submit(guest_client.get, _DETAIL, headers=_bearer())
            third_response = third.result(timeout=10)
            assert third_response.status_code == 200
            assert third_response.json()["checks"]["backup"] == _UNKNOWN
            assert third_response.json()["status"] == "healthy"
            assert read.call_count == 2
        finally:
            release.set()
        for result in (first, second):
            response = result.result(timeout=10)
            assert response.status_code == 200
            assert response.json()["checks"]["backup"] == {"status": "ok", "age_seconds": 1}

"""HTTP-level contract for the health endpoints (`/health`, `/health/detail`)."""

import datetime
from typing import Any
from unittest.mock import AsyncMock, create_autospec, patch

import pytest
from psycopg import OperationalError
from psycopg.errors import QueryCanceled

import app.middleware.rate_limiting as rl
from app.services.db import get_db_cursor as _real_get_db_cursor
from app.sources import (
    ConfiguredSource,
    FixtureConfig,
    SourceDisplay,
    SourceSchedule,
    configure_sources,
)
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor, replace_test_catalogue_sources
from tests.source_fixtures import TEST_SOURCE_NAME, legacy_source


def _patch_get_db_cursor(**kwargs):
    """Patch the health cursor factory using its real signature."""
    return patch(
        "app.routes.health.get_db_cursor",
        new=create_autospec(_real_get_db_cursor, **kwargs),
    )


DETAIL_URL = "/health/detail"


def _bearer_header() -> dict[str, Any]:
    """Authorization header carrying the correct health-detail token."""
    assert settings.health_detail_token is not None
    token = settings.health_detail_token.get_secret_value()
    return {"Authorization": f"Bearer {token}"}


def _outbox_row(**overrides: Any) -> dict[str, Any]:
    """A clean outbox diagnostics row, or one with named fields overridden."""
    return dict(
        {
            "pending_count": 0,
            "sending_count": 0,
            "dead_count": 0,
            "recent_failure_count": 0,
            "pending_age": None,
            "sending_age": None,
            "retention_overdue_count": 0,
        },
        **overrides,
    )


def _detail_cursor_ctxs(
    sync_row,
    outbox_row=None,
    *,
    additional_sync_rows=(),
    source_names=(TEST_SOURCE_NAME, "offline_archive"),
):
    """One source batch plus one independent outbox read on the same connection."""
    rows = [
        {**row, "source": name}
        for name, row in zip(source_names, (sync_row, *additional_sync_rows), strict=False)
        if row is not None
    ]
    cur = make_async_cursor(
        fetchall=rows,
        fetchone=[_outbox_row() if outbox_row is None else outbox_row],
    )
    return [FakeCursorCtx(cur)]


_FRESH_REBUILD_AT = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)

_CLEAN_SYNC_ROW = {
    "last_harvest_date": datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=5),
    "last_full_rebuild_date": _FRESH_REBUILD_AT,
    "last_sync_error": None,
    "last_sync_error_at": None,
    "last_rebuild_error": None,
    "last_rebuild_error_at": None,
}


class TestLivenessProbe:
    """`/health` never inspects application dependencies."""

    def test_alive_response_never_touches_the_database(self, guest_client):
        """The liveness probe stays successful even when PostgreSQL is down."""
        guest_client.mock_pool.connection.side_effect = RuntimeError("db down")

        response = guest_client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "alive"}
        guest_client.mock_pool.connection.assert_not_called()

    def test_response_is_not_cacheable(self, guest_client):
        """Check response is not cacheable (HTTP 200)."""
        response = guest_client.get("/health")

        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"


class TestLivenessHasNoBackendDependencies:
    """`/health` reads no dependencies; readiness belongs to `/health/detail`."""

    def test_health_performs_no_redis_operation(self, guest_client):
        """The liveness exemption prevents limiter storage access."""
        storage_double = create_autospec(rl.limiter.limiter.storage, instance=True, spec_set=True)
        with patch.object(rl.limiter.limiter, "storage", new=storage_double):
            response = guest_client.get("/health")

        assert response.status_code == 200
        assert storage_double.mock_calls == []

    def test_health_detail_does_perform_a_redis_operation_as_the_positive_control(
        self, guest_client
    ):
        """The detailed endpoint retains the ordinary rate-limit backstop."""
        storage_double = create_autospec(rl.limiter.limiter.storage, instance=True, spec_set=True)
        with patch.object(rl.limiter.limiter, "storage", new=storage_double):
            guest_client.get(DETAIL_URL)

        assert storage_double.mock_calls != []

    def test_health_body_makes_no_dependency_readiness_claim(self, guest_client):
        """An unreachable database leaves the liveness payload unchanged."""
        guest_client.mock_pool.connection.side_effect = RuntimeError("db down")

        response = guest_client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "alive"}
        guest_client.mock_pool.connection.assert_not_called()


class TestHealthDetailAuthorization:
    """Authorization failure returns 404 without revealing diagnostics."""

    def test_missing_authorization_header_is_rejected_as_not_found(self, guest_client):
        """Check missing authorization header is rejected as not found (HTTP 404)."""
        response = guest_client.get(DETAIL_URL)

        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}

    def test_wrong_bearer_token_is_rejected_as_not_found(self, guest_client):
        """A wrong token receives the same response as a missing token."""
        response = guest_client.get(DETAIL_URL, headers={"Authorization": "Bearer wrong-token"})

        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}

    def test_non_bearer_scheme_is_rejected_as_not_found(self, guest_client):
        """The correct token under another authorization scheme is rejected."""
        token = settings.health_detail_token.get_secret_value()
        response = guest_client.get(DETAIL_URL, headers={"Authorization": f"Basic {token}"})

        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}

    def test_no_token_configured_fails_secure_even_with_a_header(self, guest_client, monkeypatch):
        """An unconfigured token never opens non-debug diagnostics."""
        monkeypatch.setattr(settings, "health_detail_token", None)

        response = guest_client.get(DETAIL_URL, headers={"Authorization": "Bearer anything-at-all"})

        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}

    def test_debug_mode_grants_open_access_without_any_token(self, guest_client, monkeypatch):
        """Development debug mode permits diagnostics without a token."""
        monkeypatch.setattr(settings, "fastapi_debug", True)

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(_CLEAN_SYNC_ROW),
        ):
            response = guest_client.get(DETAIL_URL)

        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_denied_response_is_not_cacheable(self, guest_client):
        """Check denied response is not cacheable (HTTP 404)."""
        response = guest_client.get(DETAIL_URL)

        assert response.status_code == 404
        assert response.headers["Cache-Control"] == "no-store"

    def test_authorized_response_is_not_cacheable(self, guest_client):
        """Successful diagnostics also refuse caching."""
        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(_CLEAN_SYNC_ROW),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"


class TestHealthDetailDatabaseAndSyncDiagnostics:
    """Database reachability and independent source error/staleness channels."""

    def test_database_failure_reports_503_unhealthy(self, guest_client):
        """Failure to obtain a database connection makes readiness unhealthy."""
        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=Exception("connection refused"),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "unhealthy"
        assert body["checks"]["database"] == "disconnected"

    def test_database_up_and_sync_clean_reports_healthy(self, guest_client):
        """Clean source state appears under its configured identity."""
        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(_CLEAN_SYNC_ROW),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "healthy"
        assert body["checks"]["database"] == "ok"
        source_checks = body["checks"]["sources"][TEST_SOURCE_NAME]
        assert source_checks["status"] == "healthy"
        assert source_checks["sync"].startswith("last harvest:")
        assert "sync_error" not in source_checks

    def test_recorded_sync_error_reports_degraded_but_http_200(self, guest_client):
        """A recorded incremental error degrades diagnostics while HTTP stays 200."""
        error_at = datetime.datetime(2026, 6, 2, 8, 30, tzinfo=datetime.UTC)
        sync_row = dict(
            _CLEAN_SYNC_ROW,
            last_sync_error="boom",
            last_sync_error_at=error_at,
        )

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(sync_row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["database"] == "ok"
        source_checks = body["checks"]["sources"][TEST_SOURCE_NAME]
        assert source_checks["sync_error"] == "boom"
        assert source_checks["sync_error_at"] == str(error_at)
        assert "rebuild_error" not in source_checks

    def test_recorded_rebuild_error_reports_degraded_via_its_own_keys(self, guest_client):
        """A rebuild error retains its own channel independently of incremental sync."""
        error_at = datetime.datetime(2026, 6, 2, 9, 0, tzinfo=datetime.UTC)
        row = dict(
            _CLEAN_SYNC_ROW,
            last_rebuild_error="Full rebuild ABORTED — 0/2 inserted",
            last_rebuild_error_at=error_at,
        )

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["database"] == "ok"
        source_checks = body["checks"]["sources"][TEST_SOURCE_NAME]
        assert source_checks["rebuild_error"] == "Full rebuild ABORTED — 0/2 inserted"
        assert source_checks["rebuild_error_at"] == str(error_at)
        assert "sync_error" not in source_checks

    def test_both_error_channels_surface_independently(self, guest_client):
        """Neither error channel masks the other."""
        row = dict(
            _CLEAN_SYNC_ROW,
            last_sync_error="Incremental sync (fetch): boom",
            last_sync_error_at=datetime.datetime(2026, 6, 2, 8, 30, tzinfo=datetime.UTC),
            last_rebuild_error="Full rebuild: upstream returned 0 live records",
            last_rebuild_error_at=datetime.datetime(2026, 6, 2, 3, 0, tzinfo=datetime.UTC),
        )

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        source_checks = body["checks"]["sources"][TEST_SOURCE_NAME]
        assert source_checks["sync_error"] == "Incremental sync (fetch): boom"
        assert source_checks["rebuild_error"] == "Full rebuild: upstream returned 0 live records"

    def test_missing_sync_history_reports_degraded_not_unhealthy(self, guest_client):
        """A missing configured-source row degrades reachable storage diagnostics."""
        cursor_contexts = _detail_cursor_ctxs(None)
        cur = cursor_contexts[0].cursor
        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=cursor_contexts,
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        body = response.json()
        assert response.status_code == 200
        assert body["status"] == "degraded"
        assert body["checks"]["sources"][TEST_SOURCE_NAME]["sync_status_missing"] == (
            f"sync_status row for source {TEST_SOURCE_NAME!r} is missing"
        )
        status_query = cur.execute.await_args_list[1]
        assert "WHERE source = ANY(%s::text[])" in status_query.args[0]
        assert status_query.args[1] == ([TEST_SOURCE_NAME],)

    def test_stale_harvest_reports_degraded_but_http_200(self, guest_client):
        """A scheduler that stops completing harvests must not remain healthy."""
        source = guest_client.app.state.configured_sources[0]
        stale_row = dict(_CLEAN_SYNC_ROW)
        stale_row["last_harvest_date"] = datetime.datetime.now(datetime.UTC) - datetime.timedelta(
            seconds=2 * source.schedule.incremental_interval_seconds + 60
        )
        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(stale_row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        source_checks = body["checks"]["sources"][TEST_SOURCE_NAME]
        assert "sync_stale" in source_checks
        assert "sync_error" not in source_checks

    def test_stale_rebuild_reports_degraded_but_http_200(self, guest_client):
        """An old successful rebuild degrades even without a recorded error."""
        source = guest_client.app.state.configured_sources[0]
        stale_row = dict(_CLEAN_SYNC_ROW)
        stale_row["last_full_rebuild_date"] = datetime.datetime.now(
            datetime.UTC
        ) - datetime.timedelta(seconds=2 * source.schedule.rebuild_interval_seconds + 3600)

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(stale_row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        source_checks = body["checks"]["sources"][TEST_SOURCE_NAME]
        assert "full_rebuild_stale" in source_checks
        assert "sync_error" not in source_checks

    def test_never_rebuilt_reports_degraded_with_never_message(self, guest_client):
        """An install awaiting its first successful rebuild reports that state."""
        fresh_install_row = dict(_CLEAN_SYNC_ROW)
        fresh_install_row["last_full_rebuild_date"] = None

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(fresh_install_row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        body = response.json()
        assert response.status_code == 200
        assert body["status"] == "degraded"
        source_checks = body["checks"]["sources"][TEST_SOURCE_NAME]
        assert source_checks["full_rebuild"] == "last rebuild: never"
        assert "full_rebuild_stale" in source_checks

    @pytest.mark.parametrize(
        "failure,expected_status_code",
        [
            (OperationalError("connection lost"), 503),
            (QueryCanceled("statement timeout"), 200),
        ],
        ids=["operational_error_after_select_one_is_unhealthy", "query_canceled_stays_degraded"],
    )
    def test_failure_after_a_successful_select_one_is_classified_by_exception_type(
        self, guest_client, failure, expected_status_code
    ):
        """Connection loss is unhealthy; statement cancellation is degraded."""
        cur = make_async_cursor()
        cur.execute = AsyncMock(side_effect=[None, failure])
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == expected_status_code
        assert response.json()["status"] in {"unhealthy", "degraded"}


class TestHealthDetailOutboxDiagnostics:
    """Global outbox diagnostics remain independent of source error channels."""

    @pytest.mark.parametrize(
        "overrides",
        [
            {"pending_count": 1, "pending_age": 900},
            {"sending_count": 1, "sending_age": 900},
            {"retention_overdue_count": 1},
        ],
        ids=["pending_delivery_stalled", "sending_delivery_stalled", "retention_cleanup_overdue"],
    )
    def test_outbox_problem_is_degraded_without_failing_liveness(self, guest_client, overrides):
        """Check outbox problem is degraded without failing liveness (HTTP 200)."""
        cur = _detail_cursor_ctxs(_CLEAN_SYNC_ROW, _outbox_row(**overrides))[0].cursor
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)) as cursor:
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["outbox_degraded"] is True
        assert set(body["checks"]["outbox"]) == {
            "counts_capped_at",
            "pending_count",
            "sending_count",
            "dead_count",
            "recent_failure_count",
            "oldest_pending_age_seconds",
            "oldest_sending_age_seconds",
            "retention_overdue_count",
        }
        cursor.assert_called_once()
        assert guest_client.get("/health").json() == {"status": "alive"}

    def test_dead_letters_are_visible_without_treating_cancellation_as_outage(self, guest_client):
        """Dead letters alone remain visible without degrading readiness."""
        cur = _detail_cursor_ctxs(_CLEAN_SYNC_ROW, _outbox_row(dead_count=3))[0].cursor
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.json()["status"] == "healthy"
        assert response.json()["checks"]["outbox"]["dead_count"] == 3

    def test_recent_terminal_delivery_failures_keep_the_status_degraded(self, guest_client):
        """Recent terminal failures remain actionable diagnostics."""
        cur = _detail_cursor_ctxs(
            _CLEAN_SYNC_ROW, _outbox_row(dead_count=1, recent_failure_count=1)
        )[0].cursor
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        assert response.json()["status"] == "degraded"

    def test_outbox_query_failure_is_not_misreported_as_sync_failure(self, guest_client):
        """Check outbox query failure is not misreported as sync failure (HTTP 200)."""
        cur = _detail_cursor_ctxs(_CLEAN_SYNC_ROW, RuntimeError("outbox query failed"))[0].cursor
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        checks = response.json()["checks"]
        assert response.json()["status"] == "degraded"
        assert checks["outbox_error"] == "Outbox diagnostics unavailable"
        assert checks["sources"][TEST_SOURCE_NAME]["sync"].startswith("last harvest:")


class TestHealthDetailConfiguredSources:
    """Selected sources retain independent diagnostics and captured schedules."""

    @staticmethod
    def _sources() -> tuple[ConfiguredSource, ConfiguredSource]:
        """Build online and offline sources with distinct scheduling intervals."""
        primary = legacy_source(
            schedule=SourceSchedule(
                incremental_interval_seconds=7200,
                rebuild_interval_seconds=172800,
                write_timeout_seconds=119,
            )
        )
        offline = configure_sources(
            (
                FixtureConfig(
                    name="offline_archive",
                    display=SourceDisplay(label="Offline archive"),
                    schedule=SourceSchedule(
                        incremental_interval_seconds=3600,
                        rebuild_interval_seconds=86400,
                        write_timeout_seconds=113,
                    ),
                ),
            )
        )[0]
        return primary, offline

    def test_two_sources_are_reported_in_configuration_order_with_bound_queries(
        self, guest_client, monkeypatch
    ):
        """Check two sources are reported in configuration order with bound queries (HTTP 200)."""
        sources = self._sources()
        replace_test_catalogue_sources(monkeypatch, guest_client.app, sources)
        contexts = _detail_cursor_ctxs(_CLEAN_SYNC_ROW, additional_sync_rows=(_CLEAN_SYNC_ROW,))
        cur = contexts[0].cursor
        with _patch_get_db_cursor(side_effect=contexts):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "healthy"
        assert list(body["checks"]["sources"]) == [source.name for source in sources]
        for source in sources:
            source_checks = body["checks"]["sources"][source.name]
            assert source_checks["status"] == "healthy"
            assert source_checks["sync"].startswith("last harvest:")
            assert source_checks["full_rebuild"].startswith("last rebuild:")
            assert isinstance(source_checks["harvest_age_seconds"], (int, float))
            assert isinstance(source_checks["rebuild_age_seconds"], (int, float))
        status_query = cur.execute.await_args_list[1]
        assert "WHERE source = ANY(%s::text[])" in status_query.args[0]
        assert status_query.args[1] == ([source.name for source in sources],)
        assert cur.execute.await_count == 3
        cur.fetchall.assert_awaited_once()

    @pytest.mark.parametrize("problem", ["missing", "sync_error", "rebuild_error"])
    def test_one_problem_source_degrades_the_whole_response_without_tainting_its_peer(
        self, guest_client, monkeypatch, problem
    ):
        """Check one problem source degrades the whole response without tainting its peer (HTTP 200)."""
        sources = self._sources()
        replace_test_catalogue_sources(monkeypatch, guest_client.app, sources)
        second_row: dict[str, Any] | None = None if problem == "missing" else dict(_CLEAN_SYNC_ROW)
        if second_row is not None:
            column = "last_sync_error" if problem == "sync_error" else "last_rebuild_error"
            second_row[column] = "offline source failure"

        with _patch_get_db_cursor(
            side_effect=_detail_cursor_ctxs(_CLEAN_SYNC_ROW, additional_sync_rows=(second_row,))
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["database"] == "ok"
        by_source = body["checks"]["sources"]
        assert by_source[sources[0].name]["status"] == "healthy"
        assert by_source[sources[1].name]["status"] == "degraded"
        if problem == "missing":
            assert by_source[sources[1].name]["sync_status_missing"] == (
                f"sync_status row for source {sources[1].name!r} is missing"
            )
            assert by_source[sources[1].name]["harvest_age_seconds"] is None
            assert by_source[sources[1].name]["rebuild_age_seconds"] is None
        else:
            assert by_source[sources[1].name][problem] == "offline source failure"
            assert problem not in by_source[sources[0].name]

    @pytest.mark.parametrize(
        ("date_field", "elapsed_seconds", "stale_key", "age_key"),
        [
            ("last_harvest_date", 10800, "sync_stale", "harvest_age_seconds"),
            ("last_full_rebuild_date", 259200, "full_rebuild_stale", "rebuild_age_seconds"),
        ],
        ids=["incremental", "rebuild"],
    )
    def test_staleness_uses_each_sources_own_interval(
        self, guest_client, monkeypatch, date_field, elapsed_seconds, stale_key, age_key
    ):
        """Check staleness uses each sources own interval (HTTP 200)."""
        sources = self._sources()
        replace_test_catalogue_sources(monkeypatch, guest_client.app, sources)
        row = dict(_CLEAN_SYNC_ROW)
        row[date_field] = datetime.datetime.now(datetime.UTC) - datetime.timedelta(
            seconds=elapsed_seconds
        )
        with _patch_get_db_cursor(
            side_effect=_detail_cursor_ctxs(row, additional_sync_rows=(row,))
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        by_source = body["checks"]["sources"]
        assert by_source[sources[0].name]["status"] == "healthy"
        assert stale_key not in by_source[sources[0].name]
        assert by_source[sources[1].name]["status"] == "degraded"
        assert stale_key in by_source[sources[1].name]
        for source in sources:
            assert by_source[source.name][age_key] >= elapsed_seconds

    def test_reconfigured_source_schedule_changes_health_thresholds(
        self, guest_client, monkeypatch
    ):
        """Check reconfigured source schedule changes health thresholds (HTTP 200)."""
        captured = self._sources()[0]
        reconfigured = legacy_source(
            schedule=SourceSchedule(
                incremental_interval_seconds=1,
                rebuild_interval_seconds=1,
            )
        )

        for source, expected in ((captured, "healthy"), (reconfigured, "degraded")):
            replace_test_catalogue_sources(monkeypatch, guest_client.app, (source,))
            with _patch_get_db_cursor(side_effect=_detail_cursor_ctxs(_CLEAN_SYNC_ROW)):
                response = guest_client.get(DETAIL_URL, headers=_bearer_header())

            assert response.status_code == 200
            body = response.json()
            assert body["status"] == expected
            checks = body["checks"]["sources"][source.name]
            assert checks["status"] == expected
            assert ("sync_stale" in checks) == (expected == "degraded")
            assert ("full_rebuild_stale" in checks) == (expected == "degraded")

    def test_unauthorized_requests_read_neither_source_state_nor_postgresql(
        self, guest_client, monkeypatch
    ):
        """Check unauthorized requests read neither source state nor postgresql (HTTP 404)."""
        monkeypatch.delattr(guest_client.app.state, "configured_sources")
        with _patch_get_db_cursor() as cursor:
            response = guest_client.get(DETAIL_URL)

        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}
        cursor.assert_not_called()
        guest_client.mock_pool.connection.assert_not_called()

    @pytest.mark.parametrize(
        ("failure", "expected_status_code"),
        [
            (QueryCanceled("statement timeout"), 200),
            (OperationalError("connection lost"), 503),
        ],
        ids=["source-read-failure", "connection-failure"],
    )
    def test_outbox_read_failure_preserves_all_batched_source_diagnostics(
        self, guest_client, monkeypatch, failure, expected_status_code
    ):
        """Check outbox read failure preserves all batched source diagnostics."""
        sources = self._sources()
        replace_test_catalogue_sources(monkeypatch, guest_client.app, sources)
        cur = _detail_cursor_ctxs(_CLEAN_SYNC_ROW, additional_sync_rows=(_CLEAN_SYNC_ROW,))[
            0
        ].cursor
        cur.execute.side_effect = [None, None, failure]
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == expected_status_code
        body = response.json()
        assert body["status"] == ("degraded" if expected_status_code == 200 else "unhealthy")
        by_source = body["checks"]["sources"]
        assert by_source[sources[0].name]["status"] == "healthy"
        assert by_source[sources[0].name]["sync"].startswith("last harvest:")
        assert by_source[sources[1].name]["status"] == "healthy"
        assert by_source[sources[1].name]["sync"].startswith("last harvest:")
        assert "outbox" not in body["checks"]
        cur.fetchall.assert_awaited_once()
        cur.fetchone.assert_not_awaited()
        assert cur.execute.await_count == 3


@pytest.mark.parametrize("source_count", [0, 1, 40])
def test_health_source_round_trips_are_constant_and_rows_are_matched_by_name(
    guest_client, monkeypatch, source_count
):
    """Check health source round trips are constant and rows are matched by name (HTTP 200)."""
    sources = tuple(legacy_source(name=f"batch_source_{n}") for n in range(source_count))
    replace_test_catalogue_sources(monkeypatch, guest_client.app, sources)
    # Reverse SQL result order and leave one selected source absent. Conversion
    # must preserve configuration order and missing-row semantics independently.
    rows = [
        {**_CLEAN_SYNC_ROW, "source": source.name}
        for source in reversed(sources)
        if source is not sources[-1]
    ]
    cur = make_async_cursor(fetchall=rows, fetchone=[_outbox_row()])
    with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
        response = guest_client.get(DETAIL_URL, headers=_bearer_header())
    assert response.status_code == 200
    checks = response.json()["checks"]["sources"]
    assert list(checks) == [source.name for source in sources]
    assert cur.execute.await_count == (3 if sources else 2)
    cur.fetchone.assert_awaited_once()
    if sources:
        cur.fetchall.assert_awaited_once()
        statement, params = cur.execute.await_args_list[1].args
        assert "WHERE source = ANY(%s::text[])" in statement
        assert params == ([source.name for source in sources],)
    else:
        cur.fetchall.assert_not_awaited()
        assert all("sync_status" not in call.args[0] for call in cur.execute.await_args_list)
    for source in sources[:-1]:
        assert checks[source.name]["status"] == "healthy"
    if sources:
        assert checks[sources[-1].name]["sync"] == "no sync history"


def test_no_configured_sources_still_reads_outbox_without_touching_sync_status(
    guest_client, monkeypatch
):
    """Check no configured sources still reads outbox without touching sync status (HTTP 200)."""
    replace_test_catalogue_sources(monkeypatch, guest_client.app, ())
    cur = make_async_cursor(fetchone=[_outbox_row(dead_count=2)])
    cur.fetchall.side_effect = RuntimeError("source batch must not run")

    async def reject_source_queries(statement, *_args):
        """Reject source-status queries while permitting other diagnostic work."""
        if "sync_status" in statement:
            raise RuntimeError("source diagnostics are unavailable")

    cur.execute.side_effect = reject_source_queries
    with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
        response = guest_client.get(DETAIL_URL, headers=_bearer_header())
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["checks"]["sources"] == {}
    assert body["checks"]["outbox"]["dead_count"] == 2
    assert cur.execute.await_count == 2
    cur.fetchall.assert_not_awaited()
    cur.fetchone.assert_awaited_once()

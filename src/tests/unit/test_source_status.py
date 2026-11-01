"""Public source summaries reflect selected state without exposing diagnostics."""

from dataclasses import fields
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

import pytest
from psycopg import OperationalError
from psycopg_pool import AsyncConnectionPool, PoolTimeout

import app.services.source_status as source_status_module
from app.services import SourceStatus, get_source_statuses
from app.services.db import get_db_cursor as _real_get_db_cursor
from app.sources import (
    ConfiguredSource,
    FixtureConfig,
    SourceDisplay,
    SourceSchedule,
    configure_sources,
)
from tests.fixtures import FakeCursorCtx, make_async_cursor

_NOW = datetime(2026, 1, 4, 12, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _fixed_source_clock(monkeypatch):
    """Replace source-status datetime with a mock returning the fixed NOW value."""
    clock = create_autospec(datetime)
    clock.now.return_value = _NOW
    monkeypatch.setattr(source_status_module, "datetime", clock)


def _source(name: str = "archive_alpha", *, interval: int = 100) -> ConfiguredSource:
    """Configure a fixture source with incremental seconds and a tenfold rebuild interval."""
    return configure_sources(
        (
            FixtureConfig(
                name=name,
                display=SourceDisplay(label=f"Label for {name}", sensitivity_badge="Mixed access"),
                schedule=SourceSchedule(
                    incremental_interval_seconds=interval,
                    rebuild_interval_seconds=interval * 10,
                ),
            ),
        )
    )[0]


@pytest.mark.parametrize(
    ("present", "harvest_age", "rebuild_age", "sync_failed", "rebuild_failed", "expected"),
    [
        (False, None, None, False, False, "pending"),
        (True, None, None, False, False, "pending"),
        (True, None, 100, False, False, "pending"),
        (True, 10, None, False, False, "pending"),
        (True, 10, 100, False, False, "active"),
        (True, None, 100, True, False, "degraded"),
        (True, 10, None, False, True, "degraded"),
        (True, 201, 100, False, False, "degraded"),
        (True, 10, 2001, False, False, "degraded"),
        (True, None, 2001, False, False, "degraded"),
        (True, 200, 2000, False, False, "active"),
    ],
    ids=[
        "missing-row",
        "never-synchronized",
        "harvest-missing",
        "rebuild-missing",
        "active",
        "incremental-error-before-incomplete-history",
        "rebuild-error-before-incomplete-history",
        "stale-harvest",
        "stale-rebuild",
        "stale-operation-before-incomplete-history",
        "exact-two-interval-boundary",
    ],
)
async def test_public_source_status_classifies_persisted_history(
    present, harvest_age, rebuild_age, sync_failed, rebuild_failed, expected
):
    """Check public source status classifies persisted history."""
    source = _source()
    rows = (
        [
            {
                "source": source.name,
                "last_harvest_date": (
                    None if harvest_age is None else _NOW - timedelta(seconds=harvest_age)
                ),
                "last_full_rebuild_date": (
                    None if rebuild_age is None else _NOW - timedelta(seconds=rebuild_age)
                ),
                "sync_failed": sync_failed,
                "rebuild_failed": rebuild_failed,
            }
        ]
        if present
        else []
    )
    cur = make_async_cursor(fetchall=rows)
    pool = create_autospec(AsyncConnectionPool, instance=True)
    with patch.object(
        source_status_module,
        "get_db_cursor",
        new=create_autospec(_real_get_db_cursor, return_value=FakeCursorCtx(cur)),
    ):
        statuses = await get_source_statuses(pool, configured_sources=(source,))

    assert statuses == (
        SourceStatus(source.name, source.display.label, source.display.sensitivity_badge, expected),
    )


async def test_public_source_scope_keeps_configuration_order_and_each_sources_intervals():
    """Check public source scope keeps configuration order and each sources intervals."""
    sources = (_source(interval=100), _source("archive_beta", interval=1000))
    # Database order differs deliberately; the same history is stale only for alpha.
    rows = [
        {
            "source": source.name,
            "last_harvest_date": _NOW - timedelta(seconds=300),
            "last_full_rebuild_date": _NOW - timedelta(seconds=3000),
            "sync_failed": False,
            "rebuild_failed": False,
        }
        for source in reversed(sources)
    ]
    cur = make_async_cursor(fetchall=rows)
    pool = create_autospec(AsyncConnectionPool, instance=True)
    with patch.object(
        source_status_module,
        "get_db_cursor",
        new=create_autospec(_real_get_db_cursor, return_value=FakeCursorCtx(cur)),
    ):
        statuses = await get_source_statuses(pool, configured_sources=sources)

    assert [row.name for row in statuses] == [source.name for source in sources]
    assert [row.status for row in statuses] == ["degraded", "active"]
    query, parameters = cur.execute.await_args.args
    assert "WHERE source = ANY(%s::text[])" in query
    assert parameters == ([source.name for source in sources],)
    cur.execute.assert_awaited_once()
    cur.fetchall.assert_awaited_once_with()
    assert {field.name for field in fields(SourceStatus)} == {
        "name",
        "label",
        "sensitivity_badge",
        "status",
    }


@pytest.mark.parametrize("duplicate", [False, True], ids=["empty", "duplicate-name"])
async def test_invalid_source_scopes_fail_before_database_access(duplicate):
    """Check invalid source scopes fail before database access (ValueError)."""
    source = _source()
    sources = (source, source) if duplicate else ()
    pool = create_autospec(AsyncConnectionPool, instance=True)
    with (
        patch.object(source_status_module, "get_db_cursor", autospec=True) as get_cursor,
        pytest.raises(ValueError),
    ):
        await get_source_statuses(pool, configured_sources=sources)

    get_cursor.assert_not_called()
    pool.connection.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [OperationalError("connection lost"), PoolTimeout("pool busy")],
    ids=["database-disconnected", "pool-capacity-exhausted"],
)
async def test_database_read_failures_propagate_to_application_handling(failure):
    """Check database read failures propagate to application handling."""
    pool = create_autospec(AsyncConnectionPool, instance=True)
    with (
        patch.object(source_status_module, "get_db_cursor", autospec=True, side_effect=failure),
        pytest.raises(type(failure)) as raised,
    ):
        await get_source_statuses(pool, configured_sources=(_source(),))

    assert raised.value is failure

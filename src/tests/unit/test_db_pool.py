"""Pool exhaustion logging and propagation without opening PostgreSQL."""

import logging
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, create_autospec

import pytest
from psycopg_pool import AsyncConnectionPool, PoolTimeout
from pydantic import ValidationError

from app.services.db import _POOL_ACQUIRE_TIMEOUT, create_pool, create_search_pool, get_db_cursor
from config import settings
from tests.unit.settings_builders import base_kwargs, make_settings


def _pool_that_times_out() -> AsyncConnectionPool:
    """A mock AsyncConnectionPool whose `.connection()` context manager
    raises PoolTimeout on entry — the shape psycopg_pool presents when the
    pool is exhausted past its acquire timeout."""
    pool = create_autospec(AsyncConnectionPool, instance=True, spec_set=True)

    @asynccontextmanager
    async def _conn():
        """Raise PoolTimeout when entering the fake connection context."""
        raise PoolTimeout("couldn't get a connection from the pool")
        yield  # pragma: no cover - unreachable, makes this an async CM

    pool.connection = _conn
    return pool


async def test_get_db_cursor_reraises_pool_timeout():
    """PoolTimeout from pool.connection() propagates out of get_db_cursor
    (not swallowed), so the caller sees the failure."""
    pool = _pool_that_times_out()

    with pytest.raises(PoolTimeout):
        async with get_db_cursor(pool):
            pass  # pragma: no cover - body never runs; entry raises


async def test_get_db_cursor_logs_pool_size_on_timeout(caplog):
    """The exhaustion is logged at WARNING with the configured pool size —
    the operator-facing signal that max_size needs raising, not a silent
    reraise."""
    pool = _pool_that_times_out()

    with (
        caplog.at_level(logging.WARNING, logger="app.services.db"),
        pytest.raises(PoolTimeout),
    ):
        async with get_db_cursor(pool):
            pass  # pragma: no cover

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "pool exhaustion must emit a WARNING"
    assert str(settings.database_pool_size) in warnings[-1].getMessage()


@pytest.mark.parametrize(
    "size",
    [1, 2, 5],
    ids=["size-1-min-clamped-to-1", "size-2-min-equals-size", "size-5-min-capped-at-2"],
)
def test_create_pool_clamps_min_size_to_configured_ceiling(monkeypatch, size):
    """Create pool clamps min size to configured ceiling."""
    monkeypatch.setattr(settings, "database_pool_size", size)
    pool = create_pool()
    assert pool.min_size == min(2, size)
    assert pool.max_size == size


class TestPoolAdmissionIsExplicitlyBounded:
    """Set waiter capacity and acquisition timeout explicitly when constructing the pool."""

    def test_create_pool_uses_the_configured_max_waiting_and_a_bounded_timeout(self, monkeypatch):
        """Create pool uses the configured max waiting and a bounded timeout."""
        monkeypatch.setattr(settings, "database_pool_max_waiting", 17)
        pool = create_pool()
        assert pool.max_waiting == 17
        assert pool.timeout == _POOL_ACQUIRE_TIMEOUT
        assert 0 < pool.timeout < 30.0


class TestDatabasePoolMaxWaitingBounds:
    """Accept waiter capacities 1..1000 and reject values outside that range."""

    @pytest.mark.parametrize("value", [1, 1000], ids=["lower-bound-1", "upper-bound-1000"])
    def test_boundary_values_are_accepted(self, value):
        """Boundary values are accepted."""
        configured = make_settings(**base_kwargs(database_pool_max_waiting=value))
        assert configured.database_pool_max_waiting == value

    @pytest.mark.parametrize(
        "value", [0, -1, 1001], ids=["zero", "negative", "above-upper-bound-1001"]
    )
    def test_out_of_range_values_are_rejected(self, value):
        """Out of range values are rejected."""
        with pytest.raises(ValidationError, match="database_pool_max_waiting"):
            make_settings(**base_kwargs(database_pool_max_waiting=value))


async def test_search_pool_has_independent_admission_and_read_only_deadlines(monkeypatch):
    """Search pool has independent admission and read only deadlines."""
    monkeypatch.setattr(settings, "database_pool_size", 9)
    monkeypatch.setattr(settings, "database_pool_max_waiting", 20)
    monkeypatch.setattr(settings, "search_pool_timeout_seconds", 0.1)
    monkeypatch.setattr(settings, "search_statement_timeout_ms", 500)
    pool = create_search_pool()
    assert pool.min_size == pool.max_size == 1
    assert pool.max_waiting == 1
    assert pool.timeout == 0.1
    connection = AsyncMock()
    assert pool._configure is not None
    await pool._configure(connection)
    statements = [call.args[0] for call in connection.execute.await_args_list]
    rendered = [item.as_string() if hasattr(item, "as_string") else item for item in statements]
    assert "SET application_name = 'oralhistarchiv-search'" in rendered
    assert "SET statement_timeout = '500ms'" in rendered
    assert "SET max_parallel_workers_per_gather = 0" in rendered
    assert "SET default_transaction_read_only = on" in rendered
    assert connection.set_autocommit.await_args_list[-1].args == (False,)

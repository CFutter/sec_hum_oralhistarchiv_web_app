"""Unit-level coverage for db.get_db_cursor's failure branch.

The happy path (real cursor from a live pool) is exercised throughout the
integration tier; this file pins the pool-exhaustion arm (db.py: the
`except PoolTimeout` log-and-reraise) with no database, by driving a mock
pool whose `connection()` raises PoolTimeout.

get_db_cursor must LOG the exhaustion (with the configured pool
size, for the operator) and then RE-RAISE — callers depend on the timeout
propagating, not being swallowed into a None cursor.

The only real pool constructed here is created with open=False and never
opened, so no database is touched.
"""

import logging
from contextlib import asynccontextmanager
from unittest.mock import create_autospec

import pytest
from psycopg_pool import AsyncConnectionPool, PoolTimeout
from pydantic import ValidationError

from app.services.db import _POOL_ACQUIRE_TIMEOUT, create_pool, get_db_cursor
from config import settings
from tests.unit.settings_builders import base_kwargs, make_settings


def _pool_that_times_out() -> AsyncConnectionPool:
    """A mock AsyncConnectionPool whose `.connection()` context manager
    raises PoolTimeout on entry — the shape psycopg_pool presents when the
    pool is exhausted past its acquire timeout."""
    pool = create_autospec(AsyncConnectionPool, instance=True, spec_set=True)

    @asynccontextmanager
    async def _conn():
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
    # The configured pool size appears in the message so the operator knows
    # the current ceiling.
    assert str(settings.database_pool_size) in warnings[-1].getMessage()


@pytest.mark.parametrize(
    "size",
    [1, 2, 5],
    ids=["size-1-min-clamped-to-1", "size-2-min-equals-size", "size-5-min-capped-at-2"],
)
def test_create_pool_clamps_min_size_to_configured_ceiling(monkeypatch, size):
    """Validator-accepts-what-a-consumer-rejects — the settings
    boundary allows DATABASE_POOL_SIZE=1 (ge=1), but psycopg_pool raises
    when min_size > max_size, so create_pool must clamp min_size to
    min(2, configured size); for size 1 the pool is exactly 1/1. Asserting
    the pool attributes pins the clamp directly: a create_pool without the
    min(2, ...) clamp fails on these lines, not only via psycopg_pool's ValueError.

    create_pool returns the pool UNOPENED (open=False) and this test never
    opens it, so nothing connects.
    """
    monkeypatch.setattr(settings, "database_pool_size", size)
    pool = create_pool()
    assert pool.min_size == min(2, size)
    assert pool.max_size == size


class TestPoolAdmissionIsExplicitlyBounded:
    """The pool never falls back to psycopg_pool's own defaults for waiter
    admission: `max_waiting` comes from settings and the acquire timeout is
    the module's own bounded constant, not psycopg_pool's 30s default."""

    def test_create_pool_uses_the_configured_max_waiting_and_a_bounded_timeout(self, monkeypatch):
        monkeypatch.setattr(settings, "database_pool_max_waiting", 17)
        pool = create_pool()
        assert pool.max_waiting == 17
        assert pool.timeout == _POOL_ACQUIRE_TIMEOUT
        assert 0 < pool.timeout < 30.0


class TestDatabasePoolMaxWaitingBounds:
    """`database_pool_max_waiting` accepts its documented 1..1000 range and
    rejects anything outside it — an unbounded or zero waiter queue would
    let one slow request either queue forever or be rejected immediately."""

    @pytest.mark.parametrize("value", [1, 1000], ids=["lower-bound-1", "upper-bound-1000"])
    def test_boundary_values_are_accepted(self, value):
        configured = make_settings(**base_kwargs(database_pool_max_waiting=value))
        assert configured.database_pool_max_waiting == value

    @pytest.mark.parametrize(
        "value", [0, -1, 1001], ids=["zero", "negative", "above-upper-bound-1001"]
    )
    def test_out_of_range_values_are_rejected(self, value):
        with pytest.raises(ValidationError, match="database_pool_max_waiting"):
            make_settings(**base_kwargs(database_pool_max_waiting=value))

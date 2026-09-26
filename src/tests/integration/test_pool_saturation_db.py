"""Bounded PostgreSQL connection-pool admission against a real database.

``create_pool()`` (app/services/db.py) constructs a psycopg_pool
``AsyncConnectionPool`` with a bounded ``max_size`` and ``max_waiting``. These
tests hold every pooled connection open from independent coroutines and prove
that admission beyond the configured bound fails promptly with
``TooManyRequests`` rather than queuing unboundedly or falling back to an
unpooled connection, that a saturation rejection performs no partial database
mutation, and that the two public routes documented to behave identically for
a known and an unknown address keep that contract when the pool is exhausted.
"""

import asyncio
import time
from contextlib import asynccontextmanager
from unittest.mock import create_autospec, patch

import httpx
import psycopg
import pytest
from psycopg_pool import TooManyRequests

import app.main as _app_main
from app.main import app
from app.services.db import create_pool, get_db_cursor
from app.services.registration import register_local_user
from config import settings

from .conftest import TEST_DATABASE_URL

pytestmark = pytest.mark.usefixtures("clean_db")

_BOUNDED_WAIT_SECONDS = 5.0


@asynccontextmanager
async def _small_pool(monkeypatch, *, pool_size: int, max_waiting: int):
    """Open a real pool with the settings values patched small."""
    monkeypatch.setattr(settings, "database_pool_size", pool_size)
    monkeypatch.setattr(settings, "database_pool_max_waiting", max_waiting)
    pool = create_pool(application_name="pool-saturation-test")
    # wait=True warms min_size connections before the test starts admitting
    # contenders, so the bound under test is max_size + max_waiting, not an
    # unrelated startup race against still-connecting pooled connections.
    await pool.open(wait=True)
    try:
        yield pool
    finally:
        await pool.close()


async def _hold_connection(pool, release: asyncio.Event, ready: asyncio.Event) -> None:
    """Check out one connection and keep it until told to release it."""
    async with pool.connection() as conn:
        await conn.execute("SELECT 1")
        ready.set()
        await release.wait()


async def _wait_until(predicate, *, timeout: float = _BOUNDED_WAIT_SECONDS, interval: float = 0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return predicate()


class TestExcessContendersAreRejectedWithinTheConfiguredBound:
    """Requests beyond max_size + max_waiting fail fast; the rest wait."""

    async def test_excess_contenders_fail_promptly_while_waiters_stay_within_the_bound(
        self, monkeypatch
    ):
        async with _small_pool(monkeypatch, pool_size=2, max_waiting=2) as pool:
            holder_release = asyncio.Event()
            holder_ready = [asyncio.Event(), asyncio.Event()]
            holders = [
                asyncio.create_task(_hold_connection(pool, holder_release, holder_ready[i]))
                for i in range(2)
            ]
            assert await _wait_until(lambda: all(e.is_set() for e in holder_ready))
            assert pool.get_stats()["pool_available"] == 0

            async def _contend():
                async with get_db_cursor(pool) as cur:
                    await cur.execute("SELECT 1")
                    return "admitted"

            contenders = [asyncio.create_task(_contend()) for _ in range(5)]
            # Give the two within-bound waiters a chance to register as
            # waiting before we assert the immediate rejections.
            assert await _wait_until(lambda: pool.get_stats()["requests_waiting"] >= 1)

            rejected = []
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and len(rejected) < 3:
                for task in contenders:
                    if task.done() and task not in rejected:
                        rejected.append(task)
                await asyncio.sleep(0.01)

            assert len(rejected) == 3, "expected exactly 3 contenders to be rejected immediately"
            for task in rejected:
                with pytest.raises(TooManyRequests):
                    task.result()

            # The waiting count for the two admitted-to-the-queue contenders
            # never exceeds the configured max_waiting bound.
            assert pool.get_stats()["requests_waiting"] <= 2

            holder_release.set()
            await asyncio.wait_for(asyncio.gather(*holders), timeout=_BOUNDED_WAIT_SECONDS)
            remaining = [t for t in contenders if t not in rejected]
            assert len(remaining) == 2
            results = await asyncio.wait_for(
                asyncio.gather(*remaining), timeout=_BOUNDED_WAIT_SECONDS
            )
            assert results == ["admitted", "admitted"]

    async def test_a_pool_under_its_bound_admits_every_contender(self, monkeypatch):
        """Positive control: within max_size + max_waiting, nothing is rejected."""
        async with _small_pool(monkeypatch, pool_size=2, max_waiting=2) as pool:

            async def _contend():
                async with get_db_cursor(pool) as cur:
                    await cur.execute("SELECT 1")
                    return "admitted"

            results = await asyncio.wait_for(
                asyncio.gather(*[_contend() for _ in range(4)]), timeout=_BOUNDED_WAIT_SECONDS
            )
            assert results == ["admitted"] * 4


class TestPoolRecoveryAfterSaturation:
    """Releasing every held connection restores clean admission."""

    async def test_a_new_acquire_succeeds_after_holders_release_without_leaking_transaction_state(
        self, monkeypatch
    ):
        async with _small_pool(monkeypatch, pool_size=1, max_waiting=1) as pool:
            release = asyncio.Event()
            ready = asyncio.Event()

            async def _hold_with_uncommitted_setting():
                async with pool.connection() as conn:
                    await conn.execute("SET LOCAL search_path TO pg_temp")
                    ready.set()
                    await release.wait()
                    # No commit: exiting the context returns the connection to
                    # the pool, which must roll the open transaction back.

            holder = asyncio.create_task(_hold_with_uncommitted_setting())
            assert await _wait_until(ready.is_set)

            release.set()
            await asyncio.wait_for(holder, timeout=_BOUNDED_WAIT_SECONDS)

            async with get_db_cursor(pool, row_factory=None) as cur:
                await cur.execute("SHOW search_path")
                row = await cur.fetchone()
            assert row[0] != "pg_temp", (
                "a borrower observed the prior holder's uncommitted SET LOCAL"
            )
            assert pool.get_stats()["requests_waiting"] == 0
            assert pool.get_stats()["pool_available"] == 1


class TestSaturationRejectionPerformsNoPartialMutation:
    """A service call rejected by pool admission leaves no trace."""

    async def test_registration_rejected_by_a_saturated_pool_writes_nothing(self, monkeypatch):
        async with _small_pool(monkeypatch, pool_size=1, max_waiting=1) as pool:
            release = asyncio.Event()
            ready = asyncio.Event()
            holder = asyncio.create_task(_hold_connection(pool, release, ready))
            assert await _wait_until(ready.is_set)

            waiter_ready = asyncio.Event()
            waiter_release = asyncio.Event()

            async def _occupy_the_waiting_slot():
                waiter_ready.set()
                async with pool.connection() as conn:
                    await conn.execute("SELECT 1")
                    await waiter_release.wait()

            waiter = asyncio.create_task(_occupy_the_waiting_slot())
            assert await _wait_until(
                lambda: pool.get_stats()["requests_waiting"] >= 1 or waiter.done()
            )

            email = "saturation-rejected@uzh.ch"
            with pytest.raises(TooManyRequests):
                await register_local_user(
                    pool,
                    email=email,
                    display_name="Saturation Rejected",
                    password="Sup3rSecret!pw-for-tests",
                )

            release.set()
            waiter_release.set()
            await asyncio.wait_for(asyncio.gather(holder, waiter), timeout=_BOUNDED_WAIT_SECONDS)

            assert await _wait_until(
                lambda: pool.get_stats()["pool_available"] == pool.get_stats()["pool_size"]
            )
            assert pool.get_stats()["requests_waiting"] == 0

        with psycopg.connect(TEST_DATABASE_URL) as conn:
            user_row = conn.execute("SELECT 1 FROM users WHERE email = %s", (email,)).fetchone()
            outbox_row = conn.execute(
                "SELECT 1 FROM email_outbox eo JOIN users u ON u.id = eo.user_id "
                "WHERE u.email = %s",
                (email,),
            ).fetchone()
        assert user_row is None, "a rejected registration inserted a user row anyway"
        assert outbox_row is None, "a rejected registration queued an email anyway"

    async def test_registration_against_an_available_pool_writes_the_expected_rows(
        self, monkeypatch
    ):
        """Positive control: the same call against a healthy pool commits both rows."""
        async with _small_pool(monkeypatch, pool_size=2, max_waiting=2) as pool:
            email = "saturation-control@uzh.ch"
            user = await register_local_user(
                pool,
                email=email,
                display_name="Saturation Control",
                password="Sup3rSecret!pw-for-tests",
            )
            assert user.email == email

        with psycopg.connect(TEST_DATABASE_URL) as conn:
            user_row = conn.execute("SELECT 1 FROM users WHERE email = %s", (email,)).fetchone()
            outbox_row = conn.execute(
                "SELECT 1 FROM email_outbox eo JOIN users u ON u.id = eo.user_id "
                "WHERE u.email = %s",
                (email,),
            ).fetchone()
        assert user_row is not None
        assert outbox_row is not None


# ---------------------------------------------------------------------------
# Real HTTP traffic against a saturated application pool
# ---------------------------------------------------------------------------

_REAL_LIFESPAN_TARGETS = {
    name: getattr(_app_main, name)
    for name in (
        "validate_security_settings",
        "validate_runtime_schema",
        "reconcile_federated_session_policy",
        "setup_logging",
        "seed_admin_user",
    )
}


@asynccontextmanager
async def _real_app_http_client(monkeypatch, *, pool_size: int, max_waiting: int):
    """A real ASGI transport over the production app, small pool patched in first.

    Local to this module: the shared ``e2e_client`` fixture (conftest.py) uses
    a synchronous ``TestClient`` and always builds the pool from whatever
    ``settings`` holds when its own background loop starts, which races the
    patch below. Driving the lifespan directly on the current event loop
    keeps pool construction and the patched settings on one loop.
    """
    monkeypatch.setattr(settings, "database_pool_size", pool_size)
    monkeypatch.setattr(settings, "database_pool_max_waiting", max_waiting)
    with (
        patch(
            "app.main.validate_security_settings",
            new=create_autospec(_REAL_LIFESPAN_TARGETS["validate_security_settings"]),
        ),
        patch(
            "app.main.validate_runtime_schema",
            new=create_autospec(_REAL_LIFESPAN_TARGETS["validate_runtime_schema"]),
        ),
        patch(
            "app.main.reconcile_federated_session_policy",
            new=create_autospec(_REAL_LIFESPAN_TARGETS["reconcile_federated_session_policy"]),
        ),
        patch(
            "app.main.setup_logging",
            new=create_autospec(_REAL_LIFESPAN_TARGETS["setup_logging"]),
        ),
        patch(
            "app.main.seed_admin_user",
            new=create_autospec(_REAL_LIFESPAN_TARGETS["seed_admin_user"]),
        ),
    ):
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                yield client, app.state.db_pool


async def _saturate(pool, *, waiting_slots: int):
    """Hold the sole connection and fill every waiting slot; return the tasks/events."""
    release = asyncio.Event()
    ready = asyncio.Event()
    holder = asyncio.create_task(_hold_connection(pool, release, ready))
    assert await _wait_until(ready.is_set)

    waiter_releases = [asyncio.Event() for _ in range(waiting_slots)]

    async def _wait_in_queue(evt: asyncio.Event):
        async with pool.connection() as conn:
            await conn.execute("SELECT 1")
            await evt.wait()

    waiters = [asyncio.create_task(_wait_in_queue(evt)) for evt in waiter_releases]
    assert await _wait_until(lambda: pool.get_stats()["requests_waiting"] >= waiting_slots)
    return release, holder, waiter_releases, waiters


class TestKnownAndUnknownAddressesUnderAPoolSaturatedByRealTraffic:
    """/forgot-password and /send_verification stay enumeration-neutral under saturation."""

    async def test_forgot_password_is_identical_for_a_known_and_an_unknown_address(
        self, monkeypatch, user_factory
    ):
        known = user_factory()
        async with _real_app_http_client(monkeypatch, pool_size=1, max_waiting=1) as (
            client,
            pool,
        ):
            csrf_response = await client.get("/forgot-password")
            csrf = csrf_response.cookies.get("csrf_token")

            release, holder, waiter_releases, waiters = await _saturate(pool, waiting_slots=1)
            try:
                known_response = await client.post(
                    "/forgot-password",
                    data={"email": known.email, "csrf_token": csrf},
                )
                unknown_response = await client.post(
                    "/forgot-password",
                    data={"email": "no-such-account@uzh.ch", "csrf_token": csrf},
                )
            finally:
                release.set()
                for evt in waiter_releases:
                    evt.set()
                await asyncio.wait_for(
                    asyncio.gather(holder, *waiters), timeout=_BOUNDED_WAIT_SECONDS
                )

        assert known_response.status_code == unknown_response.status_code == 200
        assert known_response.text == unknown_response.text
        # x-request-id is minted fresh per request by design; every other
        # header must be identical between the two addresses.
        known_headers = {k: v for k, v in known_response.headers.items() if k != "x-request-id"}
        unknown_headers = {k: v for k, v in unknown_response.headers.items() if k != "x-request-id"}
        assert known_headers == unknown_headers

        with psycopg.connect(TEST_DATABASE_URL) as conn:
            token_row = conn.execute(
                "SELECT password_reset_token_hash FROM users WHERE id = %s", (known.id,)
            ).fetchone()
            outbox_row = conn.execute(
                "SELECT 1 FROM email_outbox WHERE user_id = %s", (known.id,)
            ).fetchone()
        assert token_row[0] is None, "a saturated pool still minted a reset token"
        assert outbox_row is None, "a saturated pool still enqueued a reset email"

    async def test_forgot_password_mints_a_token_for_a_known_address_when_the_pool_is_healthy(
        self, monkeypatch, user_factory
    ):
        """Positive control: outside saturation the known-address path still works."""
        known = user_factory()
        async with _real_app_http_client(monkeypatch, pool_size=2, max_waiting=2) as (
            client,
            _pool,
        ):
            csrf_response = await client.get("/forgot-password")
            csrf = csrf_response.cookies.get("csrf_token")
            response = await client.post(
                "/forgot-password",
                data={"email": known.email, "csrf_token": csrf},
            )
        assert response.status_code == 200

        with psycopg.connect(TEST_DATABASE_URL) as conn:
            token_row = conn.execute(
                "SELECT password_reset_token_hash FROM users WHERE id = %s", (known.id,)
            ).fetchone()
            outbox_row = conn.execute(
                "SELECT 1 FROM email_outbox WHERE user_id = %s", (known.id,)
            ).fetchone()
        assert token_row[0] is not None
        assert outbox_row is not None

    async def test_send_verification_is_identical_for_a_known_and_an_unknown_address(
        self, monkeypatch, user_factory
    ):
        known = user_factory(email_verified=False)
        async with _real_app_http_client(monkeypatch, pool_size=1, max_waiting=1) as (
            client,
            pool,
        ):
            csrf_response = await client.get("/send_verification")
            csrf = csrf_response.cookies.get("csrf_token")

            release, holder, waiter_releases, waiters = await _saturate(pool, waiting_slots=1)
            try:
                known_response = await client.post(
                    "/send_verification",
                    data={"email": known.email, "csrf_token": csrf},
                )
                unknown_response = await client.post(
                    "/send_verification",
                    data={"email": "no-such-account@uzh.ch", "csrf_token": csrf},
                )
            finally:
                release.set()
                for evt in waiter_releases:
                    evt.set()
                await asyncio.wait_for(
                    asyncio.gather(holder, *waiters), timeout=_BOUNDED_WAIT_SECONDS
                )

        assert known_response.status_code == unknown_response.status_code == 200
        assert known_response.text == unknown_response.text

        with psycopg.connect(TEST_DATABASE_URL) as conn:
            token_row = conn.execute(
                "SELECT email_verification_token_hash FROM users WHERE id = %s", (known.id,)
            ).fetchone()
        assert token_row[0] is None, "a saturated pool still minted a verification token"

    async def test_send_verification_mints_a_token_for_a_known_address_when_the_pool_is_healthy(
        self, monkeypatch, user_factory
    ):
        """Positive control: outside saturation the known-address path still works."""
        known = user_factory(email_verified=False)
        async with _real_app_http_client(monkeypatch, pool_size=2, max_waiting=2) as (
            client,
            _pool,
        ):
            csrf_response = await client.get("/send_verification")
            csrf = csrf_response.cookies.get("csrf_token")
            response = await client.post(
                "/send_verification",
                data={"email": known.email, "csrf_token": csrf},
            )
        assert response.status_code == 200

        with psycopg.connect(TEST_DATABASE_URL) as conn:
            token_row = conn.execute(
                "SELECT email_verification_token_hash FROM users WHERE id = %s", (known.id,)
            ).fetchone()
        assert token_row[0] is not None

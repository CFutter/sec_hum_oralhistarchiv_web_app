"""Integration tests: the scheduler ACTUALLY runs its coroutine jobs, plus
the unverified-account reaper against a real PostgreSQL.

create_scheduler must build an AsyncIOScheduler. A BackgroundScheduler
would "run" the async jobs by calling the coroutine
function in a thread, producing an un-awaited coroutine object that is
silently discarded — the executed-event log line would still fire, so only
an OBSERVABLE side effect (the expired-session DELETE landing in the real
database) proves the coroutine was awaited.

Reaper (app.services.users.reap_unverified_accounts): deletes only LOCAL,
UNVERIFIED accounts older than the cutoff; audit-logs each deletion with a
HASHED email (never the raw address).
"""

import asyncio
import logging
from unittest.mock import MagicMock, create_autospec, patch

import psycopg
from psycopg_pool import AsyncConnectionPool

from app.services import scheduler as scheduler_module
from app.services.crypto import audit_email_hash
from app.services.scheduler import RunningJobTracker, create_scheduler
from app.services.session_ids import hash_session_id
from app.services.users import reap_unverified_accounts
from tests.integration.conftest import TEST_DATABASE_URL

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _session_exists(raw_session_id: str) -> bool:
    """True if the sessions row for this RAW id is still in the database."""
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        row = conn.execute(
            "SELECT 1 FROM sessions WHERE id = %s",
            (hash_session_id(raw_session_id),),
        ).fetchone()
    return row is not None


def _age_user(user_id: int, days: int) -> None:
    """Backdate a user's created_at by `days` (the factory can't — the column
    defaults to now())."""
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        conn.execute(
            "UPDATE users SET created_at = CURRENT_TIMESTAMP - %s * INTERVAL '1 day' WHERE id = %s",
            (days, user_id),
        )
        conn.commit()


def _user_exists(user_id: int) -> bool:
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        row = conn.execute("SELECT 1 FROM users WHERE id = %s", (user_id,)).fetchone()
    return row is not None


def _scheduler_pool_mock() -> MagicMock:
    pool = MagicMock(spec=AsyncConnectionPool)
    pool.max_size = 2
    return pool


# ---------------------------------------------------------------------------
# The scheduler executes its coroutine jobs for real
# ---------------------------------------------------------------------------


async def _wait_until_session_gone(raw_session_id: str, timeout: float = 5.0) -> None:
    """Bounded poll of the real database row instead of a fixed sleep budget."""

    async def _poll() -> None:
        while _session_exists(raw_session_id):
            await asyncio.sleep(0.05)

    await asyncio.wait_for(_poll(), timeout)


async def test_scheduler_executes_session_cleanup_against_real_db(
    db_pool, user_factory, session_factory
):
    """A started scheduler's session_cleanup job (next_run_time=now)
    DELETEs the expired session row from the real database while leaving the
    live one intact.

    Guards the AsyncIOScheduler-vs-BackgroundScheduler silent-noop: with a
    BackgroundScheduler the coroutine would be created but never awaited, the
    EXECUTED event would still log, and the expired row would survive —
    which is exactly what this test polls for.
    """
    user = user_factory()
    expired_raw = session_factory(user.id, expires_in_seconds=-60)
    live_raw = session_factory(user.id, expires_in_seconds=28800)
    assert _session_exists(expired_raw)

    # Patch the sync jobs BEFORE create_scheduler so add_job captures the
    # mocks — incremental_sync also has next_run_time=now and would otherwise
    # hit the network. autospec against the real coroutine functions so a
    # signature drift on either wrapper fails here, not silently.
    with (
        patch(
            "app.services.scheduler.sync_and_invalidate",
            new=create_autospec(scheduler_module.sync_and_invalidate),
        ),
        patch(
            "app.services.scheduler.rebuild_and_invalidate",
            new=create_autospec(scheduler_module.rebuild_and_invalidate),
        ),
    ):
        running_jobs = RunningJobTracker()
        sched = create_scheduler(db_pool, MagicMock(), running_jobs)
        sched.start()
        try:
            # Bounded poll for the observable DELETE, not a fixed iteration budget.
            await _wait_until_session_gone(expired_raw)
        finally:
            sched.shutdown(wait=False)
            await asyncio.wait_for(
                running_jobs.wait_until_empty(),
                timeout=5.0,
            )

    assert running_jobs.active_job_ids == ()
    assert not _session_exists(expired_raw), (
        "expired session row survived — the cleanup coroutine was never "
        "actually awaited by the scheduler"
    )
    assert _session_exists(live_raw), "live session must not be cleaned up"


# ---------------------------------------------------------------------------
# reap_unverified_accounts — direct service calls against the real DB
# ---------------------------------------------------------------------------


async def test_reap_deletes_old_local_unverified_account(db_pool, user_factory):
    """A local, unverified account older than the 7-day default cutoff is
    deleted and counted; the reaper returns 1."""
    stale = user_factory(email_verified=False)
    _age_user(stale.id, days=8)

    deleted = await reap_unverified_accounts(db_pool)

    assert deleted == 1
    assert not _user_exists(stale.id)


async def test_reap_keeps_old_verified_local_account(db_pool, user_factory):
    """A local account that DID verify is kept no matter how old it is —
    the reaper must never delete verified users."""
    verified = user_factory(email_verified=True)
    _age_user(verified.id, days=8)

    deleted = await reap_unverified_accounts(db_pool)

    assert deleted == 0
    assert _user_exists(verified.id)


async def test_reap_keeps_recent_unverified_local_account(db_pool, user_factory):
    """A local unverified account still inside the grace window (created_at
    newer than the cutoff) is kept — users get the full window to verify."""
    fresh = user_factory(email_verified=False)  # created_at = now()

    deleted = await reap_unverified_accounts(db_pool)

    assert deleted == 0
    assert _user_exists(fresh.id)


async def test_reap_never_touches_shibboleth_accounts(db_pool, user_factory):
    """The auth_method='local' guard: a Shibboleth user is exempt even when
    email_verified=false and old (production auto-verifies Shibboleth users
    at creation; we force the flag off via the factory to prove the guard is
    on auth_method, not just on the verified flag)."""
    shib = user_factory(auth_method="shibboleth", email_verified=False)
    _age_user(shib.id, days=30)

    deleted = await reap_unverified_accounts(db_pool)

    assert deleted == 0
    assert _user_exists(shib.id)


async def test_reap_audit_log_hashes_email(db_pool, user_factory, caplog):
    """Each reaped account emits a 'user_reaped_unverified' audit record whose
    email field is the keyed HMAC hash, NOT the raw address — the audit trail
    must not leak PII (SIEM operators see only the correlation token)."""
    stale = user_factory(email_verified=False)
    _age_user(stale.id, days=8)

    with caplog.at_level(logging.INFO, logger="audit"):
        deleted = await reap_unverified_accounts(db_pool)

    assert deleted == 1
    records = [r for r in caplog.records if r.getMessage() == "user_reaped_unverified"]
    assert len(records) == 1
    rec = records[0]
    assert rec.user_id == stale.id
    assert rec.reason == "verification_not_completed"
    # The email field is the truncated keyed hash, never the raw address.
    assert rec.email_hash == audit_email_hash(stale.email)[:16]
    assert rec.email_hash != stale.email
    assert stale.email not in rec.email_hash


async def test_reap_max_age_days_override(db_pool, user_factory):
    """An explicit max_age_days=1 overrides the settings default: a 2-day-old
    unverified account (inside the default 7-day window) is reaped."""
    stale = user_factory(email_verified=False)
    _age_user(stale.id, days=2)

    # Sanity: the default window would keep it.
    assert await reap_unverified_accounts(db_pool) == 0
    assert _user_exists(stale.id)

    deleted = await reap_unverified_accounts(db_pool, max_age_days=1)

    assert deleted == 1
    assert not _user_exists(stale.id)

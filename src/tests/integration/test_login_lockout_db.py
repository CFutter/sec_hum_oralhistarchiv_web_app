"""Integration tests: the service-level lockout contract against the real
database.

Covers `verify_password`'s PasswordCheck contract (user, password_ok,
locked_until, failure_reason, auth_revision), the verify_dummy timing
equalization on every non-success path, the dummy-only verify on locked
accounts, the transparent rehash upgrade, and `record_login_failure`'s
threshold/transition behaviour. The same contract observed through HTTP is
covered in `test_login_lockout_routes_db.py`.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import psycopg
import pytest
from argon2 import PasswordHasher
from starlette.concurrency import run_in_threadpool as real_run_in_threadpool

from app.routes.auth.login import _record_failure_and_queue_notice
from app.services import authentication, password_reset, users
from app.services.authentication import record_login_failure, verify_password
from app.services.db import get_db_cursor
from app.services.tokens import hash_token
from config import settings
from tests.integration.conftest import DEFAULT_PASSWORD


def _user_lock_state(sync_conn, user_id):
    """(failed_login_count, locked_until) straight from the users table."""
    row = sync_conn.execute(
        "SELECT failed_login_count, locked_until FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()
    return row[0], row[1]


def _set_locked_until(sync_conn, user_id, dt):
    sync_conn.execute("UPDATE users SET locked_until = %s WHERE id = %s", (dt, user_id))
    sync_conn.commit()


class TestPasswordCheckOutcomes:
    """The PasswordCheck 3(+2)-tuple contract returned by verify_password."""

    async def test_correct_password_on_active_account_succeeds(self, db_pool, user_factory):
        """Correct password on a local, active account ->
        (user, True, None, None, auth_revision). Guards the consolidated
        single-query lookup returning the full PasswordCheck."""
        u = user_factory()
        check = await verify_password(db_pool, u.email, DEFAULT_PASSWORD)

        assert check.user is not None
        assert check.user.id == u.id
        assert check.password_ok is True
        assert check.locked_until is None
        assert check.failure_reason is None
        assert check.auth_revision is not None

    async def test_wrong_password_returns_user_for_failure_recording(self, db_pool, user_factory):
        """Wrong password -> (user, False, None, "wrong_password") with user
        NON-None. The PasswordCheck design point: the route needs the user id
        to record the failure. Also pins that argon2's VerifyMismatchError was
        CAUGHT inside verify_password (argon2 raises, it never returns
        False) — a leak here would 500 the login route."""
        u = user_factory()
        check = await verify_password(db_pool, u.email, "definitely-not-the-password")

        assert check.user is not None
        assert check.user.id == u.id
        assert check.password_ok is False
        assert check.locked_until is None
        assert check.failure_reason == "wrong_password"
        assert check.auth_revision == 0

    async def test_expired_lock_auto_clears_and_correct_password_succeeds(
        self, db_pool, user_factory, sync_conn
    ):
        """locked_until in the PAST is treated as unlocked — correct password
        -> password_ok True, locked_until None (lock auto-expires, no manual
        reset required)."""
        u = user_factory()
        _set_locked_until(sync_conn, u.id, datetime.now(UTC) - timedelta(minutes=1))
        check = await verify_password(db_pool, u.email, DEFAULT_PASSWORD)

        assert check.user is not None
        assert check.password_ok is True
        assert check.locked_until is None
        assert check.failure_reason is None
        assert check.auth_revision is not None

    async def test_correct_password_does_not_invoke_dummy_verify(self, db_pool, user_factory):
        """Positive control for the dummy-verify timing guard below: a
        successful credential check has no need of the dummy path at all."""
        u = user_factory()
        real = authentication.verify_dummy
        with patch(
            "app.services.authentication.verify_dummy",
            autospec=True,
            side_effect=real,
        ) as dummy_spy:
            check = await verify_password(db_pool, u.email, DEFAULT_PASSWORD)

        assert check.password_ok is True
        dummy_spy.assert_not_awaited()

    @pytest.mark.parametrize(
        "factory_kwargs,password,expect_user,failure_reason,auth_revision",
        [
            pytest.param(
                None, "any-password", False, "unknown_email", None, id="unknown_email_has_no_user"
            ),
            pytest.param(
                {"auth_method": "shibboleth"},
                "any-password",
                True,
                "non_local_account",
                None,
                id="shibboleth_account_rejected",
            ),
            pytest.param(
                {"is_active": False},
                DEFAULT_PASSWORD,
                True,
                "inactive_account",
                None,
                id="inactive_account_rejected",
            ),
            pytest.param(
                {"password_hash": "not-a-valid-argon2-hash-at-all"},
                "any-password",
                True,
                "unverifiable_hash",
                0,
                id="corrupt_hash_rejected",
            ),
        ],
    )
    async def test_rejected_password_check_runs_dummy_verify_for_timing_parity(
        self,
        db_pool,
        user_factory,
        factory_kwargs,
        password,
        expect_user,
        failure_reason,
        auth_revision,
    ):
        """Every non-success branch of verify_password (unknown email,
        Shibboleth account, inactive account, an unparseable hash) still runs
        verify_dummy — the user-enumeration timing guard, asserted by CALL
        (spy on verify_dummy) rather than wall-clock. Losing the dummy verify
        on any of these branches would reopen the enumeration oracle, and for
        the corrupt-hash branch a shifted argon2 exception hierarchy that let
        it escape would also 500 the login route."""
        u = user_factory(**factory_kwargs) if factory_kwargs is not None else None
        real = authentication.verify_dummy
        with patch(
            "app.services.authentication.verify_dummy",
            autospec=True,
            side_effect=real,
        ) as dummy_spy:
            check = await verify_password(
                db_pool,
                u.email if u is not None else "no-such-user@nowhere.example",
                password,
            )

        if expect_user:
            assert check.user is not None
            assert check.user.id == u.id
        else:
            assert check.user is None
        assert check.password_ok is False
        assert check.locked_until is None
        assert check.failure_reason == failure_reason
        assert check.auth_revision == auth_revision
        dummy_spy.assert_awaited_once_with(password)


class TestLockedAccountPasswordCheck:
    async def test_locked_account_rejects_correct_password_using_dummy_hash_only(
        self, db_pool, user_factory, sync_conn
    ):
        """A currently locked account rejects EVEN the correct password,
        returns locked_until non-None, and the REAL hash is never
        Argon2-verified — every _ph.verify call on the locked path uses
        _DUMMY_HASH only. Guards the lockout-check ordering inside the
        consolidated function (locked must short-circuit before the real
        verify)."""
        u = user_factory()
        lock_expiry = datetime.now(UTC) + timedelta(minutes=15)
        _set_locked_until(sync_conn, u.id, lock_expiry)

        calls = []

        async def recording(func, *args, **kwargs):
            calls.append((func, args))
            return await real_run_in_threadpool(func, *args, **kwargs)

        with patch(
            "app.services.authentication.run_password_work", autospec=True, side_effect=recording
        ):
            check = await verify_password(db_pool, u.email, DEFAULT_PASSWORD)

        assert check.user is not None
        assert check.user.id == u.id
        assert check.password_ok is False
        assert check.locked_until is not None
        assert check.locked_until == lock_expiry
        assert check.auth_revision is None
        assert check.failure_reason == "account_locked"

        # NB: bound-method equality (==), not identity — password_hasher.verify
        # is a fresh bound-method object on every attribute access.
        verify_calls = [
            args for func, args in calls if func == authentication.password_hasher.verify
        ]
        assert verify_calls, "dummy verify must run on the locked path (timing parity)"
        for args in verify_calls:
            assert args[0] == authentication._DUMMY_HASH, (
                "real password hash was Argon2-verified on the locked path"
            )


class TestLockoutThreshold:
    async def test_lockout_engages_exactly_at_threshold_and_does_not_refire(
        self, db_pool, user_factory, sync_conn
    ):
        """The NEGATIVE side of the threshold. Existing tests prove locking
        AT 3 failures; nothing proves NOT locked at 2. A `>=` -> `>` drift in
        record_login_failure's CASE weakens lockout by one attempt with no
        test turning red. The tail also pins that just_locked fires EXACTLY
        once — a `==` -> `>=` drift re-fires the account_locked audit event
        and the locked-notice email on every further attempt."""
        u = user_factory()
        threshold = settings.login_failure_threshold  # 3 in the test env

        for i in range(threshold - 1):
            count, just_locked = await record_login_failure(db_pool, u.id, expected_auth_revision=0)
            assert count == i + 1
            assert just_locked is False, f"locked early at attempt {i + 1}"
            _, locked_until = _user_lock_state(sync_conn, u.id)
            assert locked_until is None, f"locked_until set at attempt {i + 1}"

        # POSITIVE CONTROL: the very next failure DOES lock, exactly once.
        count, just_locked = await record_login_failure(db_pool, u.id, expected_auth_revision=0)
        assert count == threshold
        assert just_locked is True
        _, locked_until = _user_lock_state(sync_conn, u.id)
        assert locked_until is not None

        # just_locked must NOT re-fire on subsequent failures.
        count, again = await record_login_failure(db_pool, u.id, expected_auth_revision=0)
        assert count == threshold
        assert again is False, (
            "just_locked fired twice — account_locked audit and the locked-notice "
            "email now fire on every further attempt"
        )

    async def test_a_failure_arriving_while_the_account_is_locked_changes_nothing(
        self, db_pool, user_factory, sync_conn
    ):
        """Attempts that land while the lock is live must leave both the
        counter and the expiry exactly where the locking failure left them.
        Incrementing would silently deepen the streak, and rewriting the
        expiry would let an attacker keep the owner locked out indefinitely
        by guessing once per window."""
        threshold = settings.login_failure_threshold
        user = user_factory(failed_login_count=threshold - 1)

        count, just_locked = await record_login_failure(db_pool, user.id, expected_auth_revision=0)
        assert (count, just_locked) == (threshold, True)
        locked_state = _user_lock_state(sync_conn, user.id)
        assert locked_state[1] is not None

        for _ in range(3):
            count, just_locked = await record_login_failure(
                db_pool, user.id, expected_auth_revision=0
            )
            assert count == threshold
            assert just_locked is False

        assert _user_lock_state(sync_conn, user.id) == locked_state

    async def test_the_next_failure_after_the_lock_expires_starts_a_fresh_budget(
        self, db_pool, user_factory, sync_conn
    ):
        """Once the lock has run out, the streak starts over: the first
        failure counts as one and leaves the account usable, and only a full
        new streak locks it again."""
        threshold = settings.login_failure_threshold
        user = user_factory(
            failed_login_count=threshold + 2,
            locked_until=datetime.now(UTC) - timedelta(minutes=1),
        )

        count, just_locked = await record_login_failure(db_pool, user.id, expected_auth_revision=0)

        assert count == 1
        assert just_locked is False
        failed_count, locked_until = _user_lock_state(sync_conn, user.id)
        assert failed_count == 1
        assert locked_until is None

        for attempt in range(2, threshold):
            count, just_locked = await record_login_failure(
                db_pool, user.id, expected_auth_revision=0
            )
            assert count == attempt
            assert just_locked is False

        count, just_locked = await record_login_failure(db_pool, user.id, expected_auth_revision=0)
        assert count == threshold
        assert just_locked is True
        _, locked_until = _user_lock_state(sync_conn, user.id)
        assert locked_until is not None and locked_until > datetime.now(UTC)


class TestPasswordHashInvariants:
    async def test_local_account_password_hash_cannot_be_null(self, db_pool, user_factory):
        """The verify_password NULL-hash branch is UNREACHABLE for local
        accounts because a DB CHECK constraint (users_local_password_required)
        forbids that state. Pin the constraint itself — it is what keeps a
        local login from ever reaching a NULL-hash ambiguity. A migration
        that drops it would make this test the tripwire."""
        u = user_factory()

        with pytest.raises(psycopg.errors.CheckViolation, match="local_password_required"):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute("UPDATE users SET password_hash = NULL WHERE id = %s", (u.id,))

    async def test_weak_hash_is_transparently_upgraded_on_successful_verify(
        self, db_pool, user_factory, sync_conn
    ):
        """A hash made with weaker argon2 params succeeds AND is
        transparently upgraded in the DB (check_needs_rehash path), and the
        new stored hash still verifies the same password."""
        password = "Rehash-me-p4ssword!"
        weak_ph = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
        weak_hash = weak_ph.hash(password)
        # Precondition of the scenario: the app's hasher wants this rehashed.
        assert authentication.password_hasher.check_needs_rehash(weak_hash) is True

        u = user_factory(password_hash=weak_hash)
        check = await verify_password(db_pool, u.email, password)

        assert check.user is not None
        assert check.password_ok is True
        assert check.locked_until is None
        assert check.failure_reason is None
        assert check.auth_revision is not None

        row = sync_conn.execute("SELECT password_hash FROM users WHERE id = %s", (u.id,)).fetchone()
        new_hash = row[0]
        assert new_hash != weak_hash, "stored hash was not upgraded"
        assert authentication.password_hasher.check_needs_rehash(new_hash) is False
        # The upgraded hash still verifies the original password (raises if not).
        authentication.password_hasher.verify(new_hash, password)


class TestStaleFailureAfterRecovery:
    """`_record_failure_and_queue_notice`'s auth_revision compare-and-swap
    against a failure check that was already stale by the time it landed:
    the account was recovered (password reset or admin unlock, both of
    which bump auth_revision) between the failed verify_password call and
    the failure being recorded, so the recorded failure must be discarded
    instead of re-locking (or, for an already-unusable hash, re-failing) an
    account that is no longer in the state the check observed.
    """

    @pytest.mark.parametrize(
        "recovery",
        ["password_reset", "admin_unlock"],
        ids=["recovered_by_password_reset", "recovered_by_admin_unlock"],
    )
    @pytest.mark.parametrize(
        "broken_hash",
        [False, True],
        ids=["wrong_password", "unverifiable_hash"],
    )
    async def test_obsolete_password_failures_cannot_relock_recovered_accounts(
        self, db_pool, sync_conn, user_factory, admin_actor, monkeypatch, recovery, broken_hash
    ):
        """A failure captured against auth_revision 0 is recorded AFTER the
        account was already recovered (revision bumped to 1): the CAS in
        record_login_failure_cur must see the mismatch and discard the
        failure entirely — failed_login_count and locked_until stay at
        their recovered values, auth_revision is left at 1 (not
        incremented again), and no lockout notice is queued for a
        credential state the account no longer has."""
        token_hash = hash_token("reset-token")
        columns = {
            "password_reset_token_hash": token_hash,
            "password_reset_created_at": datetime.now(UTC),
        }
        if broken_hash:
            columns["password_hash"] = "unusable-hash"
        user = user_factory(**columns)
        monkeypatch.setattr(settings, "login_failure_threshold", 1)
        check = await authentication.verify_password(db_pool, user.email, "wrong-password")
        assert check.password_ok is False
        assert check.auth_revision == 0
        assert check.failure_reason == ("unverifiable_hash" if broken_hash else "wrong_password")
        if recovery == "password_reset":
            await password_reset.update_password_with_token(
                db_pool,
                user.id,
                token_hash,
                "Fresh-Password-Without-Common-Words-824!",
                expected_email=user.email,
            )
        else:
            await users.set_user_active(
                db_pool,
                user.id,
                True,
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
            )
        result = await _record_failure_and_queue_notice(
            db_pool, check.user, check.failure_reason, expected_auth_revision=check.auth_revision
        )
        assert result == (None, False)
        assert sync_conn.execute(
            "SELECT auth_revision, failed_login_count, locked_until FROM users WHERE id = %s",
            (user.id,),
        ).fetchone() == (1, 0, None)
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM email_outbox WHERE user_id = %s", (user.id,)
            ).fetchone()[0]
            == 0
        )

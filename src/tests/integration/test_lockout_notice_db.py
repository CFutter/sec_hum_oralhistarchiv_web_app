"""Integration tests for the durable lockout-notice claim against PostgreSQL.

`queue_lockout_notice_cur` claims the one lockout notice allowed per failure
streak with a compare-and-set UPDATE that shares its transaction with
`record_login_failure_cur`. This module proves, against the real database:

- exactly one pending outbox row and a non-NULL marker on the first
  unlocked-to-locked transition;
- an expired lock ends the streak, so the next failure releases the marker
  and the following lockout sends one notice of its own; a successful login
  releases it the same way;
- two genuinely concurrent transition attempts (independent connections)
  produce at most one notice and one marker, and two concurrent failures
  after an expiry share one fresh budget instead of each restarting it;
- every recovery writer (password reset, administrator reactivation,
  federated approval, TOTP-recovery redemption) clears the failure counter,
  the lock, and the marker together, while a redemption that fails before
  its commit leaves all three untouched;
- an outbox failure inside the claim's transaction rolls back the counter,
  the lock, and the marker together, and the account can still be locked on
  a later, unbroken attempt.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

import pytest

from app.routes.auth.login import _record_failure_and_queue_notice
from app.services import authentication, federated_session_policy, totp_recover, users
from app.services.password_reset import (
    generate_reset_token,
    store_reset_token_hash,
    update_password_with_token,
)
from app.services.tokens import hash_token
from app.services.totp_recovery_codes import normalize_recovery_code
from config import settings
from tests.integration.conftest import DEFAULT_PASSWORD, do_login

_ISSUER = "https://idp.test.example/idp/shibboleth"
_SUBJECT = "urn:test:subject:lockout-notice"
_RECOVERY_CODE = "AAAAA-BBBBB-CCCCC-DDDDD"


def _lock_state(sync_conn, user_id):
    """(failed_login_count, locked_until, lockout_notice_enqueued_at)."""
    row = sync_conn.execute(
        """SELECT failed_login_count, locked_until, lockout_notice_enqueued_at
           FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()
    return row[0], row[1], row[2]


def _notice_outbox_rows(sync_conn, user_id):
    return sync_conn.execute(
        """SELECT status FROM email_outbox
           WHERE user_id = %s AND message_type = 'account_locked_notice'
           ORDER BY id""",
        (user_id,),
    ).fetchall()


def _install_active_recovery_codes(sync_conn, user_id: int) -> None:
    """Give a user an active generation with one known, unused recovery code."""
    sync_conn.execute(
        "UPDATE users SET totp_recovery_code_generation = 1 WHERE id = %s",
        (user_id,),
    )
    canonical = normalize_recovery_code(_RECOVERY_CODE)
    assert canonical is not None
    sync_conn.execute(
        """INSERT INTO totp_recovery_codes (user_id, generation, position, code_hash)
           VALUES (%s, 1, 1, %s)""",
        (user_id, hash_token(canonical)),
    )
    sync_conn.commit()


def _authorize_recovery(sync_conn, user_id: int) -> None:
    """Install a live, revision-bound recovery authorization for one user."""
    sync_conn.execute(
        """UPDATE users
           SET totp_secret = NULL,
               last_totp_step = NULL,
               totp_recovery_required = true,
               totp_recovery_authorized_at = clock_timestamp(),
               totp_recovery_expires_at = clock_timestamp() + INTERVAL '30 minutes',
               totp_recovery_auth_revision = auth_revision
           WHERE id = %s""",
        (user_id,),
    )
    sync_conn.commit()


async def _fail_once(db_pool, user):
    """One wrong-password attempt recorded and notice-checked in one transaction."""
    check = await authentication.verify_password(db_pool, user.email, "wrong-password")
    assert check.user is not None
    return await _record_failure_and_queue_notice(
        db_pool, check.user, check.failure_reason, expected_auth_revision=check.auth_revision
    )


class TestLockoutNoticeSingleClaim:
    def test_first_transition_creates_exactly_one_pending_notice_and_a_marker(
        self, e2e_client, user_factory, sync_conn
    ):
        """The threshold-crossing failure creates exactly one pending
        account_locked_notice row and sets a non-NULL marker."""
        threshold = settings.login_failure_threshold
        user = user_factory()
        for _ in range(threshold):
            do_login(e2e_client, user.email, "wrong-password")

        assert _notice_outbox_rows(sync_conn, user.id) == [("pending",)]
        _, _, marker = _lock_state(sync_conn, user.id)
        assert marker is not None


class TestLockoutNoticeSuppressionAndReset:
    """A streak's marker is claimed once; a recovered account starts fresh."""

    async def test_an_expired_lock_releases_the_marker_and_the_next_lockout_notifies_once(
        self, db_pool, user_factory, sync_conn
    ):
        """The marker allows one notice per failure streak. When a lock
        expires the streak is over, so the first failure afterwards has to
        release the marker — otherwise the account could be locked again
        without its owner ever being told. The freed marker must then be
        claimed exactly once, by the failure that crosses the new threshold.
        """
        threshold = settings.login_failure_threshold
        user = user_factory()

        for _ in range(threshold):
            await _fail_once(db_pool, user)
        _, _, first_marker = _lock_state(sync_conn, user.id)
        assert first_marker is not None
        assert _notice_outbox_rows(sync_conn, user.id) == [("pending",)]

        sync_conn.execute(
            "UPDATE users SET locked_until = %s WHERE id = %s",
            (datetime.now(UTC) - timedelta(minutes=1), user.id),
        )
        sync_conn.commit()

        count, entered_lockout = await _fail_once(db_pool, user)
        assert (count, entered_lockout) == (1, False)
        failed_count, locked_until, marker = _lock_state(sync_conn, user.id)
        assert (failed_count, locked_until, marker) == (1, None, None)
        assert _notice_outbox_rows(sync_conn, user.id) == [("pending",)]

        for _ in range(threshold - 1):
            await _fail_once(db_pool, user)

        _, locked_until, second_marker = _lock_state(sync_conn, user.id)
        assert locked_until is not None and locked_until > datetime.now(UTC)
        assert second_marker is not None
        assert _notice_outbox_rows(sync_conn, user.id) == [("pending",), ("pending",)], (
            "the second streak must produce exactly one further notice"
        )

    async def test_concurrent_failures_after_expiry_share_one_fresh_budget(
        self, db_pool, user_factory, sync_conn
    ):
        """Two failures that arrive together once a lock has expired both see
        the expired lock before either has written. The row lock has to
        serialize them so the second continues the new streak instead of
        resetting it to one again — a budget that can be reset concurrently
        never reaches the threshold."""
        threshold = settings.login_failure_threshold
        user = user_factory(
            failed_login_count=threshold + 2,
            locked_until=datetime.now(UTC) - timedelta(minutes=1),
            lockout_notice_enqueued_at=datetime.now(UTC),
        )

        results = await asyncio.gather(_fail_once(db_pool, user), _fail_once(db_pool, user))

        assert sorted(count for count, _ in results) == [1, 2]
        assert [entered for _, entered in results] == [False, False]
        failed_count, locked_until, marker = _lock_state(sync_conn, user.id)
        assert failed_count == 2, "the two failures must share one budget, not restart it twice"
        assert locked_until is None
        assert marker is None, "the expired streak's marker must be released"

    def test_successful_login_clears_marker_and_a_fresh_lockout_creates_one_new_notice(
        self, e2e_client, user_factory, sync_conn
    ):
        """Positive control for the suppression above: a successful login
        clears the counter, the lock, and the marker, so the NEXT lockout on
        this account queues its own fresh notice."""
        threshold = settings.login_failure_threshold
        user = user_factory()
        for _ in range(threshold):
            do_login(e2e_client, user.email, "wrong-password")

        sync_conn.execute(
            "UPDATE users SET locked_until = %s WHERE id = %s",
            (datetime.now(UTC) - timedelta(minutes=1), user.id),
        )
        sync_conn.commit()

        resp = do_login(e2e_client, user.email, DEFAULT_PASSWORD)
        assert resp.status_code == 303

        failed_count, locked_until, marker = _lock_state(sync_conn, user.id)
        assert (failed_count, locked_until, marker) == (0, None, None)

        for _ in range(threshold):
            do_login(e2e_client, user.email, "wrong-password")

        assert _notice_outbox_rows(sync_conn, user.id) == [("pending",)]


class TestConcurrentLockoutTransitions:
    """Two genuinely concurrent failures on independent pooled connections."""

    async def test_two_concurrent_transition_attempts_produce_at_most_one_notice_and_marker(
        self, db_pool, user_factory, sync_conn
    ):
        """Each attempt runs its SELECT ... FOR UPDATE, its counter UPDATE,
        and its notice claim through its own connection checked out from the
        pool. Row locking must serialize them so exactly one reports the
        transition, and only one notice/marker ever exists for the streak."""
        threshold = settings.login_failure_threshold
        user = user_factory(failed_login_count=threshold - 1)

        results = await asyncio.gather(_fail_once(db_pool, user), _fail_once(db_pool, user))

        transitions = [entered for _, entered in results]
        assert transitions.count(True) == 1, (
            "row locking must let exactly one concurrent attempt win the transition"
        )
        assert _notice_outbox_rows(sync_conn, user.id) == [("pending",)]
        _, _, marker = _lock_state(sync_conn, user.id)
        assert marker is not None


@pytest.fixture
def _federation_enabled(monkeypatch, db_pool):
    monkeypatch.setattr(users.settings, "shibboleth_enabled", True)
    monkeypatch.setattr(users.settings, "shibboleth_trusted_issuers", [_ISSUER])

    async def _reconcile():
        await federated_session_policy.reconcile_federated_session_policy(db_pool)

    return _reconcile


class TestLockoutStateClearedByRecoveryPaths:
    """Every recovery writer clears the counter, the lock, and the marker
    together — proven here against the real database, not a mocked cursor."""

    async def test_password_reset_completion_clears_counter_lock_and_marker_together(
        self, db_pool, user_factory, sync_conn
    ):
        user = user_factory(
            failed_login_count=3,
            locked_until=datetime.now(UTC) + timedelta(minutes=15),
            lockout_notice_enqueued_at=datetime.now(UTC),
        )
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)

        await update_password_with_token(
            db_pool,
            user.id,
            hash_token(token),
            "Fresh-Password-Without-Common-Words-824!",
            expected_email=user.email,
        )

        assert _lock_state(sync_conn, user.id) == (0, None, None)

    async def test_admin_reactivation_clears_counter_lock_and_marker_together(
        self, db_pool, user_factory, admin_actor, sync_conn
    ):
        user = user_factory(
            is_active=False,
            failed_login_count=3,
            locked_until=datetime.now(UTC) + timedelta(minutes=15),
            lockout_notice_enqueued_at=datetime.now(UTC),
        )

        result = await users.set_user_active(
            db_pool, user.id, True, actor_id=admin_actor.id, actor_session_id=admin_actor.session_id
        )

        assert result.lock_cleared is True
        assert _lock_state(sync_conn, user.id) == (0, None, None)

    async def test_federated_approval_clears_counter_lock_and_marker_together(
        self, db_pool, user_factory, admin_actor, sync_conn, _federation_enabled
    ):
        await _federation_enabled()
        user = user_factory(
            auth_method="shibboleth",
            is_active=False,
            federated_status="pending",
            shibboleth_issuer=_ISSUER,
            shibboleth_subject_id=_SUBJECT,
            access_tier="public",
            failed_login_count=3,
            locked_until=datetime.now(UTC) + timedelta(minutes=15),
            lockout_notice_enqueued_at=datetime.now(UTC),
        )

        await users.approve_federated_user(
            db_pool,
            user.id,
            expected_issuer=_ISSUER,
            expected_subject_id=_SUBJECT,
            access_tier="vetted",
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

        assert _lock_state(sync_conn, user.id) == (0, None, None)

    async def test_totp_recovery_redemption_clears_counter_lock_and_marker_together(
        self, db_pool, user_factory, sync_conn
    ):
        user = user_factory(
            failed_login_count=3,
            locked_until=datetime.now(UTC) + timedelta(minutes=15),
            lockout_notice_enqueued_at=datetime.now(UTC),
        )
        _install_active_recovery_codes(sync_conn, user.id)
        _authorize_recovery(sync_conn, user.id)

        result = await totp_recover.redeem_totp_recovery(
            db_pool,
            email=user.email,
            password=user.password,
            recovery_code=_RECOVERY_CODE,
            ip_address="192.0.2.10",
        )

        assert result.user_id == user.id
        assert _lock_state(sync_conn, user.id) == (0, None, None)

    async def test_totp_recovery_failure_before_commit_leaves_the_marker_untouched(
        self, db_pool, user_factory, sync_conn
    ):
        """Negative control: a redemption rejected on the password check —
        before the clearing UPDATE ever runs — must leave the counter, the
        lock, and the marker exactly as they were."""
        user = user_factory(
            failed_login_count=3,
            locked_until=datetime.now(UTC) + timedelta(minutes=15),
            lockout_notice_enqueued_at=datetime.now(UTC),
        )
        _install_active_recovery_codes(sync_conn, user.id)
        _authorize_recovery(sync_conn, user.id)
        before = _lock_state(sync_conn, user.id)

        with pytest.raises(totp_recover.TotpRecoveryRedemptionRejected):
            await totp_recover.redeem_totp_recovery(
                db_pool,
                email=user.email,
                password="entirely-the-wrong-password",
                recovery_code=_RECOVERY_CODE,
                ip_address="192.0.2.11",
            )

        assert _lock_state(sync_conn, user.id) == before


class TestOutboxFailureRollsBackTheLockoutTransition:
    """The notice claim shares its transaction with the counter/lock write."""

    async def test_outbox_failure_leaves_no_partial_lockout_state(
        self, db_pool, user_factory, sync_conn
    ):
        """An outbox insert failure inside the claim's transaction rolls
        back the counter increment and the lock alongside the marker — no
        partial state survives a failed notice."""
        threshold = settings.login_failure_threshold
        user = user_factory(failed_login_count=threshold - 1)
        check = await authentication.verify_password(db_pool, user.email, "wrong-password")
        broken_enqueue = create_autospec(
            authentication.enqueue_outbound_email_cur,
            spec_set=True,
            side_effect=RuntimeError("outbox unavailable"),
        )

        with (
            patch.object(authentication, "enqueue_outbound_email_cur", broken_enqueue),
            pytest.raises(RuntimeError, match="outbox unavailable"),
        ):
            await _record_failure_and_queue_notice(
                db_pool,
                check.user,
                check.failure_reason,
                expected_auth_revision=check.auth_revision,
            )

        assert _lock_state(sync_conn, user.id) == (threshold - 1, None, None)
        outbox_count = sync_conn.execute(
            "SELECT count(*) FROM email_outbox WHERE user_id = %s", (user.id,)
        ).fetchone()[0]
        assert outbox_count == 0

    async def test_account_can_still_be_locked_on_the_next_attempt(
        self, db_pool, user_factory, sync_conn
    ):
        """Positive control: after the rolled-back failure above, the
        account is not stuck — the very next (unbroken) failure still locks
        it and queues its notice."""
        threshold = settings.login_failure_threshold
        user = user_factory(failed_login_count=threshold - 1)
        broken_check = await authentication.verify_password(db_pool, user.email, "wrong-password")
        broken_enqueue = create_autospec(
            authentication.enqueue_outbound_email_cur,
            spec_set=True,
            side_effect=RuntimeError("outbox unavailable"),
        )
        with (
            patch.object(authentication, "enqueue_outbound_email_cur", broken_enqueue),
            pytest.raises(RuntimeError),
        ):
            await _record_failure_and_queue_notice(
                db_pool,
                broken_check.user,
                broken_check.failure_reason,
                expected_auth_revision=broken_check.auth_revision,
            )

        check = await authentication.verify_password(db_pool, user.email, "wrong-password")
        count, entered_lockout = await _record_failure_and_queue_notice(
            db_pool, check.user, check.failure_reason, expected_auth_revision=check.auth_revision
        )

        assert entered_lockout is True
        assert count == threshold
        failed_count, locked_until, marker = _lock_state(sync_conn, user.id)
        assert failed_count == threshold
        assert locked_until is not None
        assert marker is not None

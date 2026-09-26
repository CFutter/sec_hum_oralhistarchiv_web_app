"""Integration tests for revocation cascades against real PostgreSQL.

Sensitive account actions — confirming an email change, resetting a
password, an admin deactivating an account, or a bulk force-logout — must
invalidate every other in-flight pending capability (a different pending
email change, a pending password reset, a pending TOTP enrollment) and mark
any queued mail for those capabilities as dead, alongside killing sessions.
Session lifecycle itself (creation, lookup, flash, cleanup) lives in
test_sessions_db.py.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import create_autospec

import psycopg
import pyotp
import pytest

from app.services import email_change, password_reset, session_revocation, sessions, totp, users
from app.services.crypto import encrypt_outbox_body, encrypt_value
from app.services.session_ids import hash_session_id
from app.services.tokens import hash_token
from tests.integration.conftest import DEFAULT_PASSWORD

_TOTP_TIME = 1_800_000_000

NEW_EMAIL = "attacker-controlled@mail.ch"
NEW_PASSWORD = "A-different-strong-password-90210!"
ACTION_TYPES = (
    "password_reset",
    "email_verification",
    "email_change_verification",
)


def _revision(sync_conn, user_id: int) -> int:
    return sync_conn.execute(
        "SELECT auth_revision FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()[0]


def _pending_state(sync_conn, user_id: int):
    return sync_conn.execute(
        """SELECT pending_totp_secret, pending_totp_created_at,
                  pending_email, pending_email_token_hash,
                  pending_email_created_at,
                  password_reset_token_hash, password_reset_created_at,
                  email_verification_token_hash,
                  email_verification_created_at
           FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()


def _seed_all_pending_state(
    sync_conn,
    user_id: int,
    *,
    email_change_hash: str,
    reset_hash: str,
) -> None:
    verification_hash = "v" * 64
    sync_conn.execute(
        """UPDATE users
           SET pending_totp_secret = %s,
               pending_totp_created_at = clock_timestamp(),
               pending_email = %s,
               pending_email_token_hash = %s,
               pending_email_created_at = clock_timestamp(),
               password_reset_token_hash = %s,
               password_reset_created_at = clock_timestamp(),
               email_verification_token_hash = %s,
               email_verification_created_at = clock_timestamp()
           WHERE id = %s""",
        (
            encrypt_value(pyotp.random_base32()),
            NEW_EMAIL,
            email_change_hash,
            reset_hash,
            verification_hash,
            user_id,
        ),
    )

    hashes = {
        "password_reset": reset_hash,
        "email_verification": verification_hash,
        "email_change_verification": email_change_hash,
    }
    recipients = {
        "password_reset": "user@example.test",
        "email_verification": "user@example.test",
        "email_change_verification": NEW_EMAIL,
    }
    expires_at = datetime.now(UTC) + timedelta(hours=1)
    for message_type in ACTION_TYPES:
        sync_conn.execute(
            """INSERT INTO email_outbox (
                   user_id, message_type, recipient, subject, body_ciphertext,
                   action_token_hash, expires_at
               ) VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (
                user_id,
                message_type,
                recipients[message_type],
                "security action",
                encrypt_outbox_body("credential-bearing body"),
                hashes[message_type],
                expires_at,
            ),
        )
    sync_conn.commit()


def _assert_cleared(sync_conn, user_id: int) -> None:
    assert _pending_state(sync_conn, user_id) == (None,) * 9
    rows = sync_conn.execute(
        """SELECT message_type, status, last_error
           FROM email_outbox
           WHERE user_id = %s AND message_type = ANY(%s)
           ORDER BY message_type""",
        (user_id, list(ACTION_TYPES)),
    ).fetchall()
    assert rows == [
        ("email_change_verification", "dead", "superseded"),
        ("email_verification", "dead", "superseded"),
        ("password_reset", "dead", "superseded"),
    ]
    assert (
        sync_conn.execute(
            "SELECT count(*) FROM sessions WHERE user_id = %s",
            (user_id,),
        ).fetchone()[0]
        == 0
    )


class TestSensitiveActionsClearPendingCapabilities:
    """Each of these actions is a distinct trigger (confirming an email
    change, resetting a password, an admin deactivating the account, or a
    bulk force-logout) but all must converge on the same outcome: every
    other pending capability is cleared, its queued mail marked dead, and
    the user's sessions killed."""

    async def test_email_confirmation_clears_other_capabilities_and_mail(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
    ):
        user = user_factory(email="user@example.test")
        session_factory(user.id, purpose="full")
        revision = _revision(sync_conn, user.id)
        email_token = email_change.generate_email_change_token(
            user.id,
            NEW_EMAIL,
            auth_revision=revision,
        )
        _seed_all_pending_state(
            sync_conn,
            user.id,
            email_change_hash=hash_token(email_token),
            reset_hash="r" * 64,
        )

        assert await email_change.confirm_email_change(
            db_pool,
            user.id,
            NEW_EMAIL,
            hash_token(email_token),
            expected_auth_revision=revision,
        )

        assert _revision(sync_conn, user.id) == revision + 1
        assert (
            sync_conn.execute(
                "SELECT email FROM users WHERE id = %s",
                (user.id,),
            ).fetchone()[0]
            == NEW_EMAIL
        )
        _assert_cleared(sync_conn, user.id)

    async def test_password_reset_kills_older_email_change_and_pending_state(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
    ):
        user = user_factory(email="user@example.test")
        session_factory(user.id, purpose="full")
        revision = _revision(sync_conn, user.id)
        email_token = email_change.generate_email_change_token(
            user.id,
            NEW_EMAIL,
            auth_revision=revision,
        )
        reset_token = password_reset.generate_reset_token(user.id, user.email)
        _seed_all_pending_state(
            sync_conn,
            user.id,
            email_change_hash=hash_token(email_token),
            reset_hash=hash_token(reset_token),
        )

        await password_reset.update_password_with_token(
            db_pool,
            user.id,
            hash_token(reset_token),
            NEW_PASSWORD,
            expected_email=user.email,
        )

        assert _revision(sync_conn, user.id) == revision + 1
        _assert_cleared(sync_conn, user.id)
        assert not await email_change.confirm_email_change(
            db_pool,
            user.id,
            NEW_EMAIL,
            hash_token(email_token),
            expected_auth_revision=revision,
        )

    async def test_revoking_all_sessions_clears_capabilities_and_mail(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
    ):
        user = user_factory(email="user@example.test")
        session_factory(user.id, purpose="full")
        revision = _revision(sync_conn, user.id)
        token = email_change.generate_email_change_token(
            user.id,
            NEW_EMAIL,
            auth_revision=revision,
        )
        _seed_all_pending_state(
            sync_conn,
            user.id,
            email_change_hash=hash_token(token),
            reset_hash="r" * 64,
        )

        await session_revocation.delete_user_sessions(db_pool, user.id)

        assert _revision(sync_conn, user.id) == revision + 1
        _assert_cleared(sync_conn, user.id)

    async def test_deactivation_clears_capabilities_and_mail(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
    ):
        admin = user_factory(is_admin=True)
        admin_session = session_factory(admin.id, purpose="full")
        target = user_factory(email="user@example.test")
        session_factory(target.id, purpose="full")
        revision = _revision(sync_conn, target.id)
        token = email_change.generate_email_change_token(
            target.id,
            NEW_EMAIL,
            auth_revision=revision,
        )
        _seed_all_pending_state(
            sync_conn,
            target.id,
            email_change_hash=hash_token(token),
            reset_hash="r" * 64,
        )

        await users.set_user_active(
            db_pool,
            target.id,
            False,
            actor_id=admin.id,
            actor_session_id=admin_session,
        )

        assert _revision(sync_conn, target.id) == revision + 1
        _assert_cleared(sync_conn, target.id)


class TestEmailChangeConfirmationRejectsRevisionMismatch:
    """confirm_email_change must not apply a token minted against a stale
    auth_revision, even when the row's pending state was never cleaned up
    in between."""

    async def test_rejects_revision_mismatch_even_if_cleanup_is_bypassed(
        self,
        db_pool,
        user_factory,
        sync_conn,
    ):
        user = user_factory()
        revision = _revision(sync_conn, user.id)
        token = email_change.generate_email_change_token(
            user.id,
            NEW_EMAIL,
            auth_revision=revision,
        )
        await email_change.store_pending_email(
            db_pool,
            user.id,
            NEW_EMAIL,
            hash_token(token),
            expected_auth_revision=revision,
        )
        sync_conn.execute(
            "UPDATE users SET auth_revision = auth_revision + 1 WHERE id = %s",
            (user.id,),
        )
        sync_conn.commit()

        assert not await email_change.confirm_email_change(
            db_pool,
            user.id,
            NEW_EMAIL,
            hash_token(token),
            expected_auth_revision=revision,
        )
        assert (
            sync_conn.execute(
                "SELECT email FROM users WHERE id = %s",
                (user.id,),
            ).fetchone()[0]
            == user.email
        )


class TestSelfEmailChangeRequiresLiveExactSession:
    """stage_self_email_change only trusts the exact session it was called
    with, whether that session is a 'totp_setup' or a 'full' session; a
    different, still-live session for the same user does not authorize
    it."""

    @pytest.mark.parametrize(
        "purpose",
        ["totp_setup", "full"],
        ids=["totp_setup_session_must_be_live", "full_session_must_be_the_exact_one"],
    )
    async def test_requires_a_live_exact_full_session(
        self,
        purpose,
        db_pool,
        user_factory,
        session_factory,
    ):
        user = user_factory()
        raw_session = session_factory(user.id, purpose=purpose)
        if purpose == "full":
            # Make the exact session stale; another live session must not
            # authorize it.
            session_factory(user.id, purpose="full")
            async with db_pool.connection() as conn:
                await conn.execute(
                    "DELETE FROM sessions WHERE id = %s",
                    (hash_session_id(raw_session),),
                )

        with pytest.raises(email_change.SelfEmailChangeRejected) as exc_info:
            await email_change.stage_self_email_change(
                db_pool,
                user_id=user.id,
                session_id=raw_session,
                current_password=DEFAULT_PASSWORD,
                new_email=NEW_EMAIL,
            )
        assert exc_info.value.reason == "invalid_session"


class TestConcurrentSessionRevocationDuringEmailChangeStaging:
    """A concurrent bulk revoke cannot slip in between password proof and
    staging and leave a half-applied result; it must serialize after
    staging completes and then remove what staging produced."""

    async def test_revoke_all_serializes_after_staging_and_removes_its_result(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        user = user_factory(email="user@example.test")
        raw_session = session_factory(user.id, purpose="full")
        revision = _revision(sync_conn, user.id)
        entered_enqueue = asyncio.Event()
        release_enqueue = asyncio.Event()
        real_enqueue = email_change.enqueue_outbound_email_cur
        calls = 0

        async def pause_first_enqueue(cur, *, user_id, email, action):
            nonlocal calls
            calls += 1
            if calls == 1:
                entered_enqueue.set()
                await release_enqueue.wait()
            return await real_enqueue(
                cur,
                user_id=user_id,
                email=email,
                action=action,
            )

        monkeypatch.setattr(
            email_change,
            "enqueue_outbound_email_cur",
            create_autospec(
                email_change.enqueue_outbound_email_cur, side_effect=pause_first_enqueue
            ),
        )
        staging = asyncio.create_task(
            email_change.stage_self_email_change(
                db_pool,
                user_id=user.id,
                session_id=raw_session,
                current_password=DEFAULT_PASSWORD,
                new_email=NEW_EMAIL,
            )
        )
        await asyncio.wait_for(entered_enqueue.wait(), timeout=5)

        revocation = asyncio.create_task(session_revocation.delete_user_sessions(db_pool, user.id))
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.shield(revocation), timeout=0.25)

        release_enqueue.set()
        await asyncio.wait_for(staging, timeout=5)
        await asyncio.wait_for(revocation, timeout=5)

        assert _revision(sync_conn, user.id) == revision + 1
        assert _pending_state(sync_conn, user.id) == (None,) * 9
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM sessions WHERE user_id = %s",
                (user.id,),
            ).fetchone()[0]
            == 0
        )
        assert (
            sync_conn.execute(
                """SELECT count(*) FROM email_outbox
               WHERE user_id = %s
                 AND message_type = ANY(%s)
                 AND status IN ('pending', 'sending')""",
                (user.id, list(ACTION_TYPES)),
            ).fetchone()[0]
            == 0
        )


def _seed_rotation_challenge(sync_conn, user_id, raw_session, revision, replacement_secret):
    sync_conn.execute(
        """INSERT INTO pending_totp_rotations
               (user_id, session_id, auth_revision, encrypted_secret, expires_at)
           VALUES (%s, %s, %s, %s, clock_timestamp() + INTERVAL '5 minutes')""",
        (user_id, hash_session_id(raw_session), revision, encrypt_value(replacement_secret)),
    )
    sync_conn.commit()


def _counts(sync_conn, user_id):
    sessions_left = sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (user_id,)
    ).fetchone()[0]
    challenges_left = sync_conn.execute(
        "SELECT count(*) FROM pending_totp_rotations WHERE user_id = %s", (user_id,)
    ).fetchone()[0]
    return sessions_left, challenges_left


class TestConcurrentRevocationDuringPendingTotpRotation:
    """A bulk session revocation and a pending TOTP-rotation confirmation
    both take exclusive locks on the same session row and the same
    pending_totp_rotations row (the live form of the source-text lock-order
    proof in TestRevocationLockOrder). Run on independent connections, one
    must serialize behind the other -- never cycle back into a deadlock --
    and whichever side loses the race must observe a coherent already-changed
    state instead of raising or half-applying its result.
    """

    async def test_bulk_revocation_and_rotation_confirmation_never_deadlock(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        active_secret = pyotp.random_base32()
        replacement_secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(active_secret))
        raw_session = session_factory(user.id, purpose="full")
        revision = _revision(sync_conn, user.id)
        _seed_rotation_challenge(sync_conn, user.id, raw_session, revision, replacement_secret)
        monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME))
        code = pyotp.TOTP(replacement_secret).at(_TOTP_TIME)

        entered = asyncio.Event()
        release = asyncio.Event()
        real_delete = session_revocation.delete_user_sessions_cur

        async def paused_delete(cur, user_id):
            await real_delete(cur, user_id)
            entered.set()
            await release.wait()

        monkeypatch.setattr(
            session_revocation,
            "delete_user_sessions_cur",
            create_autospec(session_revocation.delete_user_sessions_cur, side_effect=paused_delete),
        )

        revoke_task = asyncio.create_task(session_revocation.delete_user_sessions(db_pool, user.id))
        await asyncio.wait_for(entered.wait(), timeout=5)

        confirm_task = asyncio.create_task(
            totp.confirm_totp_rotation(db_pool, user.id, code, session_id=raw_session)
        )
        # The revoking transaction is still open, holding the deleted-but-
        # uncommitted session row: the confirming SELECT ... FOR UPDATE on
        # that exact row must block behind it rather than proceed.
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.shield(confirm_task), timeout=0.25)

        release.set()
        try:
            await asyncio.wait_for(revoke_task, timeout=5)
            outcome = await asyncio.wait_for(confirm_task, timeout=5)
        except psycopg.errors.DeadlockDetected:
            pytest.fail("bulk revocation and rotation confirmation deadlocked")

        assert outcome in (
            totp.TotpRotationOutcome.SESSION_EXPIRED,
            totp.TotpRotationOutcome.PENDING_SECRET_MISSING,
        )
        assert _counts(sync_conn, user.id) == (0, 0)

    async def test_bulk_revocation_alone_completes(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        """Positive control: without a competing confirmation, the bulk
        revocation alone still clears the session and its bound challenge."""
        user = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        raw_session = session_factory(user.id, purpose="full")
        revision = _revision(sync_conn, user.id)
        _seed_rotation_challenge(sync_conn, user.id, raw_session, revision, pyotp.random_base32())

        await session_revocation.delete_user_sessions(db_pool, user.id)

        assert _counts(sync_conn, user.id) == (0, 0)

    async def test_rotation_confirmation_alone_completes(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """Positive control: without a competing revocation, confirming the
        pending rotation alone activates the replacement secret and, as part
        of that same transaction, still clears the session and the
        challenge."""
        replacement_secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        raw_session = session_factory(user.id, purpose="full")
        revision = _revision(sync_conn, user.id)
        _seed_rotation_challenge(sync_conn, user.id, raw_session, revision, replacement_secret)
        monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME))
        code = pyotp.TOTP(replacement_secret).at(_TOTP_TIME)

        outcome = await totp.confirm_totp_rotation(db_pool, user.id, code, session_id=raw_session)

        assert outcome == totp.TotpRotationOutcome.ROTATED
        assert _counts(sync_conn, user.id) == (0, 0)

    async def test_logout_and_rotation_confirmation_never_deadlock(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """The other paired trigger the brief calls out: logging out the
        exact session races the same confirmation. `delete_session` deletes
        a single session row directly (no lock-order helper to gate), so
        this races the two real coroutines on independent connections
        without forcing a specific interleaving; either winner still leaves
        a coherent, deadlock-free result."""
        active_secret = pyotp.random_base32()
        replacement_secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(active_secret))
        raw_session = session_factory(user.id, purpose="full")
        revision = _revision(sync_conn, user.id)
        _seed_rotation_challenge(sync_conn, user.id, raw_session, revision, replacement_secret)
        monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME))
        code = pyotp.TOTP(replacement_secret).at(_TOTP_TIME)

        try:
            _, outcome = await asyncio.wait_for(
                asyncio.gather(
                    sessions.delete_session(db_pool, raw_session),
                    totp.confirm_totp_rotation(db_pool, user.id, code, session_id=raw_session),
                ),
                timeout=5,
            )
        except psycopg.errors.DeadlockDetected:
            pytest.fail("logout and rotation confirmation deadlocked")

        assert outcome in (
            totp.TotpRotationOutcome.ROTATED,
            totp.TotpRotationOutcome.SESSION_EXPIRED,
        )
        assert _counts(sync_conn, user.id) == (0, 0)


def _challenge_exists(sync_conn, user_id) -> bool:
    return (
        sync_conn.execute(
            "SELECT 1 FROM pending_totp_rotations WHERE user_id = %s", (user_id,)
        ).fetchone()
        is not None
    )


class TestSessionLifecycleCascadesExactChallenge:
    """Each of the three ways a session's lifecycle ends -- logout, expiry
    cleanup, and a direct bulk revocation -- deletes the sessions row that
    pending_totp_rotations.session_id foreign-keys to, so the database's own
    ON DELETE CASCADE removes exactly the challenge bound to that session
    and never a different user's still-live challenge."""

    def _seed_two_users_with_challenges(self, sync_conn, user_factory, session_factory, **kwargs):
        target = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        target_session = session_factory(target.id, purpose="full", **kwargs)
        bystander = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        bystander_session = session_factory(bystander.id, purpose="full")
        _seed_rotation_challenge(
            sync_conn,
            target.id,
            target_session,
            _revision(sync_conn, target.id),
            pyotp.random_base32(),
        )
        _seed_rotation_challenge(
            sync_conn,
            bystander.id,
            bystander_session,
            _revision(sync_conn, bystander.id),
            pyotp.random_base32(),
        )
        return target, target_session, bystander

    async def test_logout_cascades_exactly_the_challenge_bound_to_that_session(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        target, target_session, bystander = self._seed_two_users_with_challenges(
            sync_conn, user_factory, session_factory
        )

        await sessions.delete_session(db_pool, target_session)

        assert not _challenge_exists(sync_conn, target.id)
        assert _challenge_exists(sync_conn, bystander.id)

    async def test_expiry_cleanup_cascades_exactly_the_challenge_bound_to_that_session(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        target, _target_session, bystander = self._seed_two_users_with_challenges(
            sync_conn, user_factory, session_factory, expires_in_seconds=-10
        )

        cleaned = await sessions.cleanup_expired_sessions(db_pool)

        assert cleaned == 1
        assert not _challenge_exists(sync_conn, target.id)
        assert _challenge_exists(sync_conn, bystander.id)

    async def test_direct_revocation_cascades_exactly_the_challenge_bound_to_that_session(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        target, _target_session, bystander = self._seed_two_users_with_challenges(
            sync_conn, user_factory, session_factory
        )

        await session_revocation.delete_user_sessions(db_pool, target.id)

        assert not _challenge_exists(sync_conn, target.id)
        assert _challenge_exists(sync_conn, bystander.id)


class TestUserDeletionCascadesItsChallenges:
    """Deleting a user row removes its own pending_totp_rotations challenge
    (the users.id foreign key on that table) and leaves no ciphertext
    behind; a different user's challenge is untouched."""

    async def test_deleting_the_user_row_removes_its_challenge_and_leaves_no_ciphertext(
        self, user_factory, session_factory, sync_conn
    ):
        target = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        target_session = session_factory(target.id, purpose="full")
        bystander = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        bystander_session = session_factory(bystander.id, purpose="full")
        _seed_rotation_challenge(
            sync_conn,
            target.id,
            target_session,
            _revision(sync_conn, target.id),
            pyotp.random_base32(),
        )
        _seed_rotation_challenge(
            sync_conn,
            bystander.id,
            bystander_session,
            _revision(sync_conn, bystander.id),
            pyotp.random_base32(),
        )

        sync_conn.execute("DELETE FROM users WHERE id = %s", (target.id,))
        sync_conn.commit()

        assert (
            sync_conn.execute(
                "SELECT encrypted_secret FROM pending_totp_rotations WHERE user_id = %s",
                (target.id,),
            ).fetchone()
            is None
        )
        assert _challenge_exists(sync_conn, bystander.id)

"""A pending TOTP-rotation challenge is fenced to the exact `auth_revision`
it was created under.

`begin_totp_rotation` stamps the challenge it creates with the user's
current `auth_revision`. `confirm_totp_rotation` re-reads that revision at
confirmation time and refuses to promote the replacement secret when it no
longer matches -- whatever changed the revision in between (a password
change, an email-address change, an administrator membership write, or any
other revision-bumping writer) removes the stale challenge instead of
silently promoting it.
"""

from types import SimpleNamespace

import pyotp
import pytest

from app.services import email_change, password_reset, totp, users
from app.services.crypto import decrypt_value, encrypt_value
from app.services.session_ids import hash_session_id
from app.services.tokens import hash_token

pytestmark = pytest.mark.integration

_TOTP_TIME = 1_800_000_000
NEW_EMAIL = "rotated-owner@mail.ch"
NEW_PASSWORD = "A-different-strong-password-90210!"


def _revision(sync_conn, user_id: int) -> int:
    return sync_conn.execute(
        "SELECT auth_revision FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()[0]


def _seed_rotation_challenge(sync_conn, user_id, raw_session, revision, replacement_secret):
    sync_conn.execute(
        """INSERT INTO pending_totp_rotations
               (user_id, session_id, auth_revision, encrypted_secret, expires_at)
           VALUES (%s, %s, %s, %s, clock_timestamp() + INTERVAL '5 minutes')""",
        (user_id, hash_session_id(raw_session), revision, encrypt_value(replacement_secret)),
    )
    sync_conn.commit()


def _challenge_row(sync_conn, user_id):
    return sync_conn.execute(
        "SELECT auth_revision FROM pending_totp_rotations WHERE user_id = %s",
        (user_id,),
    ).fetchone()


def _active_totp_secret(sync_conn, user_id) -> str:
    return sync_conn.execute("SELECT totp_secret FROM users WHERE id = %s", (user_id,)).fetchone()[
        0
    ]


class TestRevisionChangeInvalidatesAPendingRotation:
    """Whatever bumps `auth_revision` between `begin_totp_rotation` and
    `confirm_totp_rotation` invalidates the challenge: confirmation fences
    on the revision it was staged under, not merely on the session."""

    async def test_admin_reactivation_invalidates_the_challenge_without_touching_the_session(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """`set_user_active(True)` bumps `auth_revision` but neither deletes
        sessions nor touches `pending_totp_rotations` directly: this is the
        cleanest proof that confirmation's own revision comparison -- not a
        session cascade -- is what fences the stale challenge."""
        active_secret = pyotp.random_base32()
        replacement_secret = pyotp.random_base32()
        admin = user_factory(is_admin=True)
        admin_session = session_factory(admin.id, purpose="full")
        target = user_factory(totp_secret=encrypt_value(active_secret))
        target_session = session_factory(target.id, purpose="full")
        revision = _revision(sync_conn, target.id)
        _seed_rotation_challenge(sync_conn, target.id, target_session, revision, replacement_secret)
        monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME))
        code = pyotp.TOTP(replacement_secret).at(_TOTP_TIME)

        await users.set_user_active(
            db_pool,
            target.id,
            True,
            actor_id=admin.id,
            actor_session_id=admin_session,
        )
        assert _revision(sync_conn, target.id) == revision + 1

        outcome = await totp.confirm_totp_rotation(
            db_pool, target.id, code, session_id=target_session
        )

        assert outcome is totp.TotpRotationOutcome.PENDING_SECRET_MISSING
        assert _challenge_row(sync_conn, target.id) is None
        assert decrypt_value(_active_totp_secret(sync_conn, target.id)) == active_secret
        # The session itself was never touched by this revision-changing
        # writer: the invalidation is the revision check, not a cascade.
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM sessions WHERE id = %s",
                (hash_session_id(target_session),),
            ).fetchone()[0]
            == 1
        )

    async def test_password_change_invalidates_the_challenge(
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

        reset_token = password_reset.generate_reset_token(user.id, user.email)
        await password_reset.store_reset_token_hash(
            db_pool, user.id, hash_token(reset_token), expected_email=user.email
        )
        await password_reset.update_password_with_token(
            db_pool,
            user.id,
            hash_token(reset_token),
            NEW_PASSWORD,
            expected_email=user.email,
        )
        assert _revision(sync_conn, user.id) == revision + 1

        outcome = await totp.confirm_totp_rotation(db_pool, user.id, code, session_id=raw_session)

        assert outcome is totp.TotpRotationOutcome.SESSION_EXPIRED
        assert _challenge_row(sync_conn, user.id) is None

    async def test_email_change_invalidates_the_challenge(
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

        email_token = email_change.generate_email_change_token(
            user.id, NEW_EMAIL, auth_revision=revision
        )
        await email_change.store_pending_email(
            db_pool,
            user.id,
            NEW_EMAIL,
            hash_token(email_token),
            expected_auth_revision=revision,
        )
        assert await email_change.confirm_email_change(
            db_pool,
            user.id,
            NEW_EMAIL,
            hash_token(email_token),
            expected_auth_revision=revision,
        )
        assert _revision(sync_conn, user.id) == revision + 1

        outcome = await totp.confirm_totp_rotation(db_pool, user.id, code, session_id=raw_session)

        assert outcome is totp.TotpRotationOutcome.SESSION_EXPIRED
        assert _challenge_row(sync_conn, user.id) is None

    async def test_unchanged_revision_confirm_succeeds(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """Positive control: when nothing bumps `auth_revision` between
        start and confirm, the challenge is still current and confirmation
        promotes the replacement secret."""
        active_secret = pyotp.random_base32()
        replacement_secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(active_secret))
        raw_session = session_factory(user.id, purpose="full")
        revision = _revision(sync_conn, user.id)
        _seed_rotation_challenge(sync_conn, user.id, raw_session, revision, replacement_secret)
        monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME))
        code = pyotp.TOTP(replacement_secret).at(_TOTP_TIME)

        outcome = await totp.confirm_totp_rotation(db_pool, user.id, code, session_id=raw_session)

        assert outcome is totp.TotpRotationOutcome.ROTATED
        assert _challenge_row(sync_conn, user.id) is None
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM sessions WHERE user_id = %s", (user.id,)
            ).fetchone()[0]
            == 0
        )

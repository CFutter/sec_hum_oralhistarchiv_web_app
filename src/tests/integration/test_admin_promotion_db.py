"""The two-party administrator-promotion flow against real PostgreSQL.

An administrator's invitation grants nothing by itself: the target must
reauthenticate with their password and a fresh TOTP step to stage a new
recovery-code set, then confirm one of those codes from the exact session
that staged it. Only that final confirmation is a privilege-escalation
event, so this module exercises the real services in
`app.services.admin_promotion` end to end against the database, reading
every outcome back through an independent connection.
"""

from types import SimpleNamespace

import pyotp
import pytest

from app.services import admin_promotion, totp
from app.services.crypto import encrypt_value
from app.services.session_ids import hash_session_id
from tests.integration.conftest import DEFAULT_PASSWORD

pytestmark = pytest.mark.integration

_TOTP_TIME = 1_800_000_000


def _revision(sync_conn, user_id: int) -> int:
    return sync_conn.execute(
        "SELECT auth_revision FROM users WHERE id = %s", (user_id,)
    ).fetchone()[0]


def _request_row(sync_conn, user_id: int):
    return sync_conn.execute(
        """SELECT requested_by, expected_auth_revision, prepared_session_id, prepared_at
           FROM admin_promotion_requests WHERE user_id = %s""",
        (user_id,),
    ).fetchone()


def _is_admin(sync_conn, user_id: int) -> bool:
    return sync_conn.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,)).fetchone()[0]


def _active_recovery_generation(sync_conn, user_id: int) -> int:
    return sync_conn.execute(
        "SELECT totp_recovery_code_generation FROM users WHERE id = %s", (user_id,)
    ).fetchone()[0]


def _unused_codes_for_generation(sync_conn, user_id: int, generation: int) -> int:
    return sync_conn.execute(
        """SELECT count(*) FROM totp_recovery_codes
           WHERE user_id = %s AND generation = %s AND used_at IS NULL""",
        (user_id, generation),
    ).fetchone()[0]


def _session_count(sync_conn, user_id: int) -> int:
    return sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (user_id,)
    ).fetchone()[0]


@pytest.fixture(autouse=True)
def _fixed_totp_clock(monkeypatch):
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME))


@pytest.fixture
def target_secret():
    return pyotp.random_base32()


@pytest.fixture
def admin_and_target(user_factory, session_factory, target_secret):
    admin = user_factory(is_admin=True)
    admin_session = session_factory(admin.id, purpose="full")
    target = user_factory(totp_secret=encrypt_value(target_secret))
    return admin, admin_session, target


async def _prepare(db_pool, target, target_session, target_secret):
    code = pyotp.TOTP(target_secret).at(_TOTP_TIME)
    return await admin_promotion.prepare_admin_promotion(
        db_pool,
        user_id=target.id,
        session_id=target_session,
        password=DEFAULT_PASSWORD,
        totp_code=code,
    )


class TestPreparationIsBoundToItsSessionAndRevision:
    async def test_request_captures_the_targets_current_auth_revision(
        self, db_pool, sync_conn, admin_and_target
    ):
        admin, admin_session, target = admin_and_target
        revision = _revision(sync_conn, target.id)

        await admin_promotion.request_admin_promotion(
            db_pool,
            actor_id=admin.id,
            actor_session_id=admin_session,
            target_user_id=target.id,
        )

        row = _request_row(sync_conn, target.id)
        assert row is not None
        assert row[0] == admin.id
        assert row[1] == revision
        assert row[2] is None  # not yet prepared

    async def test_preparation_binds_the_prepared_session_id(
        self, db_pool, session_factory, sync_conn, admin_and_target, target_secret
    ):
        admin, admin_session, target = admin_and_target
        target_session = session_factory(target.id, purpose="full")
        await admin_promotion.request_admin_promotion(
            db_pool,
            actor_id=admin.id,
            actor_session_id=admin_session,
            target_user_id=target.id,
        )

        await _prepare(db_pool, target, target_session, target_secret)

        row = _request_row(sync_conn, target.id)
        assert row is not None
        assert row[2] == hash_session_id(target_session)
        assert row[3] is not None


class TestAdminPromotionAcceptance:
    """Acceptance is granted exactly once, only from the exact session that
    staged the recovery codes, and only while the state it was staged
    against is unchanged."""

    async def test_acceptance_from_a_different_session_is_refused_and_grants_nothing(
        self, db_pool, session_factory, sync_conn, admin_and_target, target_secret
    ):
        admin, admin_session, target = admin_and_target
        preparing_session = session_factory(target.id, purpose="full")
        other_session = session_factory(target.id, purpose="full")
        await admin_promotion.request_admin_promotion(
            db_pool,
            actor_id=admin.id,
            actor_session_id=admin_session,
            target_user_id=target.id,
        )
        prepared = await _prepare(db_pool, target, preparing_session, target_secret)

        with pytest.raises(admin_promotion.AdminPromotionRejected) as excinfo:
            await admin_promotion.accept_admin_promotion(
                db_pool,
                user_id=target.id,
                session_id=other_session,
                recovery_code=prepared.recovery_codes[0],
            )

        assert excinfo.value.reason == "codes_not_prepared"
        assert _is_admin(sync_conn, target.id) is False
        assert _session_count(sync_conn, target.id) == 2

    async def test_acceptance_from_the_preparing_session_grants_admin_exactly_once(
        self, db_pool, session_factory, sync_conn, admin_and_target, target_secret
    ):
        """The positive control for the two rejections in this class: the
        exact preparing session, with a staged recovery code, grants
        `is_admin` and activates the staged recovery-code generation as the
        active one -- and every target session, including bystanders, is
        revoked by that same acceptance."""
        admin, admin_session, target = admin_and_target
        preparing_session = session_factory(target.id, purpose="full")
        bystander_session = session_factory(target.id, purpose="full")
        await admin_promotion.request_admin_promotion(
            db_pool,
            actor_id=admin.id,
            actor_session_id=admin_session,
            target_user_id=target.id,
        )
        prepared = await _prepare(db_pool, target, preparing_session, target_secret)
        staged_generation = _request_row(sync_conn, target.id)  # sanity: request still present
        assert staged_generation is not None

        result = await admin_promotion.accept_admin_promotion(
            db_pool,
            user_id=target.id,
            session_id=preparing_session,
            recovery_code=prepared.recovery_codes[0],
        )

        assert result == admin_promotion.AcceptedAdminPromotion(
            user_id=target.id, requested_by=admin.id
        )
        assert _is_admin(sync_conn, target.id) is True
        active_generation = _active_recovery_generation(sync_conn, target.id)
        assert active_generation > 0
        # Confirming a code proves possession of the staged set; it does not
        # burn that code -- the whole set becomes active, still unused.
        assert _unused_codes_for_generation(sync_conn, target.id, active_generation) == len(
            prepared.recovery_codes
        )
        assert _session_count(sync_conn, target.id) == 0
        assert bystander_session is not None  # revoked alongside the preparing session
        assert _request_row(sync_conn, target.id) is None

    async def test_acceptance_after_the_auth_revision_moved_is_refused(
        self, db_pool, session_factory, sync_conn, admin_and_target, target_secret
    ):
        admin, admin_session, target = admin_and_target
        target_session = session_factory(target.id, purpose="full")
        await admin_promotion.request_admin_promotion(
            db_pool,
            actor_id=admin.id,
            actor_session_id=admin_session,
            target_user_id=target.id,
        )
        prepared = await _prepare(db_pool, target, target_session, target_secret)

        sync_conn.execute(
            "UPDATE users SET auth_revision = auth_revision + 1 WHERE id = %s",
            (target.id,),
        )
        sync_conn.commit()

        with pytest.raises(admin_promotion.AdminPromotionRejected) as excinfo:
            await admin_promotion.accept_admin_promotion(
                db_pool,
                user_id=target.id,
                session_id=target_session,
                recovery_code=prepared.recovery_codes[0],
            )

        assert excinfo.value.reason == "state_changed"
        assert _is_admin(sync_conn, target.id) is False

    async def test_the_invitation_cannot_be_accepted_twice(
        self, db_pool, session_factory, sync_conn, admin_and_target, target_secret
    ):
        admin, admin_session, target = admin_and_target
        preparing_session = session_factory(target.id, purpose="full")
        await admin_promotion.request_admin_promotion(
            db_pool,
            actor_id=admin.id,
            actor_session_id=admin_session,
            target_user_id=target.id,
        )
        prepared = await _prepare(db_pool, target, preparing_session, target_secret)
        await admin_promotion.accept_admin_promotion(
            db_pool,
            user_id=target.id,
            session_id=preparing_session,
            recovery_code=prepared.recovery_codes[0],
        )
        assert _is_admin(sync_conn, target.id) is True

        second_session = session_factory(target.id, purpose="full")
        with pytest.raises(admin_promotion.AdminPromotionRejected) as excinfo:
            await admin_promotion.accept_admin_promotion(
                db_pool,
                user_id=target.id,
                session_id=second_session,
                recovery_code=prepared.recovery_codes[1],
            )

        assert excinfo.value.reason == "already_admin"


class TestDecliningAnAdminPromotion:
    async def test_declining_removes_the_request(
        self, db_pool, session_factory, sync_conn, admin_and_target
    ):
        admin, admin_session, target = admin_and_target
        target_session = session_factory(target.id, purpose="full")
        await admin_promotion.request_admin_promotion(
            db_pool,
            actor_id=admin.id,
            actor_session_id=admin_session,
            target_user_id=target.id,
        )

        requested_by = await admin_promotion.decline_admin_promotion(
            db_pool, user_id=target.id, session_id=target_session
        )

        assert requested_by == admin.id
        assert _request_row(sync_conn, target.id) is None

    async def test_declining_without_a_pending_request_is_refused(
        self, db_pool, session_factory, admin_and_target
    ):
        """The positive control above proves a real request is removed;
        this proves nothing is removed (and nothing raised the wrong way)
        when there was never a request to decline."""
        _admin, _admin_session, target = admin_and_target
        target_session = session_factory(target.id, purpose="full")

        with pytest.raises(admin_promotion.AdminPromotionRejected) as excinfo:
            await admin_promotion.decline_admin_promotion(
                db_pool, user_id=target.id, session_id=target_session
            )

        assert excinfo.value.reason == "no_request"

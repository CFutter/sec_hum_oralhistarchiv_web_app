"""Durability of ``reserve_session_step_up_attempt`` across pools, failures and services.

The reservation commits in its own short transaction before any credential
work or protected mutation begins (credential_attempts.py:56-118). These
tests pin what a mocked cursor cannot: the committed count is visible through
any connection pool, not just the one that wrote it; it survives every kind
of failure that can happen *after* it commits (a wrong credential, a
downstream SQL error, or an enclosing service transaction's own rollback);
but a failure *inside* the reservation's own transaction leaves the counter
untouched and never even reaches credential verification. The admin
promotion and admin-authorized recovery paths reserve this same budget
before their own proof, and exhausting it blocks their mutation entirely.
The integration conftest applies the application's Alembic migration and
skips this module when the configured test database is unavailable.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec

import psycopg
import pyotp
import pytest

from app.services import admin_promotion as admin_promotion_module
from app.services import authentication as authentication_module
from app.services import credential_attempts as credential_attempts_module
from app.services import totp as totp_module
from app.services.admin_promotion import (
    AdminPromotionRejected,
    accept_admin_promotion,
    prepare_admin_promotion,
    request_admin_promotion,
)
from app.services.credential_attempts import (
    SessionStepUpAttemptOutcome,
    reserve_session_step_up_attempt,
)
from app.services.crypto import encrypt_value
from app.services.db import create_pool, get_db_cursor
from app.services.session_ids import hash_session_id
from app.services.totp import TotpRotationStartOutcome, begin_totp_rotation
from app.services.totp_recover import TotpRecoveryRejected, authorize_totp_recovery
from app.services.totp_recovery_codes import TOTP_RECOVERY_CODE_COUNT
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL, install_active_recovery_codes

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


def _step_up_state(sync_conn, raw_session_id: str) -> tuple[int, bool] | None:
    return sync_conn.execute(
        """
        SELECT step_up_attempt_count, expires_at > clock_timestamp()
        FROM sessions
        WHERE id = %s
        """,
        (hash_session_id(raw_session_id),),
    ).fetchone()


def _credential_snapshot(sync_conn, user_id: int):
    return sync_conn.execute(
        """
        SELECT password_hash, totp_secret, auth_revision, failed_login_count, locked_until
        FROM users
        WHERE id = %s
        """,
        (user_id,),
    ).fetchone()


class TestReservationSharedAcrossIndependentPools:
    """The durable count belongs to the session row, not to one pool's cache."""

    async def test_the_same_session_shares_its_count_through_two_independent_pools(
        self, user_factory, session_factory, sync_conn
    ):
        user = user_factory()
        raw_session = session_factory(user.id, purpose="full")

        pool_one = create_pool(application_name="oha-tests-pool-one")
        pool_two = create_pool(application_name="oha-tests-pool-two")
        await pool_one.open()
        await pool_two.open()
        try:
            first = await reserve_session_step_up_attempt(
                pool_one, user_id=user.id, session_id=raw_session
            )
            second = await reserve_session_step_up_attempt(
                pool_two, user_id=user.id, session_id=raw_session
            )
        finally:
            await pool_one.close()
            await pool_two.close()

        assert first is SessionStepUpAttemptOutcome.RESERVED
        assert second is SessionStepUpAttemptOutcome.RESERVED
        assert _step_up_state(sync_conn, raw_session) == (2, True)


class TestReservationDurabilityAcrossLaterFailures:
    """A committed reservation survives everything that can fail afterwards."""

    @pytest.mark.parametrize(
        "case",
        ["password_failure", "totp_failure", "downstream_sql_failure", "outer_service_rollback"],
        ids=[
            "password_failure",
            "totp_failure",
            "downstream_sql_failure",
            "outer_service_rollback",
        ],
    )
    async def test_the_counter_stays_incremented_through_a_new_connection(
        self, user_factory, session_factory, monkeypatch, case
    ):
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        raw_session = session_factory(user.id, purpose="full")

        async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn:
            if case == "password_failure":
                outcome = await begin_totp_rotation(
                    conn,  # type: ignore[arg-type] - supported direct-connection path
                    user.id,
                    "wrong-password",
                    pyotp.TOTP(secret).now(),
                    session_id=raw_session,
                )
                assert outcome.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS
            elif case == "totp_failure":
                outcome = await begin_totp_rotation(
                    conn,  # type: ignore[arg-type] - supported direct-connection path
                    user.id,
                    user.password,
                    "000000",
                    session_id=raw_session,
                )
                assert outcome.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS
            elif case == "downstream_sql_failure":
                failing_cursor = create_autospec(
                    get_db_cursor,
                    spec_set=True,
                    side_effect=RuntimeError("forced downstream failure"),
                )
                monkeypatch.setattr(totp_module, "get_db_cursor", failing_cursor)
                with pytest.raises(RuntimeError, match="forced downstream failure"):
                    await begin_totp_rotation(
                        conn,  # type: ignore[arg-type] - supported direct-connection path
                        user.id,
                        user.password,
                        pyotp.TOTP(secret).now(),
                        session_id=raw_session,
                    )
            else:  # outer_service_rollback
                failing_lock = create_autospec(
                    admin_promotion_module.acquire_admin_action_lock_cur,
                    spec_set=True,
                    side_effect=RuntimeError("forced outer rollback"),
                )
                monkeypatch.setattr(
                    admin_promotion_module, "acquire_admin_action_lock_cur", failing_lock
                )
                with pytest.raises(RuntimeError, match="forced outer rollback"):
                    await prepare_admin_promotion(
                        conn,  # type: ignore[arg-type] - supported direct-connection path
                        user_id=user.id,
                        session_id=raw_session,
                        password=user.password,
                        totp_code="123456",
                    )

        async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as fresh:
            cur = await fresh.execute(
                "SELECT step_up_attempt_count FROM sessions WHERE id = %s",
                (hash_session_id(raw_session),),
            )
            row = await cur.fetchone()
        assert row == (1,)

    async def test_a_plain_reservation_without_any_failure_also_increments(
        self, user_factory, session_factory, sync_conn
    ):
        """POSITIVE CONTROL: nothing injected, the counter still increments."""
        user = user_factory()
        raw_session = session_factory(user.id, purpose="full")

        async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn:
            outcome = await reserve_session_step_up_attempt(
                conn,  # type: ignore[arg-type] - supported direct-connection path
                user_id=user.id,
                session_id=raw_session,
            )
        assert outcome is SessionStepUpAttemptOutcome.RESERVED
        assert _step_up_state(sync_conn, raw_session) == (1, True)


class TestReservationFailureBeforeCommitVerifiesNothing:
    """A failure inside the reservation's own transaction never reaches
    credential verification and never touches the counter."""

    async def test_a_failure_before_the_reservation_commits_runs_no_credential_work(
        self, user_factory, session_factory, sync_conn, monkeypatch
    ):
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        raw_session = session_factory(user.id, purpose="full")
        before = _credential_snapshot(sync_conn, user.id)

        failing_reservation_cursor = create_autospec(
            get_db_cursor, spec_set=True, side_effect=RuntimeError("forced reservation failure")
        )
        monkeypatch.setattr(credential_attempts_module, "get_db_cursor", failing_reservation_cursor)

        real_run_password_work = totp_module.run_password_work
        autospecced_password_work = create_autospec(
            real_run_password_work, spec_set=True, side_effect=real_run_password_work
        )
        monkeypatch.setattr(totp_module, "run_password_work", autospecced_password_work)
        real_verify_dummy = authentication_module.verify_dummy
        autospecced_verify_dummy = create_autospec(
            real_verify_dummy, spec_set=True, side_effect=real_verify_dummy
        )
        monkeypatch.setattr(authentication_module, "verify_dummy", autospecced_verify_dummy)

        with pytest.raises(RuntimeError, match="forced reservation failure"):
            await begin_totp_rotation(
                None,  # never reached: the reservation call raises first
                user.id,
                user.password,
                pyotp.TOTP(secret).now(),
                session_id=raw_session,
            )

        autospecced_password_work.assert_not_awaited()
        autospecced_verify_dummy.assert_not_awaited()
        assert _step_up_state(sync_conn, raw_session) == (0, True)
        assert _credential_snapshot(sync_conn, user.id) == before
        assert (
            sync_conn.execute(
                "SELECT COUNT(*) FROM pending_totp_rotations WHERE user_id = %s", (user.id,)
            ).fetchone()[0]
            == 0
        )

    async def test_a_reservation_without_an_injected_failure_does_verify_credentials(
        self, user_factory, session_factory, sync_conn
    ):
        """POSITIVE CONTROL: with nothing injected, the reservation commits
        and rotation start really does go on to verify the credential."""
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        raw_session = session_factory(user.id, purpose="full")

        result = await begin_totp_rotation(
            await psycopg.AsyncConnection.connect(TEST_DATABASE_URL),  # type: ignore[arg-type]
            user.id,
            user.password,
            pyotp.TOTP(secret).now(),
            session_id=raw_session,
        )

        assert result.outcome is TotpRotationStartOutcome.READY
        assert _step_up_state(sync_conn, raw_session) == (1, True)


class TestAdminPromotionReservesBeforeItsOwnProof:
    """prepare/accept reserve the target's own budget before their proof and
    perform their protected mutation only once past it."""

    async def test_prepare_reserves_before_the_proof_and_stages_one_code_set(
        self, db_pool, user_factory, session_factory, sync_conn, admin_actor
    ):
        target_secret = pyotp.random_base32()
        target = user_factory(totp_secret=encrypt_value(target_secret))
        target_session = session_factory(target.id, purpose="full")
        await request_admin_promotion(
            db_pool,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
            target_user_id=target.id,
        )

        prepared = await prepare_admin_promotion(
            db_pool,
            user_id=target.id,
            session_id=target_session,
            password=target.password,
            totp_code=pyotp.TOTP(target_secret).now(),
        )

        assert len(prepared.recovery_codes) == TOTP_RECOVERY_CODE_COUNT
        assert _step_up_state(sync_conn, target_session) == (1, True)
        pending_generation = sync_conn.execute(
            "SELECT pending_totp_recovery_code_generation FROM users WHERE id = %s",
            (target.id,),
        ).fetchone()[0]
        assert pending_generation is not None
        staged_rows = sync_conn.execute(
            "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = %s AND generation = %s",
            (target.id, pending_generation),
        ).fetchone()[0]
        assert staged_rows == TOTP_RECOVERY_CODE_COUNT
        assert sync_conn.execute(
            "SELECT is_admin FROM users WHERE id = %s", (target.id,)
        ).fetchone() == (False,)

    async def test_accept_reserves_before_the_code_proof_and_grants_once(
        self, db_pool, user_factory, session_factory, sync_conn, admin_actor
    ):
        target_secret = pyotp.random_base32()
        target = user_factory(totp_secret=encrypt_value(target_secret))
        target_session = session_factory(target.id, purpose="full")
        await request_admin_promotion(
            db_pool,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
            target_user_id=target.id,
        )
        prepared = await prepare_admin_promotion(
            db_pool,
            user_id=target.id,
            session_id=target_session,
            password=target.password,
            totp_code=pyotp.TOTP(target_secret).now(),
        )

        accepted = await accept_admin_promotion(
            db_pool,
            user_id=target.id,
            session_id=target_session,
            recovery_code=prepared.recovery_codes[0],
        )

        assert accepted.user_id == target.id
        # Two separate reservations: one from prepare, one from accept.
        # accept revokes the session it just reserved through, so read the
        # count from the row's final state before the cascade removed it.
        assert (
            sync_conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (target.id,)
            ).fetchone()[0]
            == 0
        )
        row = sync_conn.execute(
            "SELECT is_admin, auth_revision FROM users WHERE id = %s", (target.id,)
        ).fetchone()
        assert row[0] is True
        assert row[1] == 1

    async def test_exhaustion_before_prepare_stages_no_code_set(
        self, db_pool, user_factory, session_factory, sync_conn, admin_actor, monkeypatch
    ):
        target_secret = pyotp.random_base32()
        target = user_factory(totp_secret=encrypt_value(target_secret))
        target_session = session_factory(target.id, purpose="full")
        await request_admin_promotion(
            db_pool,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
            target_user_id=target.id,
        )
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", 0)

        with pytest.raises(AdminPromotionRejected) as excinfo:
            await prepare_admin_promotion(
                db_pool,
                user_id=target.id,
                session_id=target_session,
                password=target.password,
                totp_code=pyotp.TOTP(target_secret).now(),
            )

        assert excinfo.value.reason == "step_up_exhausted"
        assert (
            sync_conn.execute(
                "SELECT pending_totp_recovery_code_generation FROM users WHERE id = %s",
                (target.id,),
            ).fetchone()[0]
            is None
        )
        assert sync_conn.execute(
            "SELECT is_admin FROM users WHERE id = %s", (target.id,)
        ).fetchone() == (False,)

    async def test_exhaustion_before_accept_grants_nothing(
        self, db_pool, user_factory, session_factory, sync_conn, admin_actor, monkeypatch
    ):
        target_secret = pyotp.random_base32()
        target = user_factory(totp_secret=encrypt_value(target_secret))
        target_session = session_factory(target.id, purpose="full")
        await request_admin_promotion(
            db_pool,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
            target_user_id=target.id,
        )
        prepared = await prepare_admin_promotion(
            db_pool,
            user_id=target.id,
            session_id=target_session,
            password=target.password,
            totp_code=pyotp.TOTP(target_secret).now(),
        )
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", 1)

        with pytest.raises(AdminPromotionRejected) as excinfo:
            await accept_admin_promotion(
                db_pool,
                user_id=target.id,
                session_id=target_session,
                recovery_code=prepared.recovery_codes[0],
            )

        assert excinfo.value.reason == "step_up_exhausted"
        assert sync_conn.execute(
            "SELECT is_admin FROM users WHERE id = %s", (target.id,)
        ).fetchone() == (False,)
        assert (
            sync_conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (target.id,)
            ).fetchone()[0]
            == 1
        )


class TestAdminRecoveryAuthorizationReservesTheActorsBudget:
    """authorize_totp_recovery reserves the actor's budget before its own proof."""

    async def test_authorization_reserves_the_actors_budget(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        actor_secret = pyotp.random_base32()
        actor = user_factory(is_admin=True, totp_secret=encrypt_value(actor_secret))
        actor_session = session_factory(actor.id, purpose="full")
        target = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        install_active_recovery_codes(sync_conn, target.id)

        result = await authorize_totp_recovery(
            db_pool,
            actor_id=actor.id,
            actor_session_id=actor_session,
            target_user_id=target.id,
            admin_totp_code=pyotp.TOTP(actor_secret).now(),
        )

        assert result.target_user_id == target.id
        assert _step_up_state(sync_conn, actor_session) == (1, True)

    async def test_exhaustion_before_the_proof_authorizes_nothing_and_leaves_lockout_untouched(
        self, user_factory, session_factory, sync_conn, monkeypatch
    ):
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", 0)
        actor_secret = pyotp.random_base32()
        actor = user_factory(is_admin=True, totp_secret=encrypt_value(actor_secret))
        actor_session = session_factory(actor.id, purpose="full")
        target_secret = pyotp.random_base32()
        locked_until = datetime.now(UTC) + timedelta(minutes=10)
        target = user_factory(
            totp_secret=encrypt_value(target_secret),
            failed_login_count=3,
            locked_until=locked_until,
        )
        before = _credential_snapshot(sync_conn, target.id)

        with pytest.raises(TotpRecoveryRejected) as excinfo:
            await authorize_totp_recovery(
                await psycopg.AsyncConnection.connect(TEST_DATABASE_URL),  # type: ignore[arg-type]
                actor_id=actor.id,
                actor_session_id=actor_session,
                target_user_id=target.id,
                admin_totp_code=pyotp.TOTP(actor_secret).now(),
            )

        assert excinfo.value.reason == "actor_step_up_exhausted"
        assert _credential_snapshot(sync_conn, target.id) == before
        assert sync_conn.execute(
            "SELECT totp_recovery_required FROM users WHERE id = %s", (target.id,)
        ).fetchone() == (False,)

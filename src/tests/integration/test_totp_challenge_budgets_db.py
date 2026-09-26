"""TOTP rotation-confirmation and recovery-code attempt budgets against PostgreSQL.

Two durable, per-challenge budgets from ``app.services.totp``,
``app.services.totp_recover`` and ``app.services.totp_recovery_codes`` cannot
be proved with mock cursors: one confirmation quota per staged TOTP rotation
challenge (``pending_totp_rotations``), and one password-attempt quota per
recovery-code row (``totp_recovery_codes``), matched and charged atomically
under concurrent redemption attempts. A closing class pins the database check
and not-null constraints that remain a backstop if a future caller bypasses
these services. The integration conftest applies the application's Alembic
migration and skips this module when the configured test database is
unavailable.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec

import psycopg
import pytest
from psycopg.errors import CheckViolation, NotNullViolation

from app.services import totp_recover
from app.services.crypto import encrypt_value
from app.services.db import get_db_cursor
from app.services.session_ids import hash_session_id
from app.services.sessions import create_session_cur
from app.services.tokens import hash_token
from app.services.totp import TotpRotationOutcome, confirm_totp_rotation
from app.services.totp_recover import (
    TotpRecoveryRedemptionRejected,
    redeem_totp_recovery,
)
from app.services.totp_recovery_codes import (
    TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
    find_active_recovery_code_candidate_cur,
    has_unused_active_recovery_code_cur,
    normalize_recovery_code,
    reserve_recovery_code_password_attempt_cur,
)
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL

pytestmark = pytest.mark.integration

_RECOVERY_CODE_A = "AAAAA-BBBBB-CCCCC-DDDDD"
_RECOVERY_CODE_B = "11111-22222-33333-44444"
_UNKNOWN_RECOVERY_CODE = "EEEEE-FFFFF-00000-99999"


def _canonical_recovery_code(code: str) -> str:
    canonical = normalize_recovery_code(code)
    assert canonical is not None
    return canonical


def _session_state(sync_conn, raw_session_id: str) -> tuple[int, bool] | None:
    return sync_conn.execute(
        """
        SELECT step_up_attempt_count,
               expires_at > clock_timestamp() AS active
        FROM sessions
        WHERE id = %s
        """,
        (hash_session_id(raw_session_id),),
    ).fetchone()


def _user_login_lock_state(sync_conn, user_id: int):
    return sync_conn.execute(
        "SELECT failed_login_count, locked_until FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()


def _install_active_recovery_codes(sync_conn, user_id: int) -> None:
    """Give a user an active generation with two known, unused recovery codes.

    ``psycopg.Connection`` has no ``executemany`` (only ``Cursor`` does), so
    the batch insert runs through an explicit cursor.
    """
    sync_conn.execute(
        "UPDATE users SET totp_recovery_code_generation = 1 WHERE id = %s",
        (user_id,),
    )
    with sync_conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO totp_recovery_codes (
                user_id, generation, position, code_hash
            )
            VALUES (%s, 1, %s, %s)
            """,
            [
                (user_id, 1, hash_token(_canonical_recovery_code(_RECOVERY_CODE_A))),
                (user_id, 2, hash_token(_canonical_recovery_code(_RECOVERY_CODE_B))),
            ],
        )
    sync_conn.commit()


def _authorize_public_recovery(sync_conn, user_id: int) -> None:
    """Install a live, revision-bound recovery authorization for one user."""
    sync_conn.execute(
        """
        UPDATE users
        SET totp_secret = NULL,
            last_totp_step = NULL,
            totp_recovery_required = true,
            totp_recovery_authorized_at = clock_timestamp(),
            totp_recovery_expires_at = clock_timestamp() + INTERVAL '30 minutes',
            totp_recovery_auth_revision = auth_revision
        WHERE id = %s
        """,
        (user_id,),
    )
    sync_conn.commit()


def _recovery_code_states(sync_conn, user_id: int):
    return sync_conn.execute(
        """
        SELECT position, password_attempt_count, used_at
        FROM totp_recovery_codes
        WHERE user_id = %s AND generation = 1
        ORDER BY position
        """,
        (user_id,),
    ).fetchall()


async def _backend_pid(conn: psycopg.AsyncConnection) -> int:
    cursor = await conn.execute("SELECT pg_backend_pid()")
    row = await cursor.fetchone()
    await conn.commit()
    assert row is not None
    return row[0]


async def _reserve_recovery_password_attempt(
    *,
    user_id: int,
    code: str,
    barrier: asyncio.Barrier,
):
    async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn:
        backend_pid = await _backend_pid(conn)
        async with get_db_cursor(conn) as cur:
            candidate = await find_active_recovery_code_candidate_cur(
                cur,
                user_id=user_id,
                active_generation=1,
                candidate_code=code,
            )

        # Every independent backend completes the same nonlocking match before
        # any of them begins the serialized conditional increment.
        await barrier.wait()
        if candidate is None:
            return None, backend_pid
        async with get_db_cursor(conn) as cur:
            reservation = await reserve_recovery_code_password_attempt_cur(
                cur,
                candidate=candidate,
            )
        return reservation, backend_pid


class TestRotationConfirmationBudget:
    """One durable confirmation quota per staged TOTP rotation challenge."""

    pytestmark = pytest.mark.asyncio

    async def test_exhausted_confirmation_budget_deletes_only_that_challenge(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """Invalid confirmations commit their count and eventually discard the challenge."""
        monkeypatch.setattr(settings, "totp_rotation_confirmation_attempt_limit", 2)
        active_ciphertext = encrypt_value("JBSWY3DPEHPK3PXP")
        replacement_ciphertext = encrypt_value("KRSXG5DSNFXGOIDB")
        user = user_factory(totp_secret=active_ciphertext)
        raw_session = session_factory(user.id, purpose="full")
        session_hash = hash_session_id(raw_session)
        sync_conn.execute(
            """
            INSERT INTO pending_totp_rotations (
                user_id, session_id, auth_revision, encrypted_secret, expires_at
            )
            VALUES (%s, %s, 0, %s, clock_timestamp() + INTERVAL '5 minutes')
            """,
            (user.id, session_hash, replacement_ciphertext),
        )
        sync_conn.commit()

        first = await confirm_totp_rotation(
            db_pool,
            user.id,
            "not-a-code",
            session_id=raw_session,
        )
        assert first is TotpRotationOutcome.INVALID_NEW_CODE
        assert sync_conn.execute(
            "SELECT confirmation_attempt_count FROM pending_totp_rotations WHERE user_id = %s",
            (user.id,),
        ).fetchone() == (1,)

        second = await confirm_totp_rotation(
            db_pool,
            user.id,
            "still-not-a-code",
            session_id=raw_session,
        )

        assert second is TotpRotationOutcome.ATTEMPTS_EXHAUSTED
        assert (
            sync_conn.execute(
                "SELECT 1 FROM pending_totp_rotations WHERE user_id = %s",
                (user.id,),
            ).fetchone()
            is None
        )
        assert sync_conn.execute(
            "SELECT totp_secret FROM users WHERE id = %s",
            (user.id,),
        ).fetchone() == (active_ciphertext,)
        assert _session_state(sync_conn, raw_session) == (0, True)


class TestRecoveryCodeBudget:
    """One password-attempt budget per recovery-code row, matched and charged atomically."""

    pytestmark = pytest.mark.asyncio

    async def test_budget_is_atomic_and_isolated_per_code_under_concurrency(
        self,
        db_pool,
        user_factory,
        sync_conn,
    ):
        """Only the matched code is charged, even under concurrent reservations."""
        user = user_factory(totp_recovery_code_generation=0)
        _install_active_recovery_codes(sync_conn, user.id)

        caller_count = TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT + 5
        barrier = asyncio.Barrier(caller_count)
        results = await asyncio.wait_for(
            asyncio.gather(
                *(
                    _reserve_recovery_password_attempt(
                        user_id=user.id,
                        code=_RECOVERY_CODE_A,
                        barrier=barrier,
                    )
                    for _ in range(caller_count)
                )
            ),
            timeout=10,
        )
        reservations = [reservation for reservation, _backend in results]
        backend_pids = [backend for _reservation, backend in results]

        assert len(set(backend_pids)) == caller_count
        assert sum(reservation is not None for reservation in reservations) == (
            TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT
        )
        rows = sync_conn.execute(
            """
            SELECT position, password_attempt_count, used_at
            FROM totp_recovery_codes
            WHERE user_id = %s AND generation = 1
            ORDER BY position
            """,
            (user.id,),
        ).fetchall()
        assert rows == [
            (1, TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT, None),
            (2, 0, None),
        ]

        async with get_db_cursor(db_pool) as cur:
            assert await has_unused_active_recovery_code_cur(
                cur,
                user_id=user.id,
                active_generation=1,
            )

    async def test_candidate_lookup_is_nonlocking_and_unknown_code_does_not_mutate(
        self,
        db_pool,
        user_factory,
        sync_conn,
    ):
        """Candidate lookup can read a locked row and rejects unknown values read-only."""
        user = user_factory(totp_recovery_code_generation=0)
        _install_active_recovery_codes(sync_conn, user.id)
        lock_conn = await psycopg.AsyncConnection.connect(TEST_DATABASE_URL)
        try:
            await lock_conn.execute(
                """
                SELECT 1
                FROM totp_recovery_codes
                WHERE user_id = %s AND generation = 1 AND position = 1
                FOR UPDATE
                """,
                (user.id,),
            )

            async with asyncio.timeout(2), get_db_cursor(db_pool) as cur:
                candidate = await find_active_recovery_code_candidate_cur(
                    cur,
                    user_id=user.id,
                    active_generation=1,
                    candidate_code=_RECOVERY_CODE_A,
                )
            assert candidate is not None

            async with get_db_cursor(db_pool) as cur:
                unknown = await find_active_recovery_code_candidate_cur(
                    cur,
                    user_id=user.id,
                    active_generation=1,
                    candidate_code=_UNKNOWN_RECOVERY_CODE,
                )
            assert unknown is None
        finally:
            await lock_conn.rollback()
            await lock_conn.close()

        assert sync_conn.execute(
            """
            SELECT position, password_attempt_count, used_at
            FROM totp_recovery_codes
            WHERE user_id = %s AND generation = 1
            ORDER BY position
            """,
            (user.id,),
        ).fetchall() == [(1, 0, None), (2, 0, None)]

    async def test_wrong_password_commits_only_the_exact_code_attempt(
        self,
        db_pool,
        user_factory,
        sync_conn,
    ):
        """Bad passwords spend one matched-code slot without invoking login lockout."""
        user = user_factory(failed_login_count=2, locked_until=None)
        _install_active_recovery_codes(sync_conn, user.id)
        _authorize_public_recovery(sync_conn, user.id)
        before_lock_state = _user_login_lock_state(sync_conn, user.id)
        sync_conn.commit()

        with pytest.raises(TotpRecoveryRedemptionRejected) as caught:
            await redeem_totp_recovery(
                db_pool,
                email=user.email,
                password="definitely-not-the-account-password",
                recovery_code=_RECOVERY_CODE_A,
                ip_address="192.0.2.20",
            )

        assert caught.value.reason == "invalid_credentials"
        assert caught.value.user_id == user.id
        states = _recovery_code_states(sync_conn, user.id)
        assert states[0][:2] == (1, 1)
        assert states[0][2] is None
        assert states[1] == (2, 0, None)
        assert _user_login_lock_state(sync_conn, user.id) == before_lock_state
        assert sync_conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = %s",
            (user.id,),
        ).fetchone() == (0,)

    async def test_locked_user_can_recover_once_and_replay_is_generic(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
    ):
        """Recovery clears login lockout, consumes once, and rejects replay generically."""
        locked_until = datetime.now(UTC) + timedelta(minutes=15)
        user = user_factory(failed_login_count=5, locked_until=locked_until)
        stale_full_session = session_factory(user.id, purpose="full")
        _install_active_recovery_codes(sync_conn, user.id)
        _authorize_public_recovery(sync_conn, user.id)

        result = await redeem_totp_recovery(
            db_pool,
            email=user.email,
            password=user.password,
            recovery_code=_RECOVERY_CODE_A,
            ip_address="192.0.2.21",
        )

        assert result.user_id == user.id
        assert _session_state(sync_conn, stale_full_session) is None
        assert sync_conn.execute(
            """
            SELECT purpose, expires_at > clock_timestamp()
            FROM sessions
            WHERE id = %s AND user_id = %s
            """,
            (hash_session_id(result.session_id), user.id),
        ).fetchone() == ("totp_recovery", True)
        assert _user_login_lock_state(sync_conn, user.id) == (0, None)

        with pytest.raises(TotpRecoveryRedemptionRejected) as replay:
            await redeem_totp_recovery(
                db_pool,
                email=user.email,
                password=user.password,
                recovery_code=_RECOVERY_CODE_A,
                ip_address="192.0.2.22",
            )

        assert replay.value.reason == "invalid_credentials"
        assert replay.value.user_id is None
        states = _recovery_code_states(sync_conn, user.id)
        assert states[0][0:2] == (1, 1)
        assert states[0][2] is not None
        assert states[1] == (2, 0, None)
        assert sync_conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = %s",
            (user.id,),
        ).fetchone() == (1,)

    async def test_wrong_password_on_one_code_does_not_block_a_second_code(
        self,
        db_pool,
        user_factory,
        sync_conn,
    ):
        """Per-code budgets isolate a charged code from another retained code."""
        user = user_factory()
        _install_active_recovery_codes(sync_conn, user.id)
        _authorize_public_recovery(sync_conn, user.id)

        with pytest.raises(TotpRecoveryRedemptionRejected) as wrong_password:
            await redeem_totp_recovery(
                db_pool,
                email=user.email,
                password="wrong-password-for-code-a",
                recovery_code=_RECOVERY_CODE_A,
                ip_address="192.0.2.23",
            )
        assert wrong_password.value.reason == "invalid_credentials"

        result = await redeem_totp_recovery(
            db_pool,
            email=user.email,
            password=user.password,
            recovery_code=_RECOVERY_CODE_B,
            ip_address="192.0.2.24",
        )

        assert result.user_id == user.id
        states = _recovery_code_states(sync_conn, user.id)
        assert states[0] == (1, 1, None)
        assert states[1][0:2] == (2, 1)
        assert states[1][2] is not None

    async def test_rejects_auth_state_changed_after_password_work(
        self,
        db_pool,
        user_factory,
        sync_conn,
        monkeypatch,
    ):
        """The final locked transaction rejects a stale password/revision snapshot."""
        user = user_factory()
        _install_active_recovery_codes(sync_conn, user.id)
        _authorize_public_recovery(sync_conn, user.id)
        real_password_work = totp_recover.run_password_work

        async def verify_then_change_auth_state(function, *args):
            result = await real_password_work(function, *args)
            sync_conn.execute(
                "UPDATE users SET auth_revision = auth_revision + 1 WHERE id = %s",
                (user.id,),
            )
            sync_conn.commit()
            return result

        # autospecced against run_password_work's real signature: a caller
        # passing keyword arguments in the future would raise here instead of
        # silently stop being exercised by this fault injection.
        autospecced_password_work = create_autospec(
            totp_recover.run_password_work,
            spec_set=True,
            side_effect=verify_then_change_auth_state,
        )
        monkeypatch.setattr(totp_recover, "run_password_work", autospecced_password_work)

        with pytest.raises(TotpRecoveryRedemptionRejected) as stale:
            await redeem_totp_recovery(
                db_pool,
                email=user.email,
                password=user.password,
                recovery_code=_RECOVERY_CODE_A,
                ip_address="192.0.2.25",
            )

        assert stale.value.reason == "auth_state_changed"
        assert stale.value.user_id == user.id
        states = _recovery_code_states(sync_conn, user.id)
        assert states[0] == (1, 1, None)
        assert states[1] == (2, 0, None)
        assert sync_conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = %s",
            (user.id,),
        ).fetchone() == (0,)

    async def test_finalization_failure_rolls_back_consumption_and_revocation(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """A late session failure rolls back use/revocation but not the attempt slot."""
        locked_until = datetime.now(UTC) + timedelta(minutes=15)
        user = user_factory(failed_login_count=4, locked_until=locked_until)
        existing_session = session_factory(user.id, purpose="full")
        _install_active_recovery_codes(sync_conn, user.id)
        _authorize_public_recovery(sync_conn, user.id)
        before_lock_state = _user_login_lock_state(sync_conn, user.id)
        sync_conn.commit()
        create_session = create_autospec(
            create_session_cur, spec_set=True, side_effect=RuntimeError("session insert failed")
        )
        monkeypatch.setattr(totp_recover, "create_session_cur", create_session)

        with pytest.raises(RuntimeError, match="session insert failed"):
            await redeem_totp_recovery(
                db_pool,
                email=user.email,
                password=user.password,
                recovery_code=_RECOVERY_CODE_A,
                ip_address="192.0.2.26",
            )

        create_session.assert_awaited_once()
        states = _recovery_code_states(sync_conn, user.id)
        assert states[0] == (1, 1, None)
        assert states[1] == (2, 0, None)
        assert _session_state(sync_conn, existing_session) == (0, True)
        assert _user_login_lock_state(sync_conn, user.id) == before_lock_state
        assert sync_conn.execute(
            """
            SELECT totp_recovery_authorized_at IS NOT NULL,
                   totp_recovery_expires_at > clock_timestamp(),
                   totp_recovery_auth_revision = auth_revision
            FROM users
            WHERE id = %s
            """,
            (user.id,),
        ).fetchone() == (True, True, True)


class TestAttemptCounterCheckConstraints:
    """The database remains a backstop if a future caller bypasses these services."""

    @pytest.fixture
    def budget_rows(self, user_factory, session_factory, sync_conn):
        """A session, a staged rotation challenge, and an active recovery code."""
        user = user_factory(totp_recovery_code_generation=0)
        raw_session = session_factory(user.id, purpose="full")
        session_hash = hash_session_id(raw_session)
        _install_active_recovery_codes(sync_conn, user.id)
        sync_conn.execute(
            """
            INSERT INTO pending_totp_rotations (
                user_id, session_id, auth_revision, encrypted_secret, expires_at
            )
            VALUES (%s, %s, 0, %s, clock_timestamp() + INTERVAL '5 minutes')
            """,
            (user.id, session_hash, encrypt_value("KRSXG5DSNFXGOIDB")),
        )
        sync_conn.commit()
        return {"user_id": user.id, "raw_session": raw_session, "session_hash": session_hash}

    def test_valid_attempt_counts_persist(self, budget_rows, sync_conn):
        """A freshly-issued challenge starts every budget at its valid zero value."""
        assert _session_state(sync_conn, budget_rows["raw_session"]) == (0, True)
        assert sync_conn.execute(
            """
            SELECT confirmation_attempt_count
            FROM pending_totp_rotations
            WHERE user_id = %s
            """,
            (budget_rows["user_id"],),
        ).fetchone() == (0,)
        assert sync_conn.execute(
            """
            SELECT password_attempt_count
            FROM totp_recovery_codes
            WHERE user_id = %s AND generation = 1 AND position = 1
            """,
            (budget_rows["user_id"],),
        ).fetchone() == (0,)

    @pytest.mark.parametrize(
        ("exception", "sql", "params_of"),
        [
            pytest.param(
                NotNullViolation,
                "UPDATE sessions SET step_up_attempt_count = NULL WHERE id = %s",
                lambda rows: (rows["session_hash"],),
                id="session_step_up_attempt_count_rejects_null",
            ),
            pytest.param(
                NotNullViolation,
                """
                UPDATE pending_totp_rotations
                SET confirmation_attempt_count = NULL
                WHERE user_id = %s
                """,
                lambda rows: (rows["user_id"],),
                id="pending_rotation_confirmation_attempt_count_rejects_null",
            ),
            pytest.param(
                NotNullViolation,
                """
                UPDATE totp_recovery_codes
                SET password_attempt_count = NULL
                WHERE user_id = %s AND generation = 1 AND position = 1
                """,
                lambda rows: (rows["user_id"],),
                id="recovery_code_password_attempt_count_rejects_null",
            ),
            pytest.param(
                CheckViolation,
                "UPDATE sessions SET step_up_attempt_count = -1 WHERE id = %s",
                lambda rows: (rows["session_hash"],),
                id="session_step_up_attempt_count_rejects_negative",
            ),
            pytest.param(
                CheckViolation,
                """
                UPDATE totp_recovery_codes
                SET password_attempt_count = -1
                WHERE user_id = %s AND generation = 1 AND position = 1
                """,
                lambda rows: (rows["user_id"],),
                id="recovery_code_password_attempt_count_rejects_negative",
            ),
            pytest.param(
                CheckViolation,
                """
                UPDATE pending_totp_rotations
                SET confirmation_attempt_count = -1
                WHERE user_id = %s
                """,
                lambda rows: (rows["user_id"],),
                id="pending_rotation_confirmation_attempt_count_rejects_negative",
            ),
            pytest.param(
                CheckViolation,
                """
                UPDATE totp_recovery_codes
                SET password_attempt_count = %s
                WHERE user_id = %s AND generation = 1 AND position = 1
                """,
                lambda rows: (TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT + 1, rows["user_id"]),
                id="recovery_code_password_attempt_count_rejects_above_limit",
            ),
        ],
    )
    def test_out_of_range_updates_are_rejected(
        self, budget_rows, sync_conn, exception, sql, params_of
    ):
        """Every attempt-count column keeps its NOT NULL and CHECK constraints."""
        with pytest.raises(exception):
            sync_conn.execute(sql, params_of(budget_rows))
        sync_conn.rollback()

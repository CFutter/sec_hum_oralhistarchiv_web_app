"""Recovery-code generation lifecycle and redemption races against real PostgreSQL."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec

import psycopg
import pytest

from app.services import password_verification, totp_recover
from app.services.crypto import password_hasher
from app.services.db import get_db_cursor
from app.services.tokens import hash_token
from app.services.totp_recover import TotpRecoveryRedemptionRejected, redeem_totp_recovery
from app.services.totp_recovery_codes import (
    TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
    activate_pending_recovery_code_set_cur,
    generate_recovery_codes,
    normalize_recovery_code,
    stage_recovery_code_set_cur,
)
from tests.integration.conftest import TEST_DATABASE_URL

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_WRONG_CODE = "00000-00000-00000-00000"
_KNOWN_CODE = "ABCDE-12345-FEDCB-67890"
_UNRELATED_WELLFORMED_CODE = "11111-AAAAA-22222-BBBBB"


def _generation_rows(sync_conn, user_id: int):
    """Read recovery generations and password-attempt counts in code order."""
    return sync_conn.execute(
        """
        SELECT generation, password_attempt_count
        FROM totp_recovery_codes
        WHERE user_id = %s
        ORDER BY generation, position
        """,
        (user_id,),
    ).fetchall()


def _generation_state(sync_conn, user_id: int):
    """Read active and pending recovery-code generations."""
    return sync_conn.execute(
        """
        SELECT totp_recovery_code_generation, pending_totp_recovery_code_generation
        FROM users
        WHERE id = %s
        """,
        (user_id,),
    ).fetchone()


class TestRecoveryCodeGenerationLifecycle:
    """A newly staged or activated generation starts every counter at zero
    and leaves no obsolete generation's rows behind."""

    async def test_staging_a_new_generation_starts_every_counter_at_zero(
        self, db_pool, user_factory, sync_conn
    ):
        """Verify staging a new generation starts every counter at zero."""
        user = user_factory()

        async with get_db_cursor(db_pool) as cur:
            staged = await stage_recovery_code_set_cur(
                cur, user_id=user.id, codes=generate_recovery_codes()
            )

        rows = _generation_rows(sync_conn, user.id)
        assert {generation for generation, _count in rows} == {staged.generation}
        assert all(count == 0 for _generation, count in rows)

    async def test_activating_a_pending_generation_removes_the_obsolete_one(
        self, db_pool, user_factory, sync_conn
    ):
        """A second staging, then activation, leaves exactly the newly
        activated generation's rows — the prior active generation's rows are
        gone, and every counter in the surviving generation reads zero."""
        user = user_factory()
        async with get_db_cursor(db_pool) as cur:
            first = await stage_recovery_code_set_cur(
                cur, user_id=user.id, codes=generate_recovery_codes()
            )
        # Promote the first staged generation to active so the second
        # staging below leaves an obsolete *active* generation to remove.
        sync_conn.execute(
            "UPDATE users SET totp_recovery_code_generation = %s, "
            "pending_totp_recovery_code_generation = NULL WHERE id = %s",
            (first.generation, user.id),
        )
        sync_conn.commit()

        second_codes = generate_recovery_codes()
        async with get_db_cursor(db_pool) as cur:
            second = await stage_recovery_code_set_cur(cur, user_id=user.id, codes=second_codes)
            activated = await activate_pending_recovery_code_set_cur(
                cur, user_id=user.id, candidate_code=second_codes[0]
            )

        assert activated is True
        rows = _generation_rows(sync_conn, user.id)
        assert {generation for generation, _count in rows} == {second.generation}
        assert all(count == 0 for _generation, count in rows)
        assert _generation_state(sync_conn, user.id) == (second.generation, None)

    async def test_activating_an_unmatched_code_leaves_both_generations_intact(
        self, db_pool, user_factory, sync_conn
    ):
        """POSITIVE CONTROL for the removal above: a candidate that matches no
        unused code in the pending generation activates nothing, so both the
        active and pending generations' rows survive untouched."""
        user = user_factory()
        async with get_db_cursor(db_pool) as cur:
            first = await stage_recovery_code_set_cur(
                cur, user_id=user.id, codes=generate_recovery_codes()
            )
        sync_conn.execute(
            "UPDATE users SET totp_recovery_code_generation = %s, "
            "pending_totp_recovery_code_generation = NULL WHERE id = %s",
            (first.generation, user.id),
        )
        sync_conn.commit()

        async with get_db_cursor(db_pool) as cur:
            second = await stage_recovery_code_set_cur(
                cur, user_id=user.id, codes=generate_recovery_codes()
            )
            activated = await activate_pending_recovery_code_set_cur(
                cur, user_id=user.id, candidate_code=_WRONG_CODE
            )

        assert activated is False
        rows = _generation_rows(sync_conn, user.id)
        assert {generation for generation, _count in rows} == {first.generation, second.generation}
        assert all(count == 0 for _generation, count in rows)
        assert _generation_state(sync_conn, user.id) == (first.generation, second.generation)


def _install_known_code(sync_conn, user_id: int, *, generation: int, code: str) -> None:
    """Give a user one known, unused active recovery code at ``generation``."""
    canonical = normalize_recovery_code(code)
    assert canonical is not None
    sync_conn.execute(
        "UPDATE users SET totp_recovery_code_generation = %s WHERE id = %s",
        (generation, user_id),
    )
    sync_conn.execute(
        """
        INSERT INTO totp_recovery_codes (user_id, generation, position, code_hash)
        VALUES (%s, %s, 1, %s)
        """,
        (user_id, generation, hash_token(canonical)),
    )
    sync_conn.commit()


def _authorize_recovery(sync_conn, user_id: int, *, expires_at: datetime | None = None) -> None:
    """Install a live, revision-bound recovery authorization for one user."""
    sync_conn.execute(
        """
        UPDATE users
        SET totp_secret = NULL,
            last_totp_step = NULL,
            totp_recovery_required = true,
            totp_recovery_authorized_at = clock_timestamp(),
            totp_recovery_expires_at = %s,
            totp_recovery_auth_revision = auth_revision
        WHERE id = %s
        """,
        (expires_at or (datetime.now(UTC) + timedelta(minutes=30)), user_id),
    )
    sync_conn.commit()


def _recovery_code_rows(sync_conn, user_id: int):
    """Read recovery-code generation, position, usage and attempt counts in code order."""
    return sync_conn.execute(
        """
        SELECT generation, position, used_at, password_attempt_count
        FROM totp_recovery_codes
        WHERE user_id = %s
        ORDER BY generation, position
        """,
        (user_id,),
    ).fetchall()


def _user_recovery_snapshot(sync_conn, user_id: int):
    """Read credentials, recovery authority, generation and login-lock state."""
    return sync_conn.execute(
        """
        SELECT password_hash, auth_revision, totp_recovery_required,
               totp_recovery_authorized_at, totp_recovery_expires_at,
               totp_recovery_auth_revision, totp_recovery_code_generation,
               failed_login_count, locked_until
        FROM users
        WHERE id = %s
        """,
        (user_id,),
    ).fetchone()


def _session_count(sync_conn, user_id: int) -> int:
    """Count stored sessions for the user, including expired rows."""
    return sync_conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (user_id,)
    ).fetchone()[0]


class TestRecoveryRedemptionRejectsUnusableCodes:
    """A code that cannot be spent touches none of the account's rows."""

    @pytest.fixture
    def redeemable_user(self, user_factory, sync_conn):
        """Create a user with a known active recovery code and current recovery authorization."""
        user = user_factory()
        _install_known_code(sync_conn, user.id, generation=1, code=_KNOWN_CODE)
        _authorize_recovery(sync_conn, user.id)
        return user

    @pytest.mark.parametrize(
        "case",
        ["malformed", "random_wellformed", "wrong_generation", "used", "exhausted"],
        ids=[
            "malformed_code",
            "random_wellformed_code",
            "wrong_generation_code",
            "already_used_code",
            "exhausted_code",
        ],
    )
    async def test_unusable_code_with_a_valid_email_writes_nothing(
        self, db_pool, redeemable_user, sync_conn, case
    ):
        """Every case matches the nonlocking candidate query's exclusion
        conditions (totp_recover.py:415-422) and so never reserves, verifies,
        or consumes anything belonging to this account."""
        submitted_code = _KNOWN_CODE
        if case == "malformed":
            submitted_code = "not-a-recovery-code"
        elif case == "random_wellformed":
            submitted_code = _UNRELATED_WELLFORMED_CODE
        elif case == "wrong_generation":
            sync_conn.execute(
                "DELETE FROM totp_recovery_codes WHERE user_id = %s", (redeemable_user.id,)
            )
            sync_conn.execute(
                "UPDATE users SET totp_recovery_code_generation = 2 WHERE id = %s",
                (redeemable_user.id,),
            )
            _install_known_code(
                sync_conn, redeemable_user.id, generation=2, code=_UNRELATED_WELLFORMED_CODE
            )
        elif case == "used":
            sync_conn.execute(
                "UPDATE totp_recovery_codes SET used_at = clock_timestamp() "
                "WHERE user_id = %s AND code_hash = %s",
                (redeemable_user.id, hash_token(normalize_recovery_code(_KNOWN_CODE))),
            )
            sync_conn.commit()
        elif case == "exhausted":
            sync_conn.execute(
                "UPDATE totp_recovery_codes SET password_attempt_count = %s "
                "WHERE user_id = %s AND code_hash = %s",
                (
                    TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
                    redeemable_user.id,
                    hash_token(normalize_recovery_code(_KNOWN_CODE)),
                ),
            )
            sync_conn.commit()

        before_user = _user_recovery_snapshot(sync_conn, redeemable_user.id)
        before_codes = _recovery_code_rows(sync_conn, redeemable_user.id)
        before_sessions = _session_count(sync_conn, redeemable_user.id)

        with pytest.raises(TotpRecoveryRedemptionRejected) as excinfo:
            await redeem_totp_recovery(
                db_pool,
                email=redeemable_user.email,
                password=redeemable_user.password,
                recovery_code=submitted_code,
                ip_address="203.0.113.10",
            )

        assert excinfo.value.reason == "invalid_credentials"
        assert excinfo.value.user_id is None
        assert _user_recovery_snapshot(sync_conn, redeemable_user.id) == before_user
        assert _recovery_code_rows(sync_conn, redeemable_user.id) == before_codes
        assert _session_count(sync_conn, redeemable_user.id) == before_sessions

    async def test_the_exact_matching_unused_code_does_redeem(
        self, db_pool, redeemable_user, sync_conn
    ):
        """POSITIVE CONTROL: the genuine, unused code for the active
        generation is accepted and creates exactly one recovery session."""
        result = await redeem_totp_recovery(
            db_pool,
            email=redeemable_user.email,
            password=redeemable_user.password,
            recovery_code=_KNOWN_CODE,
            ip_address="203.0.113.11",
        )

        assert result.user_id == redeemable_user.id
        assert _session_count(sync_conn, redeemable_user.id) == 1


class TestConcurrentValidRedemption:
    """Race committed SQL reservations/finalisation with controlled valid password proofs."""

    async def test_at_most_one_session_and_the_code_is_consumed_once(
        self, user_factory, sync_conn, monkeypatch
    ) -> None:
        """Verify at most one session and the code is consumed once."""
        user = user_factory()
        _install_known_code(sync_conn, user.id, generation=1, code=_KNOWN_CODE)
        _authorize_recovery(sync_conn, user.id)

        row = sync_conn.execute(
            "SELECT password_hash FROM users WHERE id = %s", (user.id,)
        ).fetchone()
        assert row is not None
        expected_hash = row[0]
        sync_conn.commit()
        proof = await password_verification.verify_password_hash(
            password_hash=expected_hash,
            password=user.password,
            user_id=user.id,
            operation="totp_recovery",
        )
        assert isinstance(proof, password_verification.PasswordVerified)

        # Keep the database race independent of the finite hash-admission queue.
        # All permitted reservations must commit before any finalisation starts.
        proofs_ready = asyncio.Barrier(TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT)

        async def verify_known_password(
            *, password_hash: str, password: str, user_id: int, operation: str
        ) -> password_verification.PasswordVerificationResult:
            """Check the expected password-work arguments, synchronize proofs and return
            PasswordVerified.
            """
            assert password_hash == expected_hash
            assert password == user.password
            assert user_id == user.id
            assert operation == "totp_recovery"
            await proofs_ready.wait()
            return password_verification.PasswordVerified()

        verify = create_autospec(
            password_verification.verify_password_hash,
            spec_set=True,
            side_effect=verify_known_password,
        )
        dummy = create_autospec(
            password_verification.verify_dummy, spec_set=True, return_value=None
        )
        monkeypatch.setattr(totp_recover, "verify_password_hash", verify)
        monkeypatch.setattr(totp_recover, "verify_dummy", dummy)

        caller_count = TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT + 2
        barrier = asyncio.Barrier(caller_count)

        async def redeem_on_independent_connection(index: int):
            """Redeem the known recovery code after a barrier; return success or rejection reason."""
            async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn:
                await barrier.wait()
                try:
                    result = await redeem_totp_recovery(
                        conn,
                        email=user.email,
                        password=user.password,
                        recovery_code=_KNOWN_CODE,
                        ip_address=f"203.0.113.{20 + index}",
                    )
                except TotpRecoveryRedemptionRejected as exc:
                    return ("rejected", exc.reason)
                return ("ok", result)

        async with asyncio.timeout(10):
            async with asyncio.TaskGroup() as group:
                tasks = [
                    group.create_task(redeem_on_independent_connection(index))
                    for index in range(caller_count)
                ]
        results = [task.result() for task in tasks]

        assert verify.await_count == TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT
        assert dummy.await_count == caller_count - TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT

        successes = [result for kind, result in results if kind == "ok"]
        rejections = [reason for kind, reason in results if kind == "rejected"]

        assert len(successes) == 1
        assert len(rejections) == caller_count - 1
        # The public route (routes/auth/totp_recover.py:88-99) never surfaces
        # any of these reasons — every rejection renders one generic error —
        # so every loser is merely required to be a rejection, not a specific one.
        assert all(
            reason in {"invalid_credentials", "recovery_not_authorized", "account_ineligible"}
            for reason in rejections
        )
        assert successes[0].user_id == user.id

        assert _session_count(sync_conn, user.id) == 1
        used_codes = sync_conn.execute(
            "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = %s AND used_at IS NOT NULL",
            (user.id,),
        ).fetchone()[0]
        assert used_codes == 1


class TestRecoveryRedemptionRejectsStaleStateAtFinalisation:
    """Any account-state change between reservation and the final lock fails
    the whole redemption rather than partially applying it."""

    @pytest.fixture
    def redeemable_user(self, user_factory, sync_conn):
        """Create a user with a known active recovery code and current recovery authorization."""
        user = user_factory()
        _install_known_code(sync_conn, user.id, generation=1, code=_KNOWN_CODE)
        _authorize_recovery(sync_conn, user.id)
        return user

    @pytest.mark.parametrize(
        ("case", "expected_reason"),
        [
            pytest.param(
                "password_hash_changed", "auth_state_changed", id="password_changed_meanwhile"
            ),
            pytest.param(
                "authority_withdrawn", "account_ineligible", id="recovery_authority_withdrawn"
            ),
            pytest.param(
                "authorization_expired", "recovery_expired", id="authorization_expired_meanwhile"
            ),
            pytest.param(
                "generation_replaced", "invalid_credentials", id="active_generation_replaced"
            ),
        ],
    )
    async def test_a_stale_snapshot_at_finalisation_fails_the_whole_redemption(
        self, db_pool, redeemable_user, sync_conn, monkeypatch, case, expected_reason
    ):
        """Verify a stale snapshot at finalisation fails the whole redemption."""
        real_password_work = password_verification.run_password_work

        async def verify_then_mutate_account_state(function, *args):
            """Complete real password work, then apply and commit the parametrized authority
            mutation.
            """
            result = await real_password_work(function, *args)
            if case == "password_hash_changed":
                sync_conn.execute(
                    "UPDATE users SET password_hash = %s WHERE id = %s",
                    (password_hasher.hash("a-completely-different-password"), redeemable_user.id),
                )
            elif case == "authority_withdrawn":
                # The schema's users_totp_recovery_state_check only allows
                # totp_recovery_required=false together with every recovery
                # column nulled — exactly what a completed, independent
                # recovery or fresh enrollment would leave behind.
                sync_conn.execute(
                    """
                    UPDATE users
                    SET totp_recovery_required = false,
                        totp_recovery_expires_at = NULL,
                        totp_recovery_authorized_at = NULL,
                        totp_recovery_auth_revision = NULL
                    WHERE id = %s
                    """,
                    (redeemable_user.id,),
                )
            elif case == "authorization_expired":
                # authorized_at < expires_at is a DB check constraint, so age
                # both fields together into the past rather than pushing
                # expires_at alone behind the still-recent authorized_at.
                sync_conn.execute(
                    """
                    UPDATE users
                    SET totp_recovery_authorized_at = clock_timestamp() - INTERVAL '2 hours',
                        totp_recovery_expires_at = clock_timestamp() - INTERVAL '1 hour'
                    WHERE id = %s
                    """,
                    (redeemable_user.id,),
                )
            elif case == "generation_replaced":
                sync_conn.execute(
                    "DELETE FROM totp_recovery_codes WHERE user_id = %s", (redeemable_user.id,)
                )
                sync_conn.execute(
                    "UPDATE users SET totp_recovery_code_generation = 2 WHERE id = %s",
                    (redeemable_user.id,),
                )
                _install_known_code(
                    sync_conn, redeemable_user.id, generation=2, code=_UNRELATED_WELLFORMED_CODE
                )
            sync_conn.commit()
            return result

        # autospecced against run_password_work's real signature so a future
        # parameter it gains would raise here rather than silently stop being
        # exercised by this fault injection.
        autospecced_password_work = create_autospec(
            password_verification.run_password_work,
            spec_set=True,
            side_effect=verify_then_mutate_account_state,
        )
        monkeypatch.setattr(password_verification, "run_password_work", autospecced_password_work)

        with pytest.raises(TotpRecoveryRedemptionRejected) as excinfo:
            await redeem_totp_recovery(
                db_pool,
                email=redeemable_user.email,
                password=redeemable_user.password,
                recovery_code=_KNOWN_CODE,
                ip_address="203.0.113.30",
            )

        assert excinfo.value.reason == expected_reason
        assert _session_count(sync_conn, redeemable_user.id) == 0
        active_generation = sync_conn.execute(
            "SELECT totp_recovery_code_generation FROM users WHERE id = %s",
            (redeemable_user.id,),
        ).fetchone()[0]
        consumed_in_active_generation = sync_conn.execute(
            """
            SELECT COUNT(*) FROM totp_recovery_codes
            WHERE user_id = %s AND generation = %s AND used_at IS NOT NULL
            """,
            (redeemable_user.id, active_generation),
        ).fetchone()[0]
        assert consumed_in_active_generation == 0

    async def test_an_unchanged_snapshot_at_finalisation_does_redeem(
        self, db_pool, redeemable_user, sync_conn
    ):
        """POSITIVE CONTROL: with nothing mutated meanwhile, redemption succeeds."""
        result = await redeem_totp_recovery(
            db_pool,
            email=redeemable_user.email,
            password=redeemable_user.password,
            recovery_code=_KNOWN_CODE,
            ip_address="203.0.113.31",
        )
        assert result.user_id == redeemable_user.id
        assert _session_count(sync_conn, redeemable_user.id) == 1

"""Unit tests for `app.services.totp.begin_totp_rotation` and the password
snapshot it depends on (`_verify_rotation_password_snapshot`).

begin_totp_rotation has three gates in order: (1) a durable session step-up
budget, spent before any password work; (2) a fresh Argon2 + current-TOTP
proof taken outside any row lock; (3) a final transaction that re-proves the
password hash and auth revision are unchanged, locks the exact full session,
and only then issues the one-time replacement seed. Every rejection at each
gate has a positive control proving the adjacent permitted case still reaches
READY with a replacement seed.

No DB: get_db_cursor is patched with an async context manager over a mock
cursor. Time is frozen by replacing the `time` module reference inside
app.services.totp (matched_step reads time.time() directly).
"""

from unittest.mock import create_autospec, patch

import pyotp
import pytest
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

import app.services.authentication as authentication_module
import app.services.totp as totp_module
from app.services.credential_attempts import SessionStepUpAttemptOutcome
from app.services.crypto import decrypt_value, encrypt_value
from app.services.session_ids import hash_session_id
from app.services.totp import (
    TotpDecryptionError,
    TotpRotationStartOutcome,
    begin_totp_rotation,
)
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

SECRET = "JBSWY3DPEHPK3PXP"
FIXED_TS = 1_750_000_000
FIXED_STEP = FIXED_TS // 30
USER_ID = 917
SESSION_ID = "rotation-start-authorizing-session"
SESSION_HASH = hash_session_id(SESSION_ID)
PASSWORD = "correct horse battery staple"
PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$rotation-snapshot"
AUTH_REVISION = 14


class _FrozenTime:
    def __init__(self, ts: float):
        self._ts = ts

    def time(self) -> float:
        return self._ts


def _freeze_totp_time(monkeypatch, ts: float) -> None:
    monkeypatch.setattr(totp_module, "time", _FrozenTime(ts))


def _row(**overrides) -> dict[str, object]:
    row = {
        "password_hash": PASSWORD_HASH,
        "auth_revision": AUTH_REVISION,
        "is_active": True,
        "email_verified": True,
        "auth_method": "local",
        "totp_secret": encrypt_value(SECRET),
        "totp_recovery_required": False,
        "last_totp_step": None,
        "login_unlocked": True,
    }
    row.update(overrides)
    return row


class TestVerifyRotationPasswordSnapshot:
    """The out-of-transaction Argon2 proof, and its dummy-work fail-closed paths."""

    async def _run(self, *, row, run_password_work_double):
        cur = make_async_cursor(fetchone=row)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        verify_dummy = create_autospec(authentication_module.verify_dummy, spec_set=True)
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "run_password_work", run_password_work_double),
            patch.object(authentication_module, "verify_dummy", verify_dummy),
        ):
            result = await totp_module._verify_rotation_password_snapshot(
                make_mock_pool(), user_id=USER_ID, password=PASSWORD
            )
        return result, verify_dummy, run_password_work_double

    async def test_missing_password_hash_performs_only_dummy_work(self):
        password_work = create_autospec(totp_module.run_password_work, spec_set=True)
        result, verify_dummy, _ = await self._run(
            row={"password_hash": None, "auth_revision": AUTH_REVISION},
            run_password_work_double=password_work,
        )
        assert result is None
        verify_dummy.assert_awaited_once_with(PASSWORD)
        password_work.assert_not_awaited()

    async def test_wrong_password_returns_none_without_dummy_work(self):
        password_work = create_autospec(
            totp_module.run_password_work,
            side_effect=VerifyMismatchError("wrong password"),
            spec_set=True,
        )
        result, verify_dummy, _ = await self._run(
            row=_row(), run_password_work_double=password_work
        )
        assert result is None
        verify_dummy.assert_not_awaited()

    @pytest.mark.parametrize(
        "verification_error",
        [InvalidHashError("bad hash"), VerificationError("unverifiable hash")],
        ids=["invalid_hash", "verification_error"],
    )
    async def test_unverifiable_hash_fails_closed_with_dummy_work(self, verification_error):
        password_work = create_autospec(
            totp_module.run_password_work, side_effect=verification_error, spec_set=True
        )
        result, verify_dummy, _ = await self._run(
            row=_row(), run_password_work_double=password_work
        )
        assert result is None
        verify_dummy.assert_awaited_once_with(PASSWORD)

    async def test_correct_password_returns_the_hash_and_revision_snapshot(self):
        """Positive control for every rejection above."""
        password_work = create_autospec(
            totp_module.run_password_work, return_value=True, spec_set=True
        )
        result, verify_dummy, _ = await self._run(
            row=_row(), run_password_work_double=password_work
        )
        assert result == (PASSWORD_HASH, AUTH_REVISION)
        verify_dummy.assert_not_awaited()


class TestBeginTotpRotationArgumentValidation:
    async def test_negative_valid_window_is_rejected(self):
        with pytest.raises(ValueError, match="valid_window must be non-negative"):
            await begin_totp_rotation(
                make_mock_pool(),
                USER_ID,
                PASSWORD,
                "123456",
                session_id=SESSION_ID,
                valid_window=-1,
            )

    async def test_non_positive_period_is_rejected(self):
        with pytest.raises(ValueError, match="period must be positive"):
            await begin_totp_rotation(
                make_mock_pool(),
                USER_ID,
                PASSWORD,
                "123456",
                session_id=SESSION_ID,
                period=0,
            )


class TestBeginTotpRotationReservationGate:
    """The durable step-up budget is spent, and honored, before any password work."""

    @pytest.mark.parametrize(
        ("reservation_outcome", "expected"),
        [
            (
                SessionStepUpAttemptOutcome.INVALID_SESSION,
                TotpRotationStartOutcome.SESSION_EXPIRED,
            ),
            (
                SessionStepUpAttemptOutcome.ACCOUNT_LOCKED,
                TotpRotationStartOutcome.ACCOUNT_LOCKED,
            ),
            (
                SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED,
                TotpRotationStartOutcome.ATTEMPTS_EXHAUSTED,
            ),
        ],
        ids=["invalid_session_maps_to_session_expired", "account_locked", "attempts_exhausted"],
    )
    async def test_refused_reservation_short_circuits_before_password_work(
        self, reservation_outcome, expected
    ):
        reserve = create_autospec(
            totp_module.reserve_session_step_up_attempt,
            return_value=reservation_outcome,
            spec_set=True,
        )
        snapshot = create_autospec(
            totp_module._verify_rotation_password_snapshot,
            side_effect=AssertionError("must not verify a password after a refused reservation"),
            spec_set=True,
        )
        with (
            patch.object(totp_module, "reserve_session_step_up_attempt", reserve),
            patch.object(totp_module, "_verify_rotation_password_snapshot", snapshot),
        ):
            result = await begin_totp_rotation(
                make_mock_pool(), USER_ID, PASSWORD, "123456", session_id=SESSION_ID
            )
        assert result.outcome is expected
        assert result.secret is None

    async def test_unhandled_reservation_outcome_raises_runtime_error(self):
        reserve = create_autospec(
            totp_module.reserve_session_step_up_attempt,
            return_value="not-a-real-outcome",
            spec_set=True,
        )
        with (
            patch.object(totp_module, "reserve_session_step_up_attempt", reserve),
            pytest.raises(RuntimeError, match="Unhandled step-up reservation outcome"),
        ):
            await begin_totp_rotation(
                make_mock_pool(), USER_ID, PASSWORD, "123456", session_id=SESSION_ID
            )

    async def test_reserved_budget_proceeds_to_password_verification(self):
        """Positive control above: RESERVED reaches the password-verification gate."""
        reserve = create_autospec(
            totp_module.reserve_session_step_up_attempt,
            return_value=SessionStepUpAttemptOutcome.RESERVED,
            spec_set=True,
        )
        snapshot = create_autospec(
            totp_module._verify_rotation_password_snapshot, return_value=None, spec_set=True
        )
        with (
            patch.object(totp_module, "reserve_session_step_up_attempt", reserve),
            patch.object(totp_module, "_verify_rotation_password_snapshot", snapshot),
        ):
            result = await begin_totp_rotation(
                make_mock_pool(), USER_ID, PASSWORD, "123456", session_id=SESSION_ID
            )
        snapshot.assert_awaited_once()
        assert result.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS


def _patched_reservation_and_snapshot(monkeypatch, snapshot_result=(PASSWORD_HASH, AUTH_REVISION)):
    reserve = create_autospec(
        totp_module.reserve_session_step_up_attempt,
        return_value=SessionStepUpAttemptOutcome.RESERVED,
        spec_set=True,
    )
    snapshot = create_autospec(
        totp_module._verify_rotation_password_snapshot, return_value=snapshot_result, spec_set=True
    )
    monkeypatch.setattr(totp_module, "reserve_session_step_up_attempt", reserve)
    monkeypatch.setattr(totp_module, "_verify_rotation_password_snapshot", snapshot)


class TestBeginTotpRotationCredentialAndCodeValidation:
    async def test_missing_password_snapshot_is_invalid_credentials(self, monkeypatch):
        _patched_reservation_and_snapshot(monkeypatch, snapshot_result=None)
        result = await begin_totp_rotation(
            make_mock_pool(),
            USER_ID,
            "wrong password",
            pyotp.TOTP(SECRET).at(FIXED_TS),
            session_id=SESSION_ID,
        )
        assert result.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS

    async def test_malformed_current_code_is_invalid_credentials(self, monkeypatch):
        _patched_reservation_and_snapshot(monkeypatch)
        result = await begin_totp_rotation(
            make_mock_pool(), USER_ID, PASSWORD, "not-six-digits", session_id=SESSION_ID
        )
        assert result.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS


class TestBeginTotpRotationFinalTransaction:
    """The re-proving final transaction: eligibility, revision fencing, session, and secret."""

    async def _begin(
        self, monkeypatch, *, row, session_row=None, session_missing=False, valid_code=True
    ):
        if session_row is None and not session_missing:
            session_row = {"exists": 1}
        _freeze_totp_time(monkeypatch, FIXED_TS)
        _patched_reservation_and_snapshot(monkeypatch)
        cur = make_async_cursor(fetchone=[row, session_row])
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        code = pyotp.TOTP(SECRET).at(FIXED_TS) if valid_code else "000000"
        with patch.object(totp_module, "get_db_cursor", acquire):
            result = await begin_totp_rotation(
                make_mock_pool(), USER_ID, PASSWORD, code, session_id=SESSION_ID
            )
        return result, cur

    @pytest.mark.parametrize(
        "row",
        [
            _row(is_active=False),
            _row(email_verified=False),
            _row(auth_method="shibboleth"),
            _row(totp_recovery_required=True),
            _row(login_unlocked=False),
        ],
        ids=[
            "inactive_account",
            "unverified_email",
            "non_local_auth_method",
            "recovery_in_progress",
            "login_locked",
        ],
    )
    async def test_ineligible_account_state_is_rejected(self, monkeypatch, row):
        result, cur = await self._begin(monkeypatch, row=row)
        assert result.outcome is TotpRotationStartOutcome.INELIGIBLE
        assert cur.execute.await_count == 1

    async def test_changed_password_hash_since_verification_is_session_expired(self, monkeypatch):
        row = _row(password_hash="$argon2id$v=19$m=65536,t=3,p=4$changed-since-verification")
        result, cur = await self._begin(monkeypatch, row=row)
        assert result.outcome is TotpRotationStartOutcome.SESSION_EXPIRED
        assert cur.execute.await_count == 1

    async def test_changed_auth_revision_since_verification_is_session_expired(self, monkeypatch):
        row = _row(auth_revision=AUTH_REVISION + 1)
        result, cur = await self._begin(monkeypatch, row=row)
        assert result.outcome is TotpRotationStartOutcome.SESSION_EXPIRED
        assert cur.execute.await_count == 1

    async def test_missing_exact_full_session_is_session_expired(self, monkeypatch):
        result, cur = await self._begin(monkeypatch, row=_row(), session_missing=True)
        assert result.outcome is TotpRotationStartOutcome.SESSION_EXPIRED
        assert cur.execute.await_count == 2

    async def test_missing_active_secret_is_current_secret_missing(self, monkeypatch):
        result, _ = await self._begin(monkeypatch, row=_row(totp_secret=None))
        assert result.outcome is TotpRotationStartOutcome.CURRENT_SECRET_MISSING

    async def test_undecryptable_active_secret_raises_totp_decryption_error(self, monkeypatch):
        _freeze_totp_time(monkeypatch, FIXED_TS)
        _patched_reservation_and_snapshot(monkeypatch)
        row = _row(totp_secret="not-a-valid-fernet-token")
        cur = make_async_cursor(fetchone=[row, {"exists": 1}])
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            pytest.raises(TotpDecryptionError) as caught,
        ):
            await begin_totp_rotation(
                make_mock_pool(),
                USER_ID,
                PASSWORD,
                pyotp.TOTP(SECRET).at(FIXED_TS),
                session_id=SESSION_ID,
            )
        assert caught.value.user_id == USER_ID

    async def test_wrong_current_code_is_invalid_credentials(self, monkeypatch):
        result, _ = await self._begin(monkeypatch, row=_row(), valid_code=False)
        assert result.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS

    async def test_replayed_current_code_is_rejected(self, monkeypatch):
        result, cur = await self._begin(monkeypatch, row=_row(last_totp_step=FIXED_STEP))
        assert result.outcome is TotpRotationStartOutcome.REPLAYED_CURRENT_CODE
        statements = [str(call.args[0]).strip().upper() for call in cur.execute.await_args_list]
        assert not any(statement.startswith("INSERT") for statement in statements)

    async def test_ready_outcome_returns_a_replacement_seed_and_stages_the_challenge(
        self, monkeypatch
    ):
        """Positive control for every rejection in this class."""
        result, cur = await self._begin(monkeypatch, row=_row())

        assert result.outcome is TotpRotationStartOutcome.READY
        assert isinstance(result.secret, str)
        assert result.secret != SECRET

        insert_call = next(
            call
            for call in cur.execute.await_args_list
            if str(call.args[0]).strip().upper().startswith("INSERT")
        )
        (
            inserted_user_id,
            inserted_session_hash,
            inserted_auth_revision,
            inserted_ciphertext,
            inserted_ttl_seconds,
        ) = insert_call.args[1]
        assert inserted_user_id == USER_ID
        assert inserted_session_hash == SESSION_HASH
        assert inserted_auth_revision == AUTH_REVISION
        assert decrypt_value(inserted_ciphertext) == result.secret
        assert inserted_ttl_seconds == 300

        update_call = next(
            call
            for call in cur.execute.await_args_list
            if str(call.args[0]).strip().upper().startswith("UPDATE")
        )
        assert update_call.args[1] == (FIXED_STEP, USER_ID)

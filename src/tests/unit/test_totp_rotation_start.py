"""Password proof, session fencing, and pending-seed issuance when starting TOTP rotation."""

from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

import pyotp
import pytest

import app.services.totp as totp_module
from app.services.credential_attempts import SessionStepUpAttemptOutcome
from app.services.password_verification import (
    PasswordFailureReason,
    PasswordVerificationFailure,
    VerifiedPasswordSnapshot,
)
from app.services.session_ids import hash_session_id
from app.services.totp import (
    TotpDecryptionError,
    TotpRotationStartOutcome,
    begin_totp_rotation,
)
from app.services.totp_crypto import decrypt_value, encrypt_value
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

SECRET = "JBSWY3DPEHPK3PXP"
FIXED_TS = 1_750_000_000
FIXED_STEP = FIXED_TS // 30
FIXED_NOW = datetime.fromtimestamp(FIXED_TS, UTC)
USER_ID = 917
SESSION_ID = "rotation-start-authorizing-session"
SESSION_HASH = hash_session_id(SESSION_ID)
PASSWORD = "correct horse battery staple"
PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$rotation-snapshot"
AUTH_REVISION = 14
_VERIFIED_SNAPSHOT = VerifiedPasswordSnapshot(PASSWORD_HASH, AUTH_REVISION)


class _FrozenTime:
    """Provide a time-module stand-in that returns one fixed epoch timestamp."""

    def __init__(self, ts: float):
        """Store the fixed timestamp returned by this clock."""
        self._ts = ts

    def time(self) -> float:
        """Return the stored timestamp without advancing it."""
        return self._ts


def _freeze_totp_time(monkeypatch, ts: float) -> None:
    """Replace the TOTP module clock with a fixed timestamp in epoch seconds."""
    monkeypatch.setattr(totp_module, "time", _FrozenTime(ts))


def _row(**overrides) -> dict[str, object]:
    """Build an eligible password/TOTP snapshot with no consumed step and caller field overrides."""
    row = {
        "password_hash": PASSWORD_HASH,
        "auth_revision": AUTH_REVISION,
        "is_active": True,
        "email_verified": True,
        "auth_method": "local",
        "totp_secret": encrypt_value(SECRET),
        "totp_recovery_required": False,
        "last_totp_step": None,
        "locked_until": None,
    }
    row.update(overrides)
    return row


class TestBeginTotpRotationArgumentValidation:
    """Cover begin TOTP rotation argument validation."""

    async def test_negative_valid_window_is_rejected(self):
        """Check negative valid window is rejected (ValueError)."""
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
        """Check non positive period is rejected (ValueError)."""
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
        """Check refused reservation short circuits before password work."""
        reserve = create_autospec(
            totp_module.reserve_session_step_up_attempt,
            return_value=reservation_outcome,
            spec_set=True,
        )
        snapshot = create_autospec(
            totp_module.verify_password_snapshot,
            side_effect=AssertionError("must not verify a password after a refused reservation"),
            spec_set=True,
        )
        with (
            patch.object(totp_module, "reserve_session_step_up_attempt", reserve),
            patch.object(totp_module, "verify_password_snapshot", snapshot),
        ):
            result = await begin_totp_rotation(
                make_mock_pool(), USER_ID, PASSWORD, "123456", session_id=SESSION_ID
            )
        assert result.outcome is expected
        assert result.secret is None

    async def test_unhandled_reservation_outcome_raises_runtime_error(self):
        """Check unhandled reservation outcome raises runtime error."""
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
        """Check reserved budget proceeds to password verification."""
        reserve = create_autospec(
            totp_module.reserve_session_step_up_attempt,
            return_value=SessionStepUpAttemptOutcome.RESERVED,
            spec_set=True,
        )
        snapshot = create_autospec(
            totp_module.verify_password_snapshot,
            return_value=PasswordVerificationFailure(PasswordFailureReason.MISSING_HASH, None),
            spec_set=True,
        )
        with (
            patch.object(totp_module, "reserve_session_step_up_attempt", reserve),
            patch.object(totp_module, "verify_password_snapshot", snapshot),
        ):
            result = await begin_totp_rotation(
                make_mock_pool(), USER_ID, PASSWORD, "123456", session_id=SESSION_ID
            )
        snapshot.assert_awaited_once()
        assert result.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS


def _patched_reservation_and_snapshot(monkeypatch, snapshot_result=_VERIFIED_SNAPSHOT):
    """Patch successful session-budget reservation and the selected password-snapshot result."""
    reserve = create_autospec(
        totp_module.reserve_session_step_up_attempt,
        return_value=SessionStepUpAttemptOutcome.RESERVED,
        spec_set=True,
    )
    snapshot = create_autospec(
        totp_module.verify_password_snapshot, return_value=snapshot_result, spec_set=True
    )
    monkeypatch.setattr(totp_module, "reserve_session_step_up_attempt", reserve)
    monkeypatch.setattr(totp_module, "verify_password_snapshot", snapshot)


class TestBeginTotpRotationCredentialAndCodeValidation:
    """Cover begin TOTP rotation credential and code validation."""

    async def test_missing_password_snapshot_is_invalid_credentials(self, monkeypatch):
        """Check missing password snapshot is invalid credentials."""
        _patched_reservation_and_snapshot(
            monkeypatch,
            snapshot_result=PasswordVerificationFailure(PasswordFailureReason.MISSING_HASH, None),
        )
        result = await begin_totp_rotation(
            make_mock_pool(),
            USER_ID,
            "wrong password",
            pyotp.TOTP(SECRET).at(FIXED_TS),
            session_id=SESSION_ID,
        )
        assert result.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS

    async def test_malformed_current_code_is_invalid_credentials(self, monkeypatch):
        """Check malformed current code is invalid credentials."""
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
        """Start rotation at fixed time with scripted account/session rows; return the outcome and
        cursor.
        """
        if session_row is None and not session_missing:
            session_row = {"expires_at": FIXED_NOW + timedelta(hours=1)}
        _freeze_totp_time(monkeypatch, FIXED_TS)
        _patched_reservation_and_snapshot(monkeypatch)
        cur = make_async_cursor(fetchone=[row, session_row, None, {"database_now": FIXED_NOW}])
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
        ],
        ids=[
            "inactive_account",
            "unverified_email",
            "non_local_auth_method",
            "recovery_in_progress",
        ],
    )
    async def test_ineligible_account_state_is_rejected(self, monkeypatch, row):
        """Check ineligible account state is rejected."""
        result, cur = await self._begin(monkeypatch, row=row)
        assert result.outcome is TotpRotationStartOutcome.INELIGIBLE
        assert cur.execute.await_count == 1

    async def test_existing_full_session_can_prove_rotation_during_a_login_lock(self, monkeypatch):
        """Check existing full session can prove rotation during a login lock."""
        result, _cur = await self._begin(
            monkeypatch, row=_row(locked_until=FIXED_NOW + timedelta(minutes=5))
        )
        assert result.outcome is TotpRotationStartOutcome.READY
        assert result.secret is not None

    async def test_changed_password_hash_since_verification_is_session_expired(self, monkeypatch):
        """Check changed password hash since verification is session expired."""
        row = _row(password_hash="$argon2id$v=19$m=65536,t=3,p=4$changed-since-verification")
        result, cur = await self._begin(monkeypatch, row=row)
        assert result.outcome is TotpRotationStartOutcome.SESSION_EXPIRED
        assert cur.execute.await_count == 4

    async def test_changed_auth_revision_since_verification_is_session_expired(self, monkeypatch):
        """Check changed auth revision since verification is session expired."""
        row = _row(auth_revision=AUTH_REVISION + 1)
        result, cur = await self._begin(monkeypatch, row=row)
        assert result.outcome is TotpRotationStartOutcome.SESSION_EXPIRED
        assert cur.execute.await_count == 4

    async def test_missing_exact_full_session_is_session_expired(self, monkeypatch):
        """Check missing exact full session is session expired."""
        result, cur = await self._begin(monkeypatch, row=_row(), session_missing=True)
        assert result.outcome is TotpRotationStartOutcome.SESSION_EXPIRED
        assert cur.execute.await_count == 4

    async def test_missing_active_secret_is_current_secret_missing(self, monkeypatch):
        """Check missing active secret is current secret missing."""
        result, _ = await self._begin(monkeypatch, row=_row(totp_secret=None))
        assert result.outcome is TotpRotationStartOutcome.CURRENT_SECRET_MISSING

    async def test_undecryptable_active_secret_raises_totp_decryption_error(self, monkeypatch):
        """Check undecryptable active secret raises TOTP decryption error."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        _patched_reservation_and_snapshot(monkeypatch)
        row = _row(totp_secret="not-a-valid-fernet-token")
        cur = make_async_cursor(
            fetchone=[
                row,
                {"expires_at": FIXED_NOW + timedelta(hours=1)},
                None,
                {"database_now": FIXED_NOW},
            ]
        )
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
        """Check wrong current code is invalid credentials."""
        result, _ = await self._begin(monkeypatch, row=_row(), valid_code=False)
        assert result.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS

    async def test_replayed_current_code_is_rejected(self, monkeypatch):
        """Check replayed current code is rejected."""
        result, cur = await self._begin(monkeypatch, row=_row(last_totp_step=FIXED_STEP))
        assert result.outcome is TotpRotationStartOutcome.REPLAYED_CURRENT_CODE
        statements = [str(call.args[0]).strip().upper() for call in cur.execute.await_args_list]
        assert not any(statement.startswith("INSERT") for statement in statements)

    async def test_ready_outcome_returns_a_replacement_seed_and_stages_the_challenge(
        self, monkeypatch
    ):
        """Check ready outcome returns a replacement seed and stages the challenge."""
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

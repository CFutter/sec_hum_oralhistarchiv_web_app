"""Contract tests for TOTP code consumption and enrollment."""

from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

import pyotp
import pytest
import time_machine

import app.services.totp as totp_module
from app.services.session_ids import hash_session_id
from app.services.totp import (
    TotpDecryptionError,
    TotpEnrollmentOutcome,
    get_totp_secret,
    verify_and_consume_totp,
    verify_and_consume_totp_cur,
    verify_and_enroll_totp,
)
from app.services.totp_crypto import decrypt_value, encrypt_value
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

SECRET = "JBSWY3DPEHPK3PXP"
FIXED_TS = 1_750_000_000
FIXED_STEP = FIXED_TS // 30
USER_ID = 802
SESSION_ID = "enrollment-authorizing-session"


class _FrozenTime:
    """Stands in for the `time` module inside app.services.totp only."""

    def __init__(self, ts: float):
        """Store the fixed timestamp returned by this clock."""
        self._ts = ts

    def time(self) -> float:
        """Return the stored timestamp without advancing it."""
        return self._ts


def _freeze_totp_time(monkeypatch, ts: float) -> None:
    """Replace the TOTP module clock with a fixed timestamp in epoch seconds."""
    monkeypatch.setattr(totp_module, "time", _FrozenTime(ts))


class TestVerifyAndConsumeTotpStepCur:
    """The replay-safe step consumption every TOTP-gated action shares."""

    async def test_malformed_code_is_rejected_without_touching_the_database(self):
        """Check malformed code is rejected without touching the database."""
        cur = make_async_cursor()
        result = await verify_and_consume_totp_cur(cur, USER_ID, "not-six-digits")
        assert result is False
        cur.execute.assert_not_awaited()

    async def test_returns_false_when_the_user_row_is_missing(self):
        """Check returns false when the user row is missing."""
        cur = make_async_cursor(fetchone=None)
        result = await verify_and_consume_totp_cur(cur, USER_ID, "123456")
        assert result is False

    async def test_returns_false_when_the_account_has_no_totp_secret(self):
        """Check returns false when the account has no TOTP secret."""
        cur = make_async_cursor(fetchone={"totp_secret": None, "last_totp_step": None})
        result = await verify_and_consume_totp_cur(cur, USER_ID, "123456")
        assert result is False

    async def test_undecryptable_active_secret_raises_totp_decryption_error(self):
        """Unlike the pending secret, the *active* secret fails closed: a corrupted
        or mis-keyed active secret must never be silently treated as no-second-factor.
        """
        cur = make_async_cursor(
            fetchone={"totp_secret": "not-a-valid-fernet-token", "last_totp_step": None}
        )
        with pytest.raises(TotpDecryptionError) as caught:
            await verify_and_consume_totp_cur(cur, USER_ID, "123456")
        assert caught.value.user_id == USER_ID

    async def test_current_code_updates_last_totp_step_and_returns_true(self, monkeypatch):
        """Check current code updates last TOTP step and returns true."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        code = pyotp.TOTP(SECRET).at(FIXED_TS)
        cur = make_async_cursor(
            fetchone={"totp_secret": encrypt_value(SECRET), "last_totp_step": None}
        )

        result = await verify_and_consume_totp_cur(cur, USER_ID, code)

        assert result is True
        update_statement, update_params = cur.execute.await_args_list[1].args
        assert "last_totp_step" in update_statement
        assert update_params == (FIXED_STEP, USER_ID)

    async def test_code_outside_the_valid_window_is_rejected(self, monkeypatch):
        """Check code outside the valid window is rejected."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        stale_code = pyotp.TOTP(SECRET).at(FIXED_TS - 120)
        cur = make_async_cursor(
            fetchone={"totp_secret": encrypt_value(SECRET), "last_totp_step": None}
        )

        result = await verify_and_consume_totp_cur(cur, USER_ID, stale_code)

        assert result is False
        assert cur.execute.await_count == 1

    async def test_replayed_step_is_rejected_without_a_second_update(self, monkeypatch):
        """Check replayed step is rejected without a second update."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        code = pyotp.TOTP(SECRET).at(FIXED_TS)
        cur = make_async_cursor(
            fetchone={"totp_secret": encrypt_value(SECRET), "last_totp_step": FIXED_STEP}
        )

        result = await verify_and_consume_totp_cur(cur, USER_ID, code)

        assert result is False
        assert cur.execute.await_count == 1


class TestVerifyAndConsumeTotpStandaloneTransaction:
    """`verify_and_consume_totp`: the same primitive wrapped in its own get_db_cursor."""

    async def test_delegates_to_verify_and_consume_totp_cur_within_one_cursor(self, monkeypatch):
        """Check delegates to verify and consume TOTP cur within one cursor."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        code = pyotp.TOTP(SECRET).at(FIXED_TS)
        cur = make_async_cursor(
            fetchone={"totp_secret": encrypt_value(SECRET), "last_totp_step": None}
        )
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            result = await verify_and_consume_totp(make_mock_pool(), USER_ID, code)
        assert result is True
        acquire.assert_called_once()


class TestGetTotpSecret:
    """`get_totp_secret`: the display/flow-selection reader, distinct from the
    authoritative code-verifying readers above."""

    async def _get(self, fetchone):
        """Read a TOTP secret through a scripted cursor and return the service result."""
        cur = make_async_cursor(fetchone=fetchone)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            return await get_totp_secret(make_mock_pool(), USER_ID)

    async def test_returns_none_for_a_user_with_no_stored_secret(self):
        """Check returns none for a user with no stored secret."""
        assert await self._get(fetchone=None) is None
        assert await self._get(fetchone={"totp_secret": None}) is None

    async def test_undecryptable_stored_secret_raises_totp_decryption_error(self):
        """Check undecryptable stored secret raises TOTP decryption error."""
        with pytest.raises(TotpDecryptionError) as caught:
            await self._get(fetchone={"totp_secret": "not-a-valid-fernet-token"})
        assert caught.value.user_id == USER_ID

    async def test_decryptable_stored_secret_returns_the_plaintext(self):
        """Check decryptable stored secret returns the plaintext."""
        assert await self._get(fetchone={"totp_secret": encrypt_value(SECRET)}) == SECRET


def _enrollment_row(**overrides) -> dict[str, object]:
    """Build an eligible enrollment row bound to SESSION_ID with caller field overrides."""
    row = {
        "is_active": True,
        "auth_method": "local",
        "email_verified": True,
        "totp_secret": None,
        "pending_totp_secret": None,
        "pending_totp_created_at": None,
        "pending_totp_session_hash": hash_session_id(SESSION_ID),
        "totp_recovery_required": False,
    }
    row.update(overrides)
    return row


def _patched_session_lock(monkeypatch, matches: bool = True) -> None:
    """Patch the authorizing-session lock to return current UTC time or no match."""
    lock = create_autospec(
        totp_module._lock_authorizing_session_cur,
        side_effect=lambda *_args, **_kwargs: datetime.now(UTC) if matches else None,
        spec_set=True,
    )
    monkeypatch.setattr(totp_module, "_lock_authorizing_session_cur", lock)


class TestVerifyAndEnrollTotpEligibility:
    """Account-state gate: every ineligible row is rejected before any session/secret work."""

    @pytest.mark.parametrize(
        "row",
        [
            None,
            _enrollment_row(is_active=False),
            _enrollment_row(auth_method="shibboleth"),
            _enrollment_row(email_verified=False),
        ],
        ids=[
            "no_such_user",
            "inactive_account",
            "non_local_auth_method",
            "unverified_email",
        ],
    )
    async def test_ineligible_account_state_is_rejected(self, row):
        """Check ineligible account state is rejected."""
        cur = make_async_cursor(fetchone=row)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            outcome = await verify_and_enroll_totp(
                make_mock_pool(),
                USER_ID,
                "123456",
                "AAAAA-BBBBB-CCCCC-DDDDD",
                session_id=SESSION_ID,
            )
        assert outcome is TotpEnrollmentOutcome.INELIGIBLE
        assert cur.execute.await_count == 1

    async def test_already_configured_account_is_rejected(self):
        """Check already configured account is rejected."""
        row = _enrollment_row(totp_secret=encrypt_value("ALREADY-ENROLLED"))
        cur = make_async_cursor(fetchone=row)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            outcome = await verify_and_enroll_totp(
                make_mock_pool(),
                USER_ID,
                "123456",
                "AAAAA-BBBBB-CCCCC-DDDDD",
                session_id=SESSION_ID,
            )
        assert outcome is TotpEnrollmentOutcome.ALREADY_CONFIGURED


class TestVerifyAndEnrollTotpPendingSecretValidity:
    """A stale, missing, or undecryptable pending secret blocks promotion."""

    async def test_session_expired_returns_session_expired(self, monkeypatch):
        """Check session expired returns session expired."""
        _patched_session_lock(monkeypatch, matches=False)
        cur = make_async_cursor(fetchone=_enrollment_row())
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            outcome = await verify_and_enroll_totp(
                make_mock_pool(),
                USER_ID,
                "123456",
                "AAAAA-BBBBB-CCCCC-DDDDD",
                session_id=SESSION_ID,
            )
        assert outcome is TotpEnrollmentOutcome.SESSION_EXPIRED

    @pytest.mark.parametrize(
        "row_overrides",
        [
            {"pending_totp_secret": None},
            {
                "pending_totp_secret": encrypt_value("PENDINGSECRETVALUE"),
                "pending_totp_created_at": None,
                "pending_totp_session_hash": hash_session_id(SESSION_ID),
            },
        ],
        ids=["no_pending_secret_staged", "pending_secret_has_no_creation_timestamp"],
    )
    async def test_missing_pending_secret_is_rejected(self, monkeypatch, row_overrides):
        """Check missing pending secret is rejected."""
        _patched_session_lock(monkeypatch, matches=True)
        cur = make_async_cursor(fetchone=_enrollment_row(**row_overrides))
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            outcome = await verify_and_enroll_totp(
                make_mock_pool(),
                USER_ID,
                "123456",
                "AAAAA-BBBBB-CCCCC-DDDDD",
                session_id=SESSION_ID,
            )
        assert outcome is TotpEnrollmentOutcome.PENDING_SECRET_MISSING

    async def test_expired_pending_secret_is_rejected(self, monkeypatch):
        """Check expired pending secret is rejected."""
        _patched_session_lock(monkeypatch, matches=True)
        with time_machine.travel(datetime(2030, 1, 1, tzinfo=UTC)):
            stale_created_at = datetime.now(UTC) - timedelta(seconds=601)
            row = _enrollment_row(
                pending_totp_secret=encrypt_value("PENDINGSECRETVALUE"),
                pending_totp_created_at=stale_created_at,
            )
            cur = make_async_cursor(fetchone=row)
            acquire = create_autospec(
                totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
            )
            with patch.object(totp_module, "get_db_cursor", acquire):
                outcome = await verify_and_enroll_totp(
                    make_mock_pool(),
                    USER_ID,
                    "123456",
                    "AAAAA-BBBBB-CCCCC-DDDDD",
                    session_id=SESSION_ID,
                )
        assert outcome is TotpEnrollmentOutcome.PENDING_SECRET_MISSING

    async def test_undecryptable_pending_secret_is_rejected(self, monkeypatch):
        """Check undecryptable pending secret is rejected."""
        _patched_session_lock(monkeypatch, matches=True)
        with time_machine.travel(datetime(2030, 1, 1, tzinfo=UTC)):
            row = _enrollment_row(
                pending_totp_secret="not-a-valid-fernet-token",
                pending_totp_created_at=datetime.now(UTC),
            )
            cur = make_async_cursor(fetchone=row)
            acquire = create_autospec(
                totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
            )
            with patch.object(totp_module, "get_db_cursor", acquire):
                outcome = await verify_and_enroll_totp(
                    make_mock_pool(),
                    USER_ID,
                    "123456",
                    "AAAAA-BBBBB-CCCCC-DDDDD",
                    session_id=SESSION_ID,
                )
        assert outcome is TotpEnrollmentOutcome.PENDING_SECRET_MISSING


class TestVerifyAndEnrollTotpCodeAndRecoveryConfirmation:
    """The submitted TOTP code and the recovery-code confirmation are both required."""

    def _ready_row(self):
        """Build a ready enrollment row with an encrypted seed at frozen UTC time."""
        with time_machine.travel(datetime(2030, 1, 1, tzinfo=UTC)):
            return _enrollment_row(
                pending_totp_secret=encrypt_value(SECRET),
                pending_totp_created_at=datetime.now(UTC),
            )

    async def test_invalid_totp_code_is_rejected_before_checking_the_recovery_code(
        self, monkeypatch
    ):
        """Check invalid TOTP code is rejected before checking the recovery code."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        _patched_session_lock(monkeypatch, matches=True)
        cur = make_async_cursor(fetchone=self._ready_row())
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        activate = create_autospec(
            totp_module.activate_pending_recovery_code_set_cur, spec_set=True
        )
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "activate_pending_recovery_code_set_cur", activate),
        ):
            outcome = await verify_and_enroll_totp(
                make_mock_pool(),
                USER_ID,
                "000000",
                "AAAAA-BBBBB-CCCCC-DDDDD",
                session_id=SESSION_ID,
            )
        assert outcome is TotpEnrollmentOutcome.INVALID_CODE
        activate.assert_not_awaited()

    async def test_wrong_recovery_code_confirmation_blocks_promotion(self, monkeypatch):
        """Check wrong recovery code confirmation blocks promotion."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        _patched_session_lock(monkeypatch, matches=True)
        code = pyotp.TOTP(SECRET).at(FIXED_TS)
        cur = make_async_cursor(fetchone=self._ready_row())
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        activate = create_autospec(
            totp_module.activate_pending_recovery_code_set_cur, return_value=False, spec_set=True
        )
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "activate_pending_recovery_code_set_cur", activate),
        ):
            outcome = await verify_and_enroll_totp(
                make_mock_pool(), USER_ID, code, "WRONG-CONFIRM-CODE-HERE", session_id=SESSION_ID
            )
        assert outcome is TotpEnrollmentOutcome.INVALID_RECOVERY_CODE
        statements = [str(call.args[0]).strip().upper() for call in cur.execute.await_args_list]
        assert not any(statement.startswith("UPDATE") for statement in statements)


class TestVerifyAndEnrollTotpSuccess:
    """Positive controls: enrollment and recovery both revoke every existing session."""

    def _ready_row(self, *, recovering: bool):
        """Build a ready enrollment row with optional recovery state at frozen UTC time."""
        with time_machine.travel(datetime(2030, 1, 1, tzinfo=UTC)):
            return _enrollment_row(
                pending_totp_secret=encrypt_value(SECRET),
                pending_totp_created_at=datetime.now(UTC),
                totp_recovery_required=recovering,
            )

    async def test_initial_enrollment_promotes_the_secret_and_revokes_every_session(
        self, monkeypatch
    ):
        """Check initial enrollment promotes the secret and revokes every session."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        _patched_session_lock(monkeypatch, matches=True)
        code = pyotp.TOTP(SECRET).at(FIXED_TS)
        cur = make_async_cursor(fetchone=self._ready_row(recovering=False))
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        activate = create_autospec(
            totp_module.activate_pending_recovery_code_set_cur, return_value=True, spec_set=True
        )
        invalidate = create_autospec(
            totp_module.invalidate_pending_authentication_state_cur, spec_set=True
        )
        delete_sessions = create_autospec(totp_module.delete_user_sessions_cur, spec_set=True)
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "activate_pending_recovery_code_set_cur", activate),
            patch.object(totp_module, "invalidate_pending_authentication_state_cur", invalidate),
            patch.object(totp_module, "delete_user_sessions_cur", delete_sessions),
        ):
            outcome = await verify_and_enroll_totp(
                make_mock_pool(), USER_ID, code, "AAAAA-BBBBB-CCCCC-DDDDD", session_id=SESSION_ID
            )

        assert outcome is TotpEnrollmentOutcome.ENROLLED
        delete_sessions.assert_awaited_once_with(cur, USER_ID)
        statements = [str(call.args[0]) for call in cur.execute.await_args_list]
        assert any("totp_secret = %s" in statement for statement in statements)
        assert not any(
            "sessions" in statement and "purpose = 'full'" in statement for statement in statements
        )

    async def test_recovery_completion_deletes_every_session_and_clears_recovery_state(
        self, monkeypatch
    ):
        """Check recovery completion deletes every session and clears recovery state."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        _patched_session_lock(monkeypatch, matches=True)
        code = pyotp.TOTP(SECRET).at(FIXED_TS)
        cur = make_async_cursor(fetchone=self._ready_row(recovering=True))
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        activate = create_autospec(
            totp_module.activate_pending_recovery_code_set_cur, return_value=True, spec_set=True
        )
        invalidate = create_autospec(
            totp_module.invalidate_pending_authentication_state_cur, spec_set=True
        )
        delete_sessions = create_autospec(totp_module.delete_user_sessions_cur, spec_set=True)
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "activate_pending_recovery_code_set_cur", activate),
            patch.object(totp_module, "invalidate_pending_authentication_state_cur", invalidate),
            patch.object(totp_module, "delete_user_sessions_cur", delete_sessions),
        ):
            outcome = await verify_and_enroll_totp(
                make_mock_pool(), USER_ID, code, "AAAAA-BBBBB-CCCCC-DDDDD", session_id=SESSION_ID
            )

        assert outcome is TotpEnrollmentOutcome.RECOVERED
        delete_sessions.assert_awaited_once_with(cur, USER_ID)
        invalidate.assert_awaited_once_with(cur, USER_ID)
        statements = [str(call.args[0]) for call in cur.execute.await_args_list]
        assert any("totp_recovery_required = false" in statement for statement in statements)


def test_decrypted_ciphertext_written_matches_the_active_secret_promoted():
    """Sanity check for the helpers used above: encrypt_value/decrypt_value round-trip
    the exact secret a pending row would have stored, independent of TOTP logic.
    """
    ciphertext = encrypt_value(SECRET)
    assert decrypt_value(ciphertext) == SECRET


@pytest.fixture(autouse=True)
def _notification_boundary(monkeypatch):
    """Keep these focused cursor scenarios independent of outbox SQL plumbing."""
    queue = create_autospec(totp_module.queue_security_change_notice_cur, spec_set=True)
    monkeypatch.setattr(totp_module, "queue_security_change_notice_cur", queue)
    return queue

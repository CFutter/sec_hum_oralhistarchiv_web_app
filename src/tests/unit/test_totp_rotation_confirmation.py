"""Unit tests for `app.services.totp.confirm_totp_rotation`: the atomic
promotion of a session-bound rotation challenge staged by begin_totp_rotation.

Confirmation re-proves account eligibility, fences the challenge to the exact
auth_revision it was issued under (a password change or prior rotation must
invalidate it), and spends a bounded, durable confirmation-attempt budget
that survives a wrong code. Every rejection has a positive control proving
the adjacent permitted case still reaches ROTATED and revokes every session.

No DB: get_db_cursor is patched with an async context manager over a mock
cursor. Time is frozen by replacing the `time` module reference inside
app.services.totp (matched_step reads time.time() directly).
"""

from unittest.mock import create_autospec, patch

import pyotp
import pytest

import app.services.totp as totp_module
from app.services.crypto import decrypt_value, encrypt_value
from app.services.session_ids import hash_session_id
from app.services.totp import (
    TotpDecryptionError,
    TotpRotationOutcome,
    confirm_totp_rotation,
)
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

SECRET = "REPLACEMENTSECRETVALU"
FIXED_TS = 1_750_000_000
FIXED_STEP = FIXED_TS // 30
USER_ID = 233
SESSION_ID = "rotation-confirmation-session"
SESSION_HASH = hash_session_id(SESSION_ID)
AUTH_REVISION = 21


class _FrozenTime:
    def __init__(self, ts: float):
        self._ts = ts

    def time(self) -> float:
        return self._ts


def _freeze_totp_time(monkeypatch, ts: float) -> None:
    monkeypatch.setattr(totp_module, "time", _FrozenTime(ts))


def _user_row(**overrides) -> dict[str, object]:
    row = {
        "auth_revision": AUTH_REVISION,
        "is_active": True,
        "email_verified": True,
        "auth_method": "local",
        "totp_secret": encrypt_value("CURRENT-ACTIVE-SECRET"),
        "totp_recovery_required": False,
        "login_unlocked": True,
    }
    row.update(overrides)
    return row


def _challenge_row(**overrides) -> dict[str, object]:
    row = {
        "encrypted_secret": encrypt_value(SECRET),
        "auth_revision": AUTH_REVISION,
        "confirmation_attempt_count": 0,
        "unexpired": True,
    }
    row.update(overrides)
    return row


class TestConfirmTotpRotationArgumentValidation:
    async def test_negative_valid_window_is_rejected(self):
        with pytest.raises(ValueError, match="valid_window must be non-negative"):
            await confirm_totp_rotation(
                make_mock_pool(), USER_ID, "123456", session_id=SESSION_ID, valid_window=-1
            )

    async def test_non_positive_period_is_rejected(self):
        with pytest.raises(ValueError, match="period must be positive"):
            await confirm_totp_rotation(
                make_mock_pool(), USER_ID, "123456", session_id=SESSION_ID, period=0
            )


class TestConfirmTotpRotationAccountGate:
    async def _confirm(self, monkeypatch, fetchone, code="123456"):
        _freeze_totp_time(monkeypatch, FIXED_TS)
        cur = make_async_cursor(fetchone=fetchone)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            outcome = await confirm_totp_rotation(
                make_mock_pool(), USER_ID, code, session_id=SESSION_ID
            )
        return outcome, cur

    @pytest.mark.parametrize(
        "row",
        [
            None,
            _user_row(is_active=False),
            _user_row(email_verified=False),
            _user_row(auth_method="shibboleth"),
            _user_row(totp_recovery_required=True),
        ],
        ids=[
            "no_such_user",
            "inactive_account",
            "unverified_email",
            "non_local_auth_method",
            "recovery_in_progress",
        ],
    )
    async def test_ineligible_account_state_is_rejected(self, monkeypatch, row):
        outcome, cur = await self._confirm(monkeypatch, fetchone=row)
        assert outcome is TotpRotationOutcome.INELIGIBLE
        assert cur.execute.await_count == 1

    async def test_locked_account_is_rejected(self, monkeypatch):
        outcome, cur = await self._confirm(monkeypatch, fetchone=_user_row(login_unlocked=False))
        assert outcome is TotpRotationOutcome.ACCOUNT_LOCKED
        assert cur.execute.await_count == 1

    @pytest.mark.parametrize(
        "row",
        [
            _user_row(totp_secret=None),
            _user_row(totp_secret="not-a-valid-fernet-token"),
        ],
        ids=["no_active_secret", "undecryptable_active_secret"],
    )
    async def test_missing_or_undecryptable_active_secret_fails_closed(self, monkeypatch, row):
        cur = make_async_cursor(fetchone=row)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        _freeze_totp_time(monkeypatch, FIXED_TS)
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            pytest.raises(TotpDecryptionError) as caught,
        ):
            await confirm_totp_rotation(make_mock_pool(), USER_ID, "123456", session_id=SESSION_ID)
        assert caught.value.user_id == USER_ID


class TestConfirmTotpRotationSessionAndChallengeValidity:
    async def _confirm(self, monkeypatch, fetchone, code="123456"):
        _freeze_totp_time(monkeypatch, FIXED_TS)
        cur = make_async_cursor(fetchone=fetchone)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            outcome = await confirm_totp_rotation(
                make_mock_pool(), USER_ID, code, session_id=SESSION_ID
            )
        return outcome, cur

    async def test_missing_exact_full_session_is_session_expired(self, monkeypatch):
        outcome, cur = await self._confirm(monkeypatch, fetchone=[_user_row(), None])
        assert outcome is TotpRotationOutcome.SESSION_EXPIRED
        assert cur.execute.await_count == 2

    async def test_missing_challenge_row_is_pending_secret_missing(self, monkeypatch):
        outcome, cur = await self._confirm(monkeypatch, fetchone=[_user_row(), {"exists": 1}, None])
        assert outcome is TotpRotationOutcome.PENDING_SECRET_MISSING
        assert cur.execute.await_count == 3

    @pytest.mark.parametrize(
        "challenge_overrides",
        [
            {"unexpired": False},
            {"auth_revision": AUTH_REVISION + 1},
        ],
        ids=["expired_challenge", "auth_revision_advanced_since_issuance"],
    )
    async def test_stale_challenge_is_deleted_and_reported_missing(
        self, monkeypatch, challenge_overrides
    ):
        outcome, cur = await self._confirm(
            monkeypatch,
            fetchone=[_user_row(), {"exists": 1}, _challenge_row(**challenge_overrides)],
        )
        assert outcome is TotpRotationOutcome.PENDING_SECRET_MISSING
        statements = [str(call.args[0]).strip().upper() for call in cur.execute.await_args_list]
        assert any(statement.startswith("DELETE") for statement in statements)

    async def test_exhausted_confirmation_budget_deletes_the_challenge(self, monkeypatch):
        outcome, cur = await self._confirm(
            monkeypatch,
            fetchone=[
                _user_row(),
                {"exists": 1},
                _challenge_row(
                    confirmation_attempt_count=settings.totp_rotation_confirmation_attempt_limit
                ),
            ],
        )
        assert outcome is TotpRotationOutcome.ATTEMPTS_EXHAUSTED
        statements = [str(call.args[0]).strip().upper() for call in cur.execute.await_args_list]
        assert any(statement.startswith("DELETE") for statement in statements)
        # The attempt count is never incremented past a budget that is already spent.
        assert not any("SET CONFIRMATION_ATTEMPT_COUNT" in statement for statement in statements)

    async def test_locked_challenge_disappearing_during_increment_is_a_runtime_error(
        self, monkeypatch
    ):
        outcome_or_raise = self._confirm(
            monkeypatch,
            fetchone=[_user_row(), {"exists": 1}, _challenge_row(), None],
        )
        with pytest.raises(RuntimeError, match="Locked TOTP rotation challenge disappeared"):
            await outcome_or_raise

    async def test_undecryptable_replacement_secret_raises_totp_decryption_error(self, monkeypatch):
        outcome_or_raise = self._confirm(
            monkeypatch,
            fetchone=[
                _user_row(),
                {"exists": 1},
                _challenge_row(encrypted_secret="not-a-valid-fernet-token"),
                {"confirmation_attempt_count": 1},
            ],
        )
        with pytest.raises(TotpDecryptionError) as caught:
            await outcome_or_raise
        assert caught.value.user_id == USER_ID


class TestConfirmTotpRotationCodeVerification:
    async def _confirm(self, monkeypatch, *, code, attempt_count=0, limit=None):
        if limit is not None:
            monkeypatch.setattr(settings, "totp_rotation_confirmation_attempt_limit", limit)
        _freeze_totp_time(monkeypatch, FIXED_TS)
        cur = make_async_cursor(
            fetchone=[
                _user_row(),
                {"exists": 1},
                _challenge_row(confirmation_attempt_count=attempt_count),
                {"confirmation_attempt_count": attempt_count + 1},
            ]
        )
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        delete_sessions = create_autospec(totp_module.delete_user_sessions_cur, spec_set=True)
        invalidate = create_autospec(
            totp_module.invalidate_pending_authentication_state_cur, spec_set=True
        )
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "delete_user_sessions_cur", delete_sessions),
            patch.object(totp_module, "invalidate_pending_authentication_state_cur", invalidate),
        ):
            outcome = await confirm_totp_rotation(
                make_mock_pool(), USER_ID, code, session_id=SESSION_ID
            )
        return outcome, cur, delete_sessions

    async def test_wrong_new_code_is_reported_without_promoting(self, monkeypatch):
        outcome, cur, delete_sessions = await self._confirm(
            monkeypatch, code="000000", attempt_count=0, limit=5
        )
        assert outcome is TotpRotationOutcome.INVALID_NEW_CODE
        delete_sessions.assert_not_awaited()
        statements = [str(call.args[0]).strip().upper() for call in cur.execute.await_args_list]
        assert not any(statement.startswith("DELETE") for statement in statements)

    async def test_wrong_code_on_the_last_attempt_exhausts_and_deletes_the_challenge(
        self, monkeypatch
    ):
        """Positive control for the budget accounting: the same wrong code with
        budget remaining (above) is merely reported, not exhausted.
        """
        outcome, cur, delete_sessions = await self._confirm(
            monkeypatch, code="000000", attempt_count=1, limit=2
        )
        assert outcome is TotpRotationOutcome.ATTEMPTS_EXHAUSTED
        delete_sessions.assert_not_awaited()
        statements = [str(call.args[0]).strip().upper() for call in cur.execute.await_args_list]
        assert any(statement.startswith("DELETE") for statement in statements)

    async def test_correct_new_code_rotates_the_secret_and_revokes_every_session(self, monkeypatch):
        """Positive control for every rejection in this module."""
        code = pyotp.TOTP(SECRET).at(FIXED_TS)
        outcome, cur, delete_sessions = await self._confirm(monkeypatch, code=code, attempt_count=0)
        assert outcome is TotpRotationOutcome.ROTATED
        delete_sessions.assert_awaited_once_with(cur, USER_ID)
        update_call = next(
            call
            for call in cur.execute.await_args_list
            if str(call.args[0]).strip().upper().startswith("UPDATE USERS")
        )
        promoted_ciphertext, promoted_step, updated_user_id = update_call.args[1]
        assert updated_user_id == USER_ID
        assert promoted_step == FIXED_STEP
        assert decrypt_value(promoted_ciphertext) == SECRET

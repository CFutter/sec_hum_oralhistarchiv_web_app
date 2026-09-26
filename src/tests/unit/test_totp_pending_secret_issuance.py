"""Unit tests for the pending-secret half of app.services.totp:

`get_or_create_pending_totp_secret` (atomic read-check-write of the
enrollment/recovery pending secret) and `get_pending_totp_secret` (the
read-only redisplay path), plus the session-purpose helpers they both use.

Both entry points lock the user row FOR UPDATE and must reject every
ineligible account state, and every mismatched or expired authorizing
session, before ever generating or displaying secret material. Each
rejection test below has a positive control in the same class proving the
permitted case still reaches (and returns) the pending secret.

Pure unit tests: no DB. `get_db_cursor` is patched with an async context
manager over a mock cursor (tests.fixtures.make_async_cursor /
FakeCursorCtx), matching the idiom in test_totp.py and test_credential_budgets.py.
"""

from unittest.mock import create_autospec, patch

import pytest

import app.services.totp as totp_module
from app.services.crypto import decrypt_value, encrypt_value
from app.services.totp import (
    PendingTotpOutcome,
    PendingTotpPurpose,
    _lock_authorizing_session_cur,
    _session_purpose_matches,
    get_or_create_pending_totp_secret,
    get_pending_totp_secret,
)
from app.services.totp_recovery_codes import PendingRecoveryCodeSet
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

USER_ID = 501
SESSION_ID = "pending-secret-authorizing-session"
FIXED_CODES = tuple(f"CODE{i}-GROUP{i}-VALUE{i}" for i in range(10))


def _user_row(**overrides) -> dict[str, object]:
    row = {
        "is_active": True,
        "auth_method": "local",
        "email_verified": True,
        "totp_secret": None,
        "totp_recovery_required": False,
        "pending_totp_secret": None,
        "pending_is_current": False,
    }
    row.update(overrides)
    return row


def _patched_recovery_codes(generation: int = 9):
    """Isolate get_or_create_pending_totp_secret from totp_recovery_codes internals."""
    generate = create_autospec(
        totp_module.generate_recovery_codes, return_value=FIXED_CODES, spec_set=True
    )
    stage = create_autospec(
        totp_module.stage_recovery_code_set_cur,
        return_value=PendingRecoveryCodeSet(generation=generation, codes=FIXED_CODES),
        spec_set=True,
    )
    return generate, stage


class TestSessionPurposeMatching:
    """`_session_purpose_matches`: which live session purposes authorize which pending operation."""

    @pytest.mark.parametrize(
        "session_purpose",
        ["full", "totp_setup"],
        ids=["full_session_authorizes_enrollment", "totp_setup_session_authorizes_enrollment"],
    )
    def test_enrollment_purpose_accepts_full_and_totp_setup_sessions(self, session_purpose):
        assert _session_purpose_matches(session_purpose, PendingTotpPurpose.ENROLLMENT) is True

    def test_enrollment_purpose_rejects_a_recovery_session(self):
        """Positive control above: a recovery-scoped session must not double as enrollment authority."""
        assert _session_purpose_matches("totp_recovery", PendingTotpPurpose.ENROLLMENT) is False

    def test_recovery_purpose_accepts_only_a_totp_recovery_session(self):
        assert _session_purpose_matches("totp_recovery", PendingTotpPurpose.RECOVERY) is True

    def test_recovery_purpose_rejects_a_full_session(self):
        """Positive control above: an ordinary full session cannot authorize recovery."""
        assert _session_purpose_matches("full", PendingTotpPurpose.RECOVERY) is False

    def test_unhandled_pending_purpose_raises_value_error(self):
        """A purpose outside the enum is a programming error, not a silent rejection."""
        with pytest.raises(ValueError, match="Unhandled pending TOTP purpose"):
            _session_purpose_matches("full", "not-a-real-purpose")


class TestLockAuthorizingSessionCur:
    """`_lock_authorizing_session_cur`: the FOR UPDATE session lookup both callers share."""

    async def test_locks_and_accepts_a_live_session_with_the_matching_purpose(self):
        cur = make_async_cursor(fetchone={"purpose": "full"})
        matched = await _lock_authorizing_session_cur(
            cur,
            user_id=USER_ID,
            session_id=SESSION_ID,
            pending_purpose=PendingTotpPurpose.ENROLLMENT,
        )
        assert matched is True
        statement, params = cur.execute.await_args.args
        assert "FOR UPDATE" in statement
        assert params[1] == USER_ID

    async def test_missing_session_row_is_rejected(self):
        """Positive control above: the same helper accepts a live session with the right purpose."""
        cur = make_async_cursor(fetchone=None)
        matched = await _lock_authorizing_session_cur(
            cur,
            user_id=USER_ID,
            session_id=SESSION_ID,
            pending_purpose=PendingTotpPurpose.ENROLLMENT,
        )
        assert matched is False


class TestGetOrCreatePendingTotpSecretEligibility:
    """Every ineligible account state is rejected before any session or secret work."""

    @pytest.mark.parametrize(
        "row",
        [
            None,
            _user_row(is_active=False),
            _user_row(auth_method="shibboleth"),
        ],
        ids=["no_such_user", "inactive_account", "non_local_auth_method"],
    )
    async def test_account_gate_rejects_before_any_purpose_check(self, row):
        cur = make_async_cursor(fetchone=row)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            result = await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose=PendingTotpPurpose.ENROLLMENT,
                session_id=SESSION_ID,
            )
        assert result.outcome is PendingTotpOutcome.INELIGIBLE
        assert cur.execute.await_count == 1

    @pytest.mark.parametrize(
        "row",
        [
            _user_row(email_verified=False),
            _user_row(totp_recovery_required=True),
        ],
        ids=["enrollment_requires_verified_email", "enrollment_blocked_during_active_recovery"],
    )
    async def test_enrollment_purpose_rejects_ineligible_local_accounts(self, row):
        cur = make_async_cursor(fetchone=row)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            result = await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose=PendingTotpPurpose.ENROLLMENT,
                session_id=SESSION_ID,
            )
        assert result.outcome is PendingTotpOutcome.INELIGIBLE
        assert cur.execute.await_count == 1

    async def test_enrollment_purpose_reports_already_configured(self):
        """Positive control lives in TestGetOrCreatePendingTotpSecretReuseAndFallback below:
        an eligible, unenrolled account reaches secret issuance."""
        row = _user_row(totp_secret=encrypt_value("EXISTING"))
        cur = make_async_cursor(fetchone=row)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            result = await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose=PendingTotpPurpose.ENROLLMENT,
                session_id=SESSION_ID,
            )
        assert result.outcome is PendingTotpOutcome.ALREADY_CONFIGURED
        assert cur.execute.await_count == 1

    @pytest.mark.parametrize(
        "row",
        [
            _user_row(totp_recovery_required=False),
            _user_row(totp_recovery_required=True, totp_secret=encrypt_value("ACTIVE")),
            _user_row(totp_recovery_required=True, email_verified=False),
        ],
        ids=[
            "recovery_requires_recovery_flag_set",
            "recovery_blocked_while_a_totp_secret_is_still_active",
            "recovery_requires_verified_email",
        ],
    )
    async def test_recovery_purpose_rejects_ineligible_accounts(self, row):
        cur = make_async_cursor(fetchone=row)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            result = await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose=PendingTotpPurpose.RECOVERY,
                session_id=SESSION_ID,
            )
        assert result.outcome is PendingTotpOutcome.INELIGIBLE
        assert cur.execute.await_count == 1

    async def test_unhandled_purpose_raises_value_error_after_the_account_gate(self):
        cur = make_async_cursor(fetchone=_user_row())
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            pytest.raises(ValueError, match="Unhandled pending TOTP purpose"),
        ):
            await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose="not-a-real-purpose",
                session_id=SESSION_ID,
            )


class TestGetOrCreatePendingTotpSecretSessionAuthorization:
    """An eligible account still needs its exact authorizing session to be live."""

    async def test_session_expired_returns_session_expired_without_writing_a_secret(self):
        cur = make_async_cursor(fetchone=[_user_row(), None])
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            result = await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose=PendingTotpPurpose.ENROLLMENT,
                session_id=SESSION_ID,
            )
        assert result.outcome is PendingTotpOutcome.SESSION_EXPIRED
        assert cur.execute.await_count == 2
        statements = [str(call.args[0]).upper() for call in cur.execute.await_args_list]
        assert not any(statement.strip().startswith("UPDATE") for statement in statements)

    async def test_live_authorizing_session_allows_secret_issuance(self):
        """Positive control above: the same eligible account with a live session proceeds."""
        cur = make_async_cursor(fetchone=[_user_row(), {"purpose": "full"}])
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        generate, stage = _patched_recovery_codes()
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "generate_recovery_codes", generate),
            patch.object(totp_module, "stage_recovery_code_set_cur", stage),
        ):
            result = await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose=PendingTotpPurpose.ENROLLMENT,
                session_id=SESSION_ID,
            )
        assert result.outcome is PendingTotpOutcome.READY
        assert result.recovery_codes == FIXED_CODES


class TestGetOrCreatePendingTotpSecretReuseAndFallback:
    """A current, decryptable pending secret is reused; anything else is replaced."""

    async def test_current_decryptable_pending_secret_is_reused_without_a_write(self):
        existing_secret = "EXISTINGSECRETVALUE"
        row = _user_row(
            pending_totp_secret=encrypt_value(existing_secret),
            pending_is_current=True,
        )
        cur = make_async_cursor(fetchone=[row, {"purpose": "full"}])
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        generate, stage = _patched_recovery_codes(generation=3)
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "generate_recovery_codes", generate),
            patch.object(totp_module, "stage_recovery_code_set_cur", stage),
        ):
            result = await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose=PendingTotpPurpose.ENROLLMENT,
                session_id=SESSION_ID,
            )

        assert result.outcome is PendingTotpOutcome.READY
        assert result.secret == existing_secret
        assert result.recovery_codes == FIXED_CODES
        # Only the two reads (user row, session row) happen — no UPDATE regenerates the secret.
        assert cur.execute.await_count == 2
        statements = [str(call.args[0]).upper() for call in cur.execute.await_args_list]
        assert not any(statement.strip().startswith("UPDATE") for statement in statements)
        stage.assert_awaited_once_with(cur, user_id=USER_ID, codes=FIXED_CODES)

    async def test_undecryptable_pending_secret_is_replaced_rather_than_raising(self):
        """A corrupted/mis-keyed pending secret fails closed by regenerating, not by
        raising TotpDecryptionError — that fail-closed contract is reserved for the
        *active* secret (verify_and_consume_totp_cur), not the not-yet-trusted pending one.
        """
        row = _user_row(
            pending_totp_secret="not-a-valid-fernet-token",
            pending_is_current=True,
        )
        cur = make_async_cursor(fetchone=[row, {"purpose": "full"}])
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        generate, stage = _patched_recovery_codes()
        fixed_secret = create_autospec(
            totp_module.generate_totp_secret, return_value="FRESHLYGENERATEDSECRET", spec_set=True
        )
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "generate_recovery_codes", generate),
            patch.object(totp_module, "stage_recovery_code_set_cur", stage),
            patch.object(totp_module, "generate_totp_secret", fixed_secret),
        ):
            result = await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose=PendingTotpPurpose.ENROLLMENT,
                session_id=SESSION_ID,
            )

        assert result.outcome is PendingTotpOutcome.READY
        assert result.secret == "FRESHLYGENERATEDSECRET"
        update_call = next(
            call
            for call in cur.execute.await_args_list
            if str(call.args[0]).strip().upper().startswith("UPDATE")
        )
        new_ciphertext, updated_user_id = update_call.args[1]
        assert updated_user_id == USER_ID
        assert decrypt_value(new_ciphertext) == "FRESHLYGENERATEDSECRET"
        assert result.recovery_codes == FIXED_CODES

    async def test_expired_pending_secret_is_replaced_with_a_freshly_generated_one(self):
        row = _user_row(
            totp_recovery_required=True,
            pending_totp_secret=encrypt_value("STALESECRETVALUE"),
            pending_is_current=False,
        )
        cur = make_async_cursor(fetchone=[row, {"purpose": "totp_recovery"}])
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        generate, stage = _patched_recovery_codes()
        fixed_secret = create_autospec(
            totp_module.generate_totp_secret, return_value="REPLACEMENTSECRET", spec_set=True
        )
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            patch.object(totp_module, "generate_recovery_codes", generate),
            patch.object(totp_module, "stage_recovery_code_set_cur", stage),
            patch.object(totp_module, "generate_totp_secret", fixed_secret),
        ):
            result = await get_or_create_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                purpose=PendingTotpPurpose.RECOVERY,
                session_id=SESSION_ID,
            )

        assert result.outcome is PendingTotpOutcome.READY
        assert result.secret == "REPLACEMENTSECRET"
        assert result.recovery_codes == FIXED_CODES


class TestGetPendingTotpSecretStateMatching:
    """`get_pending_totp_secret`: the redisplay path re-checks purpose-specific state
    and the authorizing session before ever decrypting.
    """

    def _row(self, **overrides) -> dict[str, object]:
        row = {
            "is_active": True,
            "auth_method": "local",
            "email_verified": True,
            "totp_secret": None,
            "totp_recovery_required": False,
            "pending_totp_secret": encrypt_value("REDISPLAYABLESECRET"),
            "pending_is_current": True,
        }
        row.update(overrides)
        return row

    async def _call(self, purpose, row, session_row=None, *, session_missing=False):
        if session_row is None and not session_missing:
            session_row = {"purpose": "full"}
        cur = make_async_cursor(fetchone=[row, session_row])
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            return await get_pending_totp_secret(
                make_mock_pool(), USER_ID, session_id=SESSION_ID, purpose=purpose
            ), cur

    @pytest.mark.parametrize(
        "row",
        [
            None,
            {"is_active": False},
            {"pending_totp_secret": None},
            {"pending_is_current": False},
        ],
        ids=[
            "no_such_user",
            "inactive_account",
            "no_pending_secret_staged",
            "stale_pending_secret",
        ],
    )
    async def test_account_or_pending_secret_gate_returns_none_before_purpose_checks(self, row):
        """Positive control below: a live, current pending secret and matching
        purpose does return the plaintext secret.
        """
        full_row = row if row is None else self._row(**row)
        cur = make_async_cursor(fetchone=full_row)
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with patch.object(totp_module, "get_db_cursor", acquire):
            result = await get_pending_totp_secret(
                make_mock_pool(),
                USER_ID,
                session_id=SESSION_ID,
                purpose=PendingTotpPurpose.ENROLLMENT,
            )
        assert result is None
        assert cur.execute.await_count == 1

    async def test_enrollment_purpose_returns_the_secret_for_an_unenrolled_account(self):
        result, _ = await self._call(PendingTotpPurpose.ENROLLMENT, self._row())
        assert result == "REDISPLAYABLESECRET"

    async def test_enrollment_purpose_returns_none_while_recovery_is_required(self):
        """Positive control above: the same account without recovery pending gets its secret back."""
        result, cur = await self._call(
            PendingTotpPurpose.ENROLLMENT, self._row(totp_recovery_required=True)
        )
        assert result is None
        # State mismatch is checked before the session lock query is issued.
        assert cur.execute.await_count == 1

    async def test_recovery_purpose_returns_the_secret_when_recovery_is_required(self):
        result, _ = await self._call(
            PendingTotpPurpose.RECOVERY,
            self._row(totp_recovery_required=True),
            session_row={"purpose": "totp_recovery"},
        )
        assert result == "REDISPLAYABLESECRET"

    async def test_recovery_purpose_returns_none_when_recovery_is_not_required(self):
        """Positive control above: recovery redisplay succeeds once the flag is actually set."""
        result, cur = await self._call(PendingTotpPurpose.RECOVERY, self._row())
        assert result is None
        assert cur.execute.await_count == 1

    async def test_unhandled_purpose_raises_value_error(self):
        cur = make_async_cursor(fetchone=self._row())
        acquire = create_autospec(
            totp_module.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
        )
        with (
            patch.object(totp_module, "get_db_cursor", acquire),
            pytest.raises(ValueError, match="Unhandled pending TOTP purpose"),
        ):
            await get_pending_totp_secret(
                make_mock_pool(), USER_ID, session_id=SESSION_ID, purpose="not-a-real-purpose"
            )

    async def test_returns_none_when_the_authorizing_session_is_not_live(self):
        """Positive control is test_enrollment_purpose_returns_the_secret_for_an_unenrolled_account:
        state matches there AND the session is live, and the secret comes back.
        """
        result, cur = await self._call(
            PendingTotpPurpose.ENROLLMENT, self._row(), session_missing=True
        )
        assert result is None
        assert cur.execute.await_count == 2

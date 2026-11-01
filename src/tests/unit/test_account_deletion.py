"""Deletion credential boundaries and exceptional failures with signature-checked collaborators."""

import logging
from contextlib import ExitStack, contextmanager
from dataclasses import FrozenInstanceError
from unittest.mock import create_autospec, patch, sentinel

import pytest
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from psycopg import AsyncCursor

from app.services import account_deletion, password_verification
from app.services.credential_attempts import SessionStepUpAttemptOutcome
from app.services.crypto import audit_email_hash
from app.services.password_work import PasswordWorkAdmissionTimeout
from app.services.totp import TotpDecryptionError
from app.services.users import AdminActionRejected

ACTOR_ID = 41
TARGET_ID = 42
SESSION_ID = "deletion-session-secret"
PASSWORD = "fresh-deletion-password"
PASSWORD_HASH = "stored-deletion-password-hash"
EMAIL = "deletion-target@example.org"


def _actor_row(**changes):
    """Return an eligible local actor row with explicit field overrides."""
    row = {
        "email": EMAIL,
        "password_hash": PASSWORD_HASH,
        "auth_revision": 7,
        "is_active": True,
        "is_admin": False,
        "email_verified": True,
        "auth_method": "local",
        "totp_secret": "encrypted-authenticator",
        "totp_recovery_required": False,
        "login_unlocked": True,
    }
    row.update(changes)
    return row


class _CursorContext:
    """Record cursor-context entry and exit without executing SQL."""

    def __init__(self, cursor, events):
        """Keep the cursor and event list by reference."""
        self.cursor = cursor
        self.events = events

    async def __aenter__(self):
        """Record entry and return the configured cursor."""
        self.events.append("cursor_enter")
        return self.cursor

    async def __aexit__(self, exc_type, _exc_value, _traceback):
        """Record success or failure without suppressing exceptions."""
        self.events.append("cursor_exit" if exc_type is None else "cursor_error")
        return False


@contextmanager
def _dependencies(
    rows=(),
    *,
    reservation=SessionStepUpAttemptOutcome.RESERVED,
    password_error=None,
    totp=True,
    guard_error=None,
    rowcount=1,
):
    """Temporarily patch deletion collaborators and yield cursor, doubles and event order."""
    events = []
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    cursor.fetchone.side_effect = iter(rows)
    cursor.rowcount = rowcount

    async def verify_password(*_args, **_kwargs):
        """Require the snapshot cursor to be closed, then return success or raise password_error."""
        events.append("password")
        assert events[-2] == "cursor_exit", "Password work must release its snapshot connection"
        if password_error is not None:
            raise password_error
        return True

    replacements = {
        "get_db_cursor": create_autospec(
            account_deletion.get_db_cursor,
            side_effect=lambda *_args, **_kwargs: _CursorContext(cursor, events),
            spec_set=True,
        ),
        "reserve_session_step_up_attempt": create_autospec(
            account_deletion.reserve_session_step_up_attempt,
            side_effect=reservation if isinstance(reservation, Exception) else None,
            return_value=reservation,
            spec_set=True,
        ),
        "run_password_work": create_autospec(
            password_verification.run_password_work, side_effect=verify_password, spec_set=True
        ),
        "acquire_admin_action_lock_cur": create_autospec(
            account_deletion.acquire_admin_action_lock_cur, spec_set=True
        ),
        "guard_current_admin_session_cur": create_autospec(
            account_deletion.guard_current_admin_session_cur,
            side_effect=guard_error,
            spec_set=True,
        ),
        "verify_and_consume_totp_cur": create_autospec(
            account_deletion.verify_and_consume_totp_cur,
            side_effect=totp if isinstance(totp, Exception) else None,
            return_value=totp,
            spec_set=True,
        ),
    }
    with ExitStack() as stack:
        for name, replacement in replacements.items():
            stack.enter_context(
                patch.object(
                    password_verification if name == "run_password_work" else account_deletion,
                    name,
                    replacement,
                )
            )
        yield cursor, replacements, events


async def _delete(path, *, totp_code="123456"):
    """Invoke self-deletion for "self"; otherwise invoke administrator deletion."""
    if path == "self":
        return await account_deletion.delete_own_account(
            sentinel.pool,
            user_id=ACTOR_ID,
            session_id=SESSION_ID,
            password=PASSWORD,
            totp_code=totp_code,
        )
    return await account_deletion.delete_account_as_admin(
        sentinel.pool,
        actor_id=ACTOR_ID,
        actor_session_id=SESSION_ID,
        target_user_id=TARGET_ID,
        password=PASSWORD,
        totp_code=totp_code,
    )


@pytest.mark.parametrize("path", ["self", "admin"])
async def test_password_admission_failure_propagates_after_reserved_attempt(path):
    """Password admission failure propagates after reserved attempt."""
    capacity = PasswordWorkAdmissionTimeout(0.02)
    with _dependencies(rows=[_actor_row()], password_error=capacity) as (cursor, doubles, events):
        with pytest.raises(PasswordWorkAdmissionTimeout) as failure:
            await _delete(path)
        assert failure.value is capacity
        doubles["reserve_session_step_up_attempt"].assert_awaited_once()
        doubles["verify_and_consume_totp_cur"].assert_not_awaited()
        doubles["acquire_admin_action_lock_cur"].assert_not_awaited()
        assert cursor.execute.await_count == 1
        assert events == ["cursor_enter", "cursor_exit", "password"]


@pytest.mark.parametrize("path", ["self", "admin"])
@pytest.mark.parametrize(
    ("reservation", "reason"),
    [
        (SessionStepUpAttemptOutcome.INVALID_SESSION, "invalid_session"),
        (SessionStepUpAttemptOutcome.ACCOUNT_LOCKED, "account_locked"),
        (SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED, "step_up_exhausted"),
    ],
)
async def test_rejected_attempt_budget_prevents_any_credential_or_database_work(
    path, reservation, reason
):
    """Rejected attempt budget prevents any credential or database work."""
    with _dependencies(reservation=reservation) as (_, doubles, _):
        with pytest.raises(account_deletion.AccountDeletionRejected) as caught:
            await _delete(path)
        assert caught.value.reason == reason
        doubles["reserve_session_step_up_attempt"].assert_awaited_once_with(
            sentinel.pool, user_id=ACTOR_ID, session_id=SESSION_ID
        )
        doubles["get_db_cursor"].assert_not_called()
        doubles["run_password_work"].assert_not_awaited()


@pytest.mark.parametrize("path", ["self", "admin"])
async def test_unknown_reservation_cannot_silently_authorize_deletion(path):
    """Unknown reservation cannot silently authorize deletion."""
    with _dependencies(reservation=sentinel.unknown_reservation) as (_, doubles, _):
        with pytest.raises(RuntimeError, match="Unhandled step-up reservation outcome"):
            await _delete(path)
        doubles["get_db_cursor"].assert_not_called()


@pytest.mark.parametrize("path", ["self", "admin"])
async def test_failed_reservation_storage_propagates_without_credential_work(path):
    """Failed reservation storage propagates without credential work."""
    failure = RuntimeError("attempt storage unavailable")
    with _dependencies(reservation=failure) as (_, doubles, _):
        with pytest.raises(RuntimeError) as caught:
            await _delete(path)
        assert caught.value is failure
        doubles["get_db_cursor"].assert_not_called()


@pytest.mark.parametrize("path", ["self", "admin"])
@pytest.mark.parametrize(
    "verification_error",
    [InvalidHashError("invalid encoded hash"), VerificationError("hash cannot be verified")],
    ids=["invalid_hash", "verification_error"],
)
async def test_bad_stored_password_fails_closed_without_logging_proof_material(
    path, verification_error, caplog
):
    """Bad stored password fails closed without logging proof material."""
    with (
        caplog.at_level(logging.ERROR, logger=account_deletion.__name__),
        _dependencies([_actor_row()], password_error=verification_error) as (_, doubles, events),
        pytest.raises(account_deletion.AccountDeletionRejected) as caught,
    ):
        await _delete(path)
    assert caught.value.reason == "invalid_password"
    assert caught.value.__cause__ is verification_error
    assert events == ["cursor_enter", "cursor_exit", "password"]
    doubles["verify_and_consume_totp_cur"].assert_not_awaited()
    assert len(caplog.records) == 1
    assert str(ACTOR_ID) in caplog.text
    for secret in (PASSWORD, PASSWORD_HASH, EMAIL, SESSION_ID, "encrypted-authenticator"):
        assert secret not in caplog.text


@pytest.mark.parametrize("path", ["self", "admin"])
async def test_wrong_password_is_a_policy_rejection_without_an_error_log(path, caplog):
    """Wrong password is a policy rejection without an error log."""
    with (
        _dependencies([_actor_row()], password_error=VerifyMismatchError("mismatch")) as (
            _,
            doubles,
            _,
        ),
        pytest.raises(account_deletion.AccountDeletionRejected) as caught,
    ):
        await _delete(path)
    assert caught.value.reason == "invalid_password"
    assert not caplog.records
    doubles["get_db_cursor"].assert_called_once_with(sentinel.pool)


@pytest.mark.parametrize("path", ["self", "admin"])
async def test_malformed_totp_spends_attempt_but_never_enters_deletion_transaction(path):
    """Malformed TOTP spends attempt but never enters deletion transaction."""
    with (
        _dependencies([_actor_row()]) as (_, doubles, events),
        pytest.raises(account_deletion.AccountDeletionRejected) as caught,
    ):
        await _delete(path, totp_code="12\N{ARABIC-INDIC DIGIT THREE}456")
    assert caught.value.reason == "invalid_totp"
    assert events == ["cursor_enter", "cursor_exit", "password"]
    doubles["reserve_session_step_up_attempt"].assert_awaited_once()
    doubles["verify_and_consume_totp_cur"].assert_not_awaited()


async def test_undecryptable_authenticator_propagates_before_any_delete():
    """Undecryptable authenticator propagates before any delete."""
    failure = TotpDecryptionError(ACTOR_ID)
    with (
        _dependencies([_actor_row(), _actor_row(), {"present": 1}], totp=failure) as (
            cursor,
            _,
            events,
        ),
        pytest.raises(TotpDecryptionError) as caught,
    ):
        await _delete("self")
    assert caught.value is failure
    assert events[-1] == "cursor_error"
    assert all("DELETE" not in str(call.args[0]) for call in cursor.execute.await_args_list)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        (None, "ineligible_account"),
        ({"is_active": False}, "ineligible_account"),
        ({"email_verified": False}, "ineligible_account"),
        ({"auth_method": "shibboleth"}, "ineligible_account"),
        ({"password_hash": None}, "ineligible_account"),
        ({"totp_secret": None}, "ineligible_account"),
        ({"totp_recovery_required": True}, "ineligible_account"),
    ],
    ids=[
        "missing",
        "inactive",
        "unverified",
        "federated",
        "no_password",
        "no_totp",
        "recovery",
    ],
)
async def test_ineligible_actor_cannot_spend_password_work_or_delete(changes, reason):
    """Ineligible actor cannot spend password work or delete."""
    row = None if changes is None else _actor_row(**changes)
    with (
        _dependencies([row]) as (_, doubles, _),
        pytest.raises(account_deletion.AccountDeletionRejected) as caught,
    ):
        await _delete("self")
    assert caught.value.reason == reason
    doubles["run_password_work"].assert_not_awaited()
    doubles["verify_and_consume_totp_cur"].assert_not_awaited()


@pytest.mark.parametrize("locked_row", [None, _actor_row(is_active=False)])
async def test_disappearing_or_deactivated_actor_rejects_after_password_work(locked_row):
    """Disappearing or deactivated actor rejects after password work."""
    with (
        _dependencies([_actor_row(), locked_row]) as (_, doubles, events),
        pytest.raises(account_deletion.AccountDeletionRejected) as caught,
    ):
        await _delete("self")
    assert caught.value.reason == "ineligible_account"
    assert events == ["cursor_enter", "cursor_exit", "password", "cursor_enter", "cursor_error"]
    doubles["verify_and_consume_totp_cur"].assert_not_awaited()


@pytest.mark.parametrize("lock_before_snapshot", [False, True])
async def test_login_lock_does_not_replace_the_full_session_deletion_proof_budget(
    lock_before_snapshot,
):
    """Login lock does not replace the full session deletion proof budget."""
    rows = [
        _actor_row(login_unlocked=not lock_before_snapshot),
        _actor_row(login_unlocked=False),
        {"present": 1},
    ]
    with _dependencies(rows) as (cursor, doubles, _):
        result = await _delete("self")
    assert result.target_user_id == ACTOR_ID
    doubles["reserve_session_step_up_attempt"].assert_awaited_once()
    doubles["run_password_work"].assert_awaited_once()
    doubles["verify_and_consume_totp_cur"].assert_awaited_once()
    assert any("DELETE FROM users" in call.args[0] for call in cursor.execute.await_args_list)


async def test_missing_admin_target_does_not_consume_totp():
    """Missing admin target does not consume TOTP."""
    with (
        _dependencies([_actor_row(), _actor_row(), {"present": 1}, None]) as (_, doubles, _),
        pytest.raises(account_deletion.AccountDeletionRejected) as caught,
    ):
        await _delete("admin")
    assert caught.value.reason == "user_not_found"
    doubles["verify_and_consume_totp_cur"].assert_not_awaited()


async def test_admin_self_target_must_use_the_self_service_policy():
    """Admin self target must use the self service policy."""
    with (
        _dependencies([_actor_row(), _actor_row(), {"present": 1}]) as (_, doubles, _),
        pytest.raises(account_deletion.AccountDeletionRejected) as caught,
    ):
        await account_deletion.delete_account_as_admin(
            sentinel.pool,
            actor_id=ACTOR_ID,
            actor_session_id=SESSION_ID,
            target_user_id=ACTOR_ID,
            password=PASSWORD,
            totp_code="123456",
        )
    assert caught.value.reason == "self_admin_deletion"
    doubles["verify_and_consume_totp_cur"].assert_not_awaited()


async def test_current_admin_guard_rejection_cannot_reach_target_or_totp():
    """Current admin guard rejection cannot reach target or TOTP."""
    failure = AdminActionRejected("Administrator status no longer valid")
    with (
        _dependencies([_actor_row()], guard_error=failure) as (_, doubles, events),
        pytest.raises(account_deletion.AccountDeletionRejected) as caught,
    ):
        await _delete("admin")
    assert caught.value.reason == "admin_required"
    assert caught.value.__cause__ is failure
    assert events[-1] == "cursor_error"
    doubles["verify_and_consume_totp_cur"].assert_not_awaited()


async def test_success_result_is_frozen_and_contains_only_pseudonymous_address():
    """Success result is frozen and contains only pseudonymous address."""
    with _dependencies([_actor_row(), _actor_row(), {"present": 1}]) as (_, doubles, events):
        result = await _delete("self", totp_code="123 456")
    assert result == account_deletion.AccountDeletionResult(
        target_user_id=ACTOR_ID, email_hash=audit_email_hash(EMAIL), auth_method="local"
    )
    assert events[-1] == "cursor_exit"
    doubles["verify_and_consume_totp_cur"].assert_awaited_once()
    assert doubles["verify_and_consume_totp_cur"].await_args.args[2] == "123456"
    assert EMAIL not in repr(result)
    assert PASSWORD not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.__setattr__("email_hash", "replacement")


async def test_lost_locked_target_is_an_invariant_failure_without_a_success_result():
    """Lost locked target is an invariant failure without a success result."""
    with (
        _dependencies([_actor_row(), _actor_row(), {"present": 1}], rowcount=0) as (_, _, events),
        pytest.raises(RuntimeError, match="Locked deletion target unexpectedly missing"),
    ):
        await _delete("self")
    assert events[-1] == "cursor_error"

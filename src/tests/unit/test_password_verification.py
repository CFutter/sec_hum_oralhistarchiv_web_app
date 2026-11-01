"""Shared password mechanics preserve resource lifetime and workflow outcomes."""

import ast
import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import create_autospec, patch, sentinel

import pytest
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.services import admin_promotion, authentication, email_change, password_reset, totp
from app.services import password_verification as proofs
from app.services.credential_attempts import SessionStepUpAttemptOutcome
from app.services.password_verification import (
    PasswordFailureReason,
    PasswordVerificationFailure,
    PasswordVerified,
    VerifiedPasswordSnapshot,
)
from app.services.password_work import PasswordWorkAdmissionTimeout
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_sample_user_row

USER_ID = 41
PASSWORD = "password-proof-input"
STORED_HASH = "stored-password-proof-hash"
REVISION = 7


@pytest.mark.parametrize("stored", [None, "", 1, True, b"encoded"])
@pytest.mark.parametrize("missing_user", [False, True])
async def test_missing_credentials_release_the_cursor_before_dummy_work(stored, missing_user):
    """Check missing credentials release the cursor before dummy work."""
    row = None if missing_user else {"password_hash": stored, "auth_revision": REVISION}
    cursor = make_async_cursor(fetchone=row)
    events = []

    @asynccontextmanager
    async def context(_pool):
        """Record snapshot read and scope release around the scripted cursor."""
        events.append("read")
        yield cursor
        events.append("released")

    async def dummy(_password):
        """Require snapshot release before recording dummy password work."""
        assert events[-1] == "released"
        events.append("dummy")

    with (
        patch.object(proofs, "get_db_cursor", autospec=True, side_effect=context),
        patch.object(proofs, "verify_dummy", autospec=True, side_effect=dummy) as dummy_work,
        patch.object(proofs, "run_password_work", autospec=True) as work,
    ):
        result = await proofs.verify_password_snapshot(
            sentinel.pool, user_id=USER_ID, password=PASSWORD, operation="snapshot_probe"
        )
    assert result == PasswordVerificationFailure(PasswordFailureReason.MISSING_HASH, None)
    assert events == ["read", "released", "dummy"]
    dummy_work.assert_awaited_once_with(PASSWORD)
    work.assert_not_awaited()
    cursor.execute.assert_awaited_once_with(
        "SELECT password_hash, auth_revision FROM users WHERE id = %s", (USER_ID,)
    )


@pytest.mark.parametrize(
    "error_type", [None, VerifyMismatchError, InvalidHashError, VerificationError]
)
async def test_snapshot_proof_runs_after_release_and_preserves_failure_kind(error_type, caplog):
    """Check snapshot proof runs after release and preserves failure kind."""
    cursor = make_async_cursor(fetchone={"password_hash": STORED_HASH, "auth_revision": REVISION})
    released = False
    error = error_type("encoded credential could not be verified") if error_type else None

    @asynccontextmanager
    async def context(_pool):
        """Yield the snapshot cursor and mark normal scope release."""
        nonlocal released
        yield cursor
        released = True

    async def work(*_args, **_kwargs):
        """Require released snapshot scope, then raise the injected error or verify the proof."""
        assert released, "Argon2 must run after the snapshot cursor exits"
        if error is not None:
            raise error
        return True

    with (
        patch.object(proofs, "get_db_cursor", autospec=True, side_effect=context),
        patch.object(proofs, "run_password_work", autospec=True, side_effect=work) as worker,
        patch.object(proofs, "verify_dummy", autospec=True) as dummy,
        caplog.at_level(logging.ERROR, logger=proofs.__name__),
    ):
        result = await proofs.verify_password_snapshot(
            sentinel.pool, user_id=USER_ID, password=PASSWORD, operation="snapshot_probe"
        )
    worker.assert_awaited_once_with(proofs.password_hasher.verify, STORED_HASH, PASSWORD)
    if error is None:
        assert result == VerifiedPasswordSnapshot(STORED_HASH, REVISION)
        dummy.assert_not_awaited()
        assert not caplog.records
    else:
        assert isinstance(result, PasswordVerificationFailure)
        assert result.cause is error
        if error_type is VerifyMismatchError:
            assert result.reason is PasswordFailureReason.MISMATCH
            dummy.assert_not_awaited()
            assert not caplog.records
        else:
            assert result.reason is PasswordFailureReason.UNUSABLE_HASH
            dummy.assert_awaited_once_with(PASSWORD)
            assert len(caplog.records) == 1
            assert caplog.records[0].exc_info[1] is error
            assert "snapshot_probe" in caplog.records[0].getMessage()
            assert str(USER_ID) in caplog.records[0].getMessage()
    assert PASSWORD not in caplog.text
    assert STORED_HASH not in caplog.text


@pytest.mark.parametrize(
    "error",
    [
        PasswordWorkAdmissionTimeout(0.02),
        RuntimeError("worker failed"),
        MemoryError(),
        asyncio.CancelledError(),
    ],
)
async def test_noncredential_worker_failures_propagate_unchanged(error):
    """Check noncredential worker failures propagate unchanged."""
    with (
        patch.object(proofs, "run_password_work", autospec=True, side_effect=error),
        pytest.raises(type(error)) as caught,
    ):
        await proofs.verify_password_hash(
            password_hash=STORED_HASH, password=PASSWORD, user_id=USER_ID, operation="probe"
        )
    assert caught.value is error


async def test_snapshot_storage_failure_performs_no_password_work():
    """Check snapshot storage failure performs no password work (RuntimeError)."""
    error = RuntimeError("snapshot read failed")
    with (
        patch.object(proofs, "get_db_cursor", autospec=True, side_effect=error),
        patch.object(proofs, "run_password_work", autospec=True) as work,
        patch.object(proofs, "verify_dummy", autospec=True) as dummy,
        pytest.raises(RuntimeError) as caught,
    ):
        await proofs.verify_password_snapshot(
            sentinel.pool, user_id=USER_ID, password=PASSWORD, operation="probe"
        )
    assert caught.value is error
    work.assert_not_awaited()
    dummy.assert_not_awaited()


@pytest.mark.parametrize("stored", [None, "malformed"])
async def test_snapshot_dummy_admission_failure_is_not_a_credential_rejection(stored):
    """Check snapshot dummy admission failure is not a credential rejection
    (PasswordWorkAdmissionTimeout).
    """
    cursor = make_async_cursor(fetchone={"password_hash": stored, "auth_revision": REVISION})
    error = PasswordWorkAdmissionTimeout(0.02)
    with (
        patch.object(proofs, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cursor)),
        patch.object(proofs, "run_password_work", autospec=True, side_effect=InvalidHashError()),
        patch.object(proofs, "verify_dummy", autospec=True, side_effect=error),
        pytest.raises(PasswordWorkAdmissionTimeout) as caught,
    ):
        await proofs.verify_password_snapshot(
            sentinel.pool, user_id=USER_ID, password=PASSWORD, operation="probe"
        )
    assert caught.value is error


async def test_dummy_hash_is_cached_and_mismatch_is_suppressed():
    """Check dummy hash is cached and mismatch is suppressed."""
    with (
        patch.object(proofs, "_DUMMY_HASH", None),
        patch.object(
            proofs,
            "run_password_work",
            autospec=True,
            side_effect=["cached", VerifyMismatchError(), VerifyMismatchError()],
        ) as work,
    ):
        await proofs.verify_dummy(PASSWORD)
        await proofs.verify_dummy(PASSWORD)
        assert proofs._DUMMY_HASH == "cached"
    assert work.await_count == 3
    assert work.await_args_list[0].args[0] == proofs.password_hasher.hash
    assert [call.args for call in work.await_args_list[1:]] == [
        (proofs.password_hasher.verify, "cached", PASSWORD),
        (proofs.password_hasher.verify, "cached", PASSWORD),
    ]


async def test_failed_dummy_warmup_does_not_poison_the_cache():
    """Check failed dummy warmup does not poison the cache (PasswordWorkAdmissionTimeout)."""
    error = PasswordWorkAdmissionTimeout(0.02)
    with (
        patch.object(proofs, "_DUMMY_HASH", None),
        patch.object(proofs, "run_password_work", autospec=True, side_effect=[error, "retry"]),
    ):
        with pytest.raises(PasswordWorkAdmissionTimeout) as caught:
            await proofs.warm_dummy_password_hash()
        assert caught.value is error
        assert proofs._DUMMY_HASH is None
        assert await proofs.warm_dummy_password_hash() == "retry"


@pytest.mark.parametrize(
    "error", [InvalidHashError(), VerificationError(), PasswordWorkAdmissionTimeout(0.02)]
)
async def test_dummy_verification_suppresses_only_mismatch(error):
    """Check dummy verification suppresses only mismatch."""
    with (
        patch.object(proofs, "_DUMMY_HASH", "cached"),
        patch.object(proofs, "run_password_work", autospec=True, side_effect=error),
        pytest.raises(type(error)) as caught,
    ):
        await proofs.verify_dummy(PASSWORD)
    assert caught.value is error


def test_snapshot_is_immutable_and_credential_repr_is_hidden():
    """Check snapshot is immutable and credential repr is hidden (FrozenInstanceError)."""
    snapshot = VerifiedPasswordSnapshot(STORED_HASH, REVISION)
    assert STORED_HASH not in repr(snapshot)
    with pytest.raises(FrozenInstanceError):
        snapshot.auth_revision = 8
    failure = PasswordVerificationFailure(
        PasswordFailureReason.UNUSABLE_HASH, InvalidHashError("diagnostic credential material")
    )
    assert "diagnostic credential material" not in repr(failure)


@pytest.mark.parametrize("operation", ["admin_promotion", "totp_rotation"])
@pytest.mark.parametrize("reason", list(PasswordFailureReason))
async def test_snapshot_callers_preserve_workflow_rejections(operation, reason):
    """Check snapshot callers preserve workflow rejections."""
    error = VerifyMismatchError("mismatch") if reason is PasswordFailureReason.MISMATCH else None
    failure = PasswordVerificationFailure(reason, error)
    module = admin_promotion if operation == "admin_promotion" else totp
    snapshot = create_autospec(proofs.verify_password_snapshot, spec_set=True, return_value=failure)
    with (
        patch.object(
            module,
            "reserve_session_step_up_attempt",
            autospec=True,
            return_value=SessionStepUpAttemptOutcome.RESERVED,
        ),
        patch.object(module, "verify_password_snapshot", snapshot),
        patch.object(module, "get_db_cursor", autospec=True) as cursor,
    ):
        if operation == "admin_promotion":
            with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
                await admin_promotion.prepare_admin_promotion(
                    sentinel.pool,
                    user_id=USER_ID,
                    session_id="session",
                    password=PASSWORD,
                    totp_code="123456",
                )
            assert caught.value.reason == "invalid_credentials"
            assert caught.value.__cause__ is error
        else:
            result = await totp.begin_totp_rotation(
                sentinel.pool, USER_ID, PASSWORD, "123456", session_id="session"
            )
            assert result.outcome is totp.TotpRotationStartOutcome.INVALID_CREDENTIALS
            assert result.secret is None
    cursor.assert_not_called()
    snapshot.assert_awaited_once_with(
        sentinel.pool, user_id=USER_ID, password=PASSWORD, operation=operation
    )


@pytest.mark.parametrize("error_type", [VerifyMismatchError, InvalidHashError, VerificationError])
async def test_email_change_preserves_no_dummy_policy_and_original_failure_cause(error_type):
    """Check email change preserves no dummy policy and original failure cause."""
    row = {
        "password_hash": STORED_HASH,
        "auth_revision": REVISION,
        "is_active": True,
        "auth_method": "local",
        "login_unlocked": True,
    }
    cursor = make_async_cursor(fetchone=row)
    error = error_type("credential rejected")
    with (
        patch.object(
            email_change,
            "reserve_session_step_up_attempt",
            autospec=True,
            return_value=SessionStepUpAttemptOutcome.RESERVED,
        ),
        patch.object(
            email_change, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cursor)
        ) as acquire,
        patch.object(proofs, "run_password_work", autospec=True, side_effect=error),
        patch.object(proofs, "verify_dummy", autospec=True) as dummy,
        pytest.raises(email_change.SelfEmailChangeRejected) as caught,
    ):
        await email_change.stage_self_email_change(
            sentinel.pool,
            user_id=USER_ID,
            session_id="session",
            current_password=PASSWORD,
            new_email="new@example.org",
            totp_code="111111",
        )
    assert caught.value.reason == "invalid_password"
    assert caught.value.__cause__ is error
    assert acquire.call_count == 1
    dummy.assert_not_awaited()


@pytest.mark.parametrize(
    "error_type", [None, VerifyMismatchError, InvalidHashError, VerificationError]
)
async def test_login_preserves_credential_classification_and_dummy_policy(error_type):
    """Check login preserves credential classification and dummy policy."""
    row = make_sample_user_row(password_hash=STORED_HASH, auth_revision=REVISION, locked_until=None)
    cursor = make_async_cursor(fetchone=row)
    error = error_type("credential rejected") if error_type else None
    with (
        patch.object(
            authentication, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cursor)
        ),
        patch.object(
            proofs, "run_password_work", autospec=True, side_effect=error, return_value=True
        ),
        patch.object(authentication, "verify_dummy", autospec=True) as dummy,
        patch.object(authentication, "password_hasher", autospec=True) as hasher,
    ):
        hasher.check_needs_rehash.return_value = False
        result = await authentication.verify_password(sentinel.pool, "alice@example.org", PASSWORD)
    expected = (
        None
        if error_type is None
        else "wrong_password"
        if error_type is VerifyMismatchError
        else "unverifiable_hash"
    )
    assert result.failure_reason == expected
    assert result.password_ok is (error_type is None)
    assert result.auth_revision == REVISION
    assert dummy.await_count == (1 if error_type in {InvalidHashError, VerificationError} else 0)


@pytest.mark.parametrize(
    "error_type", [None, VerifyMismatchError, InvalidHashError, VerificationError]
)
async def test_password_reuse_keeps_its_no_dummy_policy(error_type):
    """Check password reuse keeps its no dummy policy."""
    error = error_type("credential rejected") if error_type else None
    with (
        patch.object(
            proofs, "run_password_work", autospec=True, side_effect=error, return_value=True
        ),
        patch.object(proofs, "verify_dummy", autospec=True) as dummy,
    ):
        result = await password_reset._is_same_as_current_password(STORED_HASH, USER_ID, PASSWORD)
    assert result is (error_type is None)
    dummy.assert_not_awaited()


@pytest.fixture(scope="module")
def real_argon2_hash():
    """Hash the test password once per module using the real Argon2 hasher."""
    return proofs.password_hasher.hash(PASSWORD)


@pytest.mark.parametrize("case", ["match", "mismatch", "unusable"])
async def test_real_argon2_and_real_bounded_worker_classify_credentials(real_argon2_hash, case):
    """Check real Argon2 and real bounded worker classify credentials."""
    result = await proofs.verify_password_hash(
        password_hash="not-an-argon2-hash" if case == "unusable" else real_argon2_hash,
        password="different password" if case == "mismatch" else PASSWORD,
        user_id=USER_ID,
        operation="real_argon2_probe",
    )
    if case == "match":
        assert isinstance(result, PasswordVerified)
    else:
        assert isinstance(result, PasswordVerificationFailure)
        assert result.reason is (
            PasswordFailureReason.MISMATCH
            if case == "mismatch"
            else PasswordFailureReason.UNUSABLE_HASH
        )


def test_compatibility_exports_share_the_single_dummy_implementation():
    """Check compatibility exports share the single dummy implementation."""
    assert authentication.verify_dummy is proofs.verify_dummy
    assert authentication.warm_dummy_password_hash is proofs.warm_dummy_password_hash


def test_shared_primitive_does_not_import_account_workflows():
    """Check shared primitive does not import account workflows."""
    source = Path(proofs.__file__).read_text()
    imports = {
        node.module for node in ast.walk(ast.parse(source)) if isinstance(node, ast.ImportFrom)
    }
    assert imports.isdisjoint(
        {
            "authentication",
            "totp",
            "admin_promotion",
            "account_deletion",
            "email_change",
            "totp_recover",
        }
    )

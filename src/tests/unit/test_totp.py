"""Contract tests for TOTP."""

import hashlib
import logging
import string
from datetime import UTC, datetime
from unittest.mock import create_autospec, patch

import pyotp
import pytest
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

import app.services.totp as totp_module
from app.services import password_verification, totp_recover
from app.services import totp_crypto as crypto_module
from app.services.crypto import audit_email_hash
from app.services.totp import matched_step
from app.services.totp_crypto import decrypt_value, encrypt_value
from app.services.totp_recovery_codes import (
    MatchedRecoveryCodeCandidate,
    ReservedRecoveryCodePasswordAttempt,
)
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

# Fixed, deterministic test vector (verified once with the pinned pyotp):
#   step = FIXED_TS // 30 = 58333333
#   code at step-2: 276064 | step-1: 036800 | step: 509970 | step+1: 629898
# '000000' matches none of the three in-window codes.
SECRET = "JBSWY3DPEHPK3PXP"
FIXED_TS = 1_750_000_000
FIXED_STEP = FIXED_TS // 30


class _FrozenTime:
    """Stands in for the `time` module inside app.services.totp only."""

    def __init__(self, ts: float):
        """Store the fixed timestamp returned by this clock."""
        self._ts = ts

    def time(self) -> float:
        """Return the stored timestamp without advancing it."""
        return self._ts


def _freeze_totp_time(monkeypatch, ts: float) -> None:
    """Freeze time.time() as seen by matched_step (patch where imported)."""
    monkeypatch.setattr(totp_module, "time", _FrozenTime(ts))


class TestCodeVerification:
    """matched_step: which codes app.services.totp accepts as a replay-safe step."""

    def test_matched_step_current_code_returns_the_exact_current_step(self, monkeypatch):
        """Check matched step current code returns the exact current step."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        code = pyotp.TOTP(SECRET).at(FIXED_TS)
        step = matched_step(SECRET, code, valid_window=1)
        assert step == FIXED_STEP

    @pytest.mark.parametrize(
        ("offset", "expected_step"),
        [(-1, FIXED_STEP - 1), (1, FIXED_STEP + 1)],
        ids=[
            "previous_window_matches_with_valid_window_one",
            "next_window_matches_with_valid_window_one",
        ],
    )
    def test_adjacent_window_code_matches_with_valid_window_one(
        self, monkeypatch, offset, expected_step
    ):
        """Check adjacent window code matches with valid window one."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        code = pyotp.TOTP(SECRET).at(FIXED_TS + 30 * offset)
        assert matched_step(SECRET, code, valid_window=1) == expected_step

    @pytest.mark.parametrize(
        "code",
        [
            pytest.param(pyotp.TOTP(SECRET).at(FIXED_TS - 60), id="two_windows_back_returns_none"),
            pytest.param("000000", id="garbage_code_returns_none"),
        ],
    )
    def test_code_outside_window_returns_none(self, monkeypatch, code):
        """A code two windows old, or an arbitrary wrong code, is rejected (None) with valid_window=1."""
        _freeze_totp_time(monkeypatch, FIXED_TS)
        in_window = {pyotp.TOTP(SECRET).at(FIXED_TS + 30 * o) for o in (-1, 0, 1)}
        assert code not in in_window  # test-vector sanity, not app behavior
        assert matched_step(SECRET, code, valid_window=1) is None

    def test_matched_step_honors_custom_period(self, monkeypatch):
        """A non-default `period` is honored both for generating the code under
        test and for computing the current step, so deployments using a
        wider step window still verify correctly.
        """
        period = 60
        _freeze_totp_time(monkeypatch, FIXED_TS)

        code = pyotp.TOTP(
            SECRET,
            interval=period,
        ).at(FIXED_TS)

        assert (
            matched_step(
                SECRET,
                code,
                valid_window=0,
                period=period,
            )
            == int(FIXED_TS) // period
        )


class TestSecretEncryptionAtRest:
    """encrypt_value / decrypt_value: the at-rest encryption for stored TOTP secrets."""

    def test_encrypt_decrypt_roundtrip(self):
        """Check encrypt decrypt roundtrip."""
        plaintext = "JBSWY3DPEHPK3PXP"
        ciphertext = encrypt_value(plaintext)
        assert ciphertext != plaintext
        assert decrypt_value(ciphertext) == plaintext

    def test_encrypt_same_plaintext_yields_distinct_ciphertexts_both_decrypt(self):
        """Two encryptions of the same plaintext differ (Fernet random IV) yet both decrypt to the
        original value.
        """
        plaintext = "correlate-me-not"
        c1 = encrypt_value(plaintext)
        c2 = encrypt_value(plaintext)
        assert c1 != c2
        assert decrypt_value(c1) == plaintext
        assert decrypt_value(c2) == plaintext

    def test_decrypt_garbage_returns_none_and_logs_warning(self, caplog):
        """Decrypt_value on non-Fernet garbage returns None (never raises) and logs a warning on the
        module logger.
        """
        with caplog.at_level(logging.WARNING, logger="app.services.totp_crypto"):
            assert decrypt_value("not-a-fernet-token") is None
        assert any(
            "Failed to decrypt" in record.getMessage() and record.levelno == logging.WARNING
            for record in caplog.records
        )

    def test_decrypt_tampered_ciphertext_returns_none(self):
        """Flipping one character of a valid ciphertext makes decrypt_value
        return None (Fernet HMAC integrity check rejects tampering) — it must
        not return corrupted plaintext or raise.
        """
        ciphertext = encrypt_value("JBSWY3DPEHPK3PXP")
        idx = 10
        flipped = "B" if ciphertext[idx] != "B" else "C"
        tampered = ciphertext[:idx] + flipped + ciphertext[idx + 1 :]
        assert tampered != ciphertext
        assert decrypt_value(tampered) is None

    def test_decrypt_value_of_non_utf8_plaintext_returns_none(self):
        """Check decrypt value of non utf8 plaintext returns none."""
        ciphertext = crypto_module._fernet_instance.encrypt(b"\xff").decode()
        assert decrypt_value(ciphertext) is None


class TestAuditEmailHash:
    """audit_email_hash: the keyed, non-reversible email token used in the audit log."""

    def test_audit_email_hash_is_deterministic(self):
        """Same email -> same token, so audit-log lines for one address can be
        correlated across events (the whole point of the token).
        """
        assert audit_email_hash("alice@example.org") == audit_email_hash("alice@example.org")

    def test_audit_email_hash_normalizes_case_and_whitespace(self):
        """' A@B.com ' hashes identically to 'a@b.com' — correlation survives
        sloppy input casing/whitespace (strip + lower before hashing).
        """
        assert audit_email_hash(" A@B.com ") == audit_email_hash("a@b.com")

    def test_audit_email_hash_default_length_is_16_hex_chars(self):
        """Default output is a 16-character lowercase-hex string (truncated
        HMAC-SHA256 hexdigest)."""
        token = audit_email_hash("alice@example.org")
        assert len(token) == 16
        assert set(token) <= set(string.hexdigits.lower())

    def test_audit_email_hash_length_param_truncates_same_digest(self):
        """The length parameter controls truncation of the SAME digest, so a
        longer token is a strict extension of the shorter one (both remain
        correlatable prefixes of the full HMAC).
        """
        short = audit_email_hash("alice@example.org", length=16)
        long = audit_email_hash("alice@example.org", length=32)
        assert len(long) == 32
        assert long.startswith(short)
        full = audit_email_hash("alice@example.org", length=64)
        assert len(full) == 64

    def test_audit_email_hash_differs_across_emails(self):
        """Different addresses produce different tokens — collisions would
        misattribute audit events between users."""
        assert audit_email_hash("alice@example.org") != audit_email_hash("bob@example.org")

    def test_audit_email_hash_is_keyed_not_plain_sha256(self):
        """The token is NOT a truncated plain sha256(email) — it is keyed (HMAC under a
        SECRET_KEY-derived key).
        """
        email = "alice@example.org"
        token = audit_email_hash(email)
        plain_prefix = hashlib.sha256(email.encode()).hexdigest()[: len(token)]
        normalized_prefix = hashlib.sha256(email.strip().lower().encode()).hexdigest()[: len(token)]
        assert token != plain_prefix
        assert token != normalized_prefix


USER_ID = 73
AUTH_REVISION = 11
GENERATION = 4
POSITION = 6
EMAIL = "owner@example.edu"
PASSWORD = "correct horse battery staple"
PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$credential-snapshot"
RECOVERY_CODE = "AAAAA-BBBBB-CCCCC-DDDDD"
_RECOVERY_NOW = datetime(2031, 1, 1, tzinfo=UTC)
_RECOVERY_EXPIRES_AT = datetime(2032, 1, 1, tzinfo=UTC)


def _eligible_recovery_row() -> dict[str, object]:
    """Build an eligible authorized recovery row with the fixed revision, deadline, and code position."""
    return {
        "id": USER_ID,
        "password_hash": PASSWORD_HASH,
        "auth_revision": AUTH_REVISION,
        "auth_method": "local",
        "is_active": True,
        "email_verified": True,
        "totp_secret": None,
        "totp_recovery_required": True,
        "totp_recovery_code_generation": GENERATION,
        "totp_recovery_authorized_at": datetime(2026, 9, 17, tzinfo=UTC),
        "totp_recovery_auth_revision": AUTH_REVISION,
        "totp_recovery_expires_at": _RECOVERY_EXPIRES_AT,
        "checked_at": _RECOVERY_NOW,
        "recovery_code_position": POSITION,
    }


def _reservation() -> ReservedRecoveryCodePasswordAttempt:
    """Build a reserved recovery-code attempt with the fixed test identity and digest."""
    return ReservedRecoveryCodePasswordAttempt(
        user_id=USER_ID,
        generation=GENERATION,
        position=POSITION,
        code_hash="reserved-recovery-code-digest",
    )


def _password_attempt() -> totp_recover._RecoveryPasswordAttempt:
    """Pair the reserved recovery attempt with the stored password hash and authentication revision."""
    return totp_recover._RecoveryPasswordAttempt(
        reservation=_reservation(),
        password_hash=PASSWORD_HASH,
        auth_revision=AUTH_REVISION,
    )


class TestRecoveryPasswordAttempts:
    """redeem_totp_recovery / _reserve_recovery_password_attempt: the bounded,
    constant-effort password work spent per recovery-code redemption attempt.
    """

    async def test_redeem_without_reservation_uses_only_dummy_password_work(self):
        """Check redeem without reservation uses only dummy password work."""
        pool = make_mock_pool()
        reserve = create_autospec(
            totp_recover._reserve_recovery_password_attempt,
            return_value=None,
            spec_set=True,
        )
        verify_dummy = create_autospec(totp_recover.verify_dummy, spec_set=True)
        password_work = create_autospec(password_verification.run_password_work, spec_set=True)
        consume = create_autospec(totp_recover.consume_reserved_recovery_code_cur, spec_set=True)
        acquire_cursor = create_autospec(
            totp_recover.get_db_cursor,
            side_effect=AssertionError("must not open a final transaction"),
            spec_set=True,
        )

        with (
            patch.object(totp_recover, "_reserve_recovery_password_attempt", reserve),
            patch.object(totp_recover, "verify_dummy", verify_dummy),
            patch.object(password_verification, "run_password_work", password_work),
            patch.object(totp_recover, "consume_reserved_recovery_code_cur", consume),
            patch.object(totp_recover, "get_db_cursor", acquire_cursor),
            pytest.raises(totp_recover.TotpRecoveryRedemptionRejected) as caught,
        ):
            await totp_recover.redeem_totp_recovery(
                pool,
                email=EMAIL,
                password=PASSWORD,
                recovery_code=RECOVERY_CODE,
                ip_address="192.0.2.10",
            )

        assert caught.value.reason == "invalid_credentials"
        assert caught.value.user_id is None
        reserve.assert_awaited_once_with(
            pool,
            email=EMAIL,
            recovery_code=RECOVERY_CODE,
        )
        verify_dummy.assert_awaited_once_with(PASSWORD)
        password_work.assert_not_awaited()
        consume.assert_not_awaited()
        acquire_cursor.assert_not_called()

    async def test_wrong_password_keeps_committed_exact_code_reservation(self):
        """A failed Argon2 check cannot roll back or release the reserved slot."""
        pool = make_mock_pool()
        initial_cur = make_async_cursor(fetchone=_eligible_recovery_row())
        locked_cur = make_async_cursor(
            fetchone=[
                _eligible_recovery_row(),
                {"position": POSITION},
                {"database_now": _RECOVERY_NOW},
            ]
        )
        reservation = _reservation()
        acquire_cursor = create_autospec(
            totp_recover.get_db_cursor,
            side_effect=[FakeCursorCtx(initial_cur), FakeCursorCtx(locked_cur)],
            spec_set=True,
        )
        reserve_code = create_autospec(
            totp_recover.reserve_recovery_code_password_attempt_cur,
            return_value=reservation,
            spec_set=True,
        )
        password_work = create_autospec(
            password_verification.run_password_work,
            side_effect=VerifyMismatchError("wrong password"),
            spec_set=True,
        )
        verify_dummy = create_autospec(totp_recover.verify_dummy, spec_set=True)
        consume = create_autospec(totp_recover.consume_reserved_recovery_code_cur, spec_set=True)

        with (
            patch.object(totp_recover, "get_db_cursor", acquire_cursor),
            patch.object(
                totp_recover,
                "reserve_recovery_code_password_attempt_cur",
                reserve_code,
            ),
            patch.object(password_verification, "run_password_work", password_work),
            patch.object(totp_recover, "verify_dummy", verify_dummy),
            patch.object(totp_recover, "consume_reserved_recovery_code_cur", consume),
            pytest.raises(totp_recover.TotpRecoveryRedemptionRejected) as caught,
        ):
            await totp_recover.redeem_totp_recovery(
                pool,
                email=EMAIL,
                password="wrong password",
                recovery_code=RECOVERY_CODE,
                ip_address="192.0.2.11",
            )

        assert caught.value.reason == "invalid_credentials"
        assert caught.value.user_id == USER_ID
        assert acquire_cursor.call_count == 2
        reserved_candidate = reserve_code.await_args.kwargs["candidate"]
        assert reserved_candidate.user_id == USER_ID
        assert reserved_candidate.generation == GENERATION
        assert reserved_candidate.position == POSITION
        reserve_code.assert_awaited_once_with(locked_cur, candidate=reserved_candidate)
        password_work.assert_awaited_once_with(
            password_verification.password_hasher.verify,
            PASSWORD_HASH,
            "wrong password",
        )
        verify_dummy.assert_not_awaited()
        consume.assert_not_awaited()

    @pytest.mark.parametrize(
        ("recovery_code", "row"),
        [
            (
                "not-a-recovery-code",
                {**_eligible_recovery_row(), "recovery_code_position": None},
            ),
            (
                RECOVERY_CODE,
                {**_eligible_recovery_row(), "recovery_code_position": None},
            ),
        ],
        ids=["malformed-code", "unknown-well-formed-code"],
    )
    async def test_unmatched_candidate_performs_only_nonlocking_reads(
        self,
        recovery_code,
        row,
    ):
        """Check unmatched candidate performs only nonlocking reads."""
        pool = make_mock_pool()
        cur = make_async_cursor(fetchone=row)
        acquire_cursor = create_autospec(
            totp_recover.get_db_cursor,
            return_value=FakeCursorCtx(cur),
            spec_set=True,
        )
        reserve_code = create_autospec(
            totp_recover.reserve_recovery_code_password_attempt_cur,
            spec_set=True,
        )

        with (
            patch.object(totp_recover, "get_db_cursor", acquire_cursor),
            patch.object(
                totp_recover,
                "reserve_recovery_code_password_attempt_cur",
                reserve_code,
            ),
        ):
            attempt = await totp_recover._reserve_recovery_password_attempt(
                pool,
                email=EMAIL,
                recovery_code=recovery_code,
            )

        assert attempt is None
        assert acquire_cursor.call_count == 1
        assert cur.execute.await_count == 1
        statements = [str(call.args[0]).upper() for call in cur.execute.await_args_list]
        assert "LEFT JOIN TOTP_RECOVERY_CODES" in statements[0]
        assert all("FOR UPDATE" not in statement for statement in statements)
        assert all("UPDATE " not in statement for statement in statements)
        assert all("DELETE " not in statement for statement in statements)
        reserve_code.assert_not_awaited()

    async def test_recovery_reservation_ignores_email_only_login_lockout(self):
        """Admin-authorized recovery remains available during ordinary login lockout."""
        pool = make_mock_pool()
        initial_cur = make_async_cursor(fetchone=_eligible_recovery_row())
        locked_cur = make_async_cursor(
            fetchone=[
                _eligible_recovery_row(),
                {"position": POSITION},
                {"database_now": _RECOVERY_NOW},
            ]
        )
        reservation = _reservation()
        acquire_cursor = create_autospec(
            totp_recover.get_db_cursor,
            side_effect=[FakeCursorCtx(initial_cur), FakeCursorCtx(locked_cur)],
            spec_set=True,
        )
        reserve_code = create_autospec(
            totp_recover.reserve_recovery_code_password_attempt_cur,
            return_value=reservation,
            spec_set=True,
        )

        with (
            patch.object(totp_recover, "get_db_cursor", acquire_cursor),
            patch.object(
                totp_recover,
                "reserve_recovery_code_password_attempt_cur",
                reserve_code,
            ),
        ):
            attempt = await totp_recover._reserve_recovery_password_attempt(
                pool,
                email=EMAIL,
                recovery_code=RECOVERY_CODE,
            )

        assert attempt is not None
        assert attempt.reservation is reservation
        statements = [
            str(call.args[0]).lower()
            for cur in (initial_cur, locked_cur)
            for call in cur.execute.await_args_list
        ]
        assert all("locked_until" not in statement for statement in statements)

    async def test_success_consumes_the_exact_reservation_without_plaintext_rematch(self):
        """Check success consumes the exact reservation without plaintext rematch."""
        pool = make_mock_pool()
        attempt = _password_attempt()
        cur = make_async_cursor(
            fetchone=[
                _eligible_recovery_row(),
                {"position": POSITION},
                {"database_now": _RECOVERY_NOW},
            ]
        )
        reserve = create_autospec(
            totp_recover._reserve_recovery_password_attempt,
            return_value=attempt,
            spec_set=True,
        )
        password_work = create_autospec(
            password_verification.run_password_work,
            return_value=True,
            spec_set=True,
        )
        verify_dummy = create_autospec(totp_recover.verify_dummy, spec_set=True)
        consume = create_autospec(
            totp_recover.consume_reserved_recovery_code_cur,
            return_value=True,
            spec_set=True,
        )
        delete_sessions = create_autospec(totp_recover.delete_user_sessions_cur, spec_set=True)
        create_session = create_autospec(
            totp_recover.create_session_cur,
            return_value="restricted-session-secret",
            spec_set=True,
        )

        with (
            patch.object(totp_recover, "_reserve_recovery_password_attempt", reserve),
            patch.object(password_verification, "run_password_work", password_work),
            patch.object(totp_recover, "verify_dummy", verify_dummy),
            patch.object(
                totp_recover,
                "get_db_cursor",
                create_autospec(
                    totp_recover.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
                ),
            ),
            patch.object(totp_recover, "consume_reserved_recovery_code_cur", consume),
            patch.object(totp_recover, "delete_user_sessions_cur", delete_sessions),
            patch.object(totp_recover, "create_session_cur", create_session),
        ):
            result = await totp_recover.redeem_totp_recovery(
                pool,
                email=EMAIL,
                password=PASSWORD,
                recovery_code=RECOVERY_CODE,
                ip_address="192.0.2.12",
            )

        assert result.user_id == USER_ID
        assert result.session_id == "restricted-session-secret"
        consume.assert_awaited_once_with(cur, reservation=attempt.reservation)
        assert RECOVERY_CODE not in repr(consume.await_args)
        verify_dummy.assert_not_awaited()
        delete_sessions.assert_awaited_once_with(cur, USER_ID)

    @pytest.mark.parametrize(
        "verification_error",
        [
            InvalidHashError("invalid encoded hash"),
            VerificationError("unverifiable encoded hash"),
        ],
        ids=["invalid-hash", "verification-error"],
    )
    async def test_unverifiable_password_hash_fails_closed(self, verification_error):
        """Check unverifiable password hash fails closed."""
        pool = make_mock_pool()
        attempt = _password_attempt()
        password_work = create_autospec(
            password_verification.run_password_work,
            side_effect=verification_error,
            spec_set=True,
        )
        verify_dummy = create_autospec(totp_recover.verify_dummy, spec_set=True)
        consume = create_autospec(totp_recover.consume_reserved_recovery_code_cur, spec_set=True)
        acquire_cursor = create_autospec(
            totp_recover.get_db_cursor,
            side_effect=AssertionError("must not finalize recovery"),
            spec_set=True,
        )

        with (
            patch.object(
                totp_recover,
                "_reserve_recovery_password_attempt",
                new=create_autospec(
                    totp_recover._reserve_recovery_password_attempt,
                    return_value=attempt,
                    spec_set=True,
                ),
            ),
            patch.object(password_verification, "run_password_work", password_work),
            patch.object(totp_recover, "verify_dummy", verify_dummy),
            patch.object(totp_recover, "consume_reserved_recovery_code_cur", consume),
            patch.object(totp_recover, "get_db_cursor", acquire_cursor),
            pytest.raises(totp_recover.TotpRecoveryRedemptionRejected) as caught,
        ):
            await totp_recover.redeem_totp_recovery(
                pool,
                email=EMAIL,
                password=PASSWORD,
                recovery_code=RECOVERY_CODE,
                ip_address="192.0.2.13",
            )

        assert caught.value.reason == "invalid_credentials"
        assert caught.value.user_id == USER_ID
        verify_dummy.assert_awaited_once_with(PASSWORD)
        consume.assert_not_awaited()
        acquire_cursor.assert_not_called()


class TestRecoverySecretRepr:
    """The recovery-attempt dataclasses hide secret fields from repr() while
    keeping non-secret identifying fields visible for logging/debugging.
    """

    def test_secret_bearing_dataclasses_hide_hashes_from_repr(self):
        """Check secret bearing dataclasses hide hashes from repr."""
        candidate = MatchedRecoveryCodeCandidate(
            user_id=USER_ID,
            generation=GENERATION,
            position=POSITION,
            code_hash="recovery-code-digest-must-not-be-logged",
        )
        attempt = totp_recover._RecoveryPasswordAttempt(
            reservation=_reservation(),
            password_hash="password-hash-must-not-be-logged",
            auth_revision=AUTH_REVISION,
        )

        assert "recovery-code-digest-must-not-be-logged" not in repr(candidate)
        assert "reserved-recovery-code-digest" not in repr(attempt.reservation)
        assert "password-hash-must-not-be-logged" not in repr(attempt)

    def test_non_secret_identifiers_remain_visible_in_repr(self):
        """Check non secret identifiers remain visible in repr."""
        candidate = MatchedRecoveryCodeCandidate(
            user_id=USER_ID,
            generation=GENERATION,
            position=POSITION,
            code_hash="recovery-code-digest-must-not-be-logged",
        )
        attempt = totp_recover._RecoveryPasswordAttempt(
            reservation=_reservation(),
            password_hash="password-hash-must-not-be-logged",
            auth_revision=AUTH_REVISION,
        )

        assert f"user_id={USER_ID}" in repr(candidate)
        assert f"generation={GENERATION}" in repr(candidate)
        assert f"position={POSITION}" in repr(candidate)
        assert f"auth_revision={AUTH_REVISION}" in repr(attempt)


def test_public_totp_rotation_preserves_timestamp_and_uses_primary_key(monkeypatch):
    """Check public TOTP rotation preserves timestamp and uses primary key."""
    old_key, new_key = Fernet(Fernet.generate_key()), Fernet(Fernet.generate_key())
    monkeypatch.setattr(crypto_module, "_fernet_instance", MultiFernet([new_key, old_key]))
    ciphertext = old_key.encrypt_at_time(b"totp-secret", 1234567890).decode()
    rotated = crypto_module.rotate_totp_value(ciphertext)
    assert new_key.decrypt(rotated.encode()) == b"totp-secret"
    assert new_key.extract_timestamp(rotated.encode()) == 1234567890


def test_public_totp_rotation_keeps_invalid_ciphertext_failure_visible():
    """Check public TOTP rotation keeps invalid ciphertext failure visible (InvalidToken)."""
    with pytest.raises(InvalidToken):
        crypto_module.rotate_totp_value("not-a-token")


@pytest.fixture(autouse=True)
def _notification_boundary(monkeypatch):
    """Keep these focused cursor scenarios independent of outbox SQL plumbing."""
    queue = create_autospec(totp_recover.queue_security_change_notice_cur, spec_set=True)
    monkeypatch.setattr(totp_recover, "queue_security_change_notice_cur", queue)
    return queue

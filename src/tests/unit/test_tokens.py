"""Token signing/validation + salt domain separation (backlog §2.1, §2.4).

Pins the itsdangerous token layer shared by three flows:

- app.services.tokens.hash_token          — SHA-256 storage hashing
- app.services.email_verification         — salt "email-verification", 24h max age
- app.services.password_reset             — salt "password-reset", 30min max age
- app.services.email_change               — salt "email-change", 1h max age

All tests are pure unit tests: no DB, no client, no Argon2. Expiry is tested
by patching itsdangerous.timed.TimestampSigner.get_timestamp during GENERATION
only (the token is signed "in the past"), then validating normally.
"""
import hashlib
import logging
import time
from unittest.mock import patch

import pytest

from app.services import email_change, email_verification, password_reset
from app.services.tokens import RESET_TOKEN_MAX_AGE_SECONDS, hash_token

EMAIL = "alice@uzh.ch"
USER_ID = 42

_TS_PATCH_TARGET = "itsdangerous.timed.TimestampSigner.get_timestamp"


def _tamper(token: str) -> str:
    """Flip a character in the PAYLOAD segment deterministically.

    Deliberately not the token's final character: base64's last char carries
    unused trailing bits, so two different final chars can decode to the same
    signature bytes and the tampered token would still verify (a real flake
    observed in CI-style full runs). Changing a payload character always
    invalidates the HMAC computed over the payload.
    """
    payload, sep, rest = token.partition(".")
    ch = payload[0]
    replacement = "A" if ch != "A" else "B"
    return replacement + payload[1:] + sep + rest


# ---------------------------------------------------------------------------
# hash_token
# ---------------------------------------------------------------------------

def test_hash_token_is_sha256_hexdigest():
    """hash_token must be exactly sha256(token).hexdigest().

    Pins the storage-hash algorithm: the DB stores this digest for
    single-use enforcement, so silently changing the algorithm would
    invalidate every outstanding verification/reset/email-change link.
    """
    token = "some-raw-token-value"
    assert hash_token(token) == hashlib.sha256(token.encode()).hexdigest()
    # 64 lowercase hex chars — the shape the DB columns expect.
    digest = hash_token("x")
    assert len(digest) == 64
    assert digest == digest.lower()


# ---------------------------------------------------------------------------
# Roundtrips — payload compat contracts
# ---------------------------------------------------------------------------

def test_verification_token_roundtrip():
    """generate → validate returns exactly {'email', 'user_id'} (§2.1).

    The verify-email route unpacks these two keys; a payload-shape change
    would break every in-flight verification link.
    """
    token = email_verification.generate_verification_token(EMAIL, USER_ID)
    data = email_verification.validate_verification_token(token)
    assert data == {"email": EMAIL, "user_id": USER_ID}


def test_reset_token_roundtrip():
    """generate → validate returns exactly {'email', 'user_id'} (§2.4)."""
    token = password_reset.generate_reset_token(EMAIL, USER_ID)
    data = password_reset.validate_reset_token(token)
    assert data == {"email": EMAIL, "user_id": USER_ID}


def test_email_change_token_self_service_omits_acting_admin_id():
    """Self-service email-change payload is {'user_id', 'new_email'} ONLY.

    Pins the payload compat contract: when acting_admin_id is not passed,
    the key must be ABSENT (not None), so self-service tokens are
    byte-compatible with tokens minted before the parameter existed.
    """
    token = email_change.generate_email_change_token(USER_ID, "new@uzh.ch")
    data = email_change.validate_email_change_token(token)
    assert data == {"user_id": USER_ID, "new_email": "new@uzh.ch"}
    assert "acting_admin_id" not in data


def test_email_change_token_carries_acting_admin_id_when_passed():
    """Admin-initiated change: acting_admin_id rides inside the signed payload.

    The confirm step reads it for the audit trail — it must survive the
    sign/validate roundtrip untampered.
    """
    token = email_change.generate_email_change_token(
        USER_ID, "new@uzh.ch", acting_admin_id=99
    )
    data = email_change.validate_email_change_token(token)
    assert data == {
        "user_id": USER_ID,
        "new_email": "new@uzh.ch",
        "acting_admin_id": 99,
    }


# ---------------------------------------------------------------------------
# Salt domain separation (security pin)
# ---------------------------------------------------------------------------

def test_verification_token_does_not_validate_as_reset_token():
    """SECURITY: a verification token must not pass reset validation.

    Both payloads are {'email','user_id'} under the same SECRET_KEY, so the
    salt is the ONLY thing separating "click to verify" from "click to take
    over the password". A shared/missing salt would let a self-served
    verification email become a password-reset link.
    """
    token = email_verification.generate_verification_token(EMAIL, USER_ID)
    assert password_reset.validate_reset_token(token) is None


def test_reset_token_does_not_validate_as_verification_token():
    """SECURITY: reverse direction of the salt separation pin —
    a reset token must not mark an email as verified."""
    token = password_reset.generate_reset_token(EMAIL, USER_ID)
    assert email_verification.validate_verification_token(token) is None


def test_email_change_token_validates_as_neither_verification_nor_reset():
    """SECURITY: an email-change token is rejected by both other validators."""
    token = email_change.generate_email_change_token(USER_ID, "new@uzh.ch")
    assert email_verification.validate_verification_token(token) is None
    assert password_reset.validate_reset_token(token) is None


def test_verification_and_reset_tokens_do_not_validate_as_email_change():
    """SECURITY: completeness of the separation matrix — neither of the
    other token types can drive the email-change confirm flow."""
    v_token = email_verification.generate_verification_token(EMAIL, USER_ID)
    r_token = password_reset.generate_reset_token(EMAIL, USER_ID)
    assert email_change.validate_email_change_token(v_token) is None
    assert email_change.validate_email_change_token(r_token) is None


# ---------------------------------------------------------------------------
# Tampering — BadSignature -> None + warning logged
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("generate", "validate", "logger_name"),
    [
        pytest.param(
            lambda: email_verification.generate_verification_token(EMAIL, USER_ID),
            email_verification.validate_verification_token,
            "app.services.email_verification",
            id="verification",
        ),
        pytest.param(
            lambda: password_reset.generate_reset_token(EMAIL, USER_ID),
            password_reset.validate_reset_token,
            "app.services.password_reset",
            id="reset",
        ),
        pytest.param(
            lambda: email_change.generate_email_change_token(USER_ID, "new@uzh.ch"),
            email_change.validate_email_change_token,
            "app.services.email_change",
            id="email-change",
        ),
    ],
)
def test_tampered_token_returns_none_and_logs_warning(
    generate, validate, logger_name, caplog
):
    """Flipping one signature character -> None (BadSignature swallowed)
    and a WARNING on the module logger.

    Guards two regressions: a validator that raises instead of returning
    None (500 on any garbled link), and one that silently drops the
    forensic warning line.
    """
    token = generate()
    tampered = _tamper(token)
    assert tampered != token
    with caplog.at_level(logging.WARNING, logger=logger_name):
        assert validate(tampered) is None
    warnings = [
        r for r in caplog.records
        if r.name == logger_name and r.levelno == logging.WARNING
    ]
    assert warnings, "expected a WARNING log for the tampered token"


# ---------------------------------------------------------------------------
# Expiry — token signed in the past, validated normally
# ---------------------------------------------------------------------------

def test_verification_token_expires_after_24_hours():
    """A verification token signed 25h ago is rejected (max age 86400s, §2.1).

    Signing time is controlled by patching TimestampSigner.get_timestamp
    during generation only; validation runs unpatched against real 'now'.
    """
    past = int(time.time()) - (86400 + 3600)
    with patch(_TS_PATCH_TARGET, return_value=past):
        token = email_verification.generate_verification_token(EMAIL, USER_ID)
    assert email_verification.validate_verification_token(token) is None


def test_reset_token_expired_after_two_hours():
    """A reset token signed 2h ago is rejected — pins the 30-minute
    RESET_TOKEN_MAX_AGE_SECONDS window (§2.4), much shorter than the
    verification token's 24h."""
    assert RESET_TOKEN_MAX_AGE_SECONDS == 1800  # the constant the window pins
    past = int(time.time()) - 7200
    with patch(_TS_PATCH_TARGET, return_value=past):
        token = password_reset.generate_reset_token(EMAIL, USER_ID)
    assert password_reset.validate_reset_token(token) is None


def test_reset_token_still_valid_after_ten_minutes():
    """A reset token signed 10 minutes ago still validates — guards against
    the expiry window being accidentally tightened below its 30-minute spec
    (which would break legitimate slow email delivery)."""
    past = int(time.time()) - 600
    with patch(_TS_PATCH_TARGET, return_value=past):
        token = password_reset.generate_reset_token(EMAIL, USER_ID)
    data = password_reset.validate_reset_token(token)
    assert data == {"email": EMAIL, "user_id": USER_ID}


def test_email_change_token_expires_after_max_age():
    """An email-change token signed 2h ago is rejected — pins the 1-hour
    EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS window."""
    assert email_change.EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS == 3600
    past = int(time.time()) - 7200
    with patch(_TS_PATCH_TARGET, return_value=past):
        token = email_change.generate_email_change_token(USER_ID, "new@uzh.ch")
    assert email_change.validate_email_change_token(token) is None

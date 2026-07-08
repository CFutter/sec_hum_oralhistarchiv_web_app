"""Unit tests: TOTP step matching (services.totp.matched_step) and the crypto
helpers (services.crypto: encrypt_value / decrypt_value / audit_email_hash).

Why these matter:
- matched_step is the foundation of TOTP replay protection: verify_and_consume_totp
  stores the *exact* step a code matched so it can never be accepted twice. If
  matched_step returned the wrong step (or matched outside the ±1 window), replayed
  or stale codes would authenticate.
- decrypt_value returning None (never raising) is what lets get_totp_secret fail
  CLOSED via TotpDecryptionError on key mismatch/corruption instead of crashing or
  silently treating an enrolled user as "no second factor".
- audit_email_hash is the keyed, non-reversible email token used in audit logs
  (cf. backlog §8.3 — audit records must not enable bulk PII harvesting). The
  anti-rainbow-table property depends on it NOT being a plain unkeyed SHA-256.

matched_step tests freeze time by replacing the `time` module reference inside
app.services.totp with a stub, so window arithmetic is fully deterministic (no
step-rollover flakiness, no probabilistic code collisions).
"""

import hashlib
import logging
import string
import time

import pyotp

import app.services.totp as totp_module
from app.services.crypto import audit_email_hash, decrypt_value, encrypt_value
from app.services.totp import matched_step

# Fixed, deterministic test vector (verified once with the pinned pyotp):
#   step = FIXED_TS // 30 = 58333333
#   code at step-2: 276064 | step-1: 036800 | step: 509970 | step+1: 629898
# '000000' matches none of the three in-window codes.
SECRET = "JBSWY3DPEHPK3PXP"
FIXED_TS = 1_750_000_000
FIXED_STEP = FIXED_TS // 30  # 58333333


class _FrozenTime:
    """Stands in for the `time` module inside app.services.totp only."""

    def __init__(self, ts: float):
        self._ts = ts

    def time(self) -> float:
        return self._ts


def _freeze_totp_time(monkeypatch, ts: float) -> None:
    """Freeze time.time() as seen by matched_step (patch where imported)."""
    monkeypatch.setattr(totp_module, "time", _FrozenTime(ts))


# ---------------------------------------------------------------------------
# matched_step
# ---------------------------------------------------------------------------

def test_matched_step_current_code_returns_current_step_real_time():
    """A code generated 'now' via pyotp matches, and the returned step is the
    current 30-second epoch step (int(time.time()) // 30).

    Guards the contract verify_and_consume_totp relies on: the step recorded
    for replay protection is the real time-step, not an offset/index.
    Real-time test per spec; tolerance of one step absorbs a window rollover
    between generating the code and calling matched_step.
    """
    t = time.time()
    code = pyotp.TOTP(SECRET).now()
    step = matched_step(SECRET, code, valid_window=1)
    assert step is not None
    assert isinstance(step, int)
    assert abs(step - int(t) // 30) <= 1


def test_matched_step_previous_window_matches_with_valid_window_one(monkeypatch):
    """A code from the PREVIOUS 30s window is accepted with valid_window=1 and
    the returned step is exactly the previous step (clock-skew tolerance).

    Regression guard: an off-by-one in the offset loop, or returning the
    current step instead of the matched one, would break replay accounting.
    """
    _freeze_totp_time(monkeypatch, FIXED_TS)
    prev_code = pyotp.TOTP(SECRET).at(FIXED_TS - 30)
    assert matched_step(SECRET, prev_code, valid_window=1) == FIXED_STEP - 1


def test_matched_step_next_window_matches_with_valid_window_one(monkeypatch):
    """The window is symmetric: a code from the NEXT step (client clock ahead)
    also matches with valid_window=1, returning step+1.
    """
    _freeze_totp_time(monkeypatch, FIXED_TS)
    next_code = pyotp.TOTP(SECRET).at(FIXED_TS + 30)
    assert matched_step(SECRET, next_code, valid_window=1) == FIXED_STEP + 1


def test_matched_step_two_windows_back_returns_none(monkeypatch):
    """A code TWO windows old is rejected (None) with valid_window=1.

    Guards the outer boundary of clock-skew tolerance: widening it would
    extend the lifetime of intercepted codes. Deterministic: at FIXED_TS the
    step-2 code (276064) differs from all three in-window codes.
    """
    _freeze_totp_time(monkeypatch, FIXED_TS)
    stale_code = pyotp.TOTP(SECRET).at(FIXED_TS - 60)
    in_window = {pyotp.TOTP(SECRET).at(FIXED_TS + 30 * o) for o in (-1, 0, 1)}
    assert stale_code not in in_window  # test-vector sanity, not app behavior
    assert matched_step(SECRET, stale_code, valid_window=1) is None


def test_matched_step_garbage_code_returns_none(monkeypatch):
    """An arbitrary wrong 6-digit code ('000000') returns None.

    Deterministic under frozen time: we first confirm '000000' is not the
    valid code for any in-window step of this fixed secret/timestamp.
    """
    _freeze_totp_time(monkeypatch, FIXED_TS)
    in_window = {pyotp.TOTP(SECRET).at(FIXED_TS + 30 * o) for o in (-1, 0, 1)}
    assert "000000" not in in_window  # test-vector sanity, not app behavior
    assert matched_step(SECRET, "000000", valid_window=1) is None


# ---------------------------------------------------------------------------
# encrypt_value / decrypt_value
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    """encrypt_value -> decrypt_value returns the original plaintext.

    The basic at-rest-encryption contract for stored TOTP secrets.
    """
    plaintext = "JBSWY3DPEHPK3PXP"
    ciphertext = encrypt_value(plaintext)
    assert ciphertext != plaintext
    assert decrypt_value(ciphertext) == plaintext


def test_encrypt_same_plaintext_yields_distinct_ciphertexts_both_decrypt():
    """Two encryptions of the same plaintext differ (Fernet random IV) yet
    both decrypt to the original value.

    Guards against a deterministic-encryption regression that would let a
    database reader detect users sharing a TOTP secret / correlate values.
    """
    plaintext = "correlate-me-not"
    c1 = encrypt_value(plaintext)
    c2 = encrypt_value(plaintext)
    assert c1 != c2
    assert decrypt_value(c1) == plaintext
    assert decrypt_value(c2) == plaintext


def test_decrypt_garbage_returns_none_and_logs_warning(caplog):
    """decrypt_value on non-Fernet garbage returns None (never raises) and
    logs a warning on the module logger.

    This None is what get_totp_secret converts into TotpDecryptionError —
    the fail-closed path for key mismatch / corruption. A raise here would
    become an unhandled 500 in every code-verifying route.
    """
    with caplog.at_level(logging.WARNING, logger="app.services.crypto"):
        assert decrypt_value("not-a-fernet-token") is None
    assert any(
        "Failed to decrypt" in record.getMessage()
        and record.levelno == logging.WARNING
        for record in caplog.records
    )


def test_decrypt_tampered_ciphertext_returns_none():
    """Flipping one character of a valid ciphertext makes decrypt_value
    return None (Fernet HMAC integrity check rejects tampering) — it must
    not return corrupted plaintext or raise.
    """
    ciphertext = encrypt_value("JBSWY3DPEHPK3PXP")
    # Flip a character in the token body, keeping length and b64 alphabet.
    idx = 10
    flipped = "B" if ciphertext[idx] != "B" else "C"
    tampered = ciphertext[:idx] + flipped + ciphertext[idx + 1:]
    assert tampered != ciphertext
    assert decrypt_value(tampered) is None


# ---------------------------------------------------------------------------
# audit_email_hash
# ---------------------------------------------------------------------------

def test_audit_email_hash_is_deterministic():
    """Same email -> same token, so audit-log lines for one address can be
    correlated across events (the whole point of the token).
    """
    assert audit_email_hash("alice@uzh.ch") == audit_email_hash("alice@uzh.ch")


def test_audit_email_hash_normalizes_case_and_whitespace():
    """' A@B.com ' hashes identically to 'a@b.com' — correlation survives
    sloppy input casing/whitespace (strip + lower before hashing).
    """
    assert audit_email_hash(" A@B.com ") == audit_email_hash("a@b.com")


def test_audit_email_hash_default_length_is_16_hex_chars():
    """Default output is a 16-character lowercase-hex string (truncated
    HMAC-SHA256 hexdigest)."""
    token = audit_email_hash("alice@uzh.ch")
    assert len(token) == 16
    assert set(token) <= set(string.hexdigits.lower())


def test_audit_email_hash_length_param_truncates_same_digest():
    """The length parameter controls truncation of the SAME digest, so a
    longer token is a strict extension of the shorter one (both remain
    correlatable prefixes of the full HMAC).
    """
    short = audit_email_hash("alice@uzh.ch", length=16)
    long = audit_email_hash("alice@uzh.ch", length=32)
    assert len(long) == 32
    assert long.startswith(short)
    full = audit_email_hash("alice@uzh.ch", length=64)
    assert len(full) == 64


def test_audit_email_hash_differs_across_emails():
    """Different addresses produce different tokens — collisions would
    misattribute audit events between users."""
    assert audit_email_hash("alice@uzh.ch") != audit_email_hash("bob@uzh.ch")


def test_audit_email_hash_is_keyed_not_plain_sha256():
    """The token is NOT a truncated plain sha256(email) — it is keyed
    (HMAC under a SECRET_KEY-derived key).

    This is the anti-rainbow-table property: a log holder without the key
    cannot precompute email -> token lookups (backlog §8.3 spirit: audit
    logs must not become a bulk PII harvesting oracle).
    """
    email = "alice@uzh.ch"
    token = audit_email_hash(email)
    plain_prefix = hashlib.sha256(email.encode()).hexdigest()[: len(token)]
    normalized_prefix = hashlib.sha256(
        email.strip().lower().encode()
    ).hexdigest()[: len(token)]
    assert token != plain_prefix
    assert token != normalized_prefix

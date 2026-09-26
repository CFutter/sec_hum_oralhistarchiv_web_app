"""Password strength validation (app.services.password_validation).

Pins the four rejection rules and their ORDER (length -> blocklist -> email
-> display name), the 4-char false-positive guard for personal-info matches,
and the fail-open (dev) / fail-closed (production) behavior when the
common-passwords data file is missing.

Pure unit tests: no DB, no client, no Argon2. Tests that need a missing
blocklist construct their own PasswordBlocklist instance so the module-level
cached blocklist (loaded from the real SecLists file) is never disturbed.
"""

import logging
from pathlib import Path

import pytest

from app.credentials import validate_seed_credentials
from app.services.password_validation import (
    MIN_PASSWORD_LENGTH,
    PasswordBlocklist,
    _blocklist,
    validate_password_strength,
)
from config import settings

# A real entry from src/app/services/data/common_passwords.txt that is >=12
# characters long — long enough to get PAST the length check (which runs
# before the blocklist check) and reach the blocklist branch.
BLOCKLISTED_12PLUS = "scandinavian"

# Clean 12+ char passwords, verified NOT to be in the data file.
CLEAN_PASSWORD = "Zq8!vN3#mK1p"  # exactly 12 chars — the minimum boundary

LENGTH_MSG = f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
COMMON_MSG = "This password is too common. Please choose a different one."
EMAIL_MSG = "Your password should not contain your email address."
NAME_MSG = "Your password should not contain your name."


# ---------------------------------------------------------------------------
# Length rule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "short_password",
    ["", "a", "elevenchars", "Zq8!vN3#mK1"],  # 0, 1, 11, 11 chars
)
def test_short_password_rejected_with_length_message(short_password):
    """Anything under 12 characters returns the length message.

    Guards the 12-char minimum (module constant MIN_PASSWORD_LENGTH) and the
    exact user-facing wording the templates display.
    """
    assert validate_password_strength(short_password) == LENGTH_MSG


def test_clean_12_char_password_passes():
    """A clean password of exactly 12 chars (the boundary) returns None.

    Pins the boundary of the length comparison (< vs <=) and
    pins that None — not empty string — signals "password OK" to callers.
    """
    assert len(CLEAN_PASSWORD) == 12
    assert validate_password_strength(CLEAN_PASSWORD) is None
    # A longer clean password also passes, even with email/name supplied.
    assert (
        validate_password_strength(
            CLEAN_PASSWORD + "-extra",
            email="alice@uzh.ch",
            display_name="Alice Müller",
        )
        is None
    )


def test_length_check_runs_before_blocklist():
    """'password' is a blocklist entry but only 8 chars: the LENGTH message
    wins, per the documented check order (length check runs first, so short
    blocklisted passwords never reach the blocklist branch).
    """
    assert validate_password_strength("password") == LENGTH_MSG


# ---------------------------------------------------------------------------
# Blocklist rule
# ---------------------------------------------------------------------------


def test_blocklisted_password_rejected_case_insensitively():
    """A 12+ char blocklist entry is rejected even when UPPERCASED.

    The file entries are lowercased at load and the candidate is lowercased
    before lookup, so casing cannot let a common password slip through.
    """
    assert len(BLOCKLISTED_12PLUS) >= 12
    assert validate_password_strength(BLOCKLISTED_12PLUS.upper()) == COMMON_MSG
    # Original casing rejected too, for completeness.
    assert validate_password_strength(BLOCKLISTED_12PLUS) == COMMON_MSG


def test_default_blocklist_loads_real_data_file_and_caches():
    """The shipped common_passwords.txt exists, loads non-empty, and the
    frozenset is cached (same object on repeated load).

    Guards against the data file being dropped from the package and against
    re-reading the 10k-line file on every validation call.
    """
    loaded = _blocklist.load_blocklist()
    assert BLOCKLISTED_12PLUS in loaded
    assert len(loaded) > 1000
    assert _blocklist.load_blocklist() is loaded  # cached, not re-read


# ---------------------------------------------------------------------------
# Email local-part rule
# ---------------------------------------------------------------------------


def test_password_containing_email_local_part_flagged():
    """Password containing the email local part (>=4 chars) is rejected,
    case-insensitively: local part 'walter' inside 'xxWALTERxx123!'.

    Guards the contextual-weakness check and its case folding.
    """
    result = validate_password_strength("xxWALTERxx123!", email="walter@x.com")
    assert result == EMAIL_MSG


def test_short_email_local_part_not_flagged():
    """False-positive guard: a local part shorter than 4 chars is ignored.

    'al@x.com' has local part 'al' (2 chars) which IS a substring of
    'walrus-thing-123' — but fragments under _MIN_PERSONAL_INFO_MATCH_CHARS
    (4) collide with ordinary words, so the check must not fire.
    """
    result = validate_password_strength("walrus-thing-123", email="al@x.com")
    assert result is None


# ---------------------------------------------------------------------------
# Display-name rule
# ---------------------------------------------------------------------------


def test_password_containing_display_name_token_flagged():
    """A display-name token >=4 chars found in the password is rejected:
    'Anna Bentley' -> 'bentley' inside 'xx-bentley-99!'.

    Guards the per-token split (surname alone triggers, not only the full
    name) and the case-insensitive comparison.
    """
    result = validate_password_strength("xx-Bentley-99!", display_name="Anna Bentley")
    assert result == NAME_MSG


def test_short_display_name_token_not_flagged():
    """False-positive guard: name tokens under 4 chars are skipped.

    'Ben Smith' splits into 'ben' (3 chars — skipped) and 'smith' (not in
    the password), so 'benny12345678' must pass even though it starts with
    'ben'.
    """
    result = validate_password_strength("benny12345678", display_name="Ben Smith")
    assert result is None


# ---------------------------------------------------------------------------
# Missing blocklist file — fail-open in dev, fail-closed in production
# ---------------------------------------------------------------------------


def test_missing_blocklist_file_dev_fails_open(caplog):
    """In dev, a missing blocklist file yields an EMPTY frozenset plus an
    error log, and validation keeps working (length + contextual checks
    still fire; blocklist check simply matches nothing).

    Guards the fail-open path: dev environments without the data file must
    not crash registration.
    """
    bl = PasswordBlocklist(Path("/nonexistent/common_passwords.txt"))
    assert not settings.is_production  # test env is ENV_STATE=dev
    with caplog.at_level(logging.ERROR, logger="app.services.password_validation"):
        loaded = bl.load_blocklist()
    assert loaded == frozenset()
    assert "Could not load password blocklist" in caplog.text
    # Validation still works without the file:
    assert bl.validate_password_strength("short") == LENGTH_MSG
    assert bl.validate_password_strength(CLEAN_PASSWORD) is None
    # Even a known-common password passes here — the empty set matches
    # nothing (that is exactly what fail-open means in dev).
    assert bl.validate_password_strength(BLOCKLISTED_12PLUS) is None


def test_missing_blocklist_file_production_fails_closed(monkeypatch):
    """In production, a missing blocklist file raises RuntimeError.

    Guards the fail-closed pin: a production deploy missing the data file
    must crash loudly on first use instead of silently accepting common
    passwords. Uses a FRESH instance (the cache is per-instance) and
    monkeypatches settings.env_state, which is_production reads at call
    time — it is not frozen at import.
    """
    monkeypatch.setattr(settings, "env_state", "production")
    bl = PasswordBlocklist(Path("/nonexistent/common_passwords.txt"))
    with pytest.raises(RuntimeError, match="blocklist missing in production"):
        bl.load_blocklist()
    # validate_password_strength on a >=12 char password reaches the
    # blocklist branch and therefore propagates the same failure.
    with pytest.raises(RuntimeError, match="blocklist missing in production"):
        bl.validate_password_strength(CLEAN_PASSWORD)


# ---------------------------------------------------------------------------
# Admin-seed password length bounds (app.credentials.validate_seed_credentials)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    ["x" * (MIN_PASSWORD_LENGTH - 1), "x" * 201],
    ids=["below_minimum_length", "above_maximum_length"],
)
def test_seed_password_outside_length_bounds_is_rejected(password):
    """ADMIN_SEED_PASSWORD shares its length bounds with local password
    validation's minimum, plus its own 200-char maximum: outside
    [MIN_PASSWORD_LENGTH, 200] the seed helper raises, naming itself."""
    with pytest.raises(ValueError, match="ADMIN_SEED_PASSWORD"):
        validate_seed_credentials("alice@uzh.ch", password)


def test_seed_password_within_length_bounds_is_accepted():
    """Positive control: a password inside the bounds is accepted and its
    normalized email is returned."""
    assert validate_seed_credentials("alice@uzh.ch", CLEAN_PASSWORD) == "alice@uzh.ch"

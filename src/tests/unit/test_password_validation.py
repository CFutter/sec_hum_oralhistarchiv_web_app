"""Password strength validation (app.services.password_validation)."""

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


@pytest.mark.parametrize(
    "short_password",
    ["", "a", "elevenchars", "Zq8!vN3#mK1"],
)
def test_short_password_rejected_with_length_message(short_password):
    """Anything under 12 characters returns the length message.

    Guards the 12-char minimum (module constant MIN_PASSWORD_LENGTH) and the
    exact user-facing wording the templates display.
    """
    assert validate_password_strength(short_password) == LENGTH_MSG


def test_clean_12_char_password_passes():
    """A clean password of exactly 12 chars (the boundary) returns None."""
    assert len(CLEAN_PASSWORD) == 12
    assert validate_password_strength(CLEAN_PASSWORD) is None
    assert (
        validate_password_strength(
            CLEAN_PASSWORD + "-extra",
            email="alice@example.org",
            display_name="Alice Müller",
        )
        is None
    )


def test_length_check_runs_before_blocklist():
    """Check length check runs before blocklist."""
    assert validate_password_strength("password") == LENGTH_MSG


def test_blocklisted_password_rejected_case_insensitively():
    """A 12+ char blocklist entry is rejected even when UPPERCASED."""
    assert len(BLOCKLISTED_12PLUS) >= 12
    assert validate_password_strength(BLOCKLISTED_12PLUS.upper()) == COMMON_MSG
    assert validate_password_strength(BLOCKLISTED_12PLUS) == COMMON_MSG


def test_default_blocklist_loads_real_data_file_and_caches():
    """The shipped common_passwords.txt exists, loads non-empty, and the frozenset is cached (same
    object on repeated load).
    """
    loaded = _blocklist.load_blocklist()
    assert BLOCKLISTED_12PLUS in loaded
    assert len(loaded) > 1000
    assert _blocklist.load_blocklist() is loaded


def test_password_containing_email_local_part_flagged():
    """Password containing the email local part (>=4 chars) is rejected, case-insensitively: local part
    'walter' inside 'xxWALTERxx123!'.
    """
    result = validate_password_strength("xxWALTERxx123!", email="walter@x.com")
    assert result == EMAIL_MSG


def test_short_email_local_part_not_flagged():
    """Check short email local part not flagged."""
    result = validate_password_strength("walrus-thing-123", email="al@x.com")
    assert result is None


def test_password_containing_display_name_token_flagged():
    """A display-name token >=4 chars found in the password is rejected: 'Anna Bentley' -> 'bentley'
    inside 'xx-bentley-99!'.
    """
    result = validate_password_strength("xx-Bentley-99!", display_name="Anna Bentley")
    assert result == NAME_MSG


def test_short_display_name_token_not_flagged():
    """Check short display name token not flagged."""
    result = validate_password_strength("benny12345678", display_name="Ben Smith")
    assert result is None


def test_missing_blocklist_file_dev_fails_open(caplog):
    """Check missing blocklist file dev fails open."""
    bl = PasswordBlocklist(Path("/nonexistent/common_passwords.txt"))
    assert not settings.is_production  # test env is ENV_STATE=dev
    with caplog.at_level(logging.ERROR, logger="app.services.password_validation"):
        loaded = bl.load_blocklist()
    assert loaded == frozenset()
    assert "Could not load password blocklist" in caplog.text
    assert bl.validate_password_strength("short") == LENGTH_MSG
    assert bl.validate_password_strength(CLEAN_PASSWORD) is None
    # Even a known-common password passes here — the empty set matches
    # nothing (that is exactly what fail-open means in dev).
    assert bl.validate_password_strength(BLOCKLISTED_12PLUS) is None


def test_missing_blocklist_file_production_fails_closed(monkeypatch):
    """In production, a missing blocklist file raises RuntimeError."""
    monkeypatch.setattr(settings, "env_state", "production")
    bl = PasswordBlocklist(Path("/nonexistent/common_passwords.txt"))
    with pytest.raises(RuntimeError, match="blocklist missing in production"):
        bl.load_blocklist()
    with pytest.raises(RuntimeError, match="blocklist missing in production"):
        bl.validate_password_strength(CLEAN_PASSWORD)


@pytest.mark.parametrize(
    "password",
    ["x" * (MIN_PASSWORD_LENGTH - 1), "x" * 201],
    ids=["below_minimum_length", "above_maximum_length"],
)
def test_seed_password_outside_length_bounds_is_rejected(password):
    """Check seed password outside length bounds is rejected (ValueError)."""
    with pytest.raises(ValueError, match="ADMIN_SEED_PASSWORD"):
        validate_seed_credentials("alice@example.org", password)


def test_seed_password_within_length_bounds_is_accepted():
    """Check seed password within length bounds is accepted."""
    assert validate_seed_credentials("alice@example.org", CLEAN_PASSWORD) == "alice@example.org"

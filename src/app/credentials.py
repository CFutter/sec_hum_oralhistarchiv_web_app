"""Shared credential bounds, normalization and secret checks, independent of settings."""

import math

from email_validator import EmailNotValidError, validate_email

LOCAL_EMAIL_MAX_CHARS = 200
LOCAL_PASSWORD_MAX_CHARS = 200
MIN_PASSWORD_LENGTH = 12
# Raw form input permits pasted whitespace; services still require six ASCII digits.
TOTP_CODE_RAW_MAX_CHARS = 16

_PUBLISHED_BOOTSTRAP_PASSWORDS = frozenset(
    {
        "change-me-immediately-use-a-strong-password",
        "GENERATE_STRONG_INITIAL_ADMIN_PASSWORD",
        "REPLACE_WITH_STRONG_ADMIN_PASSWORD",
        "REPLACE_WITH_INITIAL_ADMIN_PASSWORD",
    }
)


_WEAK_KEY_BLOCKLIST = {
    "password",
    "secret",
    "admin",
    "changeme",
    "12345678",
    "qwerty",
    "qwertz",
    "fastapi",
}

# secrets.token_urlsafe(32) produces 43 URL-safe Base64 characters.
_SECRET_MIN_CHARS = 43
_SECRET_RECOMMENDED_CHARS = 84
_SECRET_MIN_ENTROPY_BITS_PER_CHAR = 3.5
_SECRET_MIN_UNIQUE_CHARS = 5


def check_secret_strength(key: str) -> tuple[list[str], list[str]]:
    """Return blocking defects and non-blocking recommendations for ``key``.

    These are necessary conditions only. Character-frequency entropy cannot
    prove unpredictability, so operators must still generate secrets with the
    documented CSPRNG command.
    """
    blockers: list[str] = []
    warnings: list[str] = []

    if len(key) < _SECRET_MIN_CHARS:
        blockers.append("Key too short (under 43 chars / 256 bits when random)")
    elif len(key) < _SECRET_RECOMMENDED_CHARS:
        warnings.append("Key shorter than the recommended token_urlsafe(64)")

    lowered = key.lower()
    if any(word in lowered for word in _WEAK_KEY_BLOCKLIST):
        blockers.append("Key contains a common blocklisted word")

    if len(set(key)) < _SECRET_MIN_UNIQUE_CHARS:
        blockers.append("Key has too few unique characters (simple pattern)")
    if key:
        entropy = -sum(
            (key.count(character) / len(key)) * math.log2(key.count(character) / len(key))
            for character in set(key)
        )
        if entropy < _SECRET_MIN_ENTROPY_BITS_PER_CHAR:
            blockers.append(f"Key looks like a repeated/low-diversity pattern ({entropy:.2f})")

    return blockers, warnings


def normalize_email(raw: str) -> str | None:
    """Return a stripped, lowercased email with an ASCII local part, or None if invalid.

    Accepts IDN domains, skips DNS checks and rejects normalized values over 200 characters.
    """
    try:
        normalized = validate_email(
            raw.strip(), check_deliverability=False, allow_smtputf8=False
        ).normalized.lower()
    except EmailNotValidError:
        return None
    return normalized if len(normalized) <= LOCAL_EMAIL_MAX_CHARS else None


def validate_seed_credentials(email: str, password: str) -> str:
    """Return the normalized seed email or raise ValueError for invalid credentials.

    Require 12..200 password characters and reject published bootstrap passwords;
    other password-strength checks are not performed.
    """
    normalized = normalize_email(email)
    if normalized is None:
        raise ValueError("ADMIN_SEED_EMAIL must be a supported email address")
    if password in _PUBLISHED_BOOTSTRAP_PASSWORDS:
        raise ValueError("Choose a newly generated bootstrap password, not a published example")
    if not MIN_PASSWORD_LENGTH <= len(password) <= LOCAL_PASSWORD_MAX_CHARS:
        raise ValueError(
            f"ADMIN_SEED_PASSWORD must contain at least {MIN_PASSWORD_LENGTH} characters "
            f"and no more than {LOCAL_PASSWORD_MAX_CHARS} characters"
        )
    return normalized

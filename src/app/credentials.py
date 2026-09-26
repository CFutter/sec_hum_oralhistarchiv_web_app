"""Shared local-credential bounds and normalization, independent of settings."""

from email_validator import EmailNotValidError, validate_email

LOCAL_EMAIL_MAX_CHARS = 200
LOCAL_PASSWORD_MAX_CHARS = 200
MIN_PASSWORD_LENGTH = 12


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
    """Return the normalized seed email; raise ValueError for invalid email or password length.

    Password length must be 12..200 characters; this does not check password strength.
    """
    normalized = normalize_email(email)
    if normalized is None:
        raise ValueError("ADMIN_SEED_EMAIL must be a supported email address")
    if not MIN_PASSWORD_LENGTH <= len(password) <= LOCAL_PASSWORD_MAX_CHARS:
        raise ValueError(
            f"ADMIN_SEED_PASSWORD must contain at least {MIN_PASSWORD_LENGTH} characters "
            f"and no more than {LOCAL_PASSWORD_MAX_CHARS} characters"
        )
    return normalized

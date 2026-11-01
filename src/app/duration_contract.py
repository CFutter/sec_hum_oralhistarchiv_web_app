"""Supported duration limits shared by configuration and service overrides."""

import re
from typing import Final

MIN_SESSION_MAX_AGE_SECONDS: Final = 60
MAX_SESSION_MAX_AGE_SECONDS: Final = 365 * 24 * 60 * 60
MAX_LOGIN_LOCKOUT_MINUTES: Final = 7 * 24 * 60
MAX_UNVERIFIED_REAP_AFTER_DAYS: Final = 3650
MAX_OUTBOX_STALE_AFTER_SECONDS: Final = 24 * 60 * 60
MAX_SOURCE_INTERVAL_SECONDS: Final = 365 * 24 * 60 * 60
POSTGRES_STATEMENT_TIMEOUT_MAX_MS: Final = 2_147_483_647

_STATEMENT_TIMEOUT_RE = re.compile(r"([1-9][0-9]*)(ms|s|min)")
_MILLISECONDS_PER_UNIT = {"ms": 1, "s": 1000, "min": 60_000}


def _validate_integer_duration(value: object, *, name: str, minimum: int, maximum: int) -> int:
    """Return an exact int within inclusive bounds; otherwise raise ValueError."""
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def validate_session_max_age_seconds(value: object) -> int:
    """Return an exact int in 60..31536000 seconds; otherwise raise ValueError."""
    return _validate_integer_duration(
        value,
        name="max_age_seconds",
        minimum=MIN_SESSION_MAX_AGE_SECONDS,
        maximum=MAX_SESSION_MAX_AGE_SECONDS,
    )


def validate_unverified_reap_after_days(value: object) -> int:
    """Return an exact int in 1..3650 days; otherwise raise ValueError."""
    return _validate_integer_duration(
        value,
        name="max_age_days",
        minimum=1,
        maximum=MAX_UNVERIFIED_REAP_AFTER_DAYS,
    )


def validate_statement_timeout(value: object, *, name: str = "statement_timeout") -> str:
    """Return '0' or a positive ASCII ms/s/min duration; otherwise raise ValueError.

    Require no leading zeros and at most 2147483647 milliseconds; '0' disables
    the PostgreSQL statement timeout.
    """
    message = (
        f"{name} must be '0' or a positive ASCII duration like '5s', '500ms', '2min' "
        f"without leading zeros and within 1..{POSTGRES_STATEMENT_TIMEOUT_MAX_MS} milliseconds"
    )
    if not isinstance(value, str):
        raise ValueError(message)  # noqa: TRY004 - All invalid duration overrides raise ValueError.
    if value == "0":
        return value
    match = _STATEMENT_TIMEOUT_RE.fullmatch(value)
    if match is None:
        raise ValueError(message)
    quantity, unit = match.groups()
    if len(quantity) > len(str(POSTGRES_STATEMENT_TIMEOUT_MAX_MS)):
        raise ValueError(message)
    milliseconds = int(quantity) * _MILLISECONDS_PER_UNIT[unit]
    if milliseconds > POSTGRES_STATEMENT_TIMEOUT_MAX_MS:
        raise ValueError(message)
    return value

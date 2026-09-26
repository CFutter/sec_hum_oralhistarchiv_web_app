"""Validate local passwords against length, common-password, and personal-info rules."""

import logging
from pathlib import Path

from app.credentials import LOCAL_PASSWORD_MAX_CHARS, MIN_PASSWORD_LENGTH
from config import settings

logger = logging.getLogger(__name__)
__all__ = ["MIN_PASSWORD_LENGTH", "validate_password_strength", "warm_password_blocklist"]

_COMMON_PASSWORDS_FILE = Path(__file__).parent / "data" / "common_passwords.txt"
# Short personal fragments collide with ordinary words.
_MIN_PERSONAL_INFO_MATCH_CHARS = 4


class PasswordBlocklist:
    """Lazily cache lowercase passwords from a UTF-8 file for strength checks.

    Initialization is unsynchronized; concurrent first calls may read twice.
    """

    def __init__(self, file_path: Path) -> None:
        """Keep the blocklist path; defer file I/O until validation or loading."""
        self.file_path = file_path
        self._common_passwords: frozenset[str] | None = None

    def load_blocklist(self) -> frozenset[str]:
        """Return the cached, stripped lowercase nonempty file entries.

        Log read errors; raise RuntimeError in hardened environments, otherwise
        cache an empty set. Invalid UTF-8 propagates as UnicodeDecodeError.
        """
        if self._common_passwords is None:
            try:
                lines = self.file_path.read_text(encoding="utf-8").splitlines()
                self._common_passwords = frozenset(
                    line.strip().lower() for line in lines if line.strip()
                )
                logger.info(
                    "Loaded %d common passwords from blocklist",
                    len(self._common_passwords),
                )
            except OSError as e:
                logger.error("Could not load password blocklist: %s", e)  # noqa: TRY400
                if settings.is_hardened:
                    raise RuntimeError("Password blocklist missing in production") from e
                self._common_passwords = frozenset()
        return self._common_passwords

    def validate_password_strength(
        self, password: str, email: str | None = None, display_name: str | None = None
    ) -> str | None:
        """Return the first password-policy error, or None when accepted.

        Enforce credentials.MIN_PASSWORD_LENGTH through LOCAL_PASSWORD_MAX_CHARS,
        then case-insensitive blocklist membership and substrings matching the
        email local part or whitespace-delimited display-name words of at least
        four characters. None/empty context skips its check; loading may fail.
        """
        if len(password) < MIN_PASSWORD_LENGTH:
            return f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        if len(password) > LOCAL_PASSWORD_MAX_CHARS:
            return f"Password must be at most {LOCAL_PASSWORD_MAX_CHARS} characters long."

        password_lower = password.lower()

        if password_lower in self.load_blocklist():
            return "This password is too common. Please choose a different one."

        if email:
            local_part = email.split("@")[0].lower()
            if (
                local_part
                and len(local_part) >= _MIN_PERSONAL_INFO_MATCH_CHARS
                and local_part in password_lower
            ):
                return "Your password should not contain your email address."

        if display_name:
            display_name_lower = display_name.lower()
            for part in display_name_lower.split():
                if len(part) >= _MIN_PERSONAL_INFO_MATCH_CHARS and part in password_lower:
                    return "Your password should not contain your name."

        return None


_blocklist = PasswordBlocklist(_COMMON_PASSWORDS_FILE)


def validate_password_strength(
    password: str, email: str | None = None, display_name: str | None = None
) -> str | None:
    """Apply PasswordBlocklist.validate_password_strength using the bundled list."""
    return _blocklist.validate_password_strength(password, email=email, display_name=display_name)


def warm_password_blocklist() -> None:
    """Load the default list now; propagate hardened-mode or decoding failures."""
    _blocklist.load_blocklist()

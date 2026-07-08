"""Password strength validation.

Checks user-supplied passwords against a list of commonly compromised
passwords (SecLists 10k-most-common) and against contextual weakness
(password contains the email local part or a display-name word).

The 12-character minimum length is enforced here as well — form-layer
validation only bounds the maximum length. The minimum alone already
rules out all but about 10 of the 10,000 blocklisted passwords; the
explicit blocklist and contextual checks remain as defense in depth and
for clearer error messages.
"""

import logging
from pathlib import Path

from config import settings

logger = logging.getLogger(__name__)

_COMMON_PASSWORDS_FILE = Path(__file__).parent / "data" / "common_passwords.txt"
_MIN_PASSWORD_LENGTH = 12
# Minimum substring length for a personal-info match to be meaningful.
# Shorter fragments (e.g. "al", "ben") collide with ordinary words and
# would produce false positives ("Walrus", "Bentley").
_MIN_PERSONAL_INFO_MATCH_CHARS = 4

class PasswordBlocklist:
    """Lazy-loading wrapper around the common-password file plus contextual checks.
    The blocklist is read from disk on first use and cached as a frozenset."""
    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        self._common_passwords: frozenset[str] | None = None

    def load_blocklist(self) -> frozenset[str]:
        """Load the common passwords file on first use."""
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
                logger.error("Could not load password blocklist: %s", e)
                if settings.is_production:
                    raise RuntimeError("Password blocklist missing in production") from e
                self._common_passwords = frozenset()
        return self._common_passwords

    def validate_password_strength(
        self,
        password: str,
        email: str | None = None,
        display_name: str | None = None
    ) -> str | None:
        """Check a password against the blocklist and contextual weaknesses."""
        if len(password) < _MIN_PASSWORD_LENGTH:
            return f"Password must be at least {_MIN_PASSWORD_LENGTH} characters long."

        password_lower = password.lower()

        if password_lower in self.load_blocklist():
            return "This password is too common. Please choose a different one."

        if email:
            local_part = email.split("@")[0].lower()
            if local_part and len(local_part) >= _MIN_PERSONAL_INFO_MATCH_CHARS and local_part in password_lower:
                return "Your password should not contain your email address."

        if display_name:
            display_name_lower = display_name.lower()
            for part in display_name_lower.split():
                if len(part) >= _MIN_PERSONAL_INFO_MATCH_CHARS and part in password_lower:
                    return "Your password should not contain your name."

        return None


_blocklist = PasswordBlocklist(_COMMON_PASSWORDS_FILE)


def validate_password_strength(
    password: str,
    email: str | None = None,
    display_name: str | None = None
) -> str | None:
    """Module-level convenience wrapper around the default blocklist."""
    return _blocklist.validate_password_strength(
        password, email=email, display_name=display_name
    )
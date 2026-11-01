"""TOTP-only encryption; scheduler mail imports never initialize this key ring."""

import logging

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from config import settings

from .crypto import _derive_fernet

logger = logging.getLogger(__name__)


def _get_fernet() -> MultiFernet:
    """Build the TOTP key ring from TOTP_ENCRYPTION_KEYS in priority order."""
    return MultiFernet(
        [
            _derive_fernet(
                key.get_secret_value(),
                context=b"oralhistarchiv-totp-encryption-v1",
            )
            for key in settings.totp_encryption_keys
        ]
    )


_fernet_instance = _get_fernet()


def get_primary_totp_decryptor() -> Fernet:
    """Build a decryptor using only the primary configured TOTP key."""
    return _derive_fernet(
        settings.totp_encryption_keys[0].get_secret_value(),
        context=b"oralhistarchiv-totp-encryption-v1",
    )


def encrypt_value(plaintext: str) -> str:
    """Return randomized URL-safe Fernet ciphertext using the TOTP key ring."""
    return _fernet_instance.encrypt(plaintext.encode()).decode()


def rotate_totp_value(ciphertext: str) -> str:
    """Re-encrypt TOTP ciphertext with the configured primary key.

    Retains Fernet's original issuance timestamp. Raises InvalidToken for
    ciphertext unreadable by the configured ring; maintenance callers report
    and skip it. Requires process restart after changing the configured ring.
    """
    return _fernet_instance.rotate(ciphertext.encode()).decode()


def decrypt_value(ciphertext: str) -> str | None:
    """Decrypt with the TOTP key ring; log and return None on invalid data."""
    try:
        return _fernet_instance.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, UnicodeDecodeError):
        logger.warning("Failed to decrypt value — possible key mismatch or data corruption.")
        return None

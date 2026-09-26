"""Encrypt TOTP secrets/outbox bodies and hash audit email addresses.

TOTP_ENCRYPTION_KEYS and OUTBOX_ENCRYPTION_KEYS are independent HKDF/Fernet
key rings: the first encrypts, all decrypt. Retain old keys until dependent
ciphertext is retired. Rings and the SECRET_KEY-derived audit HMAC key are
cached at import; restart processes after configuration changes. SECRET_KEY
rotation invalidates signed links and changes audit hashes, not ciphertext.
Import also registers the audit-email hasher with config.logging.
"""

import base64
import hashlib
import hmac
import logging

from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import settings
from config.logging import set_audit_email_hasher

logger = logging.getLogger(__name__)

password_hasher = PasswordHasher()


def _derive_fernet(key_material: str, *, context: bytes) -> Fernet:
    """Derive a Fernet key from UTF-8 material using the HKDF context."""
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(key_material.encode())
    return Fernet(base64.urlsafe_b64encode(derived))


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


def _get_outbox_body_fernet() -> MultiFernet:
    """Build the outbox key ring: the first key encrypts, all keys decrypt."""
    return MultiFernet(
        [
            _derive_fernet(
                key.get_secret_value(),
                context=b"oralhistarchiv-email-outbox-body-v1",
            )
            for key in settings.outbox_encryption_keys
        ]
    )


_outbox_body_fernet = _get_outbox_body_fernet()


def encrypt_outbox_body(plaintext: str) -> str:
    """Encrypt a rendered email body for temporary outbox storage."""
    return _outbox_body_fernet.encrypt(plaintext.encode()).decode()


def decrypt_outbox_body(ciphertext: str) -> str | None:
    """Decrypt an outbox body; log and return None for invalid ciphertext."""
    try:
        return _outbox_body_fernet.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, UnicodeDecodeError):
        logger.warning(
            "Failed to decrypt email outbox body — possible key mismatch or data corruption."
        )
        return None


def _get_audit_hash_key() -> bytes:
    """Derive the audit-email HMAC key from SECRET_KEY using HKDF."""
    key_bytes = settings.secret_key.get_secret_value().encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"oralhistarchiv-audit-email-hash-v1",
    ).derive(key_bytes)


_audit_hash_key = _get_audit_hash_key()


def get_primary_totp_decryptor() -> Fernet:
    """Build a decryptor using only the primary configured TOTP key."""
    return _derive_fernet(
        settings.totp_encryption_keys[0].get_secret_value(),
        context=b"oralhistarchiv-totp-encryption-v1",
    )


def encrypt_value(plaintext: str) -> str:
    """Return randomized URL-safe Fernet ciphertext using the TOTP key ring."""
    return _fernet_instance.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str | None:
    """Decrypt with the TOTP key ring; log and return None on invalid data."""
    try:
        return _fernet_instance.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, UnicodeDecodeError):
        logger.warning("Failed to decrypt value — possible key mismatch or data corruption.")
        return None


def audit_email_hash(email: str, length: int = 16) -> str:
    """Return a SECRET_KEY-derived HMAC of the stripped, lowercased email.

    length applies Python slicing to the 64-character SHA-256 hex digest;
    negative lengths remove trailing characters. The result is a correlation
    token, not anonymization for someone with access to the key or a hash oracle.
    """
    mac = hmac.new(_audit_hash_key, email.strip().lower().encode(), hashlib.sha256)
    return mac.hexdigest()[:length]


set_audit_email_hasher(audit_email_hash)

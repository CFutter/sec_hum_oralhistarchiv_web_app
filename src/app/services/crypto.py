"""Application-level encryption and keyed hashing for sensitive fields.

Two independent key domains live here; they are NOT the same secret:
- TOTP-secret encryption uses TOTP_ENCRYPTION_KEYS (a list). Each entry is
  HKDF-SHA256-stretched (context "oralhistarchiv-totp-encryption-v1") into a
  Fernet key, and the list is wrapped in a MultiFernet: the FIRST key
  encrypts, ALL keys decrypt. This protects TOTP secrets at rest — a database
  compromise alone cannot generate valid TOTP codes.
- Audit-email hashing uses SECRET_KEY, HKDF-stretched (context
  "oralhistarchiv-audit-email-hash-v1") into the HMAC key used only by
  audit_email_hash(). SECRET_KEY does NOT encrypt TOTP secrets.

Fernet guarantees (for the TOTP encryption above):
- Confidentiality: AES-128-CBC
- Integrity: HMAC-SHA256 (tampered ciphertext is rejected)
- Unique ciphertext per call (random IV)

KEY ROTATION (see the README "Secrets & key rotation" section for the full
procedure):
- TOTP_ENCRYPTION_KEYS: rotate by PREPENDING a new key (it becomes the
  encryptor while old keys still decrypt), re-encrypting all stored TOTP
  secrets, then retiring the old key. Removing or replacing the key that
  existing secrets were encrypted under WITHOUT re-encrypting first makes
  every enrolled authenticator unrecoverable — affected users must re-enroll.
- SECRET_KEY: rotating it does NOT affect TOTP secrets. It breaks audit-email-
  hash correlation across the rotation boundary and invalidates outstanding
  itsdangerous tokens (email verification, password reset, email change),
  which are short-lived — users simply request new links.
"""

import base64
import logging
import hmac
import hashlib

from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from config import settings

logger = logging.getLogger(__name__)

def _derive_fernet(key_material: str) -> Fernet:
    derived = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None,
        info=b"oralhistarchiv-totp-encryption-v1").derive(key_material.encode()
    )
    return Fernet(base64.urlsafe_b64encode(derived))


def _get_fernet() -> MultiFernet:
    """Build a MultiFernet over the configured TOTP encryption keys.

    The first key encrypts; all keys can decrypt, so the key can be rotated
    by prepending a new key and retiring the old one once all stored secrets
    have been re-encrypted under it. Each key is HKDF-stretched with a fixed
    context string for domain separation.
    """
    return MultiFernet([
        _derive_fernet(k.get_secret_value())
        for k in settings.totp_encryption_keys
    ])

_fernet_instance = _get_fernet()

def _get_audit_hash_key() -> bytes:
    key_bytes = settings.secret_key.get_secret_value().encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"oralhistarchiv-audit-email-hash-v1",
    ).derive(key_bytes)

_audit_hash_key = _get_audit_hash_key()

def encrypt_value(plaintext: str) -> str:
    """Encrypt a string for database storage.

    Returns a URL-safe base64-encoded ciphertext string.
    Each call produces different ciphertext (Fernet includes a
    random IV), but all decrypt to the same plaintext.

    Args:
        plaintext: The value to encrypt (e.g., a TOTP secret).
    """
    return _fernet_instance.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str | None:
    """Decrypt a database-stored encrypted value.

    Returns the plaintext string, or None if decryption fails — e.g. corrupted
    data, tampered ciphertext, or ciphertext encrypted under a key no longer
    present in TOTP_ENCRYPTION_KEYS (a mis-sequenced key rotation).

    Args:
        ciphertext: The encrypted value from the database.
    """
    try:
        return _fernet_instance.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        logger.warning("Failed to decrypt value — possible key mismatch or data corruption.")
        return None


def audit_email_hash(email: str, length: int = 16) -> str:
    """Keyed, non-reversible token for correlating an email in audit logs
    without storing the address. HMAC-SHA256 under a SECRET_KEY-derived
    audit key, so a holder of the logs alone (e.g. a SIEM operator)
    cannot precompute a lookup table. Still NOT secret against a targeted
    check — email space is enumerable; this defeats bulk harvesting, not
    a determined per-address probe. `length` truncates for correlation use."""
    mac = hmac.new(_audit_hash_key, email.strip().lower().encode(), hashlib.sha256)
    return mac.hexdigest()[:length]
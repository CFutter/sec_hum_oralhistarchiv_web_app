"""Shared necessary-condition checks for operator-provisioned secrets."""

import math

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

"""Security validators for startup configuration checks."""
import math
import logging

from config import settings

logger = logging.getLogger(__name__)

_WEAK_KEY_BLOCKLIST = {"password", "secret", "admin", "changeme", "12345678", "qwerty", "qwertz", "fastapi"}

# secrets.token_urlsafe(32) → 43 url-safe-base64 chars = 256 bits of CSPRNG
# output. Below this the value can't physically hold 256 bits → hard reject.
_SECRET_MIN_CHARS = 43

# Recommended length; below it is acceptable-but-not-ideal → warning only.
_SECRET_RECOMMENDED_CHARS = 84

# Shannon entropy (bits/char) over the value's own character frequencies.
# Uniform base64 ≈ 6, prose ≈ 4, repeated pattern ≈ 0. Below this floor the
# value looks patterned rather than random → hard reject. NB: measures
# alphabet diversity, not unpredictability (see docstring).
_SECRET_MIN_ENTROPY_BITS_PER_CHAR = 3.5

# Fewer than this many distinct characters indicates a simple pattern
# (e.g. "abababab", "0000aaaa") rather than random output.
_SECRET_MIN_UNIQUE_CHARS = 5

# Each tuple: (setting value, display name, hardcoded insecure default)
# nosec B105 — these strings are intentionally hardcoded to detect weak keys
def _get_secrets_to_validate() -> list[tuple[str, str, str]]:
    """Collect the secrets that startup strength-validation must check.

    Returns a list one (value, display_name, insecure_default) tuple per secret.


    SECRET_KEY, SESSION_SECRET and every TOTP_ENCRYPTION_KEYS entry
    are always present and always checked. HEALTH_DETAIL_TOKEN and
    SHIBBOLETH_INTERNAL_SECRET are optional (legitimately unset in dev) and
    are included only when configured — but each gates a sensitive surface
    (internal diagnostics; the entire app-side Shibboleth trust boundary), so
    when set they must be just as strong as the core secrets.
    """
    secrets_list = [
        (
            settings.secret_key.get_secret_value(), 
            "SECRET_KEY",
            "INSECURE-DEV-KEY-CHANGE-IN-PRODUCTION"
        ),
        (
            settings.session_secret.get_secret_value(), 
            "SESSION_SECRET",
            "INSECURE-SESSION-SECRET-CHANGE-IN-PRODUCTION"
        ),
    ]
    if settings.health_detail_token is not None:
        secrets_list.append(
            (
                settings.health_detail_token.get_secret_value(),
                "HEALTH_DETAIL_TOKEN", 
                "INSECURE-DEV-HEALTH-TOKEN-CHANGE-IN-PRODUCTION"
            )
        )
    if settings.shibboleth_internal_secret is not None:
        secrets_list.append(
            (
                settings.shibboleth_internal_secret.get_secret_value(),
                "SHIBBOLETH_INTERNAL_SECRET", 
                "INSECURE-SHIB-DEV-SECRET-CHANGE-IN-PRODUCTION"
            )
        )

    for i, k in enumerate(settings.totp_encryption_keys):
        secrets_list.append((
            k.get_secret_value(),
            f"TOTP_ENCRYPTION_KEYS[{i}]",
            "INSECURE-DEV-TOTP-KEY-CHANGE-IN-PRODUCTION",
        ))
    return secrets_list


def validate_security_settings() -> None:
    """Validate critical security settings on startup.

    Checks actual configuration values rather than trusting env_state label.
    This should ensure security even if env_state is misconfigured.
    
    Aggregates all blocking issues across all settings, then raises once
    with the full list. This way operators see every problem in one
    failed startup, rather than fixing-deploying-failing N times.
    """
    all_blockers: list[str] = []
    all_warnings: list[str] = []

    for value, name, insecure_default in _get_secrets_to_validate():
        blockers, warns = _check_secret_strength(value)
        
        if value == insecure_default:
            blockers.append(
                f"Using the hardcoded default {name} from the template."
            )
        
        all_blockers.extend(f"{name}: {b}" for b in blockers)
        all_warnings.extend(f"{name}: {w}" for w in warns)
        
    all_blockers.extend(_check_cors_setting())

    if not settings.swissubase_oai_pmh_url.startswith("https://"):
        msg = (
            "SWISSUBASE_OAI_PMH_URL uses plaintext HTTP. "
            "Metadata synced over HTTP is vulnerable to interception and "
            "tampering. Use an https:// URL."
        )
        if settings.is_hardened:
            all_blockers.append(msg)
        else:
            all_warnings.append(msg) 

    if (
        settings.is_production
        and settings.rate_limit_enabled
        and not settings.rate_limit_trust_proxy
    ):
        all_blockers.append(
            "RATE_LIMIT_TRUST_PROXY=False in production: per-IP rate limiting is "
            "ineffective behind a reverse proxy. Set it True (and ensure nginx sets X-Real-IP)."
        )

    if all_blockers and settings.is_hardened:
        bullet_list = "\n  - " + "\n  - ".join(all_blockers)
        raise RuntimeError(
            f"CRITICAL SECURITY FAILURES — {len(all_blockers)} issue(s) "
            f"must be fixed before startup:{bullet_list}\n\n"
            "For weak keys, generate strong ones with: "
            "python -c 'import secrets; print(secrets.token_urlsafe(64))'"
        )

    for warning in all_warnings:
        logger.warning("SECURITY RECOMMENDATION: %s", warning)

    if all_blockers and not settings.is_hardened:
        for b in all_blockers:
            logger.warning("SECURITY (would block in production): %s", b)


def _check_secret_strength(key: str) -> tuple[list[str], list[str]]:
    """Enforce necessary conditions for a strong secret.

    This CANNOT verify randomness — Shannon entropy over character frequencies
    measures alphabet diversity, not unpredictability. The real guarantee comes
    from generating the value with a CSPRNG at sufficient length (README:
    `secrets.token_urlsafe(64)`). These checks only reject values too weak to
    have plausibly come from one; they do not certify the strong ones.
    """
    blockers: list[str] = []
    warns: list[str] = []

    if len(key) < _SECRET_MIN_CHARS:
        blockers.append("Key too short (under 43 chars / 256 bits when random)")
    elif len(key) < _SECRET_RECOMMENDED_CHARS:
        warns.append("Key shorter than the recommended token_urlsafe(64)")

    lowered = key.lower()
    if lowered in _WEAK_KEY_BLOCKLIST or any(w in lowered for w in _WEAK_KEY_BLOCKLIST):
        blockers.append("Key contains a common blocklisted word")

    if len(set(key)) < _SECRET_MIN_UNIQUE_CHARS:
        blockers.append("Key has too few unique characters (simple pattern)")
    if key:
        entropy = -sum((key.count(c) / len(key)) * math.log2(key.count(c) / len(key))
                       for c in set(key))
        if entropy < _SECRET_MIN_ENTROPY_BITS_PER_CHAR :
            blockers.append(f"Key looks like a repeated/low-diversity pattern ({entropy:.2f})")

    return blockers, warns

def _check_cors_setting() -> list[str]:
    """Collect unsafe credentialed-CORS configuration as blocker strings.

    '*' + credentials is always unsafe (Starlette reflects the request Origin,
    so any site can make credentialed reads). With credentials on, every origin
    must be a concrete https origin. Returns blockers; the caller aggregates and
    raises once.
    """
    blockers: list[str] = []
    if not settings.cors_allow_credentials:
        return blockers

    if "*" in settings.cors_origins:
        blockers.append(
            "cors_allow_credentials=True with '*' origins reflects any origin — "
            "any website could read authenticated responses. List explicit https origins."
        )

    unsafe = [
        origin for origin in settings.cors_origins
        if not origin.startswith("https://") or "localhost" in origin or "127.0.0.1" in origin
    ]
    if unsafe:
        blockers.append(
            f"cors_allow_credentials=True requires concrete https origins; unsafe entries: {unsafe}"
        )
    return blockers  
"""Security validators for startup configuration checks."""

import logging

from app.credentials import check_secret_strength as _check_secret_strength
from config import settings
from config.secret_inventory import collect_secret_inventory
from config.settings import shibboleth_activation_blockers

logger = logging.getLogger(__name__)


def _get_secrets_to_validate() -> list[tuple[str, str, str]]:
    """Return (raw value, display name, insecure default) for configured strength checks.

    Include SECRET_KEY, SESSION_SECRET, both encryption-key lists, optional
    health token, and a configured disabled-federation secret. Enabled
    federation validates its secret through the activation policy.
    """
    secrets_list = [
        (
            settings.secret_key.get_secret_value(),
            "SECRET_KEY",
            "INSECURE-DEV-KEY-CHANGE-IN-PRODUCTION",
        ),
        (
            settings.session_secret.get_secret_value(),
            "SESSION_SECRET",
            "INSECURE-SESSION-SECRET-CHANGE-IN-PRODUCTION",
        ),
    ]
    if settings.health_detail_token is not None:
        secrets_list.append(
            (
                settings.health_detail_token.get_secret_value(),
                "HEALTH_DETAIL_TOKEN",
                "INSECURE-DEV-HEALTH-TOKEN-CHANGE-IN-PRODUCTION",
            )
        )
    if settings.shibboleth_internal_secret is not None and not settings.shibboleth_enabled:
        secrets_list.append(
            (
                settings.shibboleth_internal_secret.get_secret_value(),
                "SHIBBOLETH_INTERNAL_SECRET",
                "INSECURE-SHIB-DEV-SECRET-CHANGE-IN-PRODUCTION",
            )
        )

    for i, k in enumerate(settings.totp_encryption_keys):
        secrets_list.append(
            (
                k.get_secret_value(),
                f"TOTP_ENCRYPTION_KEYS[{i}]",
                "INSECURE-DEV-TOTP-KEY-CHANGE-IN-PRODUCTION",
            )
        )
    for i, key in enumerate(settings.outbox_encryption_keys):
        secrets_list.append(
            (
                key.get_secret_value(),
                f"OUTBOX_ENCRYPTION_KEYS[{i}]",
                "INSECURE-DEV-OUTBOX-KEY-CHANGE-IN-PRODUCTION",
            )
        )
    return secrets_list


def validate_security_settings() -> None:
    """Validate secrets, CORS, hardened browser/proxy policy and federation activation.

    Call before pools, outbound I/O or ciphertext writes. Ordinary blockers raise
    RuntimeError in staging/production and log warnings in dev; enabled
    federation blockers raise in every mode. Log recommendations. Changes to
    the settings singleton require process restart.
    """
    all_blockers: list[str] = []
    all_warnings: list[str] = []
    for value, name, insecure_default in _get_secrets_to_validate():
        blockers, warns = _check_secret_strength(value)

        if value == insecure_default:
            blockers.append(f"Using the hardcoded default {name} from the template.")

        named_blockers = [f"{name}: {b}" for b in blockers]
        all_blockers.extend(named_blockers)
        all_warnings.extend(f"{name}: {w}" for w in warns)

    # Reuse construction policy to catch unsupported mutations before binding.
    federation_blockers = shibboleth_activation_blockers(
        enabled=settings.shibboleth_enabled,
        internal_secret=(
            settings.shibboleth_internal_secret.get_secret_value()
            if settings.shibboleth_internal_secret is not None
            else None
        ),
        trusted_issuers=settings.shibboleth_trusted_issuers,
        public_base_url=settings.public_base_url,
        cookies_secure=settings.cookies_secure,
        allowed_hosts=settings.allowed_hosts,
        other_secret_values=set(collect_secret_inventory(settings).federation_peers()),
    )

    all_blockers.extend(_check_cors_setting())
    if settings.is_hardened and settings.app_process_role == "web":
        if not settings.session_cookie_name.startswith("__Host-"):
            all_blockers.append("SESSION_COOKIE_NAME must use the __Host- prefix")
        if not settings.cookies_secure:
            all_blockers.append("COOKIES_SECURE must be True for hardened browser cookies")
    if (
        settings.is_hardened
        and settings.app_process_role == "web"
        and not settings.rate_limit_enabled
    ):
        all_blockers.append("RATE_LIMIT_ENABLED must be true for hardened web processes")

    # Enabled federation remains an authentication boundary even in dev.
    if settings.shibboleth_enabled and federation_blockers:
        bullet_list = "\n  - " + "\n  - ".join(federation_blockers)
        raise RuntimeError(
            "SHIBBOLETH SECURITY FAILURE — federation cannot be enabled until "
            f"{len(federation_blockers)} issue(s) are fixed:{bullet_list}"
        )

    if (
        settings.is_hardened
        and settings.app_process_role == "web"
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


def _check_cors_setting() -> list[str]:
    """Return credentialed-CORS blockers for wildcard or non-HTTPS/localhost origins.

    Return [] when credentials are disabled; this helper does not inspect
    CORS_ENABLED or reject an empty list.
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
        origin
        for origin in settings.cors_origins
        if not origin.startswith("https://") or "localhost" in origin or "127.0.0.1" in origin
    ]
    if unsafe:
        blockers.append(
            f"cors_allow_credentials=True requires concrete https origins; unsafe entries: {unsafe}"
        )
    return blockers

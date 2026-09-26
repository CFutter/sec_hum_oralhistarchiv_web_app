"""Security validators for startup configuration checks."""

import logging

from config import settings
from config.secret_strength import check_secret_strength as _check_secret_strength
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
    """Validate secrets, CORS, upstream HTTPS, proxy trust, and federation activation.

    Call before pools, outbound I/O, or ciphertext writes. Ordinary blockers
    raise RuntimeError in staging/production and log warnings in dev;
    federation activation blockers raise in every environment. Recommendations
    are logged. Settings mutation after startup requires restart.
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

    # Settings construction and this final startup gate deliberately call the
    # same pure activation-policy function. This catches unsafe mutation made
    # before the app binds and prevents the two boundaries drifting. Runtime
    # configuration changes are unsupported and require a process restart.
    other_secret_values = {
        settings.secret_key.get_secret_value(),
        settings.session_secret.get_secret_value(),
        *(key.get_secret_value() for key in settings.totp_encryption_keys),
        *(key.get_secret_value() for key in settings.outbox_encryption_keys),
    }
    if settings.health_detail_token is not None:
        other_secret_values.add(settings.health_detail_token.get_secret_value())

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
        other_secret_values=other_secret_values,
    )

    all_blockers.extend(_check_cors_setting())

    # Federation is an authentication boundary in every environment.  This
    # second, runtime-level gate intentionally remains fatal even in dev: it
    # protects publicly reachable demos and catches an unsafe mutation of the
    # already-validated Settings singleton before the callback is reachable.
    if settings.shibboleth_enabled and federation_blockers:
        bullet_list = "\n  - " + "\n  - ".join(federation_blockers)
        raise RuntimeError(
            "SHIBBOLETH SECURITY FAILURE — federation cannot be enabled until "
            f"{len(federation_blockers)} issue(s) are fixed:{bullet_list}"
        )

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

    if settings.is_hardened and settings.rate_limit_enabled and not settings.rate_limit_trust_proxy:
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

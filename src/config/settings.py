"""Validate configuration and construct the process-wide settings singleton on import.

Require an OS ENV_STATE selection before import. Only dev reads the
repository-root .env; validators may read an SMTP CA bundle. No database,
SMTP or Redis connection is opened here.
"""

import difflib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import warnings
from collections.abc import Mapping
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Annotated, Literal, NoReturn, Self, cast

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from app import (
    HOST_CSRF_COOKIE_NAME,
    HOST_PRE_SESSION_COOKIE_NAME,
    HOST_SESSION_COOKIE_NAME,
    resolve_environment,
    security_cookie_names,
)
from app.cookie_contract import CSRF_COOKIE_NAME, PRE_SESSION_COOKIE_NAME
from app.credentials import check_secret_strength, normalize_email
from app.duration_contract import (
    MAX_LOGIN_LOCKOUT_MINUTES,
    MAX_OUTBOX_STALE_AFTER_SECONDS,
    MAX_SESSION_MAX_AGE_SECONDS,
    MAX_UNVERIFIED_REAP_AFTER_DAYS,
    MIN_SESSION_MAX_AGE_SECONDS,
    validate_statement_timeout,
)
from app.federated_tier_rules import FederatedTierRule
from app.federation_contract import ISSUER_MAX_LENGTH
from app.url_safety import parse_http_url
from config.secret_inventory import collect_secret_inventory

from .redis_policy import redis_url_policy_issues

logger = logging.getLogger(__name__)

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
_MAX_SEARCH_BUDGET_FRACTION = 0.5
_HARDENED_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60
_RETIRED_SETTING_KEYS = frozenset(
    {
        "SEED_MOCK_DATA",
        "SWISSUBASE_OAI_PMH_URL",
        "OAI_INSTITUTION_FILTER",
        "SWISSUBASE_MAX_VISIBILITY",
        "SYNC_INTERVAL_SECONDS",
        "FULL_REBUILD_INTERVAL_SECONDS",
        "OAI_MAX_PAGES",
        "SYNC_WRITE_TIMEOUT_SECONDS",
        "LOCAL_AUTH_ENABLED",
    }
)

_SHIBBOLETH_INSECURE_DEFAULT = "INSECURE-SHIB-DEV-SECRET-CHANGE-IN-PRODUCTION"
_SHIBBOLETH_SECRET_MAX_CHARS = 1024
_SHIBBOLETH_SECRET_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
_CONCRETE_DNS_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


def _is_syntactically_valid_http_host(host: str | None) -> bool:
    """Accept an IP literal or an IDNA DNS name without resolving it."""
    if not host or "%" in host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii").casefold().rstrip(".")
        except UnicodeError:
            return False
        return _CONCRETE_DNS_HOST_RE.fullmatch(ascii_host) is not None
    return True


def _shibboleth_issuer_error(issuer: object) -> str | None:
    """Return a configured-issuer policy error, or None when the exact HTTPS value is valid."""
    if not isinstance(issuer, str) or not issuer:
        return "SHIBBOLETH_TRUSTED_ISSUERS cannot contain blank or non-string entries"
    if issuer != issuer.strip():
        return "SHIBBOLETH_TRUSTED_ISSUERS entries cannot have surrounding whitespace"
    if len(issuer) > ISSUER_MAX_LENGTH:
        return f"SHIBBOLETH_TRUSTED_ISSUERS entries must be at most {ISSUER_MAX_LENGTH} characters"
    if not issuer.isprintable() or any(character.isspace() for character in issuer):
        return "SHIBBOLETH_TRUSTED_ISSUERS entries cannot contain whitespace or control characters"
    if "*" in issuer or "," in issuer:
        return "SHIBBOLETH_TRUSTED_ISSUERS entries cannot contain wildcard or comma characters"
    try:
        parsed = parse_http_url(issuer, require_https=True)
    except ValueError:
        return "SHIBBOLETH_TRUSTED_ISSUERS entries must be absolute HTTPS IdP entity IDs"
    if "\\" in issuer or not _is_syntactically_valid_http_host(parsed.hostname):
        return "SHIBBOLETH_TRUSTED_ISSUERS entries must use a valid HTTPS authority host"
    return None


def _public_https_origin_error(value: object) -> str | None:
    """Return an origin error for malformed HTTPS, localhost, loopback or unspecified hosts.

    Return None otherwise; do not resolve DNS or reject other private addresses.
    """
    message = (
        "SHIBBOLETH_ENABLED=true requires a non-localhost HTTPS PUBLIC_BASE_URL "
        "in every environment"
    )
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value.isprintable()
        or "\\" in value
        or "%" in value
    ):
        return message

    try:
        parsed = parse_http_url(value, require_https=True)
    except ValueError:
        return message

    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return message

    host = (parsed.hostname or "").casefold().rstrip(".")
    try:
        ascii_host = host.encode("idna").decode("ascii").casefold().rstrip(".")
    except UnicodeError:
        return message

    if not ascii_host or ascii_host == "localhost" or ascii_host.endswith(".localhost"):
        return message

    try:
        address = ipaddress.ip_address(ascii_host)
    except ValueError:
        # libc and user agents accept historical integer, octal, hexadecimal,
        # and shortened IPv4 spellings (for example 2130706433 and 127.1).
        # inet_aton parses those deterministically without doing a DNS lookup.
        try:
            address = ipaddress.IPv4Address(socket.inet_aton(ascii_host))
        except (OSError, ValueError):
            return None

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback or address.is_unspecified:
        return message

    return None


def _shibboleth_allowed_hosts_error(allowed_hosts: list[str]) -> str | None:
    """Return an error for noncanonical DNS/IPv4 host policies, or None if valid.

    Require a nonempty list without wildcards, localhost, loopback or unspecified
    IPv4. Canonical non-loopback private IPv4 remains accepted.
    """
    message = (
        "SHIBBOLETH_ENABLED=true requires a non-empty, non-wildcard ALLOWED_HOSTS "
        "policy containing only canonical DNS names or IPv4 addresses"
    )
    if not allowed_hosts:
        return message

    for host in allowed_hosts:
        if (
            not isinstance(host, str)
            or not host
            or host != host.strip()
            or not host.isprintable()
            or "*" in host
        ):
            return message

        # Starlette 1.3 splits Host at the first colon. IPv6-shaped patterns
        # such as "[" or "[2001" can consequently match a broad family of
        # bracketed hosts. Federation permits canonical DNS names and dotted
        # IPv4 only; nginx may still listen on IPv6 behind the DNS hostname.
        try:
            packed_address = socket.inet_aton(host)
        except (OSError, ValueError):
            if (
                host != host.casefold()
                or host == "localhost"
                or host.endswith(".localhost")
                or _CONCRETE_DNS_HOST_RE.fullmatch(host) is None
            ):
                return message
        else:
            address = ipaddress.IPv4Address(packed_address)
            if host != str(address) or address.is_loopback or address.is_unspecified:
                return message

    return None


def _shibboleth_internal_secret_error(
    internal_secret: str | None,
    other_secret_values: set[str],
) -> str | None:
    """Return an error for missing, weak, non-wire-safe or reused secrets, else None."""
    if internal_secret is None:
        return (
            "SHIBBOLETH_INTERNAL_SECRET must be set whenever SHIBBOLETH_ENABLED=true "
            "(enforced in all environments). Generate one with: "
            "python -c 'import secrets; print(secrets.token_urlsafe(64))'"
        )
    if internal_secret != internal_secret.strip():
        return "SHIBBOLETH_INTERNAL_SECRET cannot have surrounding whitespace"
    if (
        internal_secret == _SHIBBOLETH_INSECURE_DEFAULT
        or len(internal_secret) > _SHIBBOLETH_SECRET_MAX_CHARS
        or not internal_secret.isprintable()
        or _SHIBBOLETH_SECRET_RE.fullmatch(internal_secret) is None
    ):
        return (
            "SHIBBOLETH_INTERNAL_SECRET must be an independent high-entropy value "
            "generated with secrets.token_urlsafe(64)"
        )

    # Run the comparatively expensive entropy scan only after the bounded
    # token_urlsafe wire-format checks above. This keeps a malformed pre-start
    # mutation from causing quadratic startup work.
    secret_blockers, _secret_warnings = check_secret_strength(internal_secret)
    if secret_blockers:
        return (
            "SHIBBOLETH_INTERNAL_SECRET must be an independent high-entropy value "
            "generated with secrets.token_urlsafe(64)"
        )
    if internal_secret in other_secret_values:
        return (
            "SHIBBOLETH_INTERNAL_SECRET must not reuse any signing, encryption, "
            "session, or health-detail secret"
        )
    return None


def shibboleth_activation_blockers(
    *,
    enabled: bool,
    internal_secret: str | None,
    trusted_issuers: list[str],
    public_base_url: object,
    cookies_secure: bool,
    allowed_hosts: list[str],
    other_secret_values: set[str],
) -> list[str]:
    """Return federation activation errors, or [] when disabled/valid.

    Check the independent callback secret, exact HTTPS issuers, HTTPS origin,
    secure cookies and concrete allowed hosts without DNS/network I/O. Restart
    processes for configuration changes; post-startup mutation is unsupported.
    """
    if not enabled:
        return []

    blockers: list[str] = []

    if secret_error := _shibboleth_internal_secret_error(internal_secret, other_secret_values):
        blockers.append(secret_error)

    if not trusted_issuers:
        blockers.append(
            "SHIBBOLETH_TRUSTED_ISSUERS must list at least one exact HTTPS IdP "
            "entity ID whenever SHIBBOLETH_ENABLED=true"
        )
    else:
        seen_issuers: set[str] = set()
        duplicate_issuer = False
        for issuer in trusted_issuers:
            if error := _shibboleth_issuer_error(issuer):
                blockers.append(error)
                break
            if issuer in seen_issuers:
                duplicate_issuer = True
            seen_issuers.add(issuer)
        if duplicate_issuer:
            blockers.append("SHIBBOLETH_TRUSTED_ISSUERS cannot contain duplicate entries")

    if origin_error := _public_https_origin_error(public_base_url):
        blockers.append(origin_error)
    if not cookies_secure:
        blockers.append(
            "COOKIES_SECURE must be True whenever SHIBBOLETH_ENABLED=true in every environment"
        )
    if allowed_hosts_error := _shibboleth_allowed_hosts_error(allowed_hosts):
        blockers.append(allowed_hosts_error)

    return blockers


class Settings(BaseSettings):
    """Validated settings; init values override OS values, dev .env and file secrets.

    The OS ENV_STATE selects dotenv policy before parsing: only dev reads the
    repository-root .env, which cannot change that selection. Source selection
    is fixed when the class is imported; restart for configuration changes.
    Validators return their input/self unless they normalize a value, and raise
    ValueError on refusal (wrapped as ValidationError during construction).
    SMTP_CA_BUNDLE validation reads certificates; source TOML is read later by
    runtime startup.
    """

    env_state: Literal["dev", "staging", "production"] = Field(...)
    app_process_role: Literal["web", "scheduler", "maintenance"] = Field(default="web")
    parser_execution_mode: Literal["service", "local"] = Field(default="service")

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE) if resolve_environment() == "dev" else None,
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Select OS-controlled dotenv loading and mask retired dotenv values before validation.

        Raise ValueError if .env tries to override ENV_STATE; retain standard source
        priority and omit dotenv outside dev. Mutate the supplied dotenv source.
        """
        mode = resolve_environment()
        if isinstance(dotenv_settings, DotEnvSettingsSource):
            dotenv_mode = dotenv_settings.env_vars.get("env_state")
            if dotenv_mode is not None and dotenv_mode != mode:
                raise ValueError("A dotenv file cannot change the OS ENV_STATE selection")
            dotenv_settings.env_vars = {
                key: "retired-setting-present" if key.upper() in _RETIRED_SETTING_KEYS else value
                for key, value in dotenv_settings.env_vars.items()
            }

        sources = super().settings_customise_sources(
            settings_cls,
            init_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
        )
        return tuple(source for source in sources if source is not dotenv_settings or mode == "dev")

    @model_validator(mode="before")
    @classmethod
    def reject_retired_settings(cls, values: object) -> object:
        """Return values or raise ValueError for retired keys in OS/parsed configuration."""
        provided = {key.upper() for key in os.environ}
        if isinstance(values, Mapping):
            provided.update(key.upper() for key in values if isinstance(key, str))

        retired = sorted(provided & _RETIRED_SETTING_KEYS)
        if "LOCAL_AUTH_ENABLED" in retired:
            raise ValueError(
                "LOCAL_AUTH_ENABLED has been removed; set LOCAL_REGISTRATION_ENABLED "
                "explicitly to control new registration. Existing local login remains available."
            )
        if retired:
            raise ValueError(
                f"Configuration keys {', '.join(retired)} have been removed; "
                "delete them and configure sources through SOURCES_CONFIG_FILE."
            )
        return values

    # SecretStr masks repr; plain strings support PostgreSQL Unix-socket URLs.

    database_url: SecretStr = Field(...)
    database_pool_size: int = Field(default=5, ge=1, le=50)
    database_pool_max_waiting: int = Field(default=32, ge=1, le=1000)
    search_statement_timeout_ms: int = Field(default=500, ge=1, le=2000)
    search_operation_timeout_seconds: float = Field(default=1.0, gt=0, le=5, allow_inf_nan=False)
    search_pool_timeout_seconds: float = Field(default=0.1, gt=0, le=1, allow_inf_nan=False)
    search_global_rate_per_second: float = Field(default=0.5, gt=0, le=1000, allow_inf_nan=False)
    search_global_burst: int = Field(default=1, ge=1, le=1000)

    @field_validator(
        "search_statement_timeout_ms",
        "search_operation_timeout_seconds",
        "search_pool_timeout_seconds",
        "search_global_rate_per_second",
        "search_global_burst",
        mode="before",
    )
    @classmethod
    def reject_boolean_search_budget(cls, value: object) -> object:
        """Return value unchanged; raise ValueError for boolean search budgets."""
        if isinstance(value, bool):
            raise ValueError("Search budgets must be numeric, not boolean")  # noqa: TRY004 - Pydantic validation
        return value

    @model_validator(mode="after")
    def validate_search_budgets(self) -> Self:
        """Return self or raise ValueError for search budgets that exceed allowed headroom.

        Pool/statement waits must be below the operation deadline; hardened modes
        require burst=1 and rate times operation deadline <= 0.5.
        """
        if self.search_pool_timeout_seconds >= self.search_operation_timeout_seconds:
            raise ValueError(
                "SEARCH_POOL_TIMEOUT_SECONDS must be below SEARCH_OPERATION_TIMEOUT_SECONDS"
            )
        if self.search_statement_timeout_ms / 1000 >= self.search_operation_timeout_seconds:
            raise ValueError(
                "SEARCH_STATEMENT_TIMEOUT_MS must be below SEARCH_OPERATION_TIMEOUT_SECONDS"
            )
        if self.is_hardened and (
            self.search_global_burst != 1
            or self.search_global_rate_per_second * self.search_operation_timeout_seconds
            > _MAX_SEARCH_BUDGET_FRACTION
        ):
            raise ValueError(
                "Deployed search requires SEARCH_GLOBAL_BURST=1 and a start rate times "
                "operation deadline no greater than 0.5"
            )
        return self

    db_statement_timeout: str = Field(
        default="5s",
        description="PostgreSQL statement_timeout. Format: '5s', '500ms', '2min'. "
        "Use positive ASCII integers without leading zeros, at most 2147483647ms. "
        "Only bare '0' disables it.",
    )
    scheduler_statement_timeout: str = Field(
        default="5min",
        description="statement_timeout for the scheduler pool. The full rebuild's "
        "source-wide DELETE outgrows the web-tier DB_STATEMENT_TIMEOUT "
        "at scale. Same duration contract as DB_STATEMENT_TIMEOUT; only bare '0' disables it.",
    )

    public_base_url: str = Field(...)

    site_name: str = Field(default="Oral History Archive")
    institution_name: str = Field(default="Your institution")
    about_summary: str = Field(
        default="Search and explore interview metadata from oral history research collections."
    )
    federated_login_label: str = Field(default="Institutional login")

    fastapi_host: str = Field(default="127.0.0.1")
    fastapi_port: int = Field(default=5000, ge=1, le=65535)
    fastapi_debug: bool = Field(default=False)
    pagination_size: int = Field(default=20, ge=1, le=100)

    secret_key: SecretStr = Field(
        ...,
        description="Application secret: derives the audit-email HMAC key and "
        "signs itsdangerous tokens (email verification, password "
        "reset, email change). Does NOT encrypt TOTP secrets — that "
        "is TOTP_ENCRYPTION_KEYS. Entropy and blocklist enforced. "
        'Generate: python -c "import secrets; print(secrets.token_urlsafe(64))"',
    )

    health_detail_token: SecretStr | None = Field(default=None)
    backup_status_file: str | None = Field(
        default=None,
        strict=True,
        min_length=1,
        max_length=4096,
        description="Optional absolute local backup-publication marker path. Missing or "
        "invalid marker content reports unknown; no archive or private key access is needed.",
    )

    @field_validator("backup_status_file")
    @classmethod
    def validate_backup_status_file(cls, value: str | None) -> str | None:
        """Return None/a canonical absolute path; raise ValueError for ambiguous/unsafe spelling.

        Reject //, empty/dot path segments and nonprintable characters without I/O.
        """
        if value is None:
            return None
        if (
            not value.startswith("/")
            or value.startswith("//")
            or any(part in {"", ".", ".."} for part in value.split("/")[1:])
            or not value.isprintable()
        ):
            raise ValueError("BACKUP_STATUS_FILE must be an unambiguous absolute local file path")
        return value

    session_secret: SecretStr = Field(...)
    session_max_age_seconds: int = Field(
        default=28800, ge=MIN_SESSION_MAX_AGE_SECONDS, le=MAX_SESSION_MAX_AGE_SECONDS
    )  # 8 hours; supported range: 1 minute to 365 days.
    session_idle_timeout_seconds: int = Field(default=1800, ge=60, le=28800)
    session_activity_update_interval_seconds: int = Field(default=60, ge=1, le=300)
    session_cookie_name: str = Field(default="oha_session")

    cookies_secure: bool = Field(
        default=True,
        description="Set the Secure flag on session/CSRF cookies. Default True. "
        "Set False ONLY for local plaintext-HTTP development "
        "(e.g. http://127.0.0.1). Never False on any environment "
        "reachable over a network.",
    )

    local_registration_enabled: bool = Field(default=True)
    totp_issuer_name: str = Field(default="")
    totp_encryption_keys: list[SecretStr] = Field(
        default_factory=list,
        description="Fernet key material for TOTP-secret encryption (JSON list). "
        "The FIRST key encrypts; ALL keys can decrypt (enables rotation). "
        'Generate each with: python -c "import secrets; print(secrets.token_urlsafe(64))"',
    )
    outbox_encryption_keys: list[SecretStr] = Field(
        ...,
        min_length=1,
        description="Key material for email-outbox body encryption (JSON list). "
        "The FIRST key encrypts; ALL keys can decrypt. "
        "Generate independently from SECRET_KEY and TOTP_ENCRYPTION_KEYS. "
        'Generate each with: python -c "import secrets; print(secrets.token_urlsafe(64))"',
    )
    login_failure_threshold: int = Field(default=10, ge=1)
    login_lockout_minutes: int = Field(default=15, ge=1, le=MAX_LOGIN_LOCKOUT_MINUTES)
    session_step_up_attempt_limit: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Maximum credential step-up submissions during one full session.",
    )
    totp_rotation_confirmation_attempt_limit: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Maximum confirmation-code submissions for one staged TOTP rotation.",
    )
    unverified_reap_after_days: int = Field(
        default=7,
        ge=1,
        le=MAX_UNVERIFIED_REAP_AFTER_DAYS,
        description="Delete unverified local accounts older than this many days.",
    )

    # Trust these assertions only behind the nginx Shibboleth boundary.
    shibboleth_enabled: bool = Field(default=False)
    federated_tier_rules: Annotated[tuple[FederatedTierRule, ...], NoDecode] = Field(
        default=(),
        description="Ordered JSON array of advisory federated tier rules. "
        "A rule proposes a tier only; it cannot approve an account or change access.",
    )
    shibboleth_internal_secret: SecretStr | None = Field(default=None)
    shibboleth_trusted_issuers: list[str] = Field(
        default_factory=list,
        description="Exact HTTPS SAML IdP entity IDs accepted by the callback. "
        "Must be non-empty whenever Shibboleth is enabled.",
    )

    trusted_proxy_ips: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])

    # Optional general Redis for catalogue-statistics cache invalidation.
    # Hardened web rate limiting uses RATE_LIMIT_REDIS_URL separately.
    redis_enabled: bool = Field(default=False)
    redis_url: SecretStr = Field(default=SecretStr("redis://localhost:6379/0"))

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(default="INFO")
    log_format: Literal["json", "text"] = Field(default="json")

    rate_limit_enabled: bool = Field(default=True)
    rate_limit_per_minute: int = Field(default=100, ge=1)
    rate_limit_per_hour: int = Field(default=1000, ge=1)
    rate_limit_per_day: int = Field(default=10000, ge=1)
    limiter_counter_capacity: int = Field(default=20000, ge=1, le=20000)
    limiter_cleanup_batch_size: int = Field(default=128, ge=1, le=1024)

    @field_validator("limiter_counter_capacity", "limiter_cleanup_batch_size", mode="before")
    @classmethod
    def reject_boolean_limiter_budget(cls, value: object) -> object:
        """Return value unchanged; raise ValueError for boolean limiter budgets."""
        if isinstance(value, bool):
            raise ValueError("Limiter budgets must be integers, not boolean")  # noqa: TRY004 - Pydantic validation
        return value

    rate_limit_trust_proxy: bool = Field(default=False)  # Should be True if behind Nginx
    rate_limit_redis_url: SecretStr = Field(
        default=SecretStr(""),
        description="Dedicated Redis credential for rate-limit counters. "
        "Empty in dev falls back to REDIS_URL when REDIS_ENABLED=true, "
        "then to process-local memory. Database 0 only; no query parameters.",
    )

    cors_enabled: bool = Field(default=False)
    cors_origins: list[str] = Field(default_factory=list)
    cors_allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST"])
    cors_allow_headers: list[str] = Field(default_factory=lambda: ["Authorization", "Content-Type"])
    cors_allow_credentials: bool = Field(default=False)
    allowed_hosts: list[str]

    # Defer source-file validation until runtime source selection.
    sources_config_file: str | None = Field(
        default=None,
        description="Explicit source TOML path required for web and scheduler startup. "
        "Read and validated during runtime source selection.",
    )
    allow_fixture_source: bool = Field(
        default=False,
        description="Explicitly permit fixture adapters in production. "
        "This does not select or bootstrap a fixture source.",
    )

    @field_validator("sources_config_file", mode="before")
    @classmethod
    def _normalize_sources_config_file(cls, value: object) -> object:
        """Map an empty string to None; preserve paths or raise ValueError for outer whitespace."""
        if isinstance(value, str):
            if not value:
                return None
            if value != value.strip():
                raise ValueError("SOURCES_CONFIG_FILE must not have surrounding whitespace")
        return value

    contact_email: str = Field(default="archive@example.org")
    # Legacy inputs remain visible to rejection and accidental-secret redaction.
    admin_seed_email: str | None = Field(default=None)
    admin_seed_password: SecretStr | None = Field(default=None)
    password_work_concurrency: int = Field(default=1, ge=1, le=2)
    password_work_admission_timeout_seconds: float = Field(
        default=1.0,
        ge=0.01,
        le=5.0,
        allow_inf_nan=False,
        description="Maximum wait for a password-work slot; does not limit running hash work.",
    )

    @field_validator("password_work_admission_timeout_seconds", mode="before")
    @classmethod
    def reject_boolean_password_admission_timeout(cls, value: object) -> object:
        """Return value unchanged; raise ValueError for boolean admission timeouts."""
        if isinstance(value, bool):
            raise ValueError(  # noqa: TRY004 - Pydantic wraps ValueError as a field error.
                "PASSWORD_WORK_ADMISSION_TIMEOUT_SECONDS must be a number"
            )
        return value

    # Terminal outbox retention: transaction size is independent of cadence.
    outbox_sent_retention_days: int = Field(default=7, ge=1, le=3650)
    outbox_dead_retention_days: int = Field(default=30, ge=1, le=3650)
    outbox_retention_batch_size: int = Field(default=1000, ge=1, le=5000)
    outbox_retention_interval_seconds: int = Field(default=60, ge=1, le=60)
    outbox_stale_after_seconds: int = Field(default=600, ge=60, le=MAX_OUTBOX_STALE_AFTER_SECONDS)

    @field_validator(
        "session_max_age_seconds",
        "session_idle_timeout_seconds",
        "session_activity_update_interval_seconds",
        "login_lockout_minutes",
        "unverified_reap_after_days",
        "outbox_sent_retention_days",
        "outbox_dead_retention_days",
        "outbox_retention_interval_seconds",
        "outbox_stale_after_seconds",
        mode="before",
    )
    @classmethod
    def reject_boolean_integer_duration(cls, value: object, info: ValidationInfo) -> object:
        """Return value unchanged; raise ValueError for boolean duration values."""
        if isinstance(value, bool):
            raise ValueError(  # noqa: TRY004 - Pydantic wraps ValueError as a field error.
                f"{info.field_name} must be an integer duration, not a boolean"
            )
        return value

    smtp_enabled: bool = Field(default=False)
    dev_mailbox_dir: str = Field(default=".dev-mailbox", min_length=1)
    smtp_host: str = Field(default="smtp.example.com")
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: str = Field(default="")
    smtp_password: SecretStr | None = Field(default=None)
    smtp_from_address: str = Field(default="noreply@example.com")
    smtp_from_name: str = Field(default="Oral History Archive")
    smtp_use_tls: bool = Field(default=True)
    smtp_ca_bundle: str | None = Field(
        default=None,
        description="PEM CA bundle for verifying the SMTP relay's certificate. "
        "Set this for an internal relay signed by a private CA. "
        "Unset = use the system trust store.",
    )

    @property
    def is_production(self) -> bool:
        """Return whether ENV_STATE is production."""
        return self.env_state == "production"

    @property
    def is_hardened(self) -> bool:
        """Return whether ENV_STATE is staging or production."""
        return self.env_state != "dev"

    @property
    def dedicated_rate_limit_storage_uri(self) -> str | None:
        """Return stripped RATE_LIMIT_REDIS_URL, or None when blank."""
        return self.rate_limit_redis_url.get_secret_value().strip() or None

    @property
    def rate_limit_storage_uri(self) -> str | None:
        """Redis URL for limiter counters, or None for "no Redis URL".

        Hardened environments accept only the dedicated RATE_LIMIT_REDIS_URL;
        None there makes validate_rate_limit_configuration refuse startup.
        Development may borrow REDIS_URL, otherwise None selects memory storage.
        """
        dedicated = self.dedicated_rate_limit_storage_uri
        if dedicated:
            return dedicated
        if not self.is_hardened and self.redis_enabled:
            return self.redis_url.get_secret_value()
        return None

    @field_validator("site_name", "institution_name", "about_summary", "federated_login_label")
    @classmethod
    def validate_site_identity(cls, value: str, info: ValidationInfo) -> str:
        """Return stripped nonblank printable display text; otherwise raise ValueError."""
        value = value.strip()
        if not value or not value.isprintable():
            raise ValueError(f"{info.field_name} must be nonblank, single-line text")
        return value

    @model_validator(mode="after")
    def resolve_totp_issuer_name(self) -> Self:
        """Strip/set TOTP issuer (blank: site_name); reject nonprintable text with ValueError."""
        issuer = self.totp_issuer_name.strip() or self.site_name
        if not issuer.isprintable():
            raise ValueError("TOTP_ISSUER_NAME must be single-line text")
        self.totp_issuer_name = issuer
        return self

    @field_validator("public_base_url")
    @classmethod
    def _normalize_public_base_url(cls, value: str) -> str:
        """Return normalized scheme://netloc; raise ValueError for non-HTTP(S) origins.

        Strip whitespace; forbid credentials, controls, nonroot paths, queries and
        fragments. Remove a trailing root slash and lowercase the scheme.
        """
        candidate = value.strip()

        try:
            parsed = parse_http_url(candidate)
        except ValueError as exc:
            raise ValueError(
                "PUBLIC_BASE_URL must be an absolute http:// or https:// "
                "URL with a host and no credentials"
            ) from exc

        if parsed.path not in {"", "/"}:
            raise ValueError("PUBLIC_BASE_URL must not contain a path")
        if "?" in candidate or "#" in candidate:
            raise ValueError("PUBLIC_BASE_URL must not contain a query or fragment")

        return f"{parsed.scheme.casefold()}://{parsed.netloc}"

    @field_validator("shibboleth_internal_secret", mode="before")
    @classmethod
    def _normalize_optional_shibboleth_secret(cls, value: object) -> object:
        """Map empty str/SecretStr to None; preserve every nonempty value exactly."""
        if isinstance(value, str) and not value:
            return None
        if isinstance(value, SecretStr) and not value.get_secret_value():
            return None
        return value

    @field_validator("shibboleth_trusted_issuers")
    @classmethod
    def _validate_shibboleth_trusted_issuers(cls, values: list[str]) -> list[str]:
        """Return exact unique HTTPS issuers, or raise ValueError for invalid/duplicate entries."""
        for issuer in values:
            if error := _shibboleth_issuer_error(issuer):
                raise ValueError(error)

        if len(set(values)) != len(values):
            raise ValueError("SHIBBOLETH_TRUSTED_ISSUERS cannot contain duplicate entries")
        return values

    @field_validator("federated_tier_rules", mode="before")
    @classmethod
    def validate_federated_tier_rules(cls, value: object) -> object:
        """Decode a JSON array or accept list/tuple, even when federation is disabled.

        Raise ValueError for other containers, malformed JSON, duplicate keys or
        nonfinite constants. Preserve ordering; field validation builds frozen rules.
        """

        def unique_object(items: list[tuple[str, object]]) -> dict[str, object]:
            """Build a JSON object; raise ValueError for duplicate keys."""
            result: dict[str, object] = {}
            for key, item in items:
                if key in result:
                    raise ValueError("FEDERATED_TIER_RULES cannot contain duplicate JSON keys")
                result[key] = item
            return result

        def reject_constant(_value: str) -> NoReturn:
            """Raise ValueError for nonfinite JSON constants."""
            raise ValueError("FEDERATED_TIER_RULES cannot contain nonfinite JSON constants")

        if isinstance(value, str):
            try:
                value = json.loads(
                    value, object_pairs_hook=unique_object, parse_constant=reject_constant
                )
            except json.JSONDecodeError as error:
                raise ValueError("FEDERATED_TIER_RULES must be an ordered JSON array") from error
        if type(value) not in (list, tuple):
            raise ValueError("FEDERATED_TIER_RULES must be an ordered JSON array")
        return value

    @field_validator("trusted_proxy_ips")
    @classmethod
    def _normalize_trusted_proxy_ips(cls, v: list[str]) -> list[str]:
        """Strip/canonicalize literal IPv4/IPv6 entries, dropping blanks; reject others.

        Raise ValueError for hostnames/CIDRs/invalid addresses. Preserve order and
        duplicates; consumers compare peer strings without DNS resolution.
        """
        normalized: list[str] = []
        invalid: list[str] = []
        for raw in v:
            entry = raw.strip()
            if not entry:
                continue
            try:
                normalized.append(str(ipaddress.ip_address(entry)))
            except ValueError:
                invalid.append(raw)
        if invalid:
            raise ValueError(
                f"TRUSTED_PROXY_IPS entries are not valid IP addresses: {invalid}. "
                "List literal IPv4/IPv6 addresses (not hostnames or CIDR ranges), "
                'e.g. TRUSTED_PROXY_IPS=["127.0.0.1", "::1"].'
            )
        return normalized

    @field_validator("smtp_ca_bundle")
    @classmethod
    def validate_smtp_ca_bundle(cls, v: str | None) -> str | None:
        """Return the CA path (empty: None) after loading it into a default TLS context.

        Read system trust and the supplied PEM file; wrap bundle-load OSError/SSLError
        as ValueError. No SMTP connection is made.
        """
        if not v:
            return None
        ctx = ssl.create_default_context()
        try:
            ctx.load_verify_locations(cafile=v)
        except (OSError, ssl.SSLError) as e:
            raise ValueError(
                f"SMTP_CA_BUNDLE could not be loaded from {v!r}: {e}. "
                "Set it to a readable PEM CA bundle, or unset it to use "
                "the system trust store."
            ) from e
        return v

    @field_validator("database_url", mode="before")
    @classmethod
    def validate_database_url(cls, value: object) -> str:
        """Return the PostgreSQL URL, rewriting postgres:// to postgresql://.

        Unwrap SecretStr; raise ValueError for other types, other prefixes or an
        empty/bare-slash suffix. This does not fully validate or connect to PostgreSQL.
        """
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if not isinstance(value, str):
            raise ValueError("DATABASE_URL must be a PostgreSQL connection string")  # noqa: TRY004 - Pydantic reports ValueError as a validation error
        database_url = value
        if database_url.startswith("postgres://"):
            database_url = "postgresql://" + database_url[len("postgres://") :]

        elif not database_url.startswith(("postgresql://", "postgres://")):
            raise ValueError("database_url must start with 'postgresql://' or 'postgres://'.")
        stripped = database_url.split("://", 1)[1]
        if not stripped or stripped == "/":
            raise ValueError("database_url must contain a database name or connection path.")
        return database_url

    @model_validator(mode="after")
    def validate_seed_pair(self) -> Self:
        """Return self or raise ValueError if either retired ADMIN_SEED credential is set."""
        if self.admin_seed_email is not None or self.admin_seed_password is not None:
            raise ValueError(
                "ADMIN_SEED_EMAIL and ADMIN_SEED_PASSWORD are no longer service settings; "
                "remove them and run scripts/bootstrap_admin.py from a protected terminal"
            )
        return self

    @model_validator(mode="after")
    def validate_registration_default(self) -> Self:
        """Disable hardened-mode registration unless the setting was explicitly supplied."""
        if self.is_hardened and "local_registration_enabled" not in self.model_fields_set:
            self.local_registration_enabled = False
        return self

    @model_validator(mode="after")
    def validate_session_policy(self) -> Self:
        """Set the hardened cookie default and reject inconsistent session policy.

        Require __Host- names and at most eight-hour age in hardened modes; __Host-
        cookies always require Secure. Activity update interval must not exceed idle
        timeout. Mutate the default name; raise ValueError on refusal and return self.
        """
        if self.is_hardened:
            if "session_cookie_name" not in self.model_fields_set:
                self.session_cookie_name = HOST_SESSION_COOKIE_NAME
            if not self.session_cookie_name.startswith("__Host-"):
                raise ValueError("Hardened SESSION_COOKIE_NAME must use the __Host- prefix")
            if self.session_max_age_seconds > _HARDENED_SESSION_MAX_AGE_SECONDS:
                raise ValueError("Hardened SESSION_MAX_AGE_SECONDS must not exceed eight hours")
        if self.session_cookie_name.startswith("__Host-") and not self.cookies_secure:
            raise ValueError("COOKIES_SECURE must be True for __Host- cookies")
        if self.session_activity_update_interval_seconds > self.session_idle_timeout_seconds:
            raise ValueError("Session activity update interval must not exceed its idle timeout")
        return self

    @property
    def csrf_cookie_name(self) -> str:
        """Return the fixed CSRF cookie name for the selected security mode."""
        return security_cookie_names(hardened=self.is_hardened)[0]

    @property
    def pre_session_cookie_name(self) -> str:
        """Return the fixed anonymous-identifier cookie name for the selected security mode."""
        return security_cookie_names(hardened=self.is_hardened)[1]

    @model_validator(mode="after")
    def validate_rate_limit_redis_credential_is_independent(self) -> Self:
        """Return self or raise ValueError if the limiter Redis password reuses another secret."""
        inventory = collect_secret_inventory(self)
        if set(inventory.rate_limit_redis_url) & inventory.rate_limiter_peers():
            raise ValueError(
                "RATE_LIMIT_REDIS_URL must not reuse a signing, encryption, session, "
                "health-detail, federation, database or general Redis secret as its password"
            )
        return self

    @field_validator("session_cookie_name")
    @classmethod
    def validate_session_cookie_name(cls, value: str) -> str:
        """Return a valid distinct cookie name; raise ValueError for reserved or __Secure- names."""
        if not value or value in {
            CSRF_COOKIE_NAME,
            PRE_SESSION_COOKIE_NAME,
            HOST_CSRF_COOKIE_NAME,
            HOST_PRE_SESSION_COOKIE_NAME,
        }:
            raise ValueError("SESSION_COOKIE_NAME must be nonempty and distinct from CSRF cookies")
        if value.startswith("__Secure-"):
            raise ValueError("SESSION_COOKIE_NAME must use the host-bound __Host- prefix")
        try:
            cookie = SimpleCookie()
            cookie[value] = "probe"
        except CookieError as exc:
            raise ValueError("SESSION_COOKIE_NAME is not a valid cookie name") from exc
        return value

    @field_validator("smtp_from_address")
    @classmethod
    def validate_smtp_from_address(cls, value: str) -> str:
        """Return normalized supported email, or raise ValueError."""
        address = normalize_email(value)
        if address is None:
            raise ValueError("SMTP_FROM_ADDRESS must be a supported email address")
        return address

    @field_validator("smtp_from_name")
    @classmethod
    def validate_smtp_from_name(cls, value: str) -> str:
        """Return nonempty printable sender text, or raise ValueError; preserve whitespace."""
        if not value or not value.isprintable():
            raise ValueError("SMTP_FROM_NAME must contain printable characters only")
        return value

    @model_validator(mode="after")
    def validate_debug_only_in_dev(self) -> Self:
        """Return self or raise ValueError if FASTAPI_DEBUG is enabled outside dev."""
        if self.is_hardened and self.fastapi_debug:
            raise ValueError("FASTAPI_DEBUG=true is only permitted when ENV_STATE=dev")
        return self

    @model_validator(mode="after")
    def _require_https_in_prod(self) -> Self:
        """Return self or raise ValueError for non-HTTPS/loopback origins in hardened modes.

        No DNS lookup occurs; this check alone permits other private/unspecified IPs.
        """
        if not self.is_hardened:
            return self

        try:
            parsed = parse_http_url(
                self.public_base_url,
                require_https=True,
            )
        except ValueError as exc:
            raise ValueError(
                "PUBLIC_BASE_URL must be a non-localhost https:// URL in staging/production"
            ) from exc

        host = parsed.hostname or ""

        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = host == "localhost" or host.endswith(".localhost")

        if is_loopback:
            raise ValueError(
                "PUBLIC_BASE_URL must be a non-localhost https:// URL in staging/production"
            )

        return self

    @model_validator(mode="after")
    def validate_cookies_secure(self) -> Self:
        """Return self or raise ValueError unless hardened modes use Secure cookies."""
        if self.is_hardened and not self.cookies_secure:
            raise ValueError(
                "COOKIES_SECURE must be True in staging/production. "
                "It may only be False for local plaintext-HTTP development."
            )
        return self

    @model_validator(mode="after")
    def require_smtp_when_hardened(self) -> Self:
        """Return self or raise ValueError unless SMTP is enabled in hardened modes."""
        if self.is_hardened and not self.smtp_enabled:
            raise ValueError(
                "SMTP_ENABLED must be true outside dev (staging and production). "
                "Verification, reset, and security notices require SMTP delivery; "
                "the private mailbox is available only in dev."
            )
        return self

    @model_validator(mode="after")
    def require_health_token_when_hardened(self) -> Self:
        """Return self or raise ValueError if hardened modes lack HEALTH_DETAIL_TOKEN."""
        if self.is_hardened and self.health_detail_token is None:
            raise ValueError(
                "HEALTH_DETAIL_TOKEN must be set outside dev (staging and "
                "production). Without it, /health/detail returns 404 in every "
                "non-debug environment. Generate one with: "
                "python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        return self

    @model_validator(mode="after")
    def validate_smtp_settings(self) -> Self:
        """Return self or raise ValueError for incomplete enabled SMTP configuration.

        Require host/sender when enabled; production also rejects the shipped
        smtp.example.com/noreply@example.com placeholders. No connection is made.
        """
        if not self.smtp_enabled:
            return self

        if not self.smtp_host:
            raise ValueError("smtp_enabled=True requires smtp_host to be set")
        if not self.smtp_from_address:
            raise ValueError("smtp_enabled=True requires smtp_from_address to be set")

        if self.is_production:
            issues = []
            if self.smtp_host == "smtp.example.com":
                issues.append("smtp_host is still the placeholder value")
            if self.smtp_from_address == "noreply@example.com":
                issues.append("smtp_from_address is still the placeholder value")
            if issues:
                raise ValueError("SMTP misconfiguration in production: " + "; ".join(issues))
        return self

    @model_validator(mode="after")
    def validate_smtp_tls_when_hardened(self) -> Self:
        """Return self or raise ValueError if enabled SMTP lacks STARTTLS in hardened modes."""
        if self.is_hardened and self.smtp_enabled and not self.smtp_use_tls:
            raise ValueError(
                "SMTP_USE_TLS must be True outside dev (staging and production). "
                "Plaintext SMTP would expose password-reset tokens and relay "
                "credentials on the wire."
            )
        return self

    @model_validator(mode="after")
    def validate_smtp_auth_pair(self) -> Self:
        """Return self or raise ValueError unless SMTP_USER/password presence agree.

        User presence uses truthiness; password presence means not None.
        """
        if bool(self.smtp_user) != (self.smtp_password is not None):
            raise ValueError(
                "SMTP_USER and SMTP_PASSWORD must be set together (provide both or neither)."
            )
        return self

    @model_validator(mode="after")
    def validate_redis_in_production(self) -> Self:
        """Warn in production without general Redis invalidation, then return self."""
        if self.is_production and not self.redis_enabled:
            warnings.warn(
                "General Redis is disabled in production. Cross-worker "
                "catalogue-statistics invalidation is unavailable; cached "
                "statistics may remain stale until their TTL expires. "
                "Hardened web rate limiting still requires RATE_LIMIT_REDIS_URL.",
                RuntimeWarning,
                stacklevel=2,
            )
        return self

    @model_validator(mode="after")
    def validate_redis_url_required(self) -> Self:
        """Return self or raise ValueError for unsafe active/general or configured limiter URLs."""
        if self.redis_enabled and not self.redis_url.get_secret_value():
            raise ValueError("REDIS_URL must be set when REDIS_ENABLED=true")
        if self.redis_enabled:
            issues = redis_url_policy_issues(
                self.redis_url.get_secret_value(), hardened=self.is_hardened
            )
            if issues:
                raise ValueError("REDIS_URL: " + "; ".join(issues))
        if self.dedicated_rate_limit_storage_uri:
            issues = redis_url_policy_issues(
                self.rate_limit_redis_url.get_secret_value(),
                hardened=self.is_hardened,
                dedicated=True,
            )
            if issues:
                raise ValueError("RATE_LIMIT_REDIS_URL: " + "; ".join(issues))
        return self

    @model_validator(mode="after")
    def require_web_admission(self) -> Self:
        """Return self; raise ValueError if hardened web processes disable per-client admission."""
        if self.is_hardened and self.app_process_role == "web" and not self.rate_limit_enabled:
            raise ValueError("RATE_LIMIT_ENABLED must be true for hardened web processes")
        return self

    @model_validator(mode="after")
    def validate_process_totp_keys(self) -> Self:
        """Return self; raise ValueError for scheduler TOTP keys or absent web/maintenance keys."""
        if self.app_process_role == "scheduler":
            if self.totp_encryption_keys:
                raise ValueError("Scheduler processes must not receive TOTP_ENCRYPTION_KEYS")
        elif not self.totp_encryption_keys:
            raise ValueError("TOTP_ENCRYPTION_KEYS must be nonempty for authentication processes")
        return self

    @model_validator(mode="after")
    def require_parser_service_outside_development(self) -> Self:
        """Return self or raise ValueError for local parser execution outside dev."""
        if self.is_hardened and self.parser_execution_mode != "service":
            raise ValueError("PARSER_EXECUTION_MODE must be service outside development")
        return self

    @model_validator(mode="after")
    def validate_cors_settings(self) -> Self:
        """Validate enabled CORS; return self, warn in dev or raise ValueError in hardened modes.

        Reject exact wildcard/empty origins and, in hardened modes, entries containing
        localhost or 127.0.0.1. Credentialed-CORS HTTPS checks run separately at startup.
        """
        if not self.cors_enabled:
            return self

        issues = []

        if "*" in self.cors_origins:
            issues.append("CORS allows all origins ('*'). This disables the same-origin policy.")

        if not self.cors_origins:
            issues.append("CORS is enabled but no origins are configured.")

        localhost_origins = [
            origin for origin in self.cors_origins if "localhost" in origin or "127.0.0.1" in origin
        ]
        if localhost_origins and self.is_hardened:
            issues.append(f"CORS includes localhost origins outside dev: {localhost_origins}")

        if issues and self.is_hardened:
            raise ValueError("CORS misconfiguration blocks startup: " + "; ".join(issues))
        if issues:
            for issue in issues:
                warnings.warn(f"CORS WARNING: {issue}", RuntimeWarning, stacklevel=2)

        return self

    @model_validator(mode="after")
    def validate_allowed_hosts(self) -> Self:
        """Return self; warn in dev or raise ValueError in hardened modes for an exact * host."""
        issues = []
        if "*" in self.allowed_hosts:
            issues.append(
                "ALLOWED_HOSTS contains '*', which accepts any Host header and "
                "disables TrustedHostMiddleware."
            )
        if issues and self.is_hardened:
            raise ValueError("ALLOWED_HOSTS misconfiguration blocks startup: " + "; ".join(issues))
        if issues:
            for issue in issues:
                warnings.warn(f"ALLOWED_HOSTS WARNING: {issue}", RuntimeWarning, stacklevel=2)
        return self

    @field_validator("allowed_hosts")
    @classmethod
    def normalize_allowed_hosts(cls, hosts: list[str], info: ValidationInfo) -> list[str]:
        """Return stripped lowercase ASCII DNS/IPv4 hosts or leading *. patterns.

        Raise ValueError for empty lists or invalid hosts. Enabled federation first
        requires exact canonical DNS/IPv4 entries without wildcards or local hosts.
        """
        if info.data.get("shibboleth_enabled") and (
            error := _shibboleth_allowed_hosts_error(hosts)
        ):
            raise ValueError(error)
        if not hosts:
            raise ValueError("ALLOWED_HOSTS is empty; every request would be rejected.")
        normalized = []
        for host in hosts:
            candidate = host.strip().lower()
            suffix = candidate[2:] if candidate.startswith("*.") else candidate
            if candidate != "*" and not suffix.isascii():
                raise ValueError("ALLOWED_HOSTS requires ASCII/punycode DNS names")
            if candidate != "*" and (
                "*" in suffix or not _is_syntactically_valid_http_host(suffix) or ":" in suffix
            ):
                raise ValueError("ALLOWED_HOSTS must contain DNS/IPv4 hosts or leading *. patterns")
            normalized.append(candidate)
        return normalized

    @model_validator(mode="after")
    def validate_shibboleth_settings(self) -> Self:
        """Return self or raise ValueError for federation blockers or origin/host mismatch.

        Apply enabled federation policy in every mode. Always require the public URL
        hostname to be ASCII/punycode and match ALLOWED_HOSTS, even when disabled.
        """
        blockers = shibboleth_activation_blockers(
            enabled=self.shibboleth_enabled,
            internal_secret=(
                self.shibboleth_internal_secret.get_secret_value()
                if self.shibboleth_internal_secret is not None
                else None
            ),
            trusted_issuers=self.shibboleth_trusted_issuers,
            public_base_url=self.public_base_url,
            cookies_secure=self.cookies_secure,
            allowed_hosts=self.allowed_hosts,
            other_secret_values=set(collect_secret_inventory(self).federation_peers()),
        )
        if blockers:
            raise ValueError("; ".join(blockers))
        hostname = parse_http_url(self.public_base_url).hostname
        if hostname is None or not hostname.isascii():
            raise ValueError("PUBLIC_BASE_URL requires an ASCII/punycode hostname")
        if not any(
            host in {"*", hostname} or (host.startswith("*.") and hostname.endswith(host[1:]))
            for host in self.allowed_hosts
        ):
            raise ValueError("PUBLIC_BASE_URL hostname must match ALLOWED_HOSTS")
        return self

    @field_validator("db_statement_timeout", "scheduler_statement_timeout")
    @classmethod
    def validate_timeout_format(cls, value: str, info: ValidationInfo) -> str:
        """Return a canonical PostgreSQL timeout ('0' disables); raise ValueError if invalid."""
        return validate_statement_timeout(value, name=info.field_name or "statement_timeout")

    def __repr__(self) -> str:
        """Return the environment summary with configuration values redacted."""
        return f"<Settings env_state={self.env_state!r}, database_url=***; ...>"

    def __str__(self) -> str:
        """Return the same redacted summary as repr()."""
        return self.__repr__()


settings = Settings(env_state=resolve_environment())


def warn_unconsumed_env_keys() -> None:
    """In dev, read .env and log unknown field/alias keys with possible spelling suggestions.

    No-op outside dev or when absent; filesystem/UTF-8 errors propagate.
    """
    if settings.env_state != "dev":
        return
    raw = Settings.model_config.get("env_file") or str(_ENV_FILE)
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else ".env"
    env_file = Path(cast("str | Path", raw))

    if not env_file.exists():
        return

    known: set[str] = set()
    for name, field in Settings.model_fields.items():
        known.add(name.upper())
        alias = getattr(field, "alias", None)
        if alias:
            known.add(alias.upper())

    declared: set[str] = set()
    for line_raw in env_file.read_text(encoding="utf-8").splitlines():
        line = line_raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        declared.add(key.upper())

    unconsumed = sorted(declared - known)

    for key in unconsumed:
        suggestion = difflib.get_close_matches(key, known, n=1, cutoff=0.8)
        hint = f" (did you mean {suggestion[0]}?)" if suggestion else ""
        logger.warning("Unconsumed .env key: %s%s", key, hint)

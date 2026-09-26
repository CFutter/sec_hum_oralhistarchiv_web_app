"""Application settings loaded from environment variables."""

import difflib
import ipaddress
import logging
import os
import re
import socket
import ssl
import warnings
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Literal, Self, cast
from urllib.parse import unquote, urlsplit

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.cookie_contract import CSRF_COOKIE_NAME, PRE_SESSION_COOKIE_NAME
from app.credentials import normalize_email, validate_seed_credentials
from app.federation_contract import ISSUER_MAX_LENGTH
from app.url_safety import parse_http_url
from config.secret_strength import check_secret_strength

logger = logging.getLogger(__name__)

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"

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
    """Return the exact-policy error for one configured or mutated issuer."""
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
    """Reject non-public HTTPS origins without performing deployment-time DNS."""
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
    """Require concrete hosts that Starlette will compare without ambiguity."""
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
    """Validate the bounded, wire-safe, independent callback credential."""
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
    """Return every fatal federation activation-policy violation.

    Settings construction and the final pre-bind startup gate both call this
    pure function. Keeping the authentication anchors and transport contract
    in one place prevents validator drift and catches unsupported mutations
    made before startup. Settings mutation after startup is not a supported
    configuration mechanism; deployment changes require a process restart.
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
    """Application configuration loaded from environment variables.

    In development (OS-level ENV_STATE unset or "dev"), pydantic-settings
    additionally reads the repo-root `.env`. Outside dev the file is never
    read by pydantic — configuration must arrive as real OS environment
    variables; the production systemd units achieve this by loading the
    root-owned /etc/oralhistarchiv/common.env and, for the web process only,
    an optional /etc/oralhistarchiv/shibboleth.env via EnvironmentFile=. The gate below inspects
    the OS environment deliberately, before parsing, so a .env can neither
    exempt itself from loading nor smuggle in a non-dev ENV_STATE (see
    require_os_level_env_state_outside_dev).
    """

    # Environment
    env_state: Literal["dev", "staging", "production"] = Field(default="dev")

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE) if os.environ.get("ENV_STATE", "dev") == "dev" else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database settings
    # Uses SecretStr instead of plain str to prevent credential exposure in
    # tracebacks, serialization, and debugger output.
    # Uses SecretStr rather than PostgresDsn because Unix sockets use a path
    # (e.g. ?host=/tmp/postgres), which PostgresDsn does not support.
    # Basic format validation is enforced via field_validator below.

    database_url: SecretStr = Field(...)
    database_pool_size: int = Field(default=5, ge=1, le=50)
    database_pool_max_waiting: int = Field(default=32, ge=1, le=1000)
    db_statement_timeout: str = Field(
        default="5s",
        description="PostgreSQL statement_timeout. Format: '5s', '500ms', '2min'. "
        "Set to '0' to disable.",
    )
    scheduler_statement_timeout: str = Field(
        default="5min",
        description="statement_timeout for the scheduler pool. The full rebuild's "
        "source-wide DELETE outgrows the web-tier DB_STATEMENT_TIMEOUT "
        "at scale. Format: '5s', '300s', '5min', or '0' to disable.",
    )

    # Base Url
    public_base_url: str = Field(...)

    # FastAPI settings
    fastapi_host: str = Field(default="127.0.0.1")
    fastapi_port: int = Field(default=5000, ge=1, le=65535)
    fastapi_debug: bool = Field(default=False)
    pagination_size: int = Field(default=20, ge=1, le=100)

    # Security settings
    secret_key: SecretStr = Field(
        ...,
        description="Application secret: derives the audit-email HMAC key and "
        "signs itsdangerous tokens (email verification, password "
        "reset, email change). Does NOT encrypt TOTP secrets — that "
        "is TOTP_ENCRYPTION_KEYS. Entropy and blocklist enforced. "
        'Generate: python -c "import secrets; print(secrets.token_urlsafe(64))"',
    )

    # Token for /health/detail endpoint access. Required in production.
    # In non-production, accessible without a token only when FASTAPI_DEBUG=true;
    # otherwise requires the token (or returns 404 if unset).
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    health_detail_token: SecretStr | None = Field(default=None)

    # Session settings
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(64))"
    session_secret: SecretStr = Field(...)
    session_max_age_seconds: int = Field(default=28800, ge=60)  # 8 hours
    session_cookie_name: str = Field(default="oha_session")

    # Cookies settings
    cookies_secure: bool = Field(
        default=True,
        description="Set the Secure flag on session/CSRF cookies. Default True. "
        "Set False ONLY for local plaintext-HTTP development "
        "(e.g. http://127.0.0.1). Never False on any environment "
        "reachable over a network.",
    )

    # Authentication settings
    local_registration_enabled: bool = Field(default=True)
    totp_issuer_name: str = Field(default="Oral History Archive UZH")
    totp_encryption_keys: list[SecretStr] = Field(
        ...,
        min_length=1,
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
    login_lockout_minutes: int = Field(default=15, ge=1)
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
        description="Delete unverified local accounts older than this many days.",
    )

    # Shibboleth settings — only relevant behind the nginx SP layer
    # (shibd + FastCGI; see Deployment.md §9)
    shibboleth_enabled: bool = Field(default=False)
    shibboleth_internal_secret: SecretStr | None = Field(default=None)
    shibboleth_trusted_issuers: list[str] = Field(
        default_factory=list,
        description="Exact HTTPS SAML IdP entity IDs accepted by the callback. "
        "Must be non-empty whenever Shibboleth is enabled.",
    )

    # Nginx settings
    trusted_proxy_ips: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])

    # Redis — shared backend for rate limiting and facet cache invalidation
    redis_enabled: bool = Field(default=False)
    redis_url: SecretStr = Field(default=SecretStr("redis://localhost:6379/0"))

    # Logging settings
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(default="INFO")
    log_format: Literal["json", "text"] = Field(default="json")

    # Rate limiting
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_per_minute: int = Field(default=100, ge=1)
    rate_limit_per_hour: int = Field(default=1000, ge=1)
    rate_limit_per_day: int = Field(default=10000, ge=1)
    rate_limit_trust_proxy: bool = Field(default=False)  # Should be True if behind Nginx
    rate_limit_redis_url: SecretStr = Field(
        default=SecretStr(""),
        description="Dedicated Redis credential for rate-limit counters. "
        "Empty in dev falls back to REDIS_URL when REDIS_ENABLED=true, "
        "then to process-local memory. Database 0 only; no query parameters.",
    )

    # CORS settings
    cors_enabled: bool = Field(default=False)
    cors_origins: list[str] = Field(default_factory=list)
    cors_allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST"])
    cors_allow_headers: list[str] = Field(default_factory=lambda: ["Authorization", "Content-Type"])
    cors_allow_credentials: bool = Field(default=False)
    allowed_hosts: list[str]

    # OAI-PMH sync — filters records by institution name
    oai_institution_filter: str = Field(...)
    swissubase_oai_pmh_url: str = Field(...)

    # Visibility ceiling — set it in the .env; the code default is the most restrictive.
    swissubase_max_visibility: Literal["public", "registered", "vetted"] = Field(default="vetted")

    sync_write_timeout_seconds: int = Field(default=120, ge=1, le=3600)
    sync_interval_seconds: int = Field(default=3600, ge=1)
    full_rebuild_interval_seconds: int = Field(default=86400, ge=1)
    oai_max_pages: int = Field(
        default=500,
        ge=1,
        description="Safety cap on OAI-PMH resumption-token pagination. "
        "Stops the harvest if the upstream returns more pages than this. "
        "Set well above your expected record count divided by page size.",
    )

    # Application
    contact_email: str = Field(default="archive@example.uzh.ch")
    admin_seed_email: str | None = Field(default=None)
    admin_seed_password: SecretStr | None = Field(default=None)
    password_work_concurrency: int = Field(default=1, ge=1, le=2)

    # Terminal outbox retention: transaction size is independent of cadence.
    outbox_sent_retention_days: int = Field(default=7, ge=1, le=3650)
    outbox_dead_retention_days: int = Field(default=30, ge=1, le=3650)
    outbox_retention_batch_size: int = Field(default=1000, ge=1, le=5000)
    outbox_retention_interval_seconds: int = Field(default=60, ge=1, le=60)
    outbox_stale_after_seconds: int = Field(default=600, ge=60)

    # Email (SMTP)
    # Required in production for password reset. Disabled by default in dev.
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

    seed_mock_data: bool = Field(
        default=False,
        description="Seed the mock restricted datasets at startup. Intended for "
        "dev and staging demo/presentation environments so all visibility "
        "tiers are exercisable. Never permitted in production.",
    )

    # --- Computed fields ---
    @property
    def is_production(self) -> bool:
        """True when running in production environment."""
        return self.env_state == "production"

    @property
    def is_hardened(self) -> bool:
        """True for any deployed (non-dev) environment — staging or production.

        Use for security properties that must hold wherever the app is exposed
        (secure cookies, strong secrets, debug off, protected health detail).
        Use is_production only for genuinely production-specific operational
        requirements (e.g. Redis-backed rate limiting, real SMTP).
        """
        return self.env_state != "dev"

    @property
    def rate_limit_storage_uri(self) -> str | None:
        """Redis URL for limiter counters, or None for "no Redis URL".

        Hardened environments accept only the dedicated RATE_LIMIT_REDIS_URL;
        None there makes validate_rate_limit_configuration refuse startup.
        Development may borrow REDIS_URL, otherwise None selects memory storage.
        """
        dedicated = self.rate_limit_redis_url.get_secret_value().strip()
        if dedicated:
            return dedicated
        if not self.is_hardened and self.redis_enabled:
            return self.redis_url.get_secret_value()
        return None

    # --- Validators ---
    @field_validator("public_base_url")
    @classmethod
    def _normalize_public_base_url(cls, value: str) -> str:
        """Require an HTTP(S) origin suitable for appending route paths."""
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

    @field_validator("oai_institution_filter")
    @classmethod
    def _normalize_institution_filter(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError(
                "OAI_INSTITUTION_FILTER must not be empty — it scopes which datasets are ingested."
            )
        return v

    @field_validator("shibboleth_internal_secret", mode="before")
    @classmethod
    def _normalize_optional_shibboleth_secret(cls, value: object) -> object:
        """Treat an empty Phase-1 environment entry as an unset secret.

        ``.env.example`` documents every setting, but Phase 1 must not
        provision the federation impersonation credential. Normalising only
        an empty string preserves exact comparison for every real secret.
        """
        if isinstance(value, str) and not value:
            return None
        if isinstance(value, SecretStr) and not value.get_secret_value():
            return None
        return value

    @field_validator("shibboleth_trusted_issuers")
    @classmethod
    def _validate_shibboleth_trusted_issuers(cls, values: list[str]) -> list[str]:
        """Validate the exact IdP allowlist without rewriting identity values."""
        for issuer in values:
            if error := _shibboleth_issuer_error(issuer):
                raise ValueError(error)

        if len(set(values)) != len(values):
            raise ValueError("SHIBBOLETH_TRUSTED_ISSUERS cannot contain duplicate entries")
        return values

    @field_validator("trusted_proxy_ips")
    @classmethod
    def _normalize_trusted_proxy_ips(cls, v: list[str]) -> list[str]:
        """Parse and canonicalize each entry, rejecting anything unparseable.

        get_client_ip compares the TCP peer string against this set verbatim,
        so an unnormalized entry ("::0001", " 10.0.0.5 ") or a hostname would
        silently never match: forwarded headers would go untrusted and every
        request would collapse onto the proxy's own IP for rate-limiting and
        audit attribution. Under the Unix-socket deployment the socket branch
        masks that, so the breakage would only surface after a topology change
        — hence failing here, at startup, with the variable named.

        Hostnames are rejected on purpose: the allowlist is compared against a
        resolved peer address, and a name would have to be resolved at match
        time. Resolve it yourself and list the address.
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
        """Fail at startup, naming the env var, if the CA bundle can't be loaded.

        services/email.py builds its TLS context at import time and loads this
        file unconditionally when set; a bad path or unparseable PEM would
        otherwise crash that import with a raw traceback before the aggregated
        validator report can run. Loading it here performs the identical
        operation on the friendly error path. An empty value is normalized to
        None, matching the consumer's truthiness check.
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
        """Basic format check — ensures the URL is a PostgreSQL connection string.

        Runs in 'before' mode so it validates the raw string before
        Pydantic wraps it in SecretStr.
        """
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if not isinstance(value, str):
            raise ValueError("DATABASE_URL must be a PostgreSQL connection string")  # noqa: TRY004 - Pydantic reports ValueError as a validation error
        database_url = value
        if database_url.startswith("postgres://"):
            database_url = "postgresql://" + database_url[len("postgres://") :]

        elif not database_url.startswith(("postgresql://", "postgres://")):
            scheme = database_url.split("://", 1)[0] if "://" in database_url else database_url[:20]
            raise ValueError(
                f"database_url must start with 'postgresql://' or 'postgres://'. "
                f"Got scheme: '{scheme}'"
            )
        stripped = database_url.split("://", 1)[1]
        if not stripped or stripped == "/":
            raise ValueError("database_url must contain a database name or connection path.")
        return database_url

    @model_validator(mode="after")
    def validate_seed_pair(self) -> Self:
        if bool(self.admin_seed_email) != bool(self.admin_seed_password):
            raise ValueError("ADMIN_SEED_EMAIL and ADMIN_SEED_PASSWORD must be set together")
        if self.admin_seed_email and self.admin_seed_password:
            self.admin_seed_email = validate_seed_credentials(
                self.admin_seed_email, self.admin_seed_password.get_secret_value()
            )
        return self

    @model_validator(mode="after")
    def validate_rate_limit_redis_credential_is_independent(self) -> Self:
        limiter_password = urlsplit(self.rate_limit_redis_url.get_secret_value().strip()).password
        if not limiter_password:
            return self
        other_values = {
            self.secret_key.get_secret_value(),
            self.session_secret.get_secret_value(),
            *(key.get_secret_value() for key in self.totp_encryption_keys),
            *(key.get_secret_value() for key in self.outbox_encryption_keys),
        }
        for optional in (self.health_detail_token, self.shibboleth_internal_secret):
            if optional is not None:
                other_values.add(optional.get_secret_value())
        for url in (self.database_url, self.redis_url):
            password = urlsplit(url.get_secret_value()).password
            if password:
                other_values.add(unquote(password))
        if unquote(limiter_password) in other_values:
            raise ValueError(
                "RATE_LIMIT_REDIS_URL must not reuse a signing, encryption, session, "
                "health-detail, federation, database or general Redis secret as its password"
            )
        return self

    @field_validator("session_cookie_name")
    @classmethod
    def validate_session_cookie_name(cls, value: str) -> str:
        if not value or value in {CSRF_COOKIE_NAME, PRE_SESSION_COOKIE_NAME}:
            raise ValueError("SESSION_COOKIE_NAME must be nonempty and distinct from CSRF cookies")
        if value.startswith(("__Secure-", "__Host-")):
            raise ValueError("SESSION_COOKIE_NAME does not support __Secure- or __Host- prefixes")
        try:
            cookie = SimpleCookie()
            cookie[value] = "probe"
        except CookieError as exc:
            raise ValueError("SESSION_COOKIE_NAME is not a valid cookie name") from exc
        return value

    @field_validator("smtp_from_address")
    @classmethod
    def validate_smtp_from_address(cls, value: str) -> str:
        address = normalize_email(value)
        if address is None:
            raise ValueError("SMTP_FROM_ADDRESS must be a supported email address")
        return address

    @field_validator("smtp_from_name")
    @classmethod
    def validate_smtp_from_name(cls, value: str) -> str:
        if not value or not value.isprintable():
            raise ValueError("SMTP_FROM_NAME must contain printable characters only")
        return value

    @model_validator(mode="after")
    def require_os_level_env_state_outside_dev(self) -> Self:
        """The env_file gate reads ENV_STATE from the OS environment BEFORE
        parsing, so a .env file cannot exempt itself from being loaded. If a
        non-dev env_state arrives while the OS-level variable is absent and a
        .env exists, the value was smuggled in via that .env — exactly the
        deployment mistake the gate exists to prevent."""
        if self.env_state != "dev" and "ENV_STATE" not in os.environ and _ENV_FILE.exists():
            raise ValueError(
                f"ENV_STATE={self.env_state} was read from {_ENV_FILE}, but outside "
                "dev it must be set as a real OS environment variable (export it, "
                "or load the file via systemd EnvironmentFile=) so the .env gate "
                "can see it before parsing."
            )
        return self

    @model_validator(mode="after")
    def validate_seed_mock_data_not_in_production(self) -> Self:
        if self.is_production and self.seed_mock_data:
            raise ValueError(
                "SEED_MOCK_DATA=true is not permitted in production. "
                "It exists for dev/staging demo environments only."
            )
        return self

    @model_validator(mode="after")
    def validate_debug_only_in_dev(self) -> Self:
        if self.is_hardened and self.fastapi_debug:
            raise ValueError("FASTAPI_DEBUG=true is only permitted when ENV_STATE=dev")
        return self

    @model_validator(mode="after")
    def _require_https_in_prod(self) -> Self:
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
        if self.is_hardened and not self.cookies_secure:
            raise ValueError(
                "COOKIES_SECURE must be True in staging/production. "
                "It may only be False for local plaintext-HTTP development."
            )
        return self

    @model_validator(mode="after")
    def require_smtp_when_hardened(self) -> Self:
        if self.is_hardened and not self.smtp_enabled:
            raise ValueError(
                "SMTP_ENABLED must be true outside dev (staging included) — "
                "verification, reset, and security notices otherwise report "
                "success while sending nothing."
            )
        return self

    @model_validator(mode="after")
    def require_health_token_when_hardened(self) -> Self:
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
        """Require SMTP fields when SMTP is enabled.

        In production, also checks for unmodified placeholder values to catch
        operators who enabled SMTP without configuring it. In dev/staging,
        only the empty-field check applies (so MailHog or other local setups
        aren't blocked by placeholder detection).
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
        if self.is_hardened and self.smtp_enabled and not self.smtp_use_tls:
            raise ValueError(
                "SMTP_USE_TLS must be True outside dev (staging and production). "
                "Plaintext SMTP would expose password-reset tokens and relay "
                "credentials on the wire."
            )
        return self

    @model_validator(mode="after")
    def validate_smtp_auth_pair(self) -> Self:
        if bool(self.smtp_user) != (self.smtp_password is not None):
            raise ValueError(
                "SMTP_USER and SMTP_PASSWORD must be set together (provide both or neither)."
            )
        return self

    @model_validator(mode="after")
    def validate_redis_in_production(self) -> Self:
        """Warn when Redis is disabled in production.

        Without Redis, the app runs a single gunicorn worker (see
        gunicorn.conf.py), which keeps slowapi's in-memory rate limiting
        correct but caps throughput to one worker and disables
        cross-worker facet-cache invalidation. This is acceptable for
        low-traffic deployments; enable Redis to scale to multiple workers.
        """
        if self.is_production and not self.redis_enabled:
            warnings.warn(
                "Redis is disabled in production. Running a single gunicorn "
                "worker (rate limiting stays correct, but throughput is capped "
                "and cross-worker facet-cache invalidation is disabled). "
                "Enable Redis to run multiple workers.",
                RuntimeWarning,
                stacklevel=2,
            )
        return self

    @model_validator(mode="after")
    def validate_redis_url_required(self) -> Self:
        if self.redis_enabled and not self.redis_url.get_secret_value():
            raise ValueError("REDIS_URL must be set when REDIS_ENABLED=true")
        return self

    @model_validator(mode="after")
    def validate_cors_settings(self) -> Self:
        """Prevent CORS misconfiguration in production and staging.

        Blocks startup if CORS is enabled with unsafe origins.
        Warns in development for awareness.
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
        """Reject a wildcard or empty ALLOWED_HOSTS in staging/production.

        TrustedHostMiddleware treats the exact entry "*" as "accept any Host",
        which disables the app-level Host check. An empty list rejects every
        request (fail-closed, but a broken deploy). Mirrors validate_cors_settings:
        block in staging/prod, warn in dev.
        """
        issues = []
        if "*" in self.allowed_hosts:
            issues.append(
                "ALLOWED_HOSTS contains '*', which accepts any Host header and "
                "disables TrustedHostMiddleware."
            )
        if not self.allowed_hosts:
            issues.append("ALLOWED_HOSTS is empty; every request would be rejected.")

        if issues and self.is_hardened:
            raise ValueError("ALLOWED_HOSTS misconfiguration blocks startup: " + "; ".join(issues))
        if issues:
            for issue in issues:
                warnings.warn(f"ALLOWED_HOSTS WARNING: {issue}", RuntimeWarning, stacklevel=2)
        return self

    @field_validator("allowed_hosts")
    @classmethod
    def normalize_allowed_hosts(cls, hosts: list[str], info: ValidationInfo) -> list[str]:
        if info.data.get("shibboleth_enabled") and (
            error := _shibboleth_allowed_hosts_error(hosts)
        ):
            raise ValueError(error)
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
        """Require the complete federation activation boundary.

        These checks are deliberately environment-independent. A publicly
        reachable development/demo deployment has the same federation trust
        boundary as production once the callback is enabled.
        """
        other_secret_values = {
            self.secret_key.get_secret_value(),
            self.session_secret.get_secret_value(),
            *(key.get_secret_value() for key in self.totp_encryption_keys),
            *(key.get_secret_value() for key in self.outbox_encryption_keys),
        }
        if self.health_detail_token is not None:
            other_secret_values.add(self.health_detail_token.get_secret_value())

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
            other_secret_values=other_secret_values,
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
    def validate_timeout_format(cls, v: str, info: ValidationInfo) -> str:
        """Reject malformed statement_timeout values at startup.

        Allows '0' (no limit), or a positive number followed by unit (ms/s/min).
        (Injection at the sink is already blocked by sql.Literal in create_pool;
        this validator exists so a typo fails here, not per-connection at runtime.)
        """
        if v == "0":
            return v
        if not re.match(r"^\d+(ms|s|min)$", v):
            raise ValueError(
                f"{info.field_name} must be '0' or like '5s', '500ms', '2min'. Got: {v!r}"
            )
        return v

    # --- Methods ---
    def __repr__(self) -> str:
        """Prevent leaking database_url in repr/logs."""
        return f"<Settings env_state={self.env_state!r}, database_url=***; ...>"

    def __str__(self) -> str:
        return self.__repr__()


settings = Settings()


def warn_unconsumed_env_keys() -> None:
    """Warn about keys in the .env file that no Settings field consumes.

    Catches dead config (e.g. CACHE_PATH) and — more importantly — typos of
    real keys (RATE_LIMIT_ENABELD), which extra='ignore' otherwise swallows
    silently, starting the app with the default value. Dev-only: the .env
    file exists only in development; prod reads real OS env vars.
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
        # honor an explicit alias if the field defines one
        alias = getattr(field, "alias", None)
        if alias:
            known.add(alias.upper())

    declared: set[str] = set()
    for line_raw in env_file.read_text().splitlines():
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

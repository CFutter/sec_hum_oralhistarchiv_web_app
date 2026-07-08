"""Application settings loaded from environment variables."""
from typing import Literal, Self, cast
import re
import logging
from pathlib import Path
import difflib

import warnings

from pydantic import Field, field_validator, model_validator, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    """Application configuration loaded from environment variables.

    Uses Pydantic Settings to load configuration from a `.env` file and
    environment variables. The `.env` will only exist in development, not in production.
    """
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),     
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Environment
    env_state: Literal["dev", "staging", "production"] = Field(default="dev")

    # Database settings
    # Uses SecretStr instead of plain str to prevent credential exposure in  
    # tracebacks, serialization, and debugger output.
    # Uses SecretStr rather than PostgresDsn because Unix sockets use a path 
    # (e.g. ?host=/tmp/postgres), which PostgresDsn does not support.
    # Basic format validation is enforced via field_validator below.
    
    database_url: SecretStr = Field(...)
    database_pool_size: int = Field(default=5, ge=1, le=50)
    db_statement_timeout: str = Field(
        default="5s",
        description="PostgreSQL statement_timeout. Format: '5s', '500ms', '2min'. "
                    "Set to '0' to disable.",
    )

    #Base Url
    public_base_url: str = Field(...)

    # FastAPI settings
    fastapi_host: str = Field(default="127.0.0.1")
    fastapi_port: int = Field(default=5000)
    fastapi_debug: bool = Field(default=False)
    pagination_size: int = Field(default=20, ge=1, le=100)

    # Security settings
    secret_key: SecretStr = Field(
        ...,
        description="Application secret: derives the audit-email HMAC key and "
                    "signs itsdangerous tokens (email verification, password "
                    "reset, email change). Does NOT encrypt TOTP secrets — that "
                    "is TOTP_ENCRYPTION_KEYS. Entropy and blocklist enforced. "
                    "Generate: python -c \"import secrets; print(secrets.token_urlsafe(64))\"",
    )

    # Token for /health/detail endpoint access. Required in production.         
    # In non-production environments, the endpoint is accessible without a token.                
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    health_detail_token: SecretStr | None = Field(default=None)              

    # Session settings
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(64))"
    session_secret: SecretStr = Field(...)
    session_max_age_seconds: int = Field(default=28800, ge=60)  # 8 hours
    session_cookie_name: str = Field(default="oha_session")

    #Cookies settings
    cookies_secure: bool = Field(
        default=True,
        description="Set the Secure flag on session/CSRF cookies. Default True. "
                    "Set False ONLY for local plaintext-HTTP development "
                    "(e.g. http://127.0.0.1). Never False on any environment "
                    "reachable over a network.",
    )

    # Authentication settings
    local_auth_enabled: bool = Field(default=True)
    totp_issuer_name: str = Field(default="Oral History Archive UZH")
    totp_encryption_keys: list[SecretStr] = Field(
        ...,
        min_length=1,
        description="Fernet key material for TOTP-secret encryption (JSON list). "
                    "The FIRST key encrypts; ALL keys can decrypt (enables rotation). "
                    "Generate each with: python -c \"import secrets; print(secrets.token_urlsafe(64))\"",
    )
    login_failure_threshold: int = Field(default=10, ge=1)
    login_lockout_minutes: int = Field(default=15, ge=1)
    unverified_reap_after_days: int = Field(
        default=7,
        ge=1,
        description="Delete unverified local accounts older than this many days.",
    )

    # Shibboleth settings — only relevant when behind nginx with mod_shib
    shibboleth_enabled: bool = Field(default=False)
    shibboleth_trusted_proxy_ip: str = Field(default="127.0.0.1")
    shibboleth_header_remote_user: str = Field(default="REMOTE_USER")
    shibboleth_header_mail: str = Field(default="mail")
    shibboleth_header_display_name: str = Field(default="displayName")
    shibboleth_header_affiliation: str = Field(default="affiliation")   
    shibboleth_header_country: str = Field(default="schacHomeOrganizationCountry")

    # Secret header for the Shibboleth callback — injected by nginx, verified
    # by shibboleth_callback. Defense-in-depth alongside the trusted proxy IP
    # check. If None, the secondary check is skipped (dev mode).
    shibboleth_internal_secret: SecretStr | None = Field(default=None)

    #Nginx settings
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
    rate_limit_trust_proxy: bool = Field(default=False) #Should be True if behind Nginx

    # CORS settings
    cors_enabled: bool = Field(default=False)
    cors_origins: list[str] = Field(default_factory=list)
    cors_allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST"])
    cors_allow_headers: list[str] = Field(default_factory=lambda: ["Authorization", "Content-Type"])
    cors_allow_credentials: bool = Field(default=False)
    allowed_hosts: list[str]

    # OAI-PMH sync — filters records by institution name
    oai_institution_filter: str = Field(...)
    swissubase_oai_pmh_url: str = Field(
        default="https://demo.swissubase.ch/oai-pmh/v1/oai",
    )
    # Visibilty should be set in the .env, here it will default to most restrictiv.
    swissubase_max_visibility: Literal["public", "registered", "vetted"] = Field(default="vetted")
    
    sync_interval_seconds: int = Field(default=3600)
    full_rebuild_interval_seconds: int = Field(default=86400)
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

    # Email (SMTP)
    # Required in production for password reset. Disabled by default in dev.
    smtp_enabled: bool = Field(default=False)
    smtp_host: str = Field(default="smtp.example.com")
    smtp_port: int = Field(default=587)
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

    # --- Validators ---    

    @field_validator("public_base_url")
    @classmethod
    def _normalize_public_base_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("PUBLIC_BASE_URL must start with http:// or https://")
        return v.rstrip("/")  
    
    @field_validator("oai_institution_filter")
    @classmethod
    def _normalize_institution_filter(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError(
                "OAI_INSTITUTION_FILTER must not be empty — it scopes which datasets are ingested."
            )
        return v


    @field_validator("database_url", mode="before")
    @classmethod
    def validate_database_url(cls, database_url: str) -> str:
        """Basic format check — ensures the URL is a PostgreSQL connection string.
        
        Runs in 'before' mode so it validates the raw string before             
        Pydantic wraps it in SecretStr.                                          
        """
        if not database_url.startswith(("postgresql://", "postgres://")):
            scheme = database_url.split("://", 1)[0] if "://" in database_url else database_url[:20]
            raise ValueError(
                f"database_url must start with 'postgresql://' or 'postgres://'. "
                f"Got scheme: '{scheme}'"
            )
        stripped = database_url.split("://", 1)[1]
        if not stripped or stripped == "/":
            raise ValueError(
                "database_url must contain a database name or connection path."
            )
        return database_url
    
    @model_validator(mode='after')
    def validate_debug_only_in_dev(self):
        if self.is_hardened and self.fastapi_debug:
            raise ValueError("FASTAPI_DEBUG=true is only permitted when ENV_STATE=dev")
        return self
        
    @model_validator(mode="after")
    def _require_https_in_prod(self) -> Self:
        if self.is_hardened:
            u = self.public_base_url
            if u.startswith("http://") or "localhost" in u or "127.0.0.1" in u:
                raise ValueError("PUBLIC_BASE_URL must be a non-localhost https:// URL in staging/production")
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
    def require_smtp_in_prod(self) -> Self:
        if self.is_production and not self.smtp_enabled:
            raise ValueError("SMTP_ENABLED must be true in production (password reset & verification depend on it).")
        return self

    @model_validator(mode="after")
    def require_health_token_in_prod(self) -> Self:
        if self.is_production and self.health_detail_token is None:
            raise ValueError("HEALTH_DETAIL_TOKEN must be set in production.")
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
        if not self.smtp_port:
            raise ValueError("smtp_enabled=True requires smtp_port to be set")
        if not self.smtp_from_address:
            raise ValueError("smtp_enabled=True requires smtp_from_address to be set")
        
        if self.is_production:
            issues = []
            if self.smtp_host == "smtp.example.com":
                issues.append("smtp_host is still the placeholder value")
            if self.smtp_from_address == "noreply@example.com":
                issues.append("smtp_from_address is still the placeholder value")
            if issues:
                raise ValueError(
                    "SMTP misconfiguration in production: " + "; ".join(issues)
                )
        return self

    @model_validator(mode="after")
    def validate_smtp_tls_in_prod(self) -> Self:
        if self.is_hardened and self.smtp_enabled and not self.smtp_use_tls:
            raise ValueError(
                "SMTP_USE_TLS must be True in production. Plaintext SMTP would expose "
                "password-reset tokens and relay credentials on the wire."
            )
        return self

    @model_validator(mode="after")
    def validate_smtp_auth_pair(self) -> "Settings":
        if bool(self.smtp_user) != (self.smtp_password is not None):
            raise ValueError("SMTP_USER and SMTP_PASSWORD must be set together (provide both or neither).")
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
                RuntimeWarning, stacklevel=2,
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
            origin for origin in self.cors_origins
            if "localhost" in origin or "127.0.0.1" in origin
        ]
        if localhost_origins and self.is_hardened:
            issues.append(
                f"CORS includes localhost origins outside dev: {localhost_origins}"
            )
 
        if issues and self.is_hardened:
            raise ValueError(
                "CORS misconfiguration blocks startup: " + "; ".join(issues)
            )
        elif issues:
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
            raise ValueError(
                "ALLOWED_HOSTS misconfiguration blocks startup: " + "; ".join(issues)
            )
        elif issues:
            for issue in issues:
                warnings.warn(f"ALLOWED_HOSTS WARNING: {issue}", RuntimeWarning, stacklevel=2)
        return self


    @model_validator(mode="after")
    def validate_shibboleth_settings(self) -> Self:
        """Require the internal secret when Shibboleth is enabled.

        The secret is injected by nginx on the Shibboleth callback path and
        verified by shibboleth_callback as a second layer of defense alongside
        the trusted-proxy IP check. Enforced in all environments (not just
        production) so staging/dev with Shibboleth enabled also gets both
        layers — without it there is only the single IP-based check.
        """
        if self.shibboleth_enabled and self.shibboleth_internal_secret is None:
            raise ValueError(
                "SHIBBOLETH_INTERNAL_SECRET must be set whenever SHIBBOLETH_ENABLED=true "
                "(enforced in all environments). Generate one with: "
                "python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        return self

    @field_validator("db_statement_timeout")
    @classmethod
    def validate_timeout_format(cls, v: str) -> str:
        """Reject non-interval values that could be SQL injection.
        
        Allows '0' (no limit), or a positive number followed by unit (ms/s/min).
        """
        if v == "0":
            return v
        if not re.match(r"^\d+(ms|s|min)$", v):
            raise ValueError(
                f"db_statement_timeout must be '0' or like '5s', '500ms', '2min'. Got: {v!r}"
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
    raw = Settings.model_config.get("env_file") or ".env"
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
            key = key[len("export "):].strip()
        declared.add(key.upper())

    unconsumed = sorted(declared - known)

    for key in unconsumed:
        suggestion = difflib.get_close_matches(key, known, n=1, cutoff=0.8)
        hint = f" (did you mean {suggestion[0]}?)" if suggestion else ""
        logger.warning("Unconsumed .env key: %s%s", key, hint)
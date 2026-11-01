"""Build explicit Settings test kwargs; unpinned fields still read the OS environment.

make_settings disables instance dotenv reads, not OS variables. Importing this
module also imports config and constructs its settings singleton.
"""

from config.settings import Settings


def base_kwargs(**overrides):
    """Return selected development defaults plus overrides; leave other fields to Settings.

    Enabling Shibboleth removes localhost from allowed_hosts unless explicitly
    overridden. Unpinned fields can still inherit OS environment values.
    """
    kw = {
        "env_state": "dev",
        "app_process_role": "web",
        "parser_execution_mode": "service",
        "database_url": "postgresql://oha:db-secret-pw@localhost:5432/oha_test",
        "public_base_url": "http://localhost:8000",
        "secret_key": "unit-test-secret-key-0123456789abcdefghijklmnopqrstuv",
        "session_secret": "unit-test-session-secret-0123456789abcdefghijklmnopq",
        "totp_encryption_keys": ["unit-test-totp-key-0123456789abcdefghijklmnopqrstu"],
        "outbox_encryption_keys": ["unit-test-outbox-key-0123456789abcdefghijklmnop"],
        "allowed_hosts": [
            "example.org",
            "localhost",
            "archive.example.org",
            "staging.archive.example.org",
        ],
        "cookies_secure": True,
        "fastapi_debug": False,
        "smtp_enabled": False,
        "smtp_user": "",
        "smtp_password": None,
        "redis_enabled": False,
        "rate_limit_enabled": True,
        "rate_limit_redis_url": "",
        "shibboleth_enabled": False,
        "federated_tier_rules": (),
        "cors_enabled": False,
        "sources_config_file": None,
        "allow_fixture_source": False,
        "password_work_admission_timeout_seconds": 1.0,
        "search_statement_timeout_ms": 500,
        "search_operation_timeout_seconds": 1.0,
        "search_pool_timeout_seconds": 0.1,
        "search_global_rate_per_second": 0.5,
        "search_global_burst": 1,
    }
    kw.update(overrides)
    if kw["shibboleth_enabled"] and "allowed_hosts" not in overrides:
        kw["allowed_hosts"] = ["example.org", "archive.example.org", "staging.archive.example.org"]
    return kw


def staging_kwargs(**overrides):
    """Return base kwargs with staging HTTPS, hosts and SMTP defaults, then apply overrides."""
    kw = base_kwargs(
        env_state="staging",
        public_base_url="https://staging.archive.example.org",
        allowed_hosts=["staging.archive.example.org", "example.org"],
        cookies_secure=True,
        smtp_enabled=True,
        smtp_host="mail.example.org",
        smtp_port=587,
        smtp_from_address="archive@example.org",
        smtp_use_tls=True,
    )
    kw.update(overrides)
    return kw


def prod_kwargs(**overrides):
    """Return base kwargs with production HTTPS, health, SMTP and general Redis defaults plus
    overrides.
    """
    kw = base_kwargs(
        env_state="production",
        public_base_url="https://archive.example.org",
        allowed_hosts=["archive.example.org", "example.org"],
        cookies_secure=True,
        health_detail_token="prod-health-token-0123456789abcdefghij",
        smtp_enabled=True,
        smtp_host="mail.example.org",
        smtp_port=587,
        smtp_from_address="archive@example.org",
        smtp_use_tls=True,
        redis_enabled=True,
        redis_url="rediss://redis.internal.example.org:6379/0",
    )
    kw.update(overrides)
    return kw


KWARGS_FOR_ENV = {
    "dev": base_kwargs,
    "staging": staging_kwargs,
    "production": prod_kwargs,
}


def make_settings(**kwargs) -> Settings:
    """Construct Settings without dotenv; unpinned OS settings and validation errors still apply."""
    return Settings(_env_file=None, **kwargs)

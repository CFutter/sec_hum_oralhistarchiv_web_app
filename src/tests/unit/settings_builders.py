"""Keyword-argument builders for constructing ``Settings`` in tests.

Every settings test constructs ``Settings(_env_file=None, **kwargs)`` so no
``.env`` file leaks in. Real OS environment variables still apply to *unset*
fields, so these builders pass an explicit value for every field a test
asserts on: one builder per environment tier, plus ``make_settings``. They
are shared by every unit module that exercises ``config.settings``.
"""

from config.settings import Settings


def base_kwargs(**overrides):
    """All mandatory fields with strong dev-safe values.

    Every toggle a validator inspects is pinned explicitly so ambient env vars
    (the conftest bootstrap block or a developer's shell) cannot change what a
    test constructs.
    """
    kw = {
        "env_state": "dev",
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
        "oai_institution_filter": "Universität Kassel",
        "cookies_secure": True,
        "fastapi_debug": False,
        "smtp_enabled": False,
        "smtp_user": "",
        "smtp_password": None,
        "redis_enabled": False,
        "shibboleth_enabled": False,
        "cors_enabled": False,
    }
    kw.update(overrides)
    if kw["shibboleth_enabled"] and "allowed_hosts" not in overrides:
        kw["allowed_hosts"] = ["example.org", "archive.example.org", "staging.archive.example.org"]
    return kw


def staging_kwargs(**overrides):
    """base_kwargs adjusted to satisfy the is_hardened (staging) validators.

    SMTP is on because require_smtp_when_hardened applies to staging:
    with SMTP disabled, send_email() returns True while sending nothing, so
    the boundary now rejects hardened deployments without SMTP.
    """
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
    """base_kwargs adjusted to satisfy every production-only validator.

    Redis is enabled with a non-empty URL so construction emits no
    'Redis is disabled in production' RuntimeWarning (keeps warns-based
    assertions elsewhere clean without relying on the filterwarnings config).
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
        redis_url="redis://redis.internal.example.org:6379/0",
    )
    kw.update(overrides)
    return kw


KWARGS_FOR_ENV = {
    "dev": base_kwargs,
    "staging": staging_kwargs,
    "production": prod_kwargs,
}


def make_settings(**kwargs) -> Settings:
    """Construct Settings without reading any .env file."""
    return Settings(_env_file=None, **kwargs)

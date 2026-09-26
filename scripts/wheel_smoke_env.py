"""Provide deterministic development settings for installed-wheel smoke checks.

These public fixture values must never be used as production credentials.
"""

from __future__ import annotations

import json
from typing import Final

_REQUIRED_SETTINGS: Final[frozenset[str]] = frozenset(
    {
        "ENV_STATE",
        "DATABASE_URL",
        "PUBLIC_BASE_URL",
        "SECRET_KEY",
        "SESSION_SECRET",
        "TOTP_ENCRYPTION_KEYS",
        "OUTBOX_ENCRYPTION_KEYS",
        "HEALTH_DETAIL_TOKEN",
        "ALLOWED_HOSTS",
        "SMTP_ENABLED",
        "REDIS_ENABLED",
        "SHIBBOLETH_ENABLED",
        "COOKIES_SECURE",
        "FASTAPI_DEBUG",
        "SEED_MOCK_DATA",
        "OAI_INSTITUTION_FILTER",
        "SWISSUBASE_OAI_PMH_URL",
    }
)

# Fixed non-production values. The release builder must not inherit
# private pytest configuration or a developer shell's settings accidentally.
_WHEEL_SMOKE_ENV: Final[dict[str, str]] = {
    "ENV_STATE": "dev",
    "DATABASE_URL": "postgresql://test:test@localhost:5432/oralhistarchiv_test",
    "PUBLIC_BASE_URL": "http://127.0.0.1:5000",
    "SECRET_KEY": "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8",
    "SESSION_SECRET": "aQ3eT6yU9iP2sD5fG8hJ1kL4zX7cV0bN3mW6rE9tY2uI5oS8",
    "TOTP_ENCRYPTION_KEYS": '["mB5nV8cX2zL7kJ4hG1fD9sA6qW3eR0tY5uI8oP2lM7wE4rT9"]',
    "OUTBOX_ENCRYPTION_KEYS": '["pQ8vN2rL6xB9mD4sF7hJ1kC5wY0zA3eR6tU9iO2gH5bV8nM4"]',
    "HEALTH_DETAIL_TOKEN": "hT7dK2mQ9wX4vB8zN1cR5jF0aG3sL6eY9uP2iO5tM8kW3qE7",
    "ALLOWED_HOSTS": '["localhost", "127.0.0.1", "testserver"]',
    "OAI_INSTITUTION_FILTER": "Universität Kassel",
    "SWISSUBASE_OAI_PMH_URL": "https://www.swissubase.ch/oai-pmh/v1/oai",
    "RATE_LIMIT_ENABLED": "true",
    "RATE_LIMIT_PER_MINUTE": "30",
    "RATE_LIMIT_PER_HOUR": "1000",
    "RATE_LIMIT_PER_DAY": "10000",
    "LOGIN_FAILURE_THRESHOLD": "3",
    "LOGIN_LOCKOUT_MINUTES": "15",
    "SMTP_ENABLED": "false",
    "REDIS_ENABLED": "false",
    "SHIBBOLETH_ENABLED": "false",
    "CORS_ENABLED": "false",
    "COOKIES_SECURE": "false",
    "FASTAPI_DEBUG": "false",
    "SEED_MOCK_DATA": "false",
    "LOG_LEVEL": "INFO",
    "LOG_FORMAT": "json",
}


def smoke_environment() -> dict[str, str]:
    """Return a copy of smoke settings; raise RuntimeError for missing/non-string values."""
    missing = _REQUIRED_SETTINGS - _WHEEL_SMOKE_ENV.keys()
    if missing:
        names = ", ".join(sorted(missing))
        raise RuntimeError(f"wheel smoke environment is missing required settings: {names}")

    invalid = sorted(
        repr(key)
        for key, value in _WHEEL_SMOKE_ENV.items()
        if not isinstance(key, str) or not isinstance(value, str)
    )
    if invalid:
        names = ", ".join(invalid)
        raise RuntimeError(f"wheel smoke environment has non-string settings: {names}")

    return _WHEEL_SMOKE_ENV.copy()


def main() -> None:
    """Print smoke settings as sorted JSON to stdout."""
    print(json.dumps(smoke_environment(), sort_keys=True))


if __name__ == "__main__":
    main()

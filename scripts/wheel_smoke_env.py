"""Provide deterministic development settings for installed-wheel smoke checks.

These public fixture values must never be used as production credentials.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Final

_SMOKE_HOST_ENV_KEYS: Final[frozenset[str]] = frozenset(
    {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "USERPROFILE",
    }
)

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
        "SOURCES_CONFIG_FILE",
        "ALLOW_FIXTURE_SOURCE",
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
    "LOG_LEVEL": "INFO",
    "LOG_FORMAT": "json",
    "SOURCES_CONFIG_FILE": "",
    "ALLOW_FIXTURE_SOURCE": "false",
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


def smoke_process_environment(host_environment: Mapping[str, str]) -> dict[str, str]:
    """Return allowed host variables plus fixed settings for offline runtime probes.

    Unknown variables are excluded even when future application settings are
    added. Build/download commands must continue using their own environment.
    Neither the supplied mapping nor the smoke defaults are mutated.
    """
    environment = {
        key: value for key, value in host_environment.items() if key.upper() in _SMOKE_HOST_ENV_KEYS
    }
    environment.update(smoke_environment())
    return environment


def main() -> None:
    """Print a complete offline smoke-process environment as sorted JSON."""
    print(json.dumps(smoke_process_environment(os.environ), sort_keys=True))


if __name__ == "__main__":
    main()

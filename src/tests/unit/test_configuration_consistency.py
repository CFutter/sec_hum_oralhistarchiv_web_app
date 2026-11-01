"""Cross-consumer normalization and safe, locale-independent diagnostics."""

import multiprocessing
import os
import runpy
import subprocess
import sys

import pytest
from pydantic import ValidationError

import config
from app.paths import PROJECT_ROOT
from tests.unit.settings_builders import base_kwargs, make_settings


@pytest.mark.parametrize(
    ("raw_url", "normalized", "expected_workers"),
    [
        ("", None, 1),
        (" \t ", None, 1),
        ("redis://limiter.example.org:6379/0", "redis://limiter.example.org:6379/0", 4),
    ],
)
def test_application_and_actual_gunicorn_config_agree_on_dedicated_limiter_presence(
    monkeypatch, raw_url, normalized, expected_workers
):
    """Application and actual Gunicorn config agree on dedicated limiter presence."""
    configured = make_settings(**base_kwargs(rate_limit_redis_url=raw_url, redis_enabled=False))
    monkeypatch.setattr(config, "settings", configured)
    monkeypatch.setattr(multiprocessing, "cpu_count", lambda: 4)
    server_config = runpy.run_path(str(PROJECT_ROOT / "gunicorn.conf.py"))
    assert configured.dedicated_rate_limit_storage_uri == normalized
    assert configured.rate_limit_storage_uri == normalized
    assert server_config["workers"] == expected_workers


def test_credential_url_with_padding_is_rejected_before_startup():
    """Credential URL with padding is rejected before startup."""
    with pytest.raises(ValidationError, match="whitespace or control characters"):
        make_settings(
            **base_kwargs(rate_limit_redis_url=" redis://named:private-value@localhost/0 ")
        )


@pytest.mark.parametrize("dsn", ["credential-canary@local/archive", "secret-scheme://local/db"])
def test_invalid_database_scheme_diagnostic_never_contains_raw_input(dsn):
    """Invalid database scheme diagnostic never contains raw input."""
    with pytest.raises(ValidationError, match="must start with") as error:
        make_settings(**base_kwargs(database_url=dsn))
    assert dsn not in str(error.value)
    assert dsn.split("://", 1)[0] not in str(error.value)


def test_development_env_warning_pass_reads_utf8_under_an_ascii_process_locale(tmp_path):
    """Development environment warning pass reads UTF-8 under an ascii process locale."""
    env_file = tmp_path / "development.env"
    env_file.write_text(
        "SITE_NAME=Archives historiques \u2013 oral\nUNKNOWN_CONFIG=1\n", encoding="utf-8"
    )
    script = """
import locale
import sys
from config.settings import Settings, settings, warn_unconsumed_env_keys
assert locale.getpreferredencoding(False).lower() not in {'utf-8', 'utf8'}
settings.env_state = 'dev'
Settings.model_config['env_file'] = sys.argv[1]
warn_unconsumed_env_keys()
"""
    env = {**os.environ, "LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}
    result = subprocess.run(
        [sys.executable, "-X", "utf8=0", "-c", script, str(env_file)],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert b"UNKNOWN_CONFIG" in result.stderr

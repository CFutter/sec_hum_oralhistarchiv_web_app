"""Canonical OS mode selection cannot be weakened by configuration overlays."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.environment import resolve_environment
from config.settings import Settings
from tests.unit.settings_builders import base_kwargs, prod_kwargs


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"env_state": "dev"},
        {"ENV_STATE": "production", "env_state": "dev"},
        {"env_state": "dev", "ENV_STATE": "production"},
        {"ENV_STATE": "Production"},
        {"ENV_STATE": ""},
        {"ENV_STATE": " dev"},
    ],
)
def test_process_mode_rejects_missing_ambiguous_and_noncanonical_values(values):
    """Process mode rejects missing ambiguous and noncanonical values."""
    with pytest.raises(ValueError):
        resolve_environment(values)


@pytest.mark.parametrize("mode", ["dev", "staging", "production"])
def test_process_mode_accepts_only_one_explicit_canonical_key(mode):
    """Process mode accepts only one explicit canonical key."""
    assert resolve_environment({"ENV_STATE": mode, "DATABASE_URL": "unread"}) == mode


def test_settings_source_rechecks_case_collisions_after_class_import(monkeypatch):
    """Settings source rechecks case collisions after class import."""
    monkeypatch.setenv("ENV_STATE", "production")
    monkeypatch.setenv("env_state", "dev")
    with pytest.raises(ValueError, match="uppercase ENV_STATE"):
        Settings(_env_file=None, **prod_kwargs())


def test_development_dotenv_cannot_change_the_process_mode(monkeypatch, tmp_path):
    """Development dotenv cannot change the process mode."""
    monkeypatch.setenv("ENV_STATE", "dev")
    path = tmp_path / "development.env"
    path.write_text("ENV_STATE=production\n", encoding="utf-8")
    with pytest.raises(ValueError, match="dotenv file cannot change"):
        Settings(_env_file=path, **base_kwargs())


def test_global_settings_import_requires_process_mode_before_other_fields(tmp_path):
    """Global settings import requires process mode before other fields."""
    source = Path(__file__).resolve().parents[2]
    environment = {key: value for key, value in os.environ.items() if key.casefold() != "env_state"}
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); import config",
            str(source),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "uppercase ENV_STATE" in result.stderr


def test_hardened_registration_is_explicit_opt_in(monkeypatch):
    """Hardened registration is explicit opt in."""
    monkeypatch.delenv("LOCAL_REGISTRATION_ENABLED", raising=False)
    assert Settings(_env_file=None, **prod_kwargs()).local_registration_enabled is False
    assert (
        Settings(
            _env_file=None, **prod_kwargs(local_registration_enabled=True)
        ).local_registration_enabled
        is True
    )
    assert Settings(_env_file=None, **base_kwargs()).local_registration_enabled is True


@pytest.mark.parametrize("name", ["LOCAL_AUTH_ENABLED", "local_auth_enabled"])
def test_obsolete_authentication_toggle_is_rejected(monkeypatch, name):
    """Obsolete authentication toggle is rejected."""
    monkeypatch.setenv(name, "false")
    with pytest.raises(ValueError, match="LOCAL_REGISTRATION_ENABLED"):
        Settings(_env_file=None, **base_kwargs())


@pytest.mark.parametrize("value", ["false", ""])
def test_obsolete_authentication_toggle_is_rejected_in_development_dotenv(tmp_path, value):
    """Obsolete authentication toggle is rejected in development dotenv."""
    path = tmp_path / "development.env"
    path.write_text(f'LOCAL_AUTH_ENABLED="{value}"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="LOCAL_REGISTRATION_ENABLED"):
        Settings(_env_file=path, **base_kwargs())

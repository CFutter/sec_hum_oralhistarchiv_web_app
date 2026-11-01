"""Offline release probes exclude ambient application and build configuration."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from app.paths import PROJECT_ROOT


def _load_script(name: str):
    """Load and execute the selected repository script in an isolated module."""
    path = PROJECT_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"wheel_smoke_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = _load_script("wheel_smoke_env")
builder = _load_script("build_release")

_HOST_VARIABLES = (
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
)
_CONTAMINANTS = {
    "ENV_STATE": "production",
    "SMTP_CA_BUNDLE": "/missing/smoke-ca.pem",
    "DATABASE_POOL_SIZE": "0",
    "DB_STATEMENT_TIMEOUT": "0s",
    "FEDERATED_TIER_RULES": "not-json",
    "ADMIN_SEED_EMAIL": "operator@example.org",
    "RATE_LIMIT_REDIS_URL": "invalid-redis-url",
    "SHIBBOLETH_ENABLED": "true",
    "REDIS_ENABLED": "true",
    "SOURCES_CONFIG_FILE": "/missing/production-sources.toml",
    "ALLOW_FIXTURE_SOURCE": "true",
    "MIGRATION_DATABASE_URL": "invalid-migration-url",
    "SEED_MOCK_DATA": "true",
    "SWISSUBASE_OAI_PMH_URL": "https://retired.example.org/oai",
    "FUTURE_APPLICATION_SETTING": "ambient-canary",
    "PYTHONPATH": "/missing/pythonpath",
    "PYTHONHOME": "/missing/pythonhome",
    "HTTP_PROXY": "http://127.0.0.1:9",
    "HTTPS_PROXY": "http://127.0.0.1:9",
    "REQUESTS_CA_BUNDLE": "/missing/requests-ca.pem",
    "SSL_CERT_FILE": "/missing/ssl-ca.pem",
    "PIP_INDEX_URL": "https://packages.example.org/simple",
    "UV_INDEX_URL": "https://packages.example.org/simple",
}


def _host_environment(work: Path) -> dict[str, str]:
    """Build a minimal child environment with work-local home/temp paths and required Windows
    variables.
    """
    environment = {
        "PATH": os.defpath,
        "HOME": str(work),
        "TMPDIR": str(work),
        "LANG": "C",
        "LC_ALL": "C",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


@pytest.mark.parametrize("name", _HOST_VARIABLES)
def test_supported_host_variable_is_preserved(name):
    """Check supported host variable is preserved."""
    result = smoke.smoke_process_environment({name: "host-value", "UNLISTED": "discard"})
    assert result == {name: "host-value", **smoke.smoke_environment()}


@pytest.mark.parametrize("name", ["Path", "SystemRoot", "lc_ctype"])
def test_host_variable_name_matching_preserves_original_spelling(name):
    """Check host variable name matching preserves original spelling."""
    result = smoke.smoke_process_environment({name: "host-value"})
    assert result == {name: "host-value", **smoke.smoke_environment()}


@pytest.mark.parametrize("lowercase", [False, True])
def test_active_retired_unknown_and_transport_variables_are_excluded(lowercase):
    """Check active retired unknown and transport variables are excluded."""
    inherited = {
        name.lower() if lowercase else name: value for name, value in _CONTAMINANTS.items()
    }
    original = inherited.copy()
    assert smoke.smoke_process_environment(inherited) == smoke.smoke_environment()
    assert inherited == original


def test_process_environment_does_not_read_global_environment_or_share_defaults(monkeypatch):
    """Check process environment does not read global environment or share defaults."""
    monkeypatch.setenv("PATH", "ambient-path-canary")
    first = smoke.smoke_process_environment({})
    first["ENV_STATE"] = "production"
    first["EXTRA"] = "changed"
    assert smoke.smoke_process_environment({}) == smoke.smoke_environment()
    assert "PATH" not in smoke.smoke_process_environment({})


def test_setting_fixtures_remain_independent_of_host_variables(monkeypatch):
    """Check setting fixtures remain independent of host variables."""
    monkeypatch.setenv("HOME", "ambient-home-canary")
    assert "HOME" not in smoke.smoke_environment()
    assert smoke.smoke_environment()["ENV_STATE"] == "dev"


@pytest.mark.parametrize("lowercase", [False, True])
def test_isolated_cli_emits_the_complete_filtered_environment(tmp_path, lowercase):
    """Check isolated CLI emits the complete filtered environment."""
    host = _host_environment(tmp_path)
    inherited = {
        **host,
        **{name.lower() if lowercase else name: value for name, value in _CONTAMINANTS.items()},
    }
    result = subprocess.run(
        [sys.executable, "-I", str(PROJECT_ROOT / "scripts/wheel_smoke_env.py")],
        cwd=tmp_path,
        env=inherited,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert json.loads(result.stdout) == {**host, **smoke.smoke_environment()}
    assert not result.stderr


@pytest.mark.parametrize("lowercase", [False, True])
def test_builder_uses_real_helper_for_all_probes_and_preserves_install_environment(
    tmp_path, lowercase
):
    """Check builder uses real helper for all probes and preserves install environment."""
    host = _host_environment(tmp_path)
    inherited = {
        **host,
        **{name.lower() if lowercase else name: value for name, value in _CONTAMINANTS.items()},
    }
    original = inherited.copy()
    with patch.object(builder, "_run", autospec=True) as run:
        builder._smoke_test_wheel(
            tmp_path / "application.whl", tmp_path / "requirements-runtime.txt", tmp_path, inherited
        )

    install_calls = [call for call in run.call_args_list if call.args[0][0] == "uv"]
    assert len(install_calls) == 4
    for call in install_calls:
        assert call.kwargs["env"] is inherited
        assert call.kwargs["cwd"] == tmp_path

    probes = [call for call in run.call_args_list if call.args[0][1:2] == ["-I"]]
    assert [call.args[0][1:] for call in probes] == [
        ["-I", str(tmp_path / "smoke_installed_wheel.py")],
        ["-I", "-m", "app.migrate", "heads"],
        ["-I", "-m", "app.migrate", "upgrade", "head", "--sql"],
    ]
    for call in probes:
        assert call.kwargs["env"] == {**host, **smoke.smoke_environment()}
        assert call.kwargs["cwd"] == tmp_path
    assert inherited == original

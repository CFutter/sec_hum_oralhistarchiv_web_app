"""Execute the dev launcher with real settings and mutation-recording stand-ins."""

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from app.paths import PROJECT_ROOT
from tests.unit.settings_builders import prod_kwargs


@pytest.fixture
def launcher_environment(tmp_path: Path) -> dict[str, str]:
    # Copy config so its real repo-relative dotenv path belongs to this test.
    """Create a fake Python launcher that records commands, retaining real settings validation."""
    config_dir = tmp_path / "src" / "config"
    shutil.copytree(PROJECT_ROOT / "src" / "config", config_dir)
    dispatcher = tmp_path / "python3"
    dispatcher.write_text(
        "#!/bin/bash\n"
        'if [[ "$1" == "-" ]]; then\n'
        f'    exec {shlex.quote(sys.executable)} "$@"\n'
        "fi\n"
        "printf '%s\\n' \"$*\" >> launcher-calls\n"
        "exit 23\n",
        encoding="utf-8",
    )
    dispatcher.chmod(0o755)
    # Start from valid settings for every tier, without inheriting operator values.
    environment: dict[str, str] = {
        key.upper(): value if isinstance(value, str) else json.dumps(value)
        for key, value in prod_kwargs().items()
        if value is not None
    }
    environment.update(
        PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        PYTHONPATH=os.pathsep.join((str(tmp_path / "src"), str(PROJECT_ROOT / "src"))),
    )
    return environment


def _run_launcher(
    tmp_path: Path,
    environment: dict[str, str],
    os_mode: str | None,
    dotenv_mode: str | None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Set OS/dotenv mode, run dev.sh with a ten-second timeout and return result plus recorded
    calls.
    """
    if os_mode is None:
        environment.pop("ENV_STATE", None)
    else:
        environment["ENV_STATE"] = os_mode
    if dotenv_mode is not None:
        (tmp_path / ".env").write_text(f"ENV_STATE={dotenv_mode}\n", encoding="utf-8")
    result = subprocess.run(
        ["bash", str(PROJECT_ROOT / "dev.sh")],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    calls_file = tmp_path / "launcher-calls"
    calls = calls_file.read_text(encoding="utf-8").splitlines() if calls_file.exists() else []
    return result, calls


@pytest.mark.parametrize(
    ("os_mode", "dotenv_mode"),
    [
        ("staging", None),
        ("production", None),
        ("staging", "dev"),
        ("production", "dev"),
        (None, "staging"),
        (None, "production"),
        (None, None),
        (None, "dev"),
        ("dev", "production"),
    ],
)
def test_hardened_missing_or_conflicting_mode_stops_before_mutations(
    tmp_path: Path,
    launcher_environment: dict[str, str],
    os_mode: str | None,
    dotenv_mode: str | None,
) -> None:
    """Hardened missing or conflicting mode stops before mutations."""
    result, calls = _run_launcher(tmp_path, launcher_environment, os_mode, dotenv_mode)
    assert result.returncode != 0
    assert calls == []
    if os_mode == "dev":
        assert "dotenv file cannot change" in result.stderr
    elif os_mode is not None:
        assert "dev.sh requires ENV_STATE=dev" in result.stderr
    else:
        assert "uppercase ENV_STATE" in result.stderr


@pytest.mark.parametrize(
    ("os_mode", "dotenv_mode"),
    [("dev", None), ("dev", "dev")],
)
def test_effective_development_settings_reach_migration_and_preserve_its_failure(
    tmp_path: Path,
    launcher_environment: dict[str, str],
    os_mode: str | None,
    dotenv_mode: str | None,
) -> None:
    """Effective development settings reach migration and preserve its failure."""
    result, calls = _run_launcher(tmp_path, launcher_environment, os_mode, dotenv_mode)
    assert result.returncode == 23, result.stderr
    assert calls == ["-m alembic -c src/alembic.ini upgrade head"]


@pytest.mark.parametrize(
    ("os_mode", "invalid_values", "field"),
    [
        ("invalid", {}, "ENV_STATE must be dev, staging or production"),
        ("dev", {"FASTAPI_PORT": "not-an-integer"}, "fastapi_port"),
    ],
)
def test_invalid_settings_stop_before_migration_or_children(
    tmp_path: Path,
    launcher_environment: dict[str, str],
    os_mode: str,
    invalid_values: dict[str, str],
    field: str,
) -> None:
    """Invalid settings stop before migration or children."""
    launcher_environment.update(invalid_values)
    result, calls = _run_launcher(tmp_path, launcher_environment, os_mode, None)
    assert result.returncode != 0
    assert calls == []
    assert field in result.stderr


def test_conflicting_os_mode_casing_cannot_pass_the_launcher_guard(
    tmp_path: Path, launcher_environment: dict[str, str]
) -> None:
    """Conflicting OS mode casing cannot pass the launcher guard."""
    launcher_environment["env_state"] = "dev"
    result, calls = _run_launcher(tmp_path, launcher_environment, "production", None)
    assert result.returncode != 0
    assert calls == []
    assert "uppercase ENV_STATE" in result.stderr

"""Dependency evidence fails on advisories, incomplete inventories and tool errors."""

import importlib.util
import json
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from app.paths import PROJECT_ROOT


def _helper():
    """Import the dependency-audit script without invoking its CLI entry point."""
    specification = importlib.util.spec_from_file_location(
        "dependency_advisory_checks", PROJECT_ROOT / "scripts/audit_dependencies.py"
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _clean_report():
    """Return one dependency with no reported vulnerabilities."""
    return {"dependencies": [{"name": "sample-package", "version": "1.0", "vulns": []}]}


@pytest.mark.parametrize(
    "report,returncode,expected",
    [
        (_clean_report(), 0, True),
        (_clean_report(), 1, False),
        (
            {
                "dependencies": [
                    {
                        "name": "sample-package",
                        "version": "1.0",
                        "vulns": [{"id": "synthetic-advisory"}],
                    }
                ]
            },
            0,
            False,
        ),
        (
            {
                "dependencies": [
                    {
                        "name": "sample-package",
                        "version": "1.0",
                        "skip_reason": "unavailable",
                        "vulns": [],
                    }
                ]
            },
            0,
            False,
        ),
        ({"dependencies": []}, 0, False),
        ({"dependencies": [{"name": "sample-package", "vulns": []}]}, 0, False),
        ({"error": "incomplete"}, 0, False),
        (None, 0, False),
        ("malformed", 0, False),
    ],
    ids=[
        "clean",
        "process-error",
        "advisory",
        "skipped",
        "empty",
        "unversioned",
        "error-report",
        "missing",
        "malformed",
    ],
)
def test_scan_requires_complete_clean_report_and_successful_process(
    tmp_path, monkeypatch, report, returncode, expected
):
    """Scan requires complete clean report and successful process."""
    helper = _helper()
    metadata = {"steps": [], "scans": {}}

    def fake_run(arguments, **kwargs):
        """Require strict scanning, write the requested report and return the configured exit
        status.
        """
        assert kwargs["check"] is False
        assert "--strict" in arguments
        report_path = Path(arguments[arguments.index("--output") + 1])
        if report == "malformed":
            report_path.write_text("not-json", encoding="utf-8")
        elif report is not None:
            report_path.write_text(json.dumps(report), encoding="utf-8")
        return subprocess.CompletedProcess(arguments, returncode, "", "")

    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    assert helper._audit("runtime", [], tmp_path, metadata, 1) is expected
    assert metadata["scans"]["runtime"] == ("passed" if expected else "failed")
    assert (tmp_path / "runtime.json").is_file()


def test_timeout_is_retained_as_failed_evidence(tmp_path, monkeypatch):
    """Timeout is retained as failed evidence."""
    helper = _helper()
    metadata = {"steps": [], "scans": {}}

    def timeout(arguments, **_kwargs):
        """Raise TimeoutExpired for the attempted scanner command."""
        raise subprocess.TimeoutExpired(arguments, 1)

    monkeypatch.setattr(helper.subprocess, "run", timeout)
    assert not helper._audit("runtime", [], tmp_path, metadata, 1)
    assert metadata["steps"][0]["error_type"] == "TimeoutExpired"
    assert json.loads((tmp_path / "runtime.json").read_text())["error"]


def test_build_scan_must_cover_every_installed_distribution():
    """Build scan must cover every installed distribution."""
    helper = _helper()
    inventory = {
        "distributions": [
            {"name": "sample_package", "version": "1.0"},
            {"name": "pip", "version": "2.0"},
        ]
    }
    assert not helper._complete_report(_clean_report(), inventory)
    complete = _clean_report()
    complete["dependencies"].append({"name": "pip", "version": "2.0", "vulns": []})
    assert helper._complete_report(complete, inventory)
    complete["dependencies"][1]["version"] = "1.0"
    assert not helper._complete_report(complete, inventory)


def test_installer_pin_requires_locked_hashes_and_does_not_resolve_latest():
    """Installer pin requires locked hashes and does not resolve latest."""
    helper = _helper()
    lock = {
        "package": [
            {"name": "pip", "version": "26.2.1", "wheels": [{"hash": "sha256:" + "a" * 64}]}
        ]
    }
    requirement = helper._installer_requirement(lock)
    assert requirement == "pip==26.2.1 --hash=sha256:" + "a" * 64 + "\n"
    lock["package"][0]["wheels"] = []
    with pytest.raises(helper.CheckFailed):
        helper._installer_requirement(lock)


def test_backend_requirements_must_match_hash_constrained_build_inputs():
    """Backend requirements must match hash constrained build inputs."""
    helper = _helper()
    project = {"build-system": {"requires": ["hatchling==1.0"], "build-backend": "hatchling.build"}}
    helper._validate_build_constraints(project, "hatchling==1.0 \\\n    --hash=sha256:abc\n")
    with pytest.raises(helper.CheckFailed):
        helper._validate_build_constraints(project, "hatchling==2.0\n")
    project["build-system"]["requires"].append("unconstrained-plugin==1.0")
    with pytest.raises(helper.CheckFailed):
        helper._validate_build_constraints(project, "hatchling==1.0\n")


def test_build_proof_uses_hashes_builds_a_wheel_and_inventories_that_interpreter(
    tmp_path, monkeypatch
):
    """Build proof uses hashes builds a wheel and inventories that interpreter."""
    helper = _helper()
    commands = {}
    environment = tmp_path / "build-environment"

    def required(arguments, _output, label, _metadata, _timeout):
        """Capture build commands, create a fake wheel and supply build-environment inventory."""
        commands[label] = arguments
        if label == "build-current-wheel":
            (Path(arguments[-1]) / "current-0.1-py3-none-any.whl").write_bytes(b"wheel")
        if label == "inventory-build-environment":
            return json.dumps(
                {
                    "prefix": str(environment),
                    "paths": [str(environment / "lib/python3.11/site-packages")],
                    "distributions": [{"name": "hatchling", "version": "1.32.0"}],
                }
            )
        return ""

    monkeypatch.setattr(helper, "_required", required)
    metadata = {}
    helper._prepare_build_environment(tmp_path, metadata, 1)
    for label in ("install-build-dependencies", "install-build-installer"):
        assert "--require-hashes" in commands[label]
        assert commands[label][commands[label].index("--python") + 1] == str(
            environment / "bin/python"
        )
    assert commands["build-current-wheel"][0] == str(environment / "bin/python")
    assert commands["inventory-build-environment"][0] == str(environment / "bin/python")
    assert (tmp_path / "build-inventory.json").is_file()
    assert metadata["built_wheel"]["filename"] == "current-0.1-py3-none-any.whl"


@pytest.mark.parametrize("failed_scope", [None, "runtime", "development-documentation", "build"])
def test_all_scopes_are_attempted_and_any_failed_scope_fails_the_run(
    tmp_path, monkeypatch, failed_scope
):
    """All scopes are attempted and any failed scope fails the run."""
    helper = _helper()
    commands = {}
    scanned = []

    def required(arguments, _output, label, _metadata, _timeout):
        """Capture the labelled command and return empty output."""
        commands[label] = arguments
        return ""

    def scan(label, arguments, _output, metadata, _timeout, **_kwargs):
        """Record every scan and fail only the configured scope."""
        scanned.append((label, arguments))
        passed = label != failed_scope
        metadata["scans"][label] = "passed" if passed else "failed"
        return passed

    monkeypatch.setattr(helper, "_required", required)
    monkeypatch.setattr(helper, "_audit", scan)
    monkeypatch.setattr(
        helper,
        "_prepare_build_environment",
        lambda *_args: {"paths": ["/build-environment/site-packages"], "distributions": []},
    )
    destination = tmp_path / "evidence"
    assert helper.run(destination) is (failed_scope is None)
    assert "--all-extras" in commands["export-development-documentation"]
    assert "--locked" in commands["export-runtime"]
    assert [scope for scope, _ in scanned] == ["runtime", "development-documentation", "build"]
    assert scanned[-1][1] == ["--path", "/build-environment/site-packages"]
    metadata = json.loads((destination / "metadata.json").read_text())
    assert metadata["input_sha256"]["uv.lock"]
    assert datetime.fromisoformat(metadata["finished_at"]) >= datetime.fromisoformat(
        metadata["started_at"]
    )
    assert metadata["status"] == ("passed" if failed_scope is None else "failed")


def test_no_tool_invocation_cannot_vacuously_pass(tmp_path, monkeypatch):
    """No tool invocation cannot vacuously pass."""
    helper = _helper()

    def unavailable(*_args):
        """Raise CheckFailed to simulate unavailable uv."""
        raise helper.CheckFailed("uv missing")

    monkeypatch.setattr(helper, "_required", unavailable)
    destination = tmp_path / "evidence"
    assert not helper.run(destination)
    assert json.loads((destination / "metadata.json").read_text())["status"] == "failed"


def test_children_do_not_receive_application_secrets_or_install_overrides(monkeypatch):
    """Children do not receive application secrets or install overrides."""
    helper = _helper()
    for name in ("SECRET_KEY", "DATABASE_URL", "PYTHONPATH", "UV_INDEX_URL", "PIP_TARGET"):
        monkeypatch.setenv(name, "must-not-reach-build-tools")
    assert all(
        name not in helper._environment()
        for name in ("SECRET_KEY", "DATABASE_URL", "PYTHONPATH", "UV_INDEX_URL", "PIP_TARGET")
    )


def test_ci_and_weekly_workflow_run_the_same_complete_check_and_preserve_failure_evidence():
    """CI and weekly workflow run the same complete check and preserve failure evidence."""
    main = (PROJECT_ROOT / ".github/workflows/ci.yml").read_text()
    security_job = main.split("  security:\n", 1)[1].split("\n  wheel-smoke:\n", 1)[0]
    recurring = (PROJECT_ROOT / ".github/workflows/dependency-advisories.yml").read_text()
    assert "schedule:" in recurring and 'cron: "41 5 * * 1"' in recurring
    for workflow in (security_job, recurring):
        assert (
            ".venv/bin/python scripts/audit_dependencies.py --output-dir dependency-advisories"
            in workflow
        )
        assert "uv sync --locked --extra dev --no-install-project" in workflow
        assert "if: always()" in workflow
        assert "dependency-advisories/*.json" in workflow
        assert "if-no-files-found: error" in workflow
        assert "retention-days: 30" in workflow
        assert "continue-on-error" not in workflow

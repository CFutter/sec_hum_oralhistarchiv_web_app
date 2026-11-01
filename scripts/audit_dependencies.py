"""Audit locked application/tooling dependencies and a real wheel-build environment.

Run with the locked development environment on a networked Python 3.11 runner.
Reports include UTC times, source/constraint hashes, resolved build inventory,
and command outcomes. Advisories, incomplete scans and process failures all fail.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess  # nosec B404 - fixed dependency-tool argument vectors
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_MAX_COMMAND_TIMEOUT_SECONDS = 1800
_EXPECTED_SCAN_COUNT = 3
_BUILD_INVENTORY = """
import importlib.metadata
import json
import sys
import sysconfig
print(json.dumps({
    'prefix': sys.prefix,
    'python': sys.version,
    'paths': sorted(set(sysconfig.get_paths()[name] for name in ('purelib', 'platlib'))),
    'distributions': sorted(
        ({'name': item.metadata['Name'], 'version': item.version}
         for item in importlib.metadata.distributions()), key=lambda item: item['name'].lower()
    ),
}))
"""
_BUILD_WHEEL = """
import sys
from hatchling.build import build_wheel, get_requires_for_build_wheel
if get_requires_for_build_wheel():
    raise SystemExit('additional build requirements need explicit hash constraints')
print(build_wheel(sys.argv[1]))
"""


class CheckFailed(RuntimeError):
    """One dependency check could not establish a complete clean result."""


def _write_json(path: Path, value: Any) -> None:
    """Overwrite path with sorted indented UTF-8 JSON and a trailing newline; errors propagate."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _environment() -> dict[str, str]:
    """Pass only OS/network settings needed by build and advisory tools."""
    allowed = {
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "SYSTEMROOT",
        "WINDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "XDG_CACHE_HOME",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update(
        UV_NO_CONFIG="1",
        UV_NO_PROGRESS="1",
        PIP_CONFIG_FILE=os.devnull,
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        PIP_NO_INPUT="1",
    )
    return environment


def _run(
    arguments: list[str], output: Path, label: str, metadata: dict[str, Any], timeout: int
) -> subprocess.CompletedProcess[str]:
    """Run a fixed command and append step timestamps/status to metadata.

    Write stdout/stderr to output/label.log after completion; nonzero exit is returned.
    OS errors/timeouts raise CheckFailed and record error_type without writing that log.
    """
    step: dict[str, Any] = {"label": label, "started_at": datetime.now(UTC).isoformat()}
    metadata["steps"].append(step)
    try:
        completed = subprocess.run(  # nosec B603 - fixed executables/options, never a shell
            arguments,
            cwd=PROJECT_ROOT,
            env=_environment(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        step.update(status="error", error_type=type(error).__name__)
        raise CheckFailed(label) from None
    finally:
        step["finished_at"] = datetime.now(UTC).isoformat()
    (output / f"{label}.log").write_text(
        completed.stdout + "\n" + completed.stderr, encoding="utf-8"
    )
    step.update(
        status="passed" if completed.returncode == 0 else "failed", exit_code=completed.returncode
    )
    return completed


def _required(
    arguments: list[str], output: Path, label: str, metadata: dict[str, Any], timeout: int
) -> str:
    """Return logged command stdout; nonzero exit or execution failure raises CheckFailed."""
    result = _run(arguments, output, label, metadata, timeout)
    if result.returncode != 0:
        raise CheckFailed(label)
    return result.stdout


def _installer_requirement(lock: dict[str, Any]) -> str:
    """Use the lock's exact installer version and distribution hashes."""
    installers = [item for item in lock["package"] if item["name"] == "pip"]
    if len(installers) != 1:
        raise CheckFailed("lock must include one installer package")
    installer = installers[0]
    version = installer["version"]
    artifacts = [*installer.get("wheels", []), installer.get("sdist", {})]
    hashes = sorted({item["hash"] for item in artifacts if "hash" in item})
    if (
        not isinstance(version, str)
        or re.fullmatch(r"[A-Za-z0-9!+_.-]+", version) is None
        or not hashes
        or any(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in hashes)
    ):
        raise CheckFailed("installer pin or hashes are invalid")
    return f"pip=={version} " + " ".join(f"--hash={value}" for value in hashes) + "\n"


def _validate_build_constraints(project: dict[str, Any], constraints: str) -> None:
    """Require Hatchling build requirements to appear verbatim in constraint lines; raise
    CheckFailed.
    """
    build = project["build-system"]
    if build["build-backend"] != "hatchling.build" or not build["requires"]:
        raise CheckFailed("unsupported build backend")
    for requirement in build["requires"]:
        if not isinstance(requirement, str) or not re.search(
            rf"(?m)^{re.escape(requirement)}\s*(?:\\|$)", constraints
        ):
            raise CheckFailed("build requirements differ from hash constraints")


def _prepare_build_environment(
    output: Path, metadata: dict[str, Any], timeout: int
) -> dict[str, Any]:
    """Create an isolated build environment, build/hash one wheel and return its installed
    inventory.

    Read project/lock/constraints, run networked hash-checked installer commands and
    write evidence under output. Mutate metadata with steps/wheel identity; failures
    raise CheckFailed or propagate file, JSON and subprocess errors.
    """
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    constraints = (PROJECT_ROOT / "build-requirements.txt").read_text(encoding="utf-8")
    _validate_build_constraints(project, constraints)
    lock = tomllib.loads((PROJECT_ROOT / "uv.lock").read_text(encoding="utf-8"))
    installer = output / "build-installer.txt"
    installer.write_text(_installer_requirement(lock), encoding="utf-8")
    environment = output / "build-environment"
    python = environment / "bin/python"
    _required(
        [sys.executable, "-m", "venv", "--without-pip", str(environment)],
        output,
        "create-build-environment",
        metadata,
        timeout,
    )
    _required(
        [
            "uv",
            "pip",
            "sync",
            "--python",
            str(python),
            "--require-hashes",
            "--only-binary=:all:",
            "--index-url",
            "https://pypi.org/simple",
            str(PROJECT_ROOT / "build-requirements.txt"),
        ],
        output,
        "install-build-dependencies",
        metadata,
        timeout,
    )
    _required(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "--require-hashes",
            "--no-deps",
            "--only-binary=:all:",
            "--index-url",
            "https://pypi.org/simple",
            "-r",
            str(installer),
        ],
        output,
        "install-build-installer",
        metadata,
        timeout,
    )
    wheels = output / "built-wheel"
    wheels.mkdir()
    _required(
        [str(python), "-I", "-c", _BUILD_WHEEL, str(wheels)],
        output,
        "build-current-wheel",
        metadata,
        timeout,
    )
    built_wheels = list(wheels.glob("*.whl"))
    if len(built_wheels) != 1:
        raise CheckFailed("build did not produce exactly one wheel")
    metadata["built_wheel"] = {
        "filename": built_wheels[0].name,
        "sha256": hashlib.sha256(built_wheels[0].read_bytes()).hexdigest(),
    }
    inventory: dict[str, Any] = json.loads(
        _required(
            [str(python), "-I", "-c", _BUILD_INVENTORY],
            output,
            "inventory-build-environment",
            metadata,
            timeout,
        )
    )
    if (
        Path(inventory["prefix"]).resolve() != environment.resolve()
        or not inventory["distributions"]
        or not inventory["paths"]
        or any(
            not Path(path).resolve().is_relative_to(environment.resolve())
            for path in inventory["paths"]
        )
    ):
        raise CheckFailed("build inventory escaped its environment")
    _write_json(output / "build-inventory.json", inventory)
    return inventory


def _normal_name(name: str) -> str:
    """Lowercase a distribution name and collapse runs of hyphens, underscores and dots to one
    hyphen.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _complete_report(report: Any, inventory: dict[str, Any] | None = None) -> bool:
    """Require nonempty unskipped dependency rows with no advisories and, if given, exact
    inventory coverage.
    """
    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        return False
    dependencies = report["dependencies"]
    if not dependencies or any(
        not isinstance(item, dict)
        or not item.get("name")
        or not item.get("version")
        or item.get("skip_reason")
        or item.get("vulns") != []
        for item in dependencies
    ):
        return False
    if inventory is not None:
        expected = {
            (_normal_name(item["name"]), item["version"]) for item in inventory["distributions"]
        }
        actual = {(_normal_name(item["name"]), item["version"]) for item in dependencies}
        if actual != expected:
            return False
    return True


def _audit(
    label: str,
    arguments: list[str],
    output: Path,
    metadata: dict[str, Any],
    timeout: int,
    *,
    inventory: dict[str, Any] | None = None,
) -> bool:
    """Run one pip-audit scan, retain its JSON/logs and record pass/fail in metadata.

    Return False for classified execution/report failures; synthesize an error report
    only when none exists. Evidence-write failures may still propagate.
    """
    report_path = output / f"{label}.json"
    try:
        result = _run(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "--strict",
                "--progress-spinner",
                "off",
                "--timeout",
                "15",
                "--format",
                "json",
                "--output",
                str(report_path),
                *arguments,
            ],
            output,
            label,
            metadata,
            timeout,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        passed = result.returncode == 0 and _complete_report(report, inventory)
    except (CheckFailed, OSError, ValueError, KeyError, TypeError):
        passed = False
        if not report_path.exists():
            _write_json(report_path, {"error": "scan_did_not_produce_a_complete_report"})
    metadata["scans"][label] = "passed" if passed else "failed"
    return passed


def run(output: Path, *, timeout: int = 300) -> bool:
    """Create a new evidence directory and return whether all three dependency scans pass.

    timeout is 1..1800 seconds per command. Run exports, network advisory scans and
    a real isolated wheel build; retain requirements, logs, inventories and UTC/hash
    metadata. Invalid timeout raises ValueError, existing output FileExistsError;
    file/input errors may propagate and partial evidence remains after failure.
    """
    if not 1 <= timeout <= _MAX_COMMAND_TIMEOUT_SECONDS:
        raise ValueError("timeout must be within 1..1800 seconds")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    metadata: dict[str, Any] = {
        "started_at": datetime.now(UTC).isoformat(),
        "source_commit": os.environ.get("GITHUB_SHA"),
        "python": sys.version,
        "input_sha256": {
            name: hashlib.sha256((PROJECT_ROOT / name).read_bytes()).hexdigest()
            for name in ("uv.lock", "pyproject.toml", "build-requirements.txt")
        },
        "steps": [],
        "scans": {},
        "status": "running",
    }
    outcomes = []
    try:
        _required(["uv", "--version"], output, "uv-version", metadata, timeout)
        for label, selection in (
            ("runtime", ["--no-dev"]),
            ("development-documentation", ["--all-extras", "--no-dev"]),
        ):
            requirements = output / f"{label}.txt"
            try:
                _required(
                    [
                        "uv",
                        "export",
                        "--locked",
                        "--no-sources",
                        "--no-emit-project",
                        "--no-header",
                        "--no-annotate",
                        "--no-hashes",
                        *selection,
                        "--output-file",
                        str(requirements),
                    ],
                    output,
                    f"export-{label}",
                    metadata,
                    timeout,
                )
                outcomes.append(
                    _audit(
                        label,
                        ["--disable-pip", "--no-deps", "-r", str(requirements)],
                        output,
                        metadata,
                        timeout,
                    )
                )
            except CheckFailed:
                metadata["scans"][label] = "failed"
                outcomes.append(False)
        try:
            inventory = _prepare_build_environment(output, metadata, timeout)
            paths = [argument for path in inventory["paths"] for argument in ("--path", path)]
            outcomes.append(_audit("build", paths, output, metadata, timeout, inventory=inventory))
        except (CheckFailed, OSError, ValueError, KeyError, TypeError):
            metadata["scans"]["build"] = "failed"
            outcomes.append(False)
    except CheckFailed:
        outcomes.append(False)
    finally:
        metadata["finished_at"] = datetime.now(UTC).isoformat()
        metadata["status"] = (
            "passed" if len(outcomes) == _EXPECTED_SCAN_COUNT and all(outcomes) else "failed"
        )
        _write_json(output / "metadata.json", metadata)
    return bool(metadata["status"] == "passed")


def main() -> int:
    """Parse output/timeout options and run checks; return 0 only for complete advisory-free
    evidence.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    arguments = parser.parse_args()
    try:
        passed = run(arguments.output_dir, timeout=arguments.timeout_seconds)
    except (OSError, ValueError, KeyError, TypeError):
        passed = False
    if not passed:
        print(
            "Dependency checks failed or are incomplete; inspect the evidence directory.",
            file=sys.stderr,
        )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

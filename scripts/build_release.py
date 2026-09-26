"""Build a release from a clean Git checkout using Python 3.11 and uv 0.12.11.

Exports uv.lock, hash-checks build/runtime dependencies, smoke-tests the
installed wheel, and writes a tarball, installer and ARTIFACT.txt. Network
access is needed unless dependencies are cached. The supplied commit must
match HEAD; output-dir must not exist.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess  # nosec B404 - fixed release commands, never a shell
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_REQUIREMENTS = PROJECT_ROOT / "build-requirements.txt"
LOCK_FILE = PROJECT_ROOT / "uv.lock"
EXPECTED_UV_VERSION = "0.12.11"
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}\b")
_REQUIREMENT_RE = re.compile(r"(?m)^[A-Za-z0-9][A-Za-z0-9._-]*==")
_FORBIDDEN_RUNTIME_PACKAGES = frozenset(
    {
        "bandit",
        "hatchling",
        "httpx",
        "mypy",
        "pip-audit",
        "pytest",
        "pytest-asyncio",
        "pytest-cov",
        "ruff",
    }
)


def _run(
    args: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
    timeout: int = 900,
) -> None:
    """Run a checked subprocess with a timeout in seconds; inherit env when None.

    OS errors, CalledProcessError and TimeoutExpired propagate.
    """
    subprocess.run(  # nosec B603 - every argument is constructed internally
        args,
        cwd=cwd,
        env=env,
        check=True,
        timeout=timeout,
    )


def _output(
    args: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
) -> str:
    """Return stripped stdout from a checked subprocess with a 30-second timeout.

    Inherits env when None; OS errors, CalledProcessError and TimeoutExpired propagate.
    """
    return subprocess.check_output(  # nosec B603 - fixed git/interpreter command
        args,
        cwd=cwd,
        env=env,
        text=True,
        timeout=30,
    ).strip()


def _sha256(path: Path) -> str:
    """Stream a file into a lowercase SHA-256 hex digest; file errors propagate."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_commit_sha(value: str) -> str:
    """Strip and lowercase a 40-digit hexadecimal commit ID; otherwise raise ValueError."""
    commit = value.strip().lower()
    if _COMMIT_RE.fullmatch(commit) is None:
        raise ValueError("--commit-sha must be a full lowercase 40-character Git SHA")
    return commit


def _assert_reviewed_source(commit: str) -> None:
    """Require a Git checkout with matching HEAD and no tracked or untracked changes.

    Raises RuntimeError for failed checks; Git command failures propagate.
    """
    if not (PROJECT_ROOT / ".git").exists():
        raise RuntimeError("release builds require a Git checkout with provenance metadata")

    actual = _output(["git", "rev-parse", "HEAD"])
    if actual != commit:
        raise RuntimeError(f"requested commit {commit} does not match checked-out HEAD {actual}")

    status = _output(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise RuntimeError("release builds require a clean source tree")


def _validate_runtime_export(text: str) -> None:
    """Reject editable/local requirements, missing hashes and forbidden tool packages.

    Raises RuntimeError; this checks export text, not distribution contents.
    """
    lowered = text.lower()
    if "-e " in lowered or "--editable" in lowered or "file:" in lowered:
        raise RuntimeError("runtime export contains an editable or local-path requirement")
    if _HASH_RE.search(text) is None:
        raise RuntimeError("runtime export contains no SHA-256 distribution hashes")

    blocks = re.split(r"(?m)(?=^[A-Za-z0-9][A-Za-z0-9._-]*==)", text)
    requirements = [block for block in blocks if _REQUIREMENT_RE.match(block)]
    if not requirements:
        raise RuntimeError("runtime export contains no pinned requirements")
    if any(_HASH_RE.search(block) is None for block in requirements):
        raise RuntimeError("every runtime requirement must carry a SHA-256 hash")

    names = {block.split("==", 1)[0].strip().lower().replace("_", "-") for block in requirements}
    forbidden = names & _FORBIDDEN_RUNTIME_PACKAGES
    if forbidden:
        raise RuntimeError(
            f"development/build packages leaked into runtime export: {sorted(forbidden)}"
        )


def _clean_environment() -> dict[str, str]:
    """Copy the process environment without UV_* or Python-path/venv overrides.

    Sets UV_NO_CONFIG and UV_NO_PROGRESS to 1; leaves the process unchanged.
    """
    env = dict(os.environ)
    for name in tuple(env):
        if name.startswith("UV_"):
            env.pop(name)
    for name in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"):
        env.pop(name, None)
    env["UV_NO_CONFIG"] = "1"
    env["UV_NO_PROGRESS"] = "1"
    return env


def _assert_uv_version(env: dict[str, str]) -> None:
    """Require uv --version to report 0.12.11; raise RuntimeError on mismatch."""
    actual = _output(["uv", "--version"], env=env).split()
    if actual[:2] != ["uv", EXPECTED_UV_VERSION]:
        raise RuntimeError(
            f"release builder requires uv {EXPECTED_UV_VERSION}; got {' '.join(actual)}"
        )


def _export_runtime_requirements(destination: Path, env: dict[str, str]) -> None:
    """Check uv.lock, export hashed runtime requirements to destination, and validate them."""
    _run(["uv", "lock", "--check", "--no-sources"], env=env)
    _run(
        [
            "uv",
            "export",
            "--quiet",
            "--locked",
            "--no-sources",
            "--no-dev",
            "--no-emit-project",
            "--no-header",
            "--no-annotate",
            "--format",
            "requirements.txt",
            "--output-file",
            str(destination),
        ],
        env=env,
    )
    _validate_runtime_export(destination.read_text(encoding="utf-8"))


def _build_distributions(work: Path, env: dict[str, str]) -> tuple[Path, Path]:
    """Build one sdist and its wheel in work/dist; return their paths.

    Uses hash-checked build constraints; raises RuntimeError for unexpected artifact
    counts and propagates file/subprocess failures.
    """
    dist = work / "dist"
    dist.mkdir()
    build_controls = [
        "--build-constraints",
        str(BUILD_REQUIREMENTS),
        "--require-hashes",
        "--no-sources",
    ]
    _run(
        [
            "uv",
            "build",
            "--sdist",
            "--out-dir",
            str(dist),
            *build_controls,
            str(PROJECT_ROOT),
        ],
        cwd=work,
        env=env,
    )
    sdists = list(dist.glob("*.tar.gz"))
    if len(sdists) != 1:
        raise RuntimeError(f"expected one sdist, found {len(sdists)}")

    _run(
        [
            "uv",
            "build",
            "--wheel",
            "--out-dir",
            str(dist),
            *build_controls,
            str(sdists[0]),
        ],
        cwd=work,
        env=env,
    )
    wheels = list(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one wheel, found {len(wheels)}")
    return sdists[0], wheels[0]


def _smoke_test_wheel(
    wheel: Path,
    runtime_requirements: Path,
    work: Path,
    env: dict[str, str],
) -> None:
    """Install hashed binary dependencies and wheel in a fresh Python 3.11 venv.

    Requires an available 3.11 interpreter; probes packaged assets and offline
    Alembic SQL. Writes under work and propagates installation/probe failures.
    """
    venv = work / "smoke-venv"
    _run(
        ["uv", "venv", "--python", "3.11", "--no-python-downloads", str(venv)],
        cwd=work,
        env=env,
    )
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    _run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "--require-hashes",
            "--no-build",
            "--strict",
            "--requirement",
            str(runtime_requirements),
        ],
        cwd=work,
        env=env,
    )
    _run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "--no-index",
            "--no-deps",
            str(wheel),
        ],
        cwd=work,
        env=env,
    )
    _run(["uv", "pip", "check", "--python", str(python)], cwd=work, env=env)

    defaults = _output([sys.executable, str(PROJECT_ROOT / "scripts/wheel_smoke_env.py")])
    smoke_env = dict(env)
    smoke_env.update(json.loads(defaults))
    probe = work / "smoke_installed_wheel.py"
    shutil.copy2(PROJECT_ROOT / "scripts/smoke_installed_wheel.py", probe)
    _run([str(python), "-I", str(probe)], cwd=work, env=smoke_env)
    _run([str(python), "-I", "-m", "app.migrate", "heads"], cwd=work, env=smoke_env)
    _run(
        [str(python), "-I", "-m", "app.migrate", "upgrade", "head", "--sql"],
        cwd=work,
        env=smoke_env,
    )


def _copy_tree(source: Path, destination: Path) -> None:
    """Copy a tree excluding Python and pytest caches; destination must not exist."""
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
    )


def _write_manifest(payload: Path, *, commit: str, wheel: Path) -> Path:
    """Write release-manifest.json with payload hashes/provenance and return its path."""
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    files = {
        path.relative_to(payload).as_posix(): _sha256(path)
        for path in sorted(payload.rglob("*"))
        if path.is_file() and path.name != "release-manifest.json"
    }
    manifest = {
        "schema_version": 1,
        "source_commit": commit,
        "project_name": project["project"]["name"],
        "project_version": project["project"]["version"],
        "python_series": "3.11",
        "uv_lock_sha256": _sha256(LOCK_FILE),
        "build_requirements_sha256": _sha256(BUILD_REQUIREMENTS),
        "application_wheel": f"wheels/{wheel.name}",
        "files": files,
    }
    destination = payload / "release-manifest.json"
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _stage_payload(
    work: Path,
    *,
    commit: str,
    sdist: Path,
    wheel: Path,
    runtime_requirements: Path,
) -> Path:
    """Copy release assets under work, write and verify the manifest, and return the root."""
    payload = work / f"oralhistarchiv-release-{commit}"
    payload.mkdir()
    (payload / "wheels").mkdir()
    (payload / "provenance").mkdir()
    (payload / "provenance/tools").mkdir()
    (payload / "scripts").mkdir()

    shutil.copy2(wheel, payload / "wheels" / wheel.name)
    shutil.copy2(sdist, payload / "provenance" / sdist.name)
    shutil.copy2(runtime_requirements, payload / "requirements-runtime.txt")
    for name in ("pyproject.toml", "uv.lock", "build-requirements.in", "build-requirements.txt"):
        shutil.copy2(PROJECT_ROOT / name, payload / "provenance" / name)
    shutil.copy2(
        PROJECT_ROOT / ".github/workflows/ci.yml",
        payload / "provenance/ci.yml",
    )
    shutil.copy2(
        PROJECT_ROOT / "scripts/build_release.py",
        payload / "provenance/tools/build_release.py",
    )
    shutil.copy2(
        PROJECT_ROOT / "deploy/install_release.py",
        payload / "provenance/tools/install_release.py",
    )
    for name in (
        "Deployment.md",
        "README.md",
        "gunicorn.conf.py",
        "oralhistarchiv.service",
        "oralhistarchiv-scheduler.service",
        "oralhistarchiv-migrate.service",
        "run_scheduler.py",
    ):
        shutil.copy2(PROJECT_ROOT / name, payload / name)

    _copy_tree(PROJECT_ROOT / "deploy", payload / "deploy")
    _copy_tree(PROJECT_ROOT / "docs", payload / "docs")
    for name in ("README.md", "reencrypt_totp.py", "verify_totp_reencryption.py"):
        shutil.copy2(PROJECT_ROOT / "scripts" / name, payload / "scripts" / name)
    _copy_tree(PROJECT_ROOT / "src/app/static", payload / "src/app/static")
    _write_manifest(payload, commit=commit, wheel=wheel)
    # Validate the assembled artifact with the same consumer used on the host.
    # This runs in PR/wheel-smoke builds as well as the release job.
    spec = importlib.util.spec_from_file_location(
        "release_installer", PROJECT_ROOT / "deploy/install_release.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("release installer module is unavailable")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    installer._verify_payload(payload)
    return payload


def _tar_filter(member: tarfile.TarInfo) -> tarfile.TarInfo:
    """Normalize archive ownership, timestamps and modes in place; return the member."""
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "root"
    member.mtime = 0
    if member.isdir():
        member.mode = 0o755
    elif member.isfile():
        member.mode = 0o755 if member.mode & 0o111 else 0o644
    return member


def _write_archive(payload: Path, output_dir: Path) -> Path:
    """Create output_dir with the tarball, installer and checksum; return the tarball path.

    The directory must not exist; filesystem/archive failures propagate.
    """
    output_dir.mkdir(parents=True, exist_ok=False)
    archive = output_dir / f"{payload.name}.tar.gz"
    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as bundle:
        bundle.add(payload, arcname=payload.name, recursive=True, filter=_tar_filter)

    shutil.copy2(PROJECT_ROOT / "deploy/install_release.py", output_dir / "install_release.py")
    (output_dir / "ARTIFACT.txt").write_text(
        f"{_sha256(archive)}  {archive.name}\n",
        encoding="ascii",
    )
    return archive


def build_release(commit_sha: str, output_dir: Path) -> Path:
    """Build and smoke-test commit_sha, then return the release archive path.

    Requires Python 3.11, uv 0.12.11, matching clean HEAD and a new output_dir.
    Runs build/install subprocesses and may download dependencies. Temporary work
    is removed; a failed archive write can leave output_dir behind. Raises
    ValueError for a malformed SHA, FileExistsError for existing output, and
    RuntimeError for contract failures; file/subprocess errors propagate.
    """
    if sys.version_info[:2] != (3, 11):
        raise RuntimeError("release artifacts must be built with Python 3.11")
    commit = _validate_commit_sha(commit_sha)
    _assert_reviewed_source(commit)
    if output_dir.exists():
        raise FileExistsError(f"release output already exists: {output_dir}")

    env = _clean_environment()
    _assert_uv_version(env)
    with tempfile.TemporaryDirectory(prefix="oha-release-") as temporary:
        work = Path(temporary)
        runtime_requirements = work / "requirements-runtime.txt"
        _export_runtime_requirements(runtime_requirements, env)
        sdist, wheel = _build_distributions(work, env)
        _smoke_test_wheel(wheel, runtime_requirements, work, env)
        payload = _stage_payload(
            work,
            commit=commit,
            sdist=sdist,
            wheel=wheel,
            runtime_requirements=runtime_requirements,
        )
        return _write_archive(payload, output_dir.resolve())


def main() -> None:
    """Parse --commit-sha/--output-dir, build the release and print its archive path."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    archive = build_release(args.commit_sha, args.output_dir)
    print(f"Built reviewed release: {archive}")


if __name__ == "__main__":
    main()

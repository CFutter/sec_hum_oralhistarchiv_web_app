"""Install an authenticated release artifact under /opt/oralhistarchiv-releases.

Run as root with Python 3.11 after independently verifying artifact provenance.
The manifest checks consistency, not authenticity. Installation requires the
provisioned deployment lock, stopped services, and PyPI access for pinned
binary dependencies; it atomically updates /opt/oralhistarchiv.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 - fixed installation commands, never a shell
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

INSTALL_ROOT = Path("/opt/oralhistarchiv-releases")
CURRENT_LINK = Path("/opt/oralhistarchiv")
_TOP_LEVEL_RE = re.compile(r"oralhistarchiv-release-(?P<commit>[0-9a-f]{40})\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ARCHIVE_MEMBERS = 20_000
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
DEPLOYMENT_LOCK = Path("/run/lock/oralhistarchiv-deploy.lock")
_COMPLETE_MARKER = ".installation-complete"
_SERVICES = (
    "oralhistarchiv.service",
    "oralhistarchiv-scheduler.service",
    "oralhistarchiv-migrate.service",
)
_REQUIRED_PAYLOAD_FILES = frozenset(
    {
        "Deployment.md",
        "README.md",
        "docs/runbooks/key-rotation.md",
        "gunicorn.conf.py",
        "oralhistarchiv.service",
        "oralhistarchiv-scheduler.service",
        "oralhistarchiv-migrate.service",
        "deploy/migrate_release.py",
        "deploy/oralhistarchiv-tmpfiles.conf",
        "deploy/bootstrap-database-roles.sql",
        "deploy/database-runtime-grants.sql",
        "deploy/verify-runtime-database-access.sql",
        "deploy/redis-security.conf.example",
        "deploy/oralhistarchiv-rate-limit-redis.service",
        "deploy/nginx.conf.example",
        "deploy/nginx-ordinary-proxy-headers.conf.example",
        "deploy/nginx-shibboleth-phase2.conf.example",
        "deploy/nginx-shibboleth-secret.conf.example",
        "requirements-runtime.txt",
        "run_scheduler.py",
        "src/app/static/css/style.css",
        "provenance/build-requirements.txt",
        "provenance/ci.yml",
        "provenance/pyproject.toml",
        "provenance/tools/build_release.py",
        "provenance/tools/install_release.py",
        "provenance/uv.lock",
    }
)


def _sha256(path: Path) -> str:
    """Stream a file into a lowercase SHA-256 hex digest; file errors propagate."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _member_parts(name: str) -> tuple[str, ...]:
    """Return normalized POSIX path parts; reject empty, absolute or parent paths.

    Raises ValueError; PurePosixPath collapses dot and repeated-separator components.
    """
    path = PurePosixPath(name)
    if not name or path.is_absolute() or not path.parts:
        raise ValueError(f"unsafe archive member path: {name!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe archive member path: {name!r}")
    return path.parts


def _inspect_archive(bundle: tarfile.TarFile) -> tuple[str, list[tarfile.TarInfo]]:
    """Validate one release root, unique regular-file/directory members and size bounds.

    Return (root name, members); raise ValueError for invalid paths, links/special
    files, more than 20,000 members or over 512 MiB of declared file content.
    """
    members = bundle.getmembers()
    if not members or len(members) > _MAX_ARCHIVE_MEMBERS:
        raise ValueError("release archive has an invalid member count")

    names: set[str] = set()
    roots: set[str] = set()
    total_size = 0
    for member in members:
        parts = _member_parts(member.name)
        normalized = PurePosixPath(*parts).as_posix()
        if normalized in names:
            raise ValueError(f"duplicate archive member: {normalized}")
        names.add(normalized)
        roots.add(parts[0])
        if not member.isdir() and not member.isreg():
            raise ValueError(f"archive contains a link or special file: {normalized}")
        if member.isreg():
            total_size += member.size
            if total_size > _MAX_ARCHIVE_BYTES:
                raise ValueError("release archive exceeds the uncompressed byte limit")

    if len(roots) != 1:
        raise ValueError("release archive must contain exactly one top-level directory")
    root = roots.pop()
    if _TOP_LEVEL_RE.fullmatch(root) is None:
        raise ValueError("release archive has an invalid top-level directory")
    return root, members


def _extract_safely(archive: Path, destination: Path) -> Path:
    """Extract validated gzip-tar members with fixed modes and return the release root.

    Destination must be a trusted directory without attacker-controlled symlinks.
    Files use exclusive creation; validation, archive and filesystem errors propagate.
    """
    with tarfile.open(archive, "r:gz") as bundle:
        root_name, members = _inspect_archive(bundle)
        for member in members:
            parts = _member_parts(member.name)
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o755)
                target.chmod(0o755)
                continue

            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError(f"could not read archive member: {member.name}")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)

    return destination / root_name


def _load_manifest(root: Path) -> dict[str, Any]:
    """Read a JSON object from release-manifest.json.

    Raises ValueError for unreadable/malformed content and TypeError for nonobjects.
    """
    manifest_path = root / "release-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("release manifest is missing or malformed") from exc
    if not isinstance(manifest, dict):
        raise TypeError("release manifest must be a JSON object")
    return manifest


def _verify_payload(root: Path) -> dict[str, Any]:
    """Return the manifest after checking release identity, required files and hashes.

    Ignores .venv contents and the completion marker. Raises ValueError for contract
    violations; file errors propagate. Hash agreement does not authenticate the release.
    """
    top_match = _TOP_LEVEL_RE.fullmatch(root.name)
    if top_match is None:
        raise ValueError("release directory name is invalid")

    manifest = _load_manifest(root)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported release-manifest schema")
    if manifest.get("source_commit") != top_match.group("commit"):
        raise ValueError("manifest commit does not match the release directory")
    if manifest.get("python_series") != "3.11":
        raise ValueError("release was not built for the deployed Python series")

    expected = manifest.get("files")
    if not isinstance(expected, dict) or not expected:
        raise ValueError("manifest files map is missing")
    if any(
        not isinstance(name, str)
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
        for name, digest in expected.items()
    ):
        raise ValueError("manifest files map contains an invalid entry")

    actual = {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and path.relative_to(root).as_posix() not in {"release-manifest.json", _COMPLETE_MARKER}
        and ".venv" not in path.relative_to(root).parts
    }
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        changed = sorted(
            name for name in set(actual) & set(expected) if actual[name] != expected[name]
        )
        raise ValueError(
            f"release payload does not match manifest; missing={missing}, "
            f"unexpected={unexpected}, changed={changed}"
        )

    if not set(actual) >= _REQUIRED_PAYLOAD_FILES:
        missing_required = sorted(_REQUIRED_PAYLOAD_FILES - set(actual))
        raise ValueError(f"release payload is incomplete: {missing_required}")

    wheel = manifest.get("application_wheel")
    if not isinstance(wheel, str) or wheel not in actual or not wheel.endswith(".whl"):
        raise ValueError("manifest application_wheel is invalid")
    wheel_files = sorted(
        path.relative_to(root).as_posix() for path in (root / "wheels").glob("*.whl")
    )
    if wheel_files != [wheel]:
        raise ValueError("release must contain exactly the manifested application wheel")
    if manifest.get("uv_lock_sha256") != actual["provenance/uv.lock"]:
        raise ValueError("manifest uv.lock digest is inconsistent")
    if manifest.get("build_requirements_sha256") != actual["provenance/build-requirements.txt"]:
        raise ValueError("manifest build-requirements digest is inconsistent")
    return manifest


def _clean_pip_environment() -> dict[str, str]:
    """Copy the environment without PIP_* or Python-path/venv overrides.

    Disable pip config, version checks and interactive input in the returned copy.
    """
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("PIP_") and name not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"}
    }
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PIP_NO_INPUT"] = "1"
    return env


def _run(args: list[str], *, env: dict[str, str], timeout: int = 900) -> None:
    """Run a checked subprocess with the supplied environment and timeout in seconds.

    OS errors, CalledProcessError and TimeoutExpired propagate.
    """
    subprocess.run(  # nosec B603 - fixed interpreter and pip arguments
        args,
        env=env,
        check=True,
        timeout=timeout,
    )


def _install_python_environment(root: Path, manifest: dict[str, Any]) -> None:
    """Create root/.venv, install pinned PyPI wheels and the app wheel, and verify imports.

    Mutates the release directory and uses network/subprocesses; failures propagate.
    """
    env = _clean_pip_environment()
    venv = root / ".venv"
    _run([sys.executable, "-m", "venv", str(venv)], env=env)
    python = venv / "bin/python"
    pip = [str(python), "-m", "pip"]
    _run(
        [
            *pip,
            "install",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--no-deps",
            "--only-binary=:all:",
            "--require-hashes",
            "--index-url",
            "https://pypi.org/simple",
            "--requirement",
            str(root / "requirements-runtime.txt"),
        ],
        env=env,
    )
    wheel = root / str(manifest["application_wheel"])
    _run(
        [
            *pip,
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--no-deps",
            str(wheel),
        ],
        env=env,
    )
    _run([*pip, "check"], env=env)
    _verify_installed_import(root)


def _verify_installed_import(root: Path) -> None:
    """Assert in an isolated child interpreter that app/config resolve inside root/.venv."""
    _run(
        [
            str(root / ".venv/bin/python"),
            "-I",
            "-c",
            "import importlib.util, sys; from pathlib import Path; "
            "venv = Path(sys.argv[1]).resolve(); "
            "assert Path(sys.prefix).resolve() == venv; "
            "assert all(Path(importlib.util.find_spec(m).origin).resolve().is_relative_to(venv) "
            "for m in ('app', 'config'))",
            str(root / ".venv"),
        ],
        env=_clean_pip_environment(),
        timeout=30,
    )


def _require_services_stopped() -> None:
    """Require web, scheduler and migration services to be inactive or failed.

    Missing units are allowed; unexpected systemctl results raise RuntimeError.
    Subprocess timeout/OS errors propagate.
    """
    for service in _SERVICES:
        result = subprocess.run(  # nosec B603 - fixed systemctl invocation
            ["/usr/bin/systemctl", "show", "--property=LoadState,ActiveState", service],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        state = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        # not-found/inactive is explicitly permitted for first installation.
        if (
            result.returncode != 0
            or state.get("LoadState") not in {"loaded", "not-found"}
            or state.get("ActiveState") not in {"inactive", "failed"}
        ):
            raise RuntimeError(f"stop application services before installation: {service}: {state}")


def install(archive: Path) -> Path:
    """Install archive under a nonblocking exclusive deployment lock; return its release path.

    Requires root, Python 3.11, an existing archive and the provisioned lock file.
    Raises PermissionError, RuntimeError or FileNotFoundError for failed preconditions;
    archive, filesystem and subprocess errors propagate. See the module for effects.
    """
    if os.geteuid() != 0:
        raise PermissionError("run the release installer as root")
    if sys.version_info[:2] != (3, 11):
        raise RuntimeError("run the release installer with Python 3.11")
    if not archive.is_file():
        raise FileNotFoundError(archive)
    # Provision this stable inode with the shipped tmpfiles rule before the
    # first install. Runtime units hold shared locks for their whole lifetime;
    # the migration unit and installers hold exclusive locks.
    with DEPLOYMENT_LOCK.open("rb") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                "deployment lock is held by a runtime or maintenance operation"
            ) from exc
        return _install_locked(archive)


def _prepare_final_release(extracted: Path, manifest: dict[str, Any]) -> Path:
    """Reuse a completed verified release or install extracted at its final path.

    Refuses symlinks/current release; quarantines incomplete prior content. Creates
    the venv and completion marker; a failed new install removes its final directory.
    Returns that directory; verification, filesystem and subprocess failures propagate.
    """
    final = INSTALL_ROOT / extracted.name
    if final.is_symlink():
        raise RuntimeError(f"release directory must not be a symlink: {final}")
    if final.exists():
        if CURRENT_LINK.resolve() == final.resolve():
            raise RuntimeError(f"refusing to replace the current release: {final}")
        if (final / _COMPLETE_MARKER).is_file():
            if _verify_payload(final) != manifest:
                raise ValueError("installed release differs from the requested artifact")
            _verify_installed_import(final)
            return final
        # Keep interrupted content recoverable, without moving a completed venv.
        quarantine = Path(tempfile.mkdtemp(prefix=".incomplete-", dir=INSTALL_ROOT))
        final.replace(quarantine / final.name)
        print(f"Preserved incomplete installation: {quarantine / final.name}")
    extracted.replace(final)
    try:
        # Console-script shebangs require the venv to be built at its final path.
        _install_python_environment(final, manifest)
        _verify_payload(final)
        (final / _COMPLETE_MARKER).write_text(manifest["source_commit"] + "\n", encoding="ascii")
    except BaseException:
        # Cancellation must leave a safely retryable state; never suppress it.
        shutil.rmtree(final, ignore_errors=True)
        raise
    return final


def _install_locked(archive: Path) -> Path:
    """Install and atomically select a release while the caller holds the deployment lock.

    Checks services before installation and selection, removes incoming temporary
    files, and returns the final path. A failed selection may leave a completed
    release available for retry; errors propagate.
    """
    _require_services_stopped()

    if CURRENT_LINK.exists() and not CURRENT_LINK.is_symlink():
        raise RuntimeError(f"{CURRENT_LINK} must be absent or a release symlink")
    if INSTALL_ROOT.exists() and INSTALL_ROOT.is_symlink():
        raise RuntimeError(f"{INSTALL_ROOT} must not be a symlink")
    INSTALL_ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    INSTALL_ROOT.chmod(0o755)

    temporary = Path(tempfile.mkdtemp(prefix=".incoming-", dir=INSTALL_ROOT))
    final: Path | None = None
    try:
        extracted = _extract_safely(archive.resolve(), temporary)
        manifest = _verify_payload(extracted)

        final = _prepare_final_release(extracted, manifest)
        _require_services_stopped()

        temporary_link = CURRENT_LINK.with_name(f".{CURRENT_LINK.name}.new-{os.getpid()}")
        temporary_link.unlink(missing_ok=True)
        try:
            temporary_link.symlink_to(final, target_is_directory=True)
            temporary_link.replace(CURRENT_LINK)
        finally:
            temporary_link.unlink(missing_ok=True)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)

    print(f"Installed source commit: {manifest['source_commit']}")
    if final is None:
        raise RuntimeError("installation completed without a verified release")
    print(f"Current release: {final}")
    return final


def main() -> None:
    """Install the positional archive with umask 022, restoring the previous mask afterward."""
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    old_umask = os.umask(0o022)
    try:
        install(args.archive)
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    main()

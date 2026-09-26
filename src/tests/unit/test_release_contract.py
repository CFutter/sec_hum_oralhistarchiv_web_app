"""Executable contract for the reviewed, hash-locked production release path.

Covers `scripts/build_release.py` (constrained, hash-verified build of the
sdist/wheel and the release manifest) and `deploy/install_release.py` (safe
extraction, manifest verification and the atomic host install), plus the
deployment artifacts (systemd units, nginx config, the deployment runbook)
that the release is installed against.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import tarfile
import tomllib
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from app.paths import PROJECT_ROOT

CI_WORKFLOW = PROJECT_ROOT / ".github/workflows/ci.yml"
DEPLOYMENT_RUNBOOK = PROJECT_ROOT / "Deployment.md"
WEB_UNIT = PROJECT_ROOT / "oralhistarchiv.service"
SCHEDULER_UNIT = PROJECT_ROOT / "oralhistarchiv-scheduler.service"
NGINX_CONFIG = PROJECT_ROOT / "deploy/nginx.conf.example"
INSTALLER_PATH = PROJECT_ROOT / "deploy/install_release.py"
BUILD_REQUIREMENTS = PROJECT_ROOT / "build-requirements.txt"
BUILD_RELEASE_PATH = PROJECT_ROOT / "scripts/build_release.py"

_REMOTE_ACTION = re.compile(r"(?m)^\s*-?\s*uses:\s*(?P<reference>[^#\s]+)")
_FULL_ACTION_SHA = re.compile(r"[^@\s]+@[0-9a-f]{40}\Z")


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_release = _load_module("build_release", BUILD_RELEASE_PATH)
install_release = _load_module("install_release", INSTALLER_PATH)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_valid_payload(parent: Path, commit: str = "a" * 40) -> tuple[Path, dict[str, Any]]:
    root = parent / f"oralhistarchiv-release-{commit}"
    required = set(install_release._REQUIRED_PAYLOAD_FILES)
    required.add("wheels/oral_history_archive-0.1.0-py3-none-any.whl")
    for relative in sorted(required):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"payload:{relative}\n", encoding="utf-8")

    files = {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    manifest = {
        "schema_version": 1,
        "source_commit": commit,
        "project_name": "Oral-History-Archive",
        "project_version": "0.1.0",
        "python_series": "3.11",
        "uv_lock_sha256": files["provenance/uv.lock"],
        "build_requirements_sha256": files["provenance/build-requirements.txt"],
        "application_wheel": "wheels/oral_history_archive-0.1.0-py3-none-any.whl",
        "files": files,
    }
    (root / "release-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True),
        encoding="utf-8",
    )
    return root, manifest


class TestReleaseBuildContract:
    """`scripts/build_release.py` builds a constrained, hash-verified sdist/wheel."""

    def test_build_backend_is_exactly_pinned_and_hash_constrained(self):
        project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        assert project["build-system"] == {
            "requires": ["hatchling==1.32.0"],
            "build-backend": "hatchling.build",
        }
        assert (PROJECT_ROOT / "build-requirements.in").read_text(encoding="utf-8").strip() == (
            "hatchling==1.32.0"
        )

        locked = BUILD_REQUIREMENTS.read_text(encoding="utf-8")
        blocks = re.split(r"(?m)(?=^[A-Za-z0-9][A-Za-z0-9._-]*==)", locked)
        requirement_blocks = [block for block in blocks if re.match(r"^[A-Za-z0-9]", block)]
        assert len(requirement_blocks) == 6
        assert all(
            re.search(r"--hash=sha256:[0-9a-f]{64}\b", block) for block in requirement_blocks
        )

    def test_runtime_export_validator_rejects_unhashed_editable_and_dev_inputs(self):
        digest = "1" * 64
        build_release._validate_runtime_export(f"requests==2.33.0 \\\n    --hash=sha256:{digest}\n")

        with pytest.raises(RuntimeError, match="no SHA-256"):
            build_release._validate_runtime_export("requests==2.33.0\n")
        with pytest.raises(RuntimeError, match="editable or local-path"):
            build_release._validate_runtime_export(
                f"-e file:///checkout \\\n    --hash=sha256:{digest}\n"
            )
        with pytest.raises(RuntimeError, match="development/build packages"):
            build_release._validate_runtime_export(
                f"pytest==9.0.3 \\\n    --hash=sha256:{digest}\n"
            )

    def test_release_builder_requires_the_reviewed_uv_version(self, monkeypatch):
        monkeypatch.setattr(build_release, "_output", lambda *_args, **_kwargs: "uv 0.12.11")
        build_release._assert_uv_version({})

        monkeypatch.setattr(build_release, "_output", lambda *_args, **_kwargs: "uv 0.12.12")
        with pytest.raises(RuntimeError, match=r"requires uv 0\.12\.11"):
            build_release._assert_uv_version({})

    def test_distribution_build_constrains_and_hash_verifies_both_builds(
        self, tmp_path, monkeypatch
    ):
        calls: list[list[str]] = []

        def fake_run(args, **_kwargs):
            calls.append(args)
            output = Path(args[args.index("--out-dir") + 1])
            if "--sdist" in args:
                (output / "oral_history_archive-0.1.0.tar.gz").write_bytes(b"sdist")
            else:
                (output / "oral_history_archive-0.1.0-py3-none-any.whl").write_bytes(b"wheel")

        monkeypatch.setattr(build_release, "_run", fake_run)
        sdist, wheel = build_release._build_distributions(tmp_path, {})

        assert sdist.name.endswith(".tar.gz")
        assert wheel.name.endswith(".whl")
        assert len(calls) == 2
        for command in calls:
            assert command[0:2] == ["uv", "build"]
            assert "--build-constraints" in command
            assert str(BUILD_REQUIREMENTS) in command
            assert "--require-hashes" in command
            assert "--no-sources" in command
        assert str(sdist) == calls[1][-1]

    def test_manifest_hashes_every_payload_file(self, tmp_path, monkeypatch):
        project_root = tmp_path / "project"
        project_root.mkdir()
        (project_root / "pyproject.toml").write_text(
            '[project]\nname="Oral-History-Archive"\nversion="0.1.0"\n',
            encoding="utf-8",
        )
        lock = project_root / "uv.lock"
        lock.write_text("version = 1\n", encoding="utf-8")
        build = project_root / "build-requirements.txt"
        build.write_text("hatchling==1.32.0\n", encoding="utf-8")
        payload = tmp_path / f"oralhistarchiv-release-{'b' * 40}"
        wheel = payload / "wheels/app.whl"
        wheel.parent.mkdir(parents=True)
        wheel.write_bytes(b"wheel")
        (payload / "runtime.txt").write_text("runtime\n", encoding="utf-8")

        monkeypatch.setattr(build_release, "PROJECT_ROOT", project_root)
        monkeypatch.setattr(build_release, "LOCK_FILE", lock)
        monkeypatch.setattr(build_release, "BUILD_REQUIREMENTS", build)
        manifest_path = build_release._write_manifest(payload, commit="b" * 40, wheel=wheel)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        assert manifest["source_commit"] == "b" * 40
        assert manifest["files"] == {
            "runtime.txt": _sha256(payload / "runtime.txt"),
            "wheels/app.whl": _sha256(wheel),
        }
        assert manifest["uv_lock_sha256"] == _sha256(lock)
        assert manifest["build_requirements_sha256"] == _sha256(build)


class TestWheelPackagingIncludesRotationAssets:
    """The wheel's packaging configuration cannot silently drop the TOTP
    rotation templates or the initial migration: `packages` names the whole
    `src/app` tree with no `exclude`, and hatchling's default wheel file
    selection is git-tracked-file based, so anything the repository tracks
    under a packaged directory ships. Actually building and installing the
    wheel to render the pages is out of scope for the unit tier (`hatchling`
    is a build-time-only dependency, not installed in this environment) —
    covered instead by `scripts/smoke_installed_wheel.py` in CI.
    """

    def test_wheel_target_declares_no_excludes_that_could_drop_a_template(self):
        project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        wheel_target = project["tool"]["hatch"]["build"]["targets"]["wheel"]
        assert wheel_target["packages"] == ["src/app", "src/config"]
        assert "exclude" not in wheel_target
        assert "exclude" not in project["tool"]["hatch"]["build"]

    def test_rotation_templates_are_tracked_under_the_packaged_app_directory(self):
        for name in ("reset_totp.html", "reset_totp_confirm.html"):
            template = PROJECT_ROOT / "src" / "app" / "templates" / name
            assert template.is_file(), f"{name} is missing from the source tree"
            tracked = subprocess.run(
                ["git", "ls-files", "--error-unmatch", str(template)],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            assert tracked.returncode == 0, (
                f"{name} is not git-tracked, so hatchling's default wheel file "
                f"selection would drop it: {tracked.stderr}"
            )


class TestReleaseInstallContract:
    """`deploy/install_release.py` only ever installs a verified, unmodified payload."""

    def test_installer_rejects_archive_traversal_and_links(self, tmp_path):
        traversal = tmp_path / "traversal.tar.gz"
        with tarfile.open(traversal, "w:gz") as bundle:
            member = tarfile.TarInfo(f"oralhistarchiv-release-{'c' * 40}/../../escaped")
            member.size = 1
            bundle.addfile(member, io.BytesIO(b"x"))
        with pytest.raises(ValueError, match="unsafe archive member path"):
            install_release._extract_safely(traversal, tmp_path / "traversal-output")

        linked = tmp_path / "linked.tar.gz"
        with tarfile.open(linked, "w:gz") as bundle:
            member = tarfile.TarInfo(f"oralhistarchiv-release-{'c' * 40}/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/shadow"
            bundle.addfile(member)
        with pytest.raises(ValueError, match="link or special file"):
            install_release._extract_safely(linked, tmp_path / "link-output")

    def test_installer_manifest_detects_changed_and_unexpected_files(self, tmp_path):
        root, manifest = _write_valid_payload(tmp_path)
        assert install_release._verify_payload(root) == manifest

        target = root / "run_scheduler.py"
        target.write_text("tampered\n", encoding="utf-8")
        with pytest.raises(ValueError, match=r"changed=\['run_scheduler.py'\]"):
            install_release._verify_payload(root)

        target.write_text("payload:run_scheduler.py\n", encoding="utf-8")
        (root / "unexpected.py").write_text("unexpected\n", encoding="utf-8")
        with pytest.raises(ValueError, match=r"unexpected=\['unexpected.py'\]"):
            install_release._verify_payload(root)

    def test_host_install_uses_only_hashed_binary_runtime_and_manifested_wheel(
        self, tmp_path, monkeypatch
    ):
        root, manifest = _write_valid_payload(tmp_path)
        calls: list[list[str]] = []
        monkeypatch.setattr(install_release, "_run", lambda args, **_kwargs: calls.append(args))

        install_release._install_python_environment(root, manifest)

        assert len(calls) == 5
        runtime_install = calls[1]
        assert "--require-hashes" in runtime_install
        assert "--no-deps" in runtime_install
        assert "--only-binary=:all:" in runtime_install
        assert "--no-cache-dir" in runtime_install
        assert "https://pypi.org/simple" in runtime_install
        wheel_install = calls[2]
        assert "--no-index" in wheel_install
        assert "--no-deps" in wheel_install
        assert str(root / manifest["application_wheel"]) == wheel_install[-1]
        assert calls[3][-1] == "check"
        assert calls[4][1:3] == ["-I", "-c"]

    def test_installer_builds_the_venv_at_its_final_absolute_path_before_switching(self):
        source = INSTALLER_PATH.read_text(encoding="utf-8")
        move = source.index("extracted.replace(final)")
        install = source.index("_install_python_environment(final, manifest)")
        switch = source.index("temporary_link.symlink_to(final")

        assert move < install < switch
        assert "_install_python_environment(extracted" not in source

    @pytest.mark.parametrize(
        "name",
        ["PIP_TARGET", "PIP_PREFIX", "PIP_USER", "PIP_ROOT", "PYTHONPATH", "PYTHONHOME"],
        ids=[
            "pip_target",
            "pip_prefix",
            "pip_user",
            "pip_root",
            "pythonpath",
            "pythonhome",
        ],
    )
    def test_installer_neutralizes_inherited_install_destinations(self, monkeypatch, name):
        """A host-environment variable that could redirect pip's install
        destination (inherited from whatever shell invoked the installer)
        must never survive into the environment the installer builds for
        its own pip invocations."""
        monkeypatch.setenv(name, "/unexpected/location")
        assert name not in install_release._clean_pip_environment()

    @pytest.mark.parametrize(
        "returncode,output",
        [
            (1, ""),
            (0, ""),
            (0, "LoadState=loaded\nActiveState=activating"),
            (0, "LoadState=error\nActiveState=inactive"),
        ],
        ids=[
            "systemctl_call_failed",
            "empty_status_output",
            "service_still_activating",
            "service_in_error_state",
        ],
    )
    def test_installer_fails_closed_on_unknown_or_running_service_state(
        self, monkeypatch, returncode, output
    ):
        """Any service state the installer cannot positively confirm as
        stopped — a failed systemctl call, unparseable output, or a service
        still activating/erroring — refuses the install rather than risking
        an in-place upgrade of a running process."""
        monkeypatch.setattr(
            install_release.subprocess,
            "run",
            lambda *a, **_k: subprocess.CompletedProcess(a, returncode, output),
        )
        with pytest.raises(RuntimeError, match="stop application services"):
            install_release._require_services_stopped()

    def test_installer_cannot_enter_while_shared_runtime_lock_is_held(self, tmp_path, monkeypatch):
        """A concurrent installer already holding the deployment lock (even
        just a shared read lock) blocks a second install from starting, so
        two installs can never race over the same release directory."""
        lock_path = tmp_path / "deploy.lock"
        lock_path.touch()
        archive = tmp_path / "artifact.tar.gz"
        archive.touch()
        monkeypatch.setattr(install_release, "DEPLOYMENT_LOCK", lock_path)
        monkeypatch.setattr(install_release.os, "geteuid", lambda: 0)
        with lock_path.open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with pytest.raises(RuntimeError, match="deployment lock"):
                install_release.install(archive)

    def test_interrupted_install_is_retryable_without_changing_current_release(
        self, tmp_path, monkeypatch
    ):
        """An install interrupted (e.g. KeyboardInterrupt) while staging the
        final release directory leaves the currently-live release symlink
        untouched and removes the half-built directory, so the operator can
        simply retry."""
        install_root = tmp_path / "releases"
        install_root.mkdir()
        incoming = tmp_path / "incoming"
        incoming.mkdir()
        extracted, manifest = _write_valid_payload(incoming)
        current = tmp_path / "current"
        previous = install_root / "previous"
        previous.mkdir()
        current.symlink_to(previous)
        monkeypatch.setattr(install_release, "INSTALL_ROOT", install_root)
        monkeypatch.setattr(install_release, "CURRENT_LINK", current)
        with (
            patch.object(
                install_release, "_install_python_environment", side_effect=KeyboardInterrupt
            ),
            pytest.raises(KeyboardInterrupt),
        ):
            install_release._prepare_final_release(extracted, manifest)
        assert current.resolve() == previous
        assert not (install_root / extracted.name).exists()

    def test_stale_partial_release_is_quarantined_then_replaced(self, tmp_path, monkeypatch):
        """A half-built release directory left behind by a previous
        interrupted install (no completion marker) is moved aside into a
        quarantine directory rather than reused, and the retry builds a
        fresh, complete release in its place."""
        install_root = tmp_path / "releases"
        install_root.mkdir()
        incoming = tmp_path / "incoming"
        incoming.mkdir()
        extracted, manifest = _write_valid_payload(incoming)
        partial = install_root / extracted.name
        partial.mkdir()
        (partial / "interrupted").touch()
        monkeypatch.setattr(install_release, "INSTALL_ROOT", install_root)
        monkeypatch.setattr(install_release, "CURRENT_LINK", tmp_path / "current")
        with patch.object(install_release, "_install_python_environment"):
            final = install_release._prepare_final_release(extracted, manifest)
        assert (final / install_release._COMPLETE_MARKER).is_file()
        assert len(list(install_root.glob(".incomplete-*/**/interrupted"))) == 1

    def test_real_release_staging_contains_the_installer_inventory(self, tmp_path):
        """A release staged by the real `build_release._stage_payload` (not a
        hand-written fixture) passes the installer's own manifest
        verification and includes the systemd unit the installer inventory
        requires — the build and install sides of the contract agree on the
        payload shape end to end."""
        wheel = tmp_path / "oral_history_archive-0.1.0-py3-none-any.whl"
        sdist = tmp_path / "oral_history_archive-0.1.0.tar.gz"
        requirements = tmp_path / "requirements.txt"
        wheel.write_bytes(b"test-wheel")
        sdist.write_bytes(b"test-sdist")
        requirements.write_text("", encoding="utf-8")
        payload = build_release._stage_payload(
            tmp_path, commit="a" * 40, sdist=sdist, wheel=wheel, runtime_requirements=requirements
        )
        install_release._verify_payload(payload)
        assert (payload / "oralhistarchiv-migrate.service").is_file()


class TestReleaseDeploymentArtifacts:
    """The published artifacts (CI gate, systemd units, nginx, runbook) match the install path."""

    def test_ci_release_is_main_only_gate_complete_and_digest_published(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        assert (
            "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"
            in workflow
        )
        assert (
            "needs: [lint, opaque-references, typecheck, security, wheel-smoke, tests]" in workflow
        )
        assert "python scripts/build_release.py" in workflow
        assert '--commit-sha "$GITHUB_SHA"' in workflow
        assert "steps.upload_release.outputs.artifact-digest" in workflow
        assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
        assert workflow.count('version: "0.12.11"') == 6

        references = _REMOTE_ACTION.findall(workflow)
        assert references
        assert all(_FULL_ACTION_SHA.fullmatch(reference) for reference in references)

    def test_production_units_import_only_from_the_release_venv(self):
        web = WEB_UNIT.read_text(encoding="utf-8")
        scheduler = SCHEDULER_UNIT.read_text(encoding="utf-8")
        for unit in (web, scheduler):
            assert "WorkingDirectory=/opt/oralhistarchiv\n" in unit
            assert "UnsetEnvironment=PYTHONPATH PYTHONHOME VIRTUAL_ENV" in unit
            assert "PYTHONPATH=/opt/oralhistarchiv" not in unit
        assert "app.migrate" not in web
        assert "migrate_release" not in web
        assert (
            "/opt/oralhistarchiv/.venv/bin/python -I /opt/oralhistarchiv/run_scheduler.py"
            in scheduler
        )
        assert "alias /opt/oralhistarchiv/src/app/static/;" in NGINX_CONFIG.read_text(
            encoding="utf-8"
        )

    def test_runbook_has_no_source_or_editable_production_install_path(self):
        runbook = DEPLOYMENT_RUNBOOK.read_text(encoding="utf-8")
        forbidden = ("git clone", "git pull", "pip install -e", ".[dev]")
        assert all(value not in runbook for value in forbidden)
        for required in (
            "Approved GitHub artifact SHA-256",
            "sha256sum --check --strict",
            "install_release.py",
            "`--require-hashes`",
            "`--no-deps`",
            "--only-binary=:all:",
            "root:root 755",
        ):
            assert required in runbook

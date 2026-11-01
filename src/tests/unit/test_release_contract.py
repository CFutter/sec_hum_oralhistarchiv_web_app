"""Executable contract for the reviewed, hash-locked production release path."""

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
from importlib import metadata
from pathlib import Path
from typing import Any
from unittest.mock import create_autospec, patch

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
_LICENSE_PATHS = (
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "src/app/static/fonts/OFL.txt",
    "src/app/services/data/SECLISTS-LICENSE.txt",
)
_PARSER_AND_MAINTENANCE_PATHS = (
    "oralhistarchiv-parser.socket",
    "oralhistarchiv-parser@.service",
    "run_parser.py",
    "scripts/rebuild_search_policy.py",
    "scripts/bootstrap_admin.py",
    "scripts/acknowledge_source_binding.py",
    "scripts/export_security_audit.py",
    "deploy/invalidate-action-email-capabilities.sql",
)

_REMOTE_ACTION = re.compile(r"(?m)^\s*-?\s*uses:\s*(?P<reference>[^#\s]+)")
_FULL_ACTION_SHA = re.compile(r"[^@\s]+@[0-9a-f]{40}\Z")


def _load_module(name: str, path: Path):
    """Load and execute the selected repository script in an isolated module."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_release = _load_module("build_release", BUILD_RELEASE_PATH)
install_release = _load_module("install_release", INSTALLER_PATH)
smoke_installed_wheel = _load_module(
    "smoke_installed_wheel", PROJECT_ROOT / "scripts/smoke_installed_wheel.py"
)


def _sha256(path: Path) -> str:
    """Return the SHA-256 hexadecimal digest of file bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def installed_licenses(tmp_path, monkeypatch):
    """Write a synthetic installed distribution and redirect license discovery to it."""
    installed = tmp_path / "site-packages"
    dist_info = installed / "oral_history_archive-0.1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.4\n"
        "Name: Oral-History-Archive\n"
        "Version: 0.1.0\n"
        "License-Expression: MIT AND OFL-1.1\n"
        + "".join(f"License-File: {relative}\n" for relative in _LICENSE_PATHS),
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text(
        "".join(f"{dist_info.name}/licenses/{relative},,\n" for relative in _LICENSE_PATHS),
        encoding="utf-8",
    )
    for relative in _LICENSE_PATHS:
        notice = dist_info / "licenses" / relative
        notice.parent.mkdir(parents=True, exist_ok=True)
        notice.write_text(f"License text for {relative}\n", encoding="utf-8")
    for relative in ("static/fonts/OFL.txt", "services/data/SECLISTS-LICENSE.txt"):
        notice = installed / "app" / relative
        notice.parent.mkdir(parents=True, exist_ok=True)
        notice.write_text(f"Packaged notice for {relative}\n", encoding="utf-8")

    monkeypatch.setattr(
        smoke_installed_wheel.metadata,
        "distribution",
        lambda _name: metadata.PathDistribution(dist_info),
    )
    monkeypatch.setattr(smoke_installed_wheel.resources, "files", lambda _name: installed / "app")
    return installed, dist_info


class TestInstalledWheelLicenses:
    """Installed license metadata must identify complete, readable shipped notices."""

    def test_complete_installed_licenses_pass(self, installed_licenses):
        """Check complete installed licenses pass."""
        installed, _ = installed_licenses
        smoke_installed_wheel._validate_installed_licenses(installed)

    @pytest.mark.parametrize(
        ("failure", "message"),
        [
            ("expression", "License-Expression must be MIT AND OFL-1.1"),
            ("metadata-record", "unexpected distribution License-File records"),
            ("wheel-record", "distribution license file is not recorded: LICENSE"),
            ("missing-license", "distribution license file is missing: LICENSE"),
            ("empty-license", "distribution license file is empty: LICENSE"),
            ("missing-notice", "packaged license notice is missing: static/fonts/OFL.txt"),
            ("empty-notice", "packaged license notice is empty: static/fonts/OFL.txt"),
        ],
    )
    def test_incomplete_installed_licenses_fail(self, installed_licenses, failure, message):
        """Check incomplete installed licenses fail (RuntimeError)."""
        installed, dist_info = installed_licenses
        if failure in {"expression", "metadata-record"}:
            path = dist_info / "METADATA"
            content = path.read_text(encoding="utf-8")
            if failure == "expression":
                content = content.replace("MIT AND OFL-1.1", "MIT")
            else:
                content = content.replace("License-File: LICENSE\n", "")
            path.write_text(content, encoding="utf-8")
        elif failure == "wheel-record":
            path = dist_info / "RECORD"
            content = path.read_text(encoding="utf-8")
            path.write_text(
                content.replace(f"{dist_info.name}/licenses/LICENSE,,\n", ""),
                encoding="utf-8",
            )
        else:
            path = (
                installed / "app/static/fonts/OFL.txt"
                if failure.endswith("notice")
                else dist_info / "licenses/LICENSE"
            )
            if failure.startswith("missing"):
                path.unlink()
            else:
                path.write_text(" \n", encoding="utf-8")

        with pytest.raises(RuntimeError, match=re.escape(message)):
            smoke_installed_wheel._validate_installed_licenses(installed)


def _write_valid_payload(parent: Path, commit: str = "a" * 40) -> tuple[Path, dict[str, Any]]:
    """Write a complete synthetic release payload and manifest; return both."""
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
        """Check build backend is exactly pinned and hash constrained."""
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

    def test_wheel_smoke_environment_overrides_ambient_source_selection(self, monkeypatch):
        """Check wheel smoke environment overrides ambient source selection."""
        monkeypatch.setenv("SOURCES_CONFIG_FILE", "/ambient/production-sources.toml")
        monkeypatch.setenv("ALLOW_FIXTURE_SOURCE", "true")
        smoke_env = _load_module(
            "wheel_smoke_env", PROJECT_ROOT / "scripts/wheel_smoke_env.py"
        ).smoke_environment()

        assert smoke_env["SOURCES_CONFIG_FILE"] == ""
        assert smoke_env["ALLOW_FIXTURE_SOURCE"] == "false"

    def test_runtime_export_validator_rejects_unhashed_editable_and_dev_inputs(self):
        """Check runtime export validator rejects unhashed editable and dev inputs (RuntimeError)."""
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
        """Check release builder requires the reviewed uv version (RuntimeError)."""
        monkeypatch.setattr(build_release, "_output", lambda *_args, **_kwargs: "uv 0.12.11")
        build_release._assert_uv_version({})

        monkeypatch.setattr(build_release, "_output", lambda *_args, **_kwargs: "uv 0.12.12")
        with pytest.raises(RuntimeError, match=r"requires uv 0\.12\.11"):
            build_release._assert_uv_version({})

    def test_distribution_build_constrains_and_hash_verifies_both_builds(
        self, tmp_path, monkeypatch
    ):
        """Check distribution build constrains and hash verifies both builds."""
        calls: list[list[str]] = []

        def fake_run(args, **_kwargs):
            """Capture build arguments and write a stand-in sdist or wheel into the requested output
            directory.
            """
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
        """Check manifest hashes every payload file."""
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

    @pytest.mark.parametrize("uppercase", [True, False], ids=["uppercase", "lowercase"])
    def test_wheel_smoke_probes_exclude_retired_source_settings(
        self, tmp_path: Path, uppercase: bool
    ) -> None:
        """Check wheel smoke probes exclude retired source settings."""
        source_keys = (
            "SWISSUBASE_OAI_PMH_URL",
            "OAI_INSTITUTION_FILTER",
            "SWISSUBASE_MAX_VISIBILITY",
            "SYNC_INTERVAL_SECONDS",
            "FULL_REBUILD_INTERVAL_SECONDS",
            "OAI_MAX_PAGES",
            "SYNC_WRITE_TIMEOUT_SECONDS",
        )
        retired_keys = {"SEED_MOCK_DATA", *source_keys}
        smoke_defaults = _load_module(
            "wheel_smoke_env_retired_source_settings",
            PROJECT_ROOT / "scripts/wheel_smoke_env.py",
        ).smoke_environment()
        assert not {name.upper() for name in smoke_defaults} & retired_keys

        inherited = {
            (name if uppercase else name.lower()): "retired-source-canary" for name in source_keys
        }
        inherited.update(
            {
                "SOURCES_CONFIG_FILE": "/ambient/production-sources.toml",
                "ALLOW_FIXTURE_SOURCE": "true",
                "SMOKE_ENV_SENTINEL": "excluded",
            }
        )
        original = inherited.copy()
        work = tmp_path / "work"
        work.mkdir()
        wheel = tmp_path / "application.whl"
        wheel.write_bytes(b"dummy wheel")
        requirements = tmp_path / "requirements-runtime.txt"
        requirements.write_text("", encoding="utf-8")

        with (
            patch.object(
                build_release,
                "_output",
                autospec=True,
                return_value=json.dumps(smoke_defaults),
            ),
            patch.object(build_release, "_run", autospec=True) as run,
        ):
            build_release._smoke_test_wheel(wheel, requirements, work, inherited)

        probes = [call for call in run.call_args_list if call.args[0][1:2] == ["-I"]]
        assert [call.args[0][1:] for call in probes] == [
            ["-I", str(work / "smoke_installed_wheel.py")],
            ["-I", "-m", "app.migrate", "heads"],
            ["-I", "-m", "app.migrate", "upgrade", "head", "--sql"],
        ]
        for call in probes:
            child_env = call.kwargs["env"]
            assert not {name.upper() for name in child_env} & retired_keys
            assert child_env["SOURCES_CONFIG_FILE"] == ""
            assert child_env["ALLOW_FIXTURE_SOURCE"] == "false"
            assert "SMOKE_ENV_SENTINEL" not in child_env
        assert inherited == original


class TestWheelPackagingIncludesRotationAssets:
    """Cover wheel packaging includes rotation assets."""

    def test_wheel_target_declares_no_excludes_that_could_drop_a_template(self):
        """Check wheel target declares no excludes that could drop a template."""
        project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        wheel_target = project["tool"]["hatch"]["build"]["targets"]["wheel"]
        assert wheel_target["packages"] == ["src/app", "src/config"]
        assert "exclude" not in wheel_target
        assert "exclude" not in project["tool"]["hatch"]["build"]

    def test_rotation_templates_are_tracked_under_the_packaged_app_directory(self):
        """Check rotation templates are tracked under the packaged app directory."""
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
        """Check installer rejects archive traversal and links (ValueError)."""
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
        """Check installer manifest detects changed and unexpected files (ValueError)."""
        root, manifest = _write_valid_payload(tmp_path)
        assert install_release.verify_payload(root) == manifest

        target = root / "run_scheduler.py"
        target.write_text("tampered\n", encoding="utf-8")
        with pytest.raises(ValueError, match=r"changed=\['run_scheduler.py'\]"):
            install_release.verify_payload(root)

        target.write_text("payload:run_scheduler.py\n", encoding="utf-8")
        (root / "unexpected.py").write_text("unexpected\n", encoding="utf-8")
        with pytest.raises(ValueError, match=r"unexpected=\['unexpected.py'\]"):
            install_release.verify_payload(root)

    @pytest.mark.parametrize("nested", [False, True], ids=["root", "nested"])
    @pytest.mark.parametrize("directory", [False, True], ids=["file", "directory"])
    def test_incoming_archives_cannot_supply_virtual_environment_content(
        self, tmp_path, nested, directory
    ):
        """Check incoming archives cannot supply virtual environment content (ValueError)."""
        archive = tmp_path / "environment.tar.gz"
        prefix = "support/" if nested else ""
        suffix = "" if directory else "/lib/python3.11/site-packages/startup.pth"
        with tarfile.open(archive, "w:gz") as bundle:
            member = tarfile.TarInfo(f"oralhistarchiv-release-{'c' * 40}/{prefix}.venv{suffix}")
            if directory:
                member.type = tarfile.DIRTYPE
                bundle.addfile(member)
            else:
                member.size = 1
                bundle.addfile(member, io.BytesIO(b"x"))
        with pytest.raises(ValueError, match="must not contain virtual environments"):
            install_release._extract_safely(archive, tmp_path / "output")
        assert not (tmp_path / "output").exists()

    @pytest.mark.parametrize("relative", [".venv/startup.pth", "support/.venv/startup.pth"])
    @pytest.mark.parametrize("manifested", [False, True])
    def test_incoming_payload_rejects_environment_content_even_when_manifested(
        self, tmp_path, relative, manifested
    ):
        """Check incoming payload rejects environment content even when manifested (ValueError)."""
        root, manifest = _write_valid_payload(tmp_path)
        target = root / relative
        target.parent.mkdir(parents=True)
        target.write_text("startup contamination", encoding="utf-8")
        if manifested:
            manifest["files"][relative] = _sha256(target)
            (root / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with pytest.raises(ValueError, match="virtual environment"):
            install_release.verify_payload(root)

    def test_completed_release_exempts_only_its_generated_root_environment(self, tmp_path):
        """Check completed release exempts only its generated root environment (ValueError)."""
        root, manifest = _write_valid_payload(tmp_path)
        generated = root / ".venv/bin/python"
        generated.parent.mkdir(parents=True)
        generated.write_text("installer-owned interpreter", encoding="utf-8")
        assert install_release.verify_payload(root, generated_environment=True) == manifest
        nested = root / "support/.venv"
        nested.mkdir(parents=True)
        with pytest.raises(ValueError, match="unexpected virtual environment"):
            install_release.verify_payload(root, generated_environment=True)

    @pytest.mark.parametrize("symlink", [False, True], ids=["existing", "broken-symlink"])
    def test_environment_creation_refuses_preexisting_paths_before_running_python(
        self, tmp_path, monkeypatch, symlink
    ):
        """Check environment creation refuses preexisting paths before running python (ValueError)."""
        root, manifest = _write_valid_payload(tmp_path)
        environment = root / ".venv"
        if symlink:
            environment.symlink_to(tmp_path / "missing-environment")
        else:
            environment.mkdir()
            (environment / "startup.pth").write_text("must not execute", encoding="utf-8")
        run = create_autospec(install_release._run)
        monkeypatch.setattr(install_release, "_run", run)
        with pytest.raises(ValueError, match="absent virtual environment"):
            install_release._install_python_environment(root, manifest)
        run.assert_not_called()

    @pytest.mark.parametrize("relative", _PARSER_AND_MAINTENANCE_PATHS)
    def test_installer_requires_parser_and_maintenance_assets_even_if_manifest_omits_them(
        self, tmp_path, relative
    ):
        """Check installer requires parser and maintenance assets even if manifest omits them
        (ValueError).
        """
        root, manifest = _write_valid_payload(tmp_path)
        (root / relative).unlink()
        del manifest["files"][relative]
        (root / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        with pytest.raises(ValueError, match="release payload is incomplete"):
            install_release.verify_payload(root)

    def test_host_install_uses_only_hashed_binary_runtime_and_manifested_wheel(
        self, tmp_path, monkeypatch
    ):
        """Check host install uses only hashed binary runtime and manifested wheel."""
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
        """Check installer builds the venv at its final absolute path before switching."""
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
        """Check installer neutralizes inherited install destinations."""
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
        """Check installer fails closed on unknown or running service state (RuntimeError)."""
        monkeypatch.setattr(
            install_release.subprocess,
            "run",
            lambda *a, **_k: subprocess.CompletedProcess(a, returncode, output),
        )
        with pytest.raises(RuntimeError, match="stop application services"):
            install_release._require_services_stopped()

    def test_installer_cannot_enter_while_shared_runtime_lock_is_held(self, tmp_path, monkeypatch):
        """Check installer cannot enter while shared runtime lock is held (RuntimeError)."""
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
        """An install interrupted (e.g."""
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
        """Check stale partial release is quarantined then replaced."""
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
        """Check real release staging contains the installer inventory."""
        wheel = tmp_path / "oral_history_archive-0.1.0-py3-none-any.whl"
        sdist = tmp_path / "oral_history_archive-0.1.0.tar.gz"
        requirements = tmp_path / "requirements.txt"
        wheel.write_bytes(b"test-wheel")
        sdist.write_bytes(b"test-sdist")
        requirements.write_text("", encoding="utf-8")
        payload = build_release._stage_payload(
            tmp_path, commit="a" * 40, sdist=sdist, wheel=wheel, runtime_requirements=requirements
        )
        manifest = install_release.verify_payload(payload)
        assert (payload / "oralhistarchiv-migrate.service").is_file()
        for relative in (*_LICENSE_PATHS, *_PARSER_AND_MAINTENANCE_PATHS):
            assert (payload / relative).read_bytes() == (PROJECT_ROOT / relative).read_bytes()
            assert manifest["files"][relative] == _sha256(PROJECT_ROOT / relative)


class TestReleaseDeploymentArtifacts:
    """The published artifacts (CI gate, systemd units, nginx, runbook) match the install path."""

    def test_ci_release_is_main_only_gate_complete_and_digest_published(self) -> None:
        """Check ci release is main only gate complete and digest published."""
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        assert (
            "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"
            in workflow
        )
        assert (
            "needs: [lint, opaque-references, site-references, typecheck, security, wheel-smoke, tests]"
            in workflow
        )
        site_references = re.search(
            r"(?ms)^  site-references:\n(?P<job>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow
        )
        assert site_references is not None, "the required site-reference job is missing"
        site_job = site_references.group("job")
        assert re.search(r"(?m)^    name: no site references$", site_job)
        assert re.search(r"(?m)^        run: bash scripts/check-no-site-refs.sh$", site_job)
        assert (
            "- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1" in site_job
        )
        assert "          persist-credentials: false" in site_job
        assert not re.search(r"(?m)^[ \t]*(?:-[ \t]*)?(?:continue-on-error|if)[ \t]*:", site_job), (
            "the site-reference job and its steps must be unconditional and blocking"
        )
        assert "python scripts/build_release.py" in workflow
        assert '--commit-sha "$GITHUB_SHA"' in workflow
        assert "steps.upload_release.outputs.artifact-digest" in workflow
        assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
        assert workflow.count('version: "0.12.11"') == 6

        references = _REMOTE_ACTION.findall(workflow)
        assert references
        assert all(_FULL_ACTION_SHA.fullmatch(reference) for reference in references)

        expected_paths = {
            "oralhistarchiv.service",
            "oralhistarchiv-scheduler.service",
            "oralhistarchiv-migrate.service",
            "deploy/migrate_release.py",
            "deploy/oralhistarchiv-tmpfiles.conf",
            "deploy/bootstrap-database-roles.sql",
            "deploy/database-runtime-grants.sql",
            "deploy/verify-runtime-database-access.sql",
            "deploy/nginx.conf.example",
            "deploy/nginx-ordinary-proxy-headers.conf.example",
            "deploy/nginx-shibboleth-phase2.conf.example",
            "deploy/nginx-shibboleth-secret.conf.example",
            "deploy/redis-security.conf.example",
            "deploy/oralhistarchiv-rate-limit-redis.service",
            *_PARSER_AND_MAINTENANCE_PATHS,
        }
        check = re.search(
            r"(?ms)^      - name: Verify required deployment assets are in the release\n"
            r"(?P<step>.*?)(?=^      - |\Z)",
            workflow,
        )
        assert check is not None, "the CI deployment-asset check is missing"
        step = check.group("step")
        ci_paths = re.search(
            r"(?ms)^          required_paths=\(\n(?P<paths>.*?)^          \)$",
            step,
        )
        assert ci_paths is not None, "the CI deployment-asset array is missing"
        assert sorted(ci_paths.group("paths").split()) == sorted(
            expected_paths | set(_LICENSE_PATHS)
        )
        assert (
            '          for relative_path in "${required_paths[@]}"; do\n'
            '            tar -tzf "$release_archive" \\\n'
            '              "${release_root}/${relative_path}" >/dev/null\n'
            "          done"
        ) in step

        runbook = DEPLOYMENT_RUNBOOK.read_text(encoding="utf-8")
        documented_paths = re.search(
            r"(?ms)^required_release_paths=\(\n(?P<paths>.*?)^\)$",
            runbook,
        )
        assert documented_paths is not None, "the runbook deployment-asset array is missing"
        assert sorted(documented_paths.group("paths").split()) == sorted(expected_paths)
        assert expected_paths <= install_release._REQUIRED_PAYLOAD_FILES
        for relative_path in expected_paths:
            assert (PROJECT_ROOT / relative_path).is_file(), relative_path

    def test_production_units_import_only_from_the_release_venv(self):
        """Check production units import only from the release venv."""
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
        """Check runbook has no source or editable production install path."""
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


@pytest.mark.parametrize("retired_key", ["SEED_MOCK_DATA", "seed_mock_data"])
def test_installed_wheel_probes_exclude_the_retired_key(tmp_path, monkeypatch, retired_key):
    """Check installed wheel probes exclude the retired key."""
    defaults = _load_module(
        "wheel_smoke_env", PROJECT_ROOT / "scripts/wheel_smoke_env.py"
    ).smoke_environment()
    assert "SEED_MOCK_DATA" not in defaults
    runner = create_autospec(build_release._run)
    output = create_autospec(build_release._output, return_value=json.dumps(defaults))
    monkeypatch.setattr(build_release, "_run", runner)
    monkeypatch.setattr(build_release, "_output", output)
    inherited = {
        retired_key: "true",
        "SOURCES_CONFIG_FILE": "/ambient/operator-sources.toml",
        "ALLOW_FIXTURE_SOURCE": "true",
    }

    build_release._smoke_test_wheel(
        tmp_path / "application.whl",
        tmp_path / "runtime-requirements.txt",
        tmp_path,
        inherited,
    )

    probes = [entry.kwargs["env"] for entry in runner.call_args_list if "-I" in entry.args[0]]
    assert len(probes) == 3
    for probe in probes:
        assert all(key.upper() != "SEED_MOCK_DATA" for key in probe)
        assert probe["SOURCES_CONFIG_FILE"] == ""
        assert probe["ALLOW_FIXTURE_SOURCE"] == "false"
    assert inherited[retired_key] == "true"

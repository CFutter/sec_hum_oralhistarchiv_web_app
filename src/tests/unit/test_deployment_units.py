"""Executable contract for the deployed systemd units and gunicorn runtime.

Covers the Gunicorn/Uvicorn worker boundary, the Unix-socket hardening of the
web and scheduler services, the scheduler's stop/drain policy, and how the
audit log is shipped off the units via journald and rsyslog. The nginx
configuration and the SQL grants are separate deployment artifacts and are
covered elsewhere.
"""

import ast
import configparser
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import tomllib
from collections.abc import Awaitable, Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any, cast

import pytest
from gunicorn.workers.base import Worker
from uvicorn_worker import UvicornWorker  # type: ignore[import-untyped]

from app.middleware.rate_limiting import _build_limiter
from app.paths import PROJECT_ROOT
from config import settings
from tests.unit.systemd_units import (
    environment_file_paths,
    start_guards_accept,
    unit_directives,
)

GUNICORN_CONFIG = PROJECT_ROOT / "gunicorn.conf.py"
WEB_ENV_EXAMPLE = PROJECT_ROOT / "deploy" / "environment" / "web.env.example"
SCHEDULER_ENV_EXAMPLE = PROJECT_ROOT / "deploy" / "environment" / "scheduler.env.example"
MIGRATION_ENV_EXAMPLE = PROJECT_ROOT / "deploy" / "environment" / "migration.env.example"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
LOCKFILE = PROJECT_ROOT / "uv.lock"
WEB_SERVICE = PROJECT_ROOT / "oralhistarchiv.service"
SCHEDULER_SERVICE = PROJECT_ROOT / "oralhistarchiv-scheduler.service"
BACKUP_UNIT = PROJECT_ROOT / "deploy" / "oralhistarchiv-backup.service"
MIGRATION_UNIT = PROJECT_ROOT / "oralhistarchiv-migrate.service"
DEPLOYMENT_RUNBOOK = PROJECT_ROOT / "Deployment.md"
RSYSLOG_CONFIG = PROJECT_ROOT / "deploy" / "rsyslog-oralhistarchiv.conf.example"

EXPECTED_GUNICORN = "26.2.0"
EXPECTED_GUNICORN_STUBS = "26.2.0.20260827"
EXPECTED_UVICORN = "0.40.0"
EXPECTED_UVICORN_WORKER = "0.4.0"
EXPECTED_SOCKET_UMASK = 0o117
EXPECTED_SOCKET_MODE = 0o660


async def gunicorn_scope_probe(
    scope: dict[str, Any],
    receive: Callable[[], Awaitable[dict[str, Any]]],
    send: Callable[[dict[str, Any]], Awaitable[None]],
) -> None:
    """Complete the ASGI lifespan and report the HTTP connection identity."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
            else:
                raise AssertionError(f"unexpected lifespan message: {message!r}")

    assert scope["type"] == "http"
    request = await receive()
    assert request["type"] == "http.request"
    body = json.dumps(
        {
            "client": scope.get("client"),
            "scheme": scope.get("scheme"),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _literal_config_assignment(name: str) -> object:
    tree = ast.parse(GUNICORN_CONFIG.read_text(), filename=str(GUNICORN_CONFIG))
    values = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            values.append(ast.literal_eval(node.value))
    assert len(values) == 1, f"expected exactly one literal assignment to {name}"
    return values[0]


def _declared_pin(group: str, package: str) -> str:
    project = tomllib.loads(PYPROJECT.read_text())
    if group == "runtime":
        requirements = project["project"]["dependencies"]
    else:
        requirements = project["project"]["optional-dependencies"][group]
    prefix = f"{package}=="
    matches = [requirement for requirement in requirements if requirement.startswith(prefix)]
    assert len(matches) == 1, f"expected exactly one exact {package} pin in {group}"
    return str(matches[0]).removeprefix(prefix)


def _locked_version(package: str) -> str:
    lock = tomllib.loads(LOCKFILE.read_text())
    matches = [entry["version"] for entry in lock["package"] if entry["name"] == package]
    assert len(matches) == 1, f"expected exactly one locked {package} distribution"
    return str(matches[0])


def _stop(process: subprocess.Popen[str]) -> tuple[str, str]:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return process.communicate(timeout=1)


def _wait_for_socket(process: subprocess.Popen[str], socket_path: Path) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if socket_path.is_socket():
            return
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            pytest.fail(
                "Gunicorn exited before binding its Unix socket\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        time.sleep(0.05)
    pytest.fail("Gunicorn did not bind its Unix socket within 15 seconds")


def _request_probe(socket_path: Path) -> dict[str, object]:
    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"X-Forwarded-For: 203.0.113.77\r\n"
        b"X-Forwarded-Proto: https\r\n"
        b"Connection: close\r\n\r\n"
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(socket_path))
        client.sendall(request)
        chunks = []
        while chunk := client.recv(65536):
            chunks.append(chunk)

    response = b"".join(chunks)
    headers, separator, body = response.partition(b"\r\n\r\n")
    assert separator
    assert headers.startswith(b"HTTP/1.1 200 ")
    return cast(dict[str, object], json.loads(body))


def _active_rsyslog_config() -> str:
    """Return executable rsyslog text with comments removed."""
    return "\n".join(line.split("#", 1)[0] for line in RSYSLOG_CONFIG.read_text().splitlines())


def _shipping_conditional(active_config: str) -> str:
    """Extract the active _SYSTEMD_UNIT conditional and its action."""
    start = active_config.index('if (($!_SYSTEMD_UNIT == "oralhistarchiv.service")')
    end = active_config.index("\n}", start)
    return active_config[start : end + 2]


class TestGunicornRuntime:
    """The Gunicorn/Uvicorn worker boundary matches the reviewed stack."""

    def test_declared_and_locked_gunicorn_stack_is_the_reviewed_stack(self) -> None:
        assert _declared_pin("runtime", "gunicorn") == EXPECTED_GUNICORN
        assert _declared_pin("runtime", "uvicorn") == EXPECTED_UVICORN
        assert _declared_pin("runtime", "uvicorn-worker") == EXPECTED_UVICORN_WORKER
        assert _declared_pin("dev", "types-gunicorn") == EXPECTED_GUNICORN_STUBS

        assert _locked_version("gunicorn") == EXPECTED_GUNICORN
        assert _locked_version("uvicorn") == EXPECTED_UVICORN
        assert _locked_version("uvicorn-worker") == EXPECTED_UVICORN_WORKER
        assert _locked_version("types-gunicorn") == EXPECTED_GUNICORN_STUBS

    def test_installed_gunicorn_stack_matches_the_reviewed_lock(self) -> None:
        assert version("gunicorn") == EXPECTED_GUNICORN
        assert version("uvicorn") == EXPECTED_UVICORN
        assert version("uvicorn-worker") == EXPECTED_UVICORN_WORKER
        assert version("types-gunicorn") == EXPECTED_GUNICORN_STUBS
        assert issubclass(UvicornWorker, Worker)

    def test_production_config_preserves_unix_socket_and_forwarded_header_boundary(
        self, tmp_path: Path
    ) -> None:
        assert _literal_config_assignment("bind") == "unix:/run/oralhistarchiv/gunicorn.sock"
        assert _literal_config_assignment("worker_class") == "uvicorn_worker.UvicornWorker"
        assert _literal_config_assignment("umask") == EXPECTED_SOCKET_UMASK
        assert _literal_config_assignment("forwarded_allow_ips") == ""

        socket_path = tmp_path / "gunicorn.sock"
        environment = os.environ.copy()
        import_paths = [str(PROJECT_ROOT / "src"), str(Path(__file__).resolve().parent)]
        if existing := environment.get("PYTHONPATH"):
            import_paths.append(existing)
        environment["PYTHONPATH"] = os.pathsep.join(import_paths)
        probe_import = f"{Path(__file__).stem}:gunicorn_scope_probe"

        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "from gunicorn.app.wsgiapp import run; run()",
                "--config",
                str(GUNICORN_CONFIG),
                "--bind",
                f"unix:{socket_path}",
                "--workers",
                "1",
                probe_import,
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_for_socket(process, socket_path)
            assert stat.S_IMODE(socket_path.stat().st_mode) == EXPECTED_SOCKET_MODE
            payload = _request_probe(socket_path)
            assert payload == {"client": None, "scheme": "http"}
        finally:
            _stop(process)


class TestServiceSocketHardening:
    """Unix-socket and unit hardening keeps the proxy, web and scheduler apart."""

    def test_web_runtime_directory_is_limited_to_the_nginx_proxy_group(self) -> None:
        assert unit_directives(WEB_SERVICE, "User") == ["oralhistarchiv"]
        assert unit_directives(WEB_SERVICE, "Group") == ["oralhistarchiv-proxy"]
        assert unit_directives(WEB_SERVICE, "UMask") == ["0077"]
        assert unit_directives(WEB_SERVICE, "RuntimeDirectory") == ["oralhistarchiv"]
        assert unit_directives(WEB_SERVICE, "RuntimeDirectoryMode") == ["0750"]

    def test_shibboleth_secret_environment_is_web_only(self) -> None:
        common = "/etc/oralhistarchiv/common.env"
        web = "/etc/oralhistarchiv/web.env"
        scheduler = "/etc/oralhistarchiv/scheduler.env"
        shibboleth = "-/etc/oralhistarchiv/shibboleth.env"

        assert unit_directives(WEB_SERVICE, "EnvironmentFile") == [
            common,
            web,
            shibboleth,
        ]
        assert unit_directives(SCHEDULER_SERVICE, "EnvironmentFile") == [
            common,
            scheduler,
        ]
        assert shibboleth not in unit_directives(SCHEDULER_SERVICE, "EnvironmentFile")

    def test_gunicorn_uses_only_the_unix_socket_with_mode_0660(self) -> None:
        assert _literal_config_assignment("bind") == "unix:/run/oralhistarchiv/gunicorn.sock"
        # Gunicorn creates a Unix socket from 0777 while temporarily applying this
        # setting: 0777 & ~0117 == 0660.
        assert _literal_config_assignment("umask") == 0o117
        assert 0o777 & ~_literal_config_assignment("umask") == 0o660
        assert _literal_config_assignment("forwarded_allow_ips") == ""

    def test_scheduler_has_a_distinct_uid_and_cannot_reach_the_web_socket_path(self) -> None:
        web_user = unit_directives(WEB_SERVICE, "User")
        scheduler_user = unit_directives(SCHEDULER_SERVICE, "User")

        assert scheduler_user == ["oralhistarchiv-scheduler"]
        assert scheduler_user != web_user
        assert unit_directives(SCHEDULER_SERVICE, "Group") == ["oralhistarchiv-scheduler"]
        assert unit_directives(SCHEDULER_SERVICE, "UMask") == ["0077"]
        assert unit_directives(SCHEDULER_SERVICE, "InaccessiblePaths") == ["-/run/oralhistarchiv"]
        assert all(
            "/run/oralhistarchiv" not in value
            for value in unit_directives(SCHEDULER_SERVICE, "ReadWritePaths")
        )

    def test_only_web_service_declares_the_socket_runtime_directory(self) -> None:
        assert unit_directives(WEB_SERVICE, "RuntimeDirectory") == ["oralhistarchiv"]
        assert unit_directives(SCHEDULER_SERVICE, "RuntimeDirectory") == []

    def test_systemd_environment_examples_preserve_json_list_quotes(self) -> None:
        """Outer shell quotes keep inner JSON quotes after EnvironmentFile parsing."""
        runbook = DEPLOYMENT_RUNBOOK.read_text()
        expected_assignments = {
            "ALLOWED_HOSTS": "'[\"archive.example.uzh.ch\"]'",
            "TOTP_ENCRYPTION_KEYS": "'[\"GENERATE_INDEPENDENT_TOKEN_URLSAFE_64\"]'",
            "OUTBOX_ENCRYPTION_KEYS": "'[\"GENERATE_INDEPENDENT_TOKEN_URLSAFE_64\"]'",
            "SHIBBOLETH_TRUSTED_ISSUERS": ("'[\"https://eduid.ch/idp/shibboleth\"]'"),
        }

        for name, value in expected_assignments.items():
            assert f"{name}={value}" in runbook
            assert re.search(rf"(?m)^{name}=\[", runbook) is None

    def test_runbook_requires_live_inventory_of_every_proxy_uid_process(self) -> None:
        runbook = DEPLOYMENT_RUNBOOK.read_text()

        # Resolve the actual nginx worker identity, fail closed, and use the same
        # value for group assignment, process inventory, and the positive probe.
        assert "www-data" not in runbook
        assert 'OHA_NGINX_WORKER_USER="$(' in runbook
        assert "set -o pipefail" in runbook
        assert "sudo nginx -T 2>&1 | awk" in runbook
        assert 'if (count != 1 || users[1] == "") exit 1' in runbook
        assert "root|*[!A-Za-z0-9_.-]*)" in runbook
        assert 'getent passwd "$OHA_NGINX_WORKER_USER"' in runbook
        assert 'id -u "$OHA_NGINX_WORKER_USER"' in runbook
        assert re.search(
            r"sudo usermod --append --groups oralhistarchiv-proxy\s+\\\s+"
            r'"\$OHA_NGINX_WORKER_USER"',
            runbook,
        )

        assert "ps -eo pid,user,group,comm,args" in runbook
        assert 'pgrep -u "$OHA_NGINX_WORKER_USER"' in runbook
        assert '"/proc/$pid/status"' in runbook
        assert "PHP-FPM" in runbook
        assert "dedicated worker UID" in runbook

    def test_runbook_uses_raw_unix_connect_positive_and_negative_controls(self) -> None:
        runbook = DEPLOYMENT_RUNBOOK.read_text()

        assert "stat -Lc 'type=%F owner=%U group=%G mode=%a path=%n'" in runbook
        assert "socket.socket(socket.AF_UNIX)" in runbook
        assert 'sudo -u "$OHA_NGINX_WORKER_USER" python3 -c' in runbook
        assert "! sudo -u oralhistarchiv-scheduler python3 -c" in runbook
        assert "! sudo -u nobody python3 -c" in runbook
        assert "--unix-socket /run/oralhistarchiv/gunicorn.sock" in runbook
        assert "! sudo ss -H -ltnp" in runbook


class TestSchedulerStopPolicy:
    """Systemd's stop policy stays aligned with Python and SMTP subprocess draining."""

    def test_scheduler_stop_budget_and_child_signal_policy(self) -> None:
        tree = ast.parse((PROJECT_ROOT / "run_scheduler.py").read_text())
        constants = {
            target.id: ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
            and target.id in {"_JOB_DRAIN_TIMEOUT_SECONDS", "_JOB_CANCELLATION_GRACE_SECONDS"}
        }
        unit = configparser.ConfigParser(interpolation=None, strict=False)
        unit.read(PROJECT_ROOT / "oralhistarchiv-scheduler.service")
        service = unit["Service"]
        seconds = service["TimeoutStopSec"]
        assert seconds.endswith("s")
        assert float(seconds[:-1]) >= (
            constants["_JOB_DRAIN_TIMEOUT_SECONDS"]
            + constants["_JOB_CANCELLATION_GRACE_SECONDS"]
            + 25
        )
        assert service["KillMode"] == "mixed"
        assert service.getboolean("SendSIGKILL") is True


class TestAuditLogShipping:
    """The audit log is shipped off the units via journald and a bounded RELP queue."""

    def test_runtime_units_have_explicit_stable_journal_identifiers(self) -> None:
        assert unit_directives(WEB_SERVICE, "StandardOutput") == ["journal"]
        assert unit_directives(WEB_SERVICE, "StandardError") == ["journal"]
        assert unit_directives(WEB_SERVICE, "SyslogIdentifier") == ["oralhistarchiv"]

        assert unit_directives(SCHEDULER_SERVICE, "StandardOutput") == ["journal"]
        assert unit_directives(SCHEDULER_SERVICE, "StandardError") == ["journal"]
        assert unit_directives(SCHEDULER_SERVICE, "SyslogIdentifier") == [
            "oralhistarchiv-scheduler"
        ]

        assert unit_directives(BACKUP_UNIT, "StandardOutput") == ["journal"]
        assert unit_directives(BACKUP_UNIT, "StandardError") == ["journal"]
        assert unit_directives(BACKUP_UNIT, "SyslogIdentifier") == ["oralhistarchiv-backup"]

        assert unit_directives(MIGRATION_UNIT, "StandardOutput") == ["journal"]
        assert unit_directives(MIGRATION_UNIT, "StandardError") == ["journal"]
        assert unit_directives(MIGRATION_UNIT, "SyslogIdentifier") == ["oralhistarchiv-migrate"]

    def test_rsyslog_selects_trusted_systemd_unit_metadata(self) -> None:
        active_config = _active_rsyslog_config()
        shipping_conditional = _shipping_conditional(active_config)

        for unit in (
            "oralhistarchiv.service",
            "oralhistarchiv-scheduler.service",
            "oralhistarchiv-backup.service",
            "oralhistarchiv-migrate.service",
        ):
            assert f'$!_SYSTEMD_UNIT == "{unit}"' in shipping_conditional

        assert "$programname" not in active_config
        assert "$syslogtag" not in active_config

    def test_remote_action_is_named_reliable_bounded_and_observable(self) -> None:
        active_config = _active_rsyslog_config()
        shipping_conditional = _shipping_conditional(active_config)

        required = (
            'name="oralhistarchiv_remote_audit"',
            'type="omrelp"',
            'tls="on"',
            'tls.authMode="name"',
            'queue.type="LinkedList"',
            'queue.filename="relp_oralhistarchiv_fwd"',
            'queue.maxDiskSpace="512m"',
            'queue.saveOnShutdown="on"',
            'action.resumeRetryCount="-1"',
            'action.reportSuspension="on"',
            'action.reportSuspensionContinuation="on"',
        )
        for directive in required:
            assert directive in shipping_conditional

        assert shipping_conditional.count('name="oralhistarchiv_remote_audit"') == 1
        assert active_config.count('name="oralhistarchiv_remote_audit"') == 1


def _declares_key(path: Path, key: str) -> bool:
    """True if `path` assigns (non-blank, non-comment) KEY=... for `key`."""
    for line_raw in path.read_text().splitlines():
        line = line_raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        declared_key = line.split("=", 1)[0].strip().removeprefix("export ").strip()
        if declared_key == key:
            return True
    return False


class TestPerProcessLimiterCredentialIsolation:
    """The rate-limit Redis credential is a web-only concern: only the web
    process overlay supplies it, so a scheduler or migration deployment
    (neither of which serves rate-limited requests) cannot be handed a
    credential it has no use for."""

    def test_scheduler_and_migration_environment_do_not_declare_the_limiter_credential(
        self,
    ) -> None:
        assert not _declares_key(SCHEDULER_ENV_EXAMPLE, "RATE_LIMIT_REDIS_URL")
        assert not _declares_key(MIGRATION_ENV_EXAMPLE, "RATE_LIMIT_REDIS_URL")

    def test_web_environment_declares_its_own_limiter_credential(self) -> None:
        assert _declares_key(WEB_ENV_EXAMPLE, "RATE_LIMIT_REDIS_URL")


class TestGunicornRecyclingAndLimiterExternality:
    """Worker recycling is bounded (never unlimited, never disabled) and the
    limiter's own construction never enables an in-process fallback that
    would let counters diverge per Gunicorn worker."""

    def test_worker_recycling_is_present_and_bounded(self) -> None:
        max_requests = _literal_config_assignment("max_requests")
        jitter = _literal_config_assignment("max_requests_jitter")
        assert isinstance(max_requests, int) and 0 < max_requests <= 100_000
        assert isinstance(jitter, int) and 0 <= jitter < max_requests

    def test_constructed_limiter_never_falls_back_to_in_process_state(self) -> None:
        constructed = _build_limiter()
        assert constructed._in_memory_fallback_enabled is False
        assert constructed._storage_uri == (settings.rate_limit_storage_uri or "memory://")


PRODUCTION_MODE_UNITS = (WEB_SERVICE, SCHEDULER_SERVICE, MIGRATION_UNIT)


class TestProductionModeStartGuard:
    """The reference production units refuse to start unless the environment
    they are actually given selects production mode.

    Loading an environment file is not enough on its own: with ENV_STATE
    simply missing, the application falls back to its development default and
    several production-only checks become advisory. The guard has to be an
    executed, unsuppressed check on the effective value.
    """

    @pytest.mark.parametrize("unit", PRODUCTION_MODE_UNITS, ids=lambda unit: unit.name)
    def test_the_unit_checks_its_mode_before_starting_its_process(self, unit: Path) -> None:
        guards = unit_directives(unit, "ExecStartPre")
        assert guards, f"{unit.name} starts its process with no mode check in front of it"

        for guard in guards:
            assert not guard.startswith("-"), (
                f"{unit.name} prefixes a start check with '-', which makes systemd ignore "
                "its exit status — the process would start whatever the environment says"
            )
            executable = Path(guard.split()[0])
            assert executable.is_absolute() and executable.is_file(), (
                f"{unit.name} names a start check systemd could not execute: {executable}"
            )

    @pytest.mark.parametrize("unit", PRODUCTION_MODE_UNITS, ids=lambda unit: unit.name)
    @pytest.mark.parametrize(
        ("declared_mode", "may_start"),
        [
            pytest.param(None, False, id="mode-absent"),
            pytest.param("dev", False, id="dev"),
            pytest.param("staging", False, id="staging"),
            pytest.param("production", True, id="production"),
        ],
    )
    def test_only_production_mode_lets_the_unit_start(
        self, unit: Path, declared_mode: str | None, may_start: bool
    ) -> None:
        """A missing value must fail as firmly as a wrong one — that is the
        case the application's own development default would otherwise
        swallow."""
        first_file = environment_file_paths(unit)[0]
        contents = {} if declared_mode is None else {first_file: {"ENV_STATE": declared_mode}}

        assert start_guards_accept(unit, contents) is may_start

    @pytest.mark.parametrize("unit", (WEB_SERVICE, SCHEDULER_SERVICE), ids=lambda unit: unit.name)
    def test_a_later_environment_file_can_take_production_mode_away(self, unit: Path) -> None:
        """Environment files are layered and the last one wins. A unit that
        merely had 'production' written somewhere in its first file would pass
        a weaker check while its processes ran in development mode."""
        paths = environment_file_paths(unit)
        assert len(paths) >= 2, (
            f"{unit.name} no longer layers environment files, so this test cannot "
            "prove the effective value is what gets checked"
        )

        overridden = {paths[0]: {"ENV_STATE": "production"}, paths[1]: {"ENV_STATE": "dev"}}
        restored = {paths[0]: {"ENV_STATE": "dev"}, paths[1]: {"ENV_STATE": "production"}}

        assert start_guards_accept(unit, overridden) is False
        assert start_guards_accept(unit, restored) is True

    def test_the_units_pass_systemd_syntax_verification(self) -> None:
        """The guard is only worth anything if systemd accepts the unit at
        all, so the shipped files are checked with systemd's own verifier."""
        verifier = shutil.which("systemd-analyze")
        if verifier is None:
            pytest.skip("systemd-analyze is not installed in this development environment")

        completed = subprocess.run(
            [verifier, "verify", "--recursive-errors=no", *(str(u) for u in PRODUCTION_MODE_UNITS)],
            check=False,
            capture_output=True,
            text=True,
        )

        assert completed.returncode == 0, (
            f"systemd rejected a shipped unit:\n{completed.stdout}\n{completed.stderr}"
        )

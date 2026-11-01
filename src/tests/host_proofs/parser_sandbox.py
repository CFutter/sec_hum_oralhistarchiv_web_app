"""Explicit deployment-host proof for parser authority restrictions.

Run this file explicitly with RUN_PARSER_SANDBOX_TESTS=1 as root on a disposable
systemd host. It is intentionally outside the default test filename pattern.
"""

import os
import pwd
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from app.paths import PROJECT_ROOT
from app.sources import parser_transport
from tests.unit.systemd_units import unit_directives

_SERVICE_UNIT = PROJECT_ROOT / "oralhistarchiv-parser@.service"


_HOST_PROOF = r"""
import errno
import os
import socket
import sys

scheduler_uid, parent_pid, port = map(int, sys.argv[1:])
assert os.getuid() not in (0, scheduler_uid), "parser retained service identity"
for name in (
    "SECRET_KEY", "SESSION_SECRET", "TOTP_ENCRYPTION_KEYS",
    "OUTBOX_ENCRYPTION_KEYS", "DATABASE_URL", "SMTP_PASSWORD",
):
    assert name not in os.environ, "service credential reached parser"

try:
    with open(f"/proc/{parent_pid}/environ", "rb") as handle:
        handle.read()
except (PermissionError, FileNotFoundError):
    pass
else:
    raise AssertionError("parser could read a different service process environment")

for path in ("/etc/oralhistarchiv", "/run/postgresql"):
    try:
        os.listdir(path)
    except (PermissionError, FileNotFoundError):
        pass
    else:
        raise AssertionError("parser could traverse protected service files")

try:
    database_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
except OSError as error:
    assert error.errno in (errno.EAFNOSUPPORT, errno.EPERM, errno.EACCES), error
else:
    database_socket.close()
    raise AssertionError("parser could create a peer-authenticated database socket")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.settimeout(2)
    try:
        client.connect(("127.0.0.1", port))
    except TimeoutError:
        pass  # Packet-filter denial drops traffic to the known listening endpoint.
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES), error
    else:
        raise AssertionError("parser could connect to a listening local database endpoint")

with open("/proc/self/status", encoding="ascii") as handle:
    status = dict(line.split(":", 1) for line in handle if ":" in line)
assert status["NoNewPrivs"].strip() == "1"
assert int(status["CapEff"].strip(), 16) == 0
"""


def test_real_systemd_parser_identity_filesystem_and_database_denials():
    """Run real denial probes using the shipped service sandbox, without service secrets."""
    assert os.environ.get("RUN_PARSER_SANDBOX_TESTS") == "1", "explicit host proof opt-in required"
    assert os.geteuid() == 0, "the deployment proof requires root"
    assert Path("/run/systemd/system").is_dir(), "a running system systemd manager is required"
    systemctl = shutil.which("systemctl")
    python = Path("/usr/bin/python3")
    assert systemctl is not None and python.is_file()
    scheduler_uid = pwd.getpwnam("oralhistarchiv-scheduler").pw_uid

    with (
        tempfile.TemporaryDirectory(prefix="oralhistarchiv-parser-proof-", dir="/run") as scratch,
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener,
    ):
        scratch_path = Path(scratch)
        scratch_path.chmod(0o755)
        script = scratch_path / "probe.py"
        script.write_text(_HOST_PROOF, encoding="utf-8")
        script.chmod(0o644)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        unit_name = f"{scratch_path.name}.service"
        unit_path = Path("/run/systemd/system") / unit_name
        original = _SERVICE_UNIT.read_text(encoding="utf-8")
        original_command = unit_directives(_SERVICE_UNIT, "ExecStart")[0]
        proof_command = f"{python} -I {script} {scheduler_uid} {os.getpid()} {port}"
        # Change only execution/lifecycle inputs. All shipped privilege,
        # filesystem and network restrictions remain active for the proof.
        proof_unit = original.replace("Type=exec", "Type=oneshot").replace(
            "WorkingDirectory=/opt/oralhistarchiv", "WorkingDirectory=/"
        )
        proof_unit = proof_unit.replace("StandardInput=socket", "StandardInput=null")
        proof_unit = proof_unit.replace(
            f"ExecStart={original_command}", f"ExecStart={proof_command}"
        )
        unit_path.write_text(proof_unit, encoding="utf-8")
        try:
            subprocess.run([systemctl, "daemon-reload"], check=True, timeout=15)
            completed = subprocess.run(
                [systemctl, "start", unit_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if completed.returncode:
                logs = subprocess.run(
                    ["journalctl", "--no-pager", "-u", unit_name, "-n", "30"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                pytest.fail(
                    f"Parser sandbox denial proof failed:\n{completed.stderr}\n{logs.stdout}"
                )
        finally:
            subprocess.run([systemctl, "stop", unit_name], check=False, timeout=10)
            unit_path.unlink(missing_ok=True)
            subprocess.run([systemctl, "daemon-reload"], check=True, timeout=15)


def test_real_parser_entrypoint_identity_handshake_and_spawned_job(monkeypatch):
    """Exercise the shipped entrypoint, effective checks, credential hello and child IPC."""
    assert os.environ.get("RUN_PARSER_SANDBOX_TESTS") == "1", "explicit host proof opt-in required"
    assert os.geteuid() == 0
    assert Path("/run/systemd/system").is_dir()
    systemctl = shutil.which("systemctl")
    assert systemctl is not None
    python = Path(os.environ["PARSER_PROOF_PYTHON"])
    assert python.is_absolute() and python.is_file()
    assert not any(character.isspace() or character == "%" for character in str(python))
    assert not str(python.resolve()).startswith(("/home/", "/root/"))
    # Install this interpreter's current project wheel/runtime dependencies under
    # /opt or /usr before invoking the proof. ProtectHome remains enabled.
    with tempfile.TemporaryDirectory(prefix="oha-parser-protocol-", dir="/run") as scratch:
        directory = Path(scratch)
        directory.chmod(0o755)
        entrypoint = directory / "run_parser.py"
        entrypoint.write_bytes((PROJECT_ROOT / "run_parser.py").read_bytes())
        entrypoint.chmod(0o644)
        socket_path = directory / "worker.sock"
        prefix = directory.name
        service_name = f"{prefix}@.service"
        socket_name = f"{prefix}.socket"
        unit_directory = Path("/run/systemd/system")
        service_path, unit_socket_path = unit_directory / service_name, unit_directory / socket_name
        service = _SERVICE_UNIT.read_text(encoding="utf-8")
        service = service.replace(
            "WorkingDirectory=/opt/oralhistarchiv", f"WorkingDirectory={directory}"
        ).replace(
            f"ExecStart={unit_directives(_SERVICE_UNIT, 'ExecStart')[0]}",
            "ExecStart=/usr/bin/env -i LANG=C.UTF-8 PATH=/usr/bin:/bin HOME=/nonexistent "
            f"{python} -I {entrypoint}\nEnvironment=PARSER_PROOF_CANARY=must-be-cleared",
        )
        socket_unit = (PROJECT_ROOT / "oralhistarchiv-parser.socket").read_text(encoding="utf-8")
        socket_unit = socket_unit.replace(
            "ListenStream=/run/oralhistarchiv-parser.sock", f"ListenStream={socket_path}"
        ).replace("Service=oralhistarchiv-parser@.service", f"Service={service_name}")
        service_path.write_text(service, encoding="utf-8")
        unit_socket_path.write_text(socket_unit, encoding="utf-8")
        monkeypatch.setenv("ORALHISTARCHIV_PARSER_SOCKET", str(socket_path))
        try:
            subprocess.run([systemctl, "daemon-reload"], check=True, timeout=15)

            subprocess.run([systemctl, "start", socket_name], check=True, timeout=15)
            assert (
                parser_transport.request_parser(
                    {"operation": "ping"}, maximum=32, deadline=time.monotonic() + 20
                )
                == b"ready"
            )
            # An invalid URL produces a bounded error in the actual spawned OAI
            # worker, without relying on an external upstream or network data.
            response = parser_transport.request_parser(
                {
                    "operation": "oai",
                    "url": "not-a-url",
                    "since": "2026-01-01",
                    "institution": "Sandbox proof",
                    "source": "proof",
                    "max_pages": 1,
                },
                maximum=4096,
                deadline=time.monotonic() + 20,
            )
            assert response.startswith(b"E")
            assert b"must-be-cleared" not in response
        except Exception:
            logs = subprocess.run(
                ["journalctl", "--no-pager", "-u", f"{prefix}@*", "-n", "50"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            pytest.fail(f"Actual parser service protocol proof failed:\n{logs.stdout}")
        finally:
            subprocess.run(
                [systemctl, "stop", socket_name, f"{prefix}@*.service"],
                check=False,
                timeout=15,
            )
            service_path.unlink(missing_ok=True)
            unit_socket_path.unlink(missing_ok=True)
            subprocess.run([systemctl, "daemon-reload"], check=True, timeout=15)


def test_parser_memory_ceiling_preserves_independent_coordinator_and_smtp_work():
    """Exhaust the shipped parser cgroup while a coordinator spawns real SMTP delivery children."""
    assert os.environ.get("RUN_PARSER_SANDBOX_TESTS") == "1"
    assert os.geteuid() == 0 and Path("/run/systemd/system").is_dir()
    systemctl = shutil.which("systemctl")
    assert systemctl is not None
    python = Path(os.environ["PARSER_PROOF_PYTHON"])
    assert python.is_absolute() and python.is_file()
    accepted: list[str] = []

    class SMTPHandler(socketserver.StreamRequestHandler):
        """Minimal loopback SMTP receiver for the parser-memory isolation proof."""

        def handle(self):
            """Serve the SMTP commands needed by the memory-isolation proof and record accepted
            bodies.
            """
            self.request.settimeout(5)
            self.wfile.write(b"220 memory-proof.example SMTP\r\n")
            while command := self.rfile.readline(4096):
                verb = command.split(b" ", 1)[0].strip().upper()
                if verb == b"DATA":
                    self.wfile.write(b"354 End with a dot\r\n")
                    body = bytearray()
                    while (line := self.rfile.readline(4096)) not in {b".\r\n", b""}:
                        body.extend(line)
                    accepted.append(body.decode("ascii"))
                    self.wfile.write(b"250 accepted\r\n")
                elif verb == b"QUIT":
                    self.wfile.write(b"221 bye\r\n")
                    return
                else:
                    self.wfile.write(b"250 ok\r\n")

    smtp_child = (
        "import smtplib,sys; "
        "client=smtplib.SMTP('127.0.0.1',int(sys.argv[1]),timeout=5); "
        "client.sendmail('probe@example.org',['operator@example.org'],sys.argv[2]); client.quit()"
    )
    coordinator = (
        "import subprocess,sys; "
        "[(subprocess.run([sys.executable,'-I','-c',sys.argv[2],sys.argv[1],line.strip()],"
        "check=True,timeout=10),print(line.strip(),flush=True)) for line in sys.stdin]"
    )
    with (
        tempfile.TemporaryDirectory(prefix="oha-parser-memory-", dir="/run") as scratch,
        socketserver.ThreadingTCPServer(("127.0.0.1", 0), SMTPHandler) as smtp,
    ):
        smtp.daemon_threads = True
        server_thread = threading.Thread(target=smtp.serve_forever, daemon=True)
        server_thread.start()
        directory = Path(scratch)
        directory.chmod(0o755)
        script = directory / "allocate.py"
        script.write_text(
            "chunks=[]\nwhile True:\n chunks.append(bytearray(8*1024*1024))\n",
            encoding="ascii",
        )
        script.chmod(0o644)
        unit_name = f"{directory.name}.service"
        unit_path = Path("/run/systemd/system") / unit_name
        command = unit_directives(_SERVICE_UNIT, "ExecStart")[0]
        proof_unit = _SERVICE_UNIT.read_text(encoding="utf-8")
        proof_unit = proof_unit.replace("Type=exec", "Type=oneshot")
        proof_unit = proof_unit.replace("CollectMode=inactive-or-failed", "CollectMode=inactive")
        proof_unit = proof_unit.replace(
            "WorkingDirectory=/opt/oralhistarchiv", "WorkingDirectory=/"
        )
        proof_unit = proof_unit.replace("StandardInput=socket", "StandardInput=null")
        proof_unit = proof_unit.replace(
            f"ExecStart={command}",
            "ExecStart=/usr/bin/env -i LANG=C.UTF-8 PATH=/usr/bin:/bin HOME=/nonexistent "
            f"{python} -I {script}",
        )
        unit_path.write_text(proof_unit, encoding="utf-8")
        process = subprocess.Popen(
            [str(python), "-I", "-u", "-c", coordinator, str(smtp.server_address[1]), smtp_child],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write("before-parser-oom\n")
            process.stdin.flush()
            assert process.stdout.readline().strip() == "before-parser-oom"
            subprocess.run([systemctl, "daemon-reload"], check=True, timeout=15)
            started = subprocess.run(
                [systemctl, "start", unit_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            result = subprocess.run(
                [systemctl, "show", unit_name, "--property=Result", "--value"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            assert started.returncode != 0 and result.stdout.strip() == "oom-kill"
            assert process.poll() is None
            process.stdin.write("after-parser-oom\n")
            process.stdin.flush()
            assert process.stdout.readline().strip() == "after-parser-oom"
            assert any("before-parser-oom" in message for message in accepted)
            assert any("after-parser-oom" in message for message in accepted)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            subprocess.run([systemctl, "stop", unit_name], check=False, timeout=10)
            subprocess.run([systemctl, "reset-failed", unit_name], check=False, timeout=10)
            unit_path.unlink(missing_ok=True)
            subprocess.run([systemctl, "daemon-reload"], check=True, timeout=15)
            smtp.shutdown()
            server_thread.join(timeout=5)

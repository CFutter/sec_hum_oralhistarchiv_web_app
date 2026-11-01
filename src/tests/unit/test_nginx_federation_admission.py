"""Execute the shipped SSO budgets before counted FastCGI backend work."""

import contextlib
import http.client
import os
import re
import secrets
import socketserver
import struct
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from .test_nginx_contract import (
    SHIBBOLETH_PHASE2_CONFIG,
    SHIBBOLETH_SECRET_INCLUDE,
    _balanced_blocks,
    _config_text,
    _direct_directives,
    _free_local_port,
    _http_level_directives,
    _required_executable,
    _wait_until_listening,
)


class _Calls:
    """Collect synchronized backend-call counts and application request details."""

    def __init__(self):
        """Initialize backend counters, synchronization primitives, and an open release gate."""
        self.counts = {"responder": 0, "authorizer": 0, "application": 0}
        self.application_requests = []
        self.application_port = None
        self.changed = threading.Condition()
        self.release = threading.Event()
        self.release.set()

    def record(self, name, *, path=None, cookie=None):
        """Count a backend call under the condition lock and notify waiting tests."""
        with self.changed:
            self.counts[name] += 1
            if name == "application":
                self.application_requests.append((path, cookie))
            self.changed.notify_all()

    def wait_for_sp_calls(self, count):
        """Wait up to three seconds for the requested combined SP call count."""
        with self.changed:
            assert self.changed.wait_for(
                lambda: self.counts["responder"] + self.counts["authorizer"] >= count,
                timeout=3,
            ), self.counts


def _read_exact(stream, size):
    """Read a nonnegative byte count, raising EOFError if the stream closes early."""
    value = bytearray()
    while len(value) < size:
        chunk = stream.recv(size - len(value))
        if not chunk:
            raise EOFError
        value.extend(chunk)
    return bytes(value)


def _record(record_type, request_id, body=b""):
    """Encode version-one FastCGI bytes; type is uint8, request ID and body length are uint16."""
    return struct.pack("!BBHHBB", 1, record_type, request_id, len(body), 0, 0) + body


@contextmanager
def _backend(calls, role):
    """Run a threaded loopback backend, yield its port, and stop it on exit."""

    class FastCGIHandler(socketserver.BaseRequestHandler):
        """Serve synthetic successful FastCGI authorization responses."""

        def handle(self):
            """Consume a FastCGI request and send synthetic claims after the release gate opens."""
            self.request.settimeout(8)
            try:
                while True:
                    _, kind, request_id, length, padding, _ = struct.unpack(
                        "!BBHHBB", _read_exact(self.request, 8)
                    )
                    _read_exact(self.request, length + padding)
                    if kind == 5 and length == 0:  # empty STDIN ends the request
                        break
                calls.record(role)
                if not calls.release.wait(timeout=8):
                    return
                payload = (
                    b"Status: 200 OK\r\nContent-Type: text/plain\r\n"
                    b"Variable-Shib-Identity-Provider: https://idp.example.org\r\n"
                    b"Variable-eduPersonUniqueId: synthetic-subject\r\n"
                    b"Variable-mail: synthetic@example.org\r\n\r\naccepted\n"
                )
                self.request.sendall(
                    _record(6, request_id, payload)
                    + _record(6, request_id)
                    + _record(3, request_id, b"\x00" * 8)
                )
            except (EOFError, OSError):
                return

    class ApplicationHandler(BaseHTTPRequestHandler):
        """Serve the synthetic application while recording forwarded requests."""

        def do_GET(self):
            """Record the application request, print its request line, and reply with HTTP 200."""
            print(f"Fake application received: {self.requestline}", flush=True)
            calls.record("application", path=self.path, cookie=self.headers.get("Cookie", ""))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            """Suppress the HTTP server's default request logging."""
            return

    server = (
        ThreadingHTTPServer(("127.0.0.1", 0), ApplicationHandler)
        if role == "application"
        else socketserver.ThreadingTCPServer(("127.0.0.1", 0), FastCGIHandler)
    )
    server.daemon_threads = True
    if role == "application":
        calls.application_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        calls.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


@contextmanager
def _edge(tmp_path, *, actual_shibboleth=None):
    """Run a local nginx edge and yield (port, calls), stopping it on exit. None selects real handling
    when NGINX_SHIBBOLETH_MODULE is set; requested real handling skips if absent unless
    REQUIRE_NGINX_SHIBBOLETH=1.
    """
    nginx = _required_executable("nginx")
    module = os.environ.get("NGINX_SHIBBOLETH_MODULE")
    if actual_shibboleth is None:
        actual_shibboleth = bool(module)
    if actual_shibboleth and not module:
        if os.environ.get("REQUIRE_NGINX_SHIBBOLETH") == "1":
            pytest.fail("NGINX_SHIBBOLETH_MODULE must identify the installed dynamic module")
        pytest.skip("actual Shibboleth module unavailable; stand-in tests run separately")
    calls = _Calls()
    with ExitStack() as stack:
        ports = {
            role: stack.enter_context(_backend(calls, role))
            for role in ("responder", "authorizer", "application")
        }
        params = tmp_path / "fastcgi_params"
        params.write_text(
            "fastcgi_param REQUEST_METHOD $request_method;\n"
            "fastcgi_param SCRIPT_NAME $uri;\n"
            "fastcgi_param CONTENT_LENGTH $content_length;\n"
            "fastcgi_param CONTENT_TYPE $content_type;\n",
            encoding="utf-8",
        )
        secret = tmp_path / "synthetic-secret.conf"
        secret.write_text(
            "proxy_set_header X-OHA-Internal-Auth synthetic-test-only;\n", encoding="utf-8"
        )
        locations = SHIBBOLETH_PHASE2_CONFIG.read_text(encoding="utf-8")
        locations = locations.replace("include fastcgi_params;", f'include "{params}";')
        locations = locations.replace(SHIBBOLETH_SECRET_INCLUDE, str(secret))
        for role in ("responder", "authorizer"):
            locations = locations.replace(
                f"unix:/run/shibboleth/shib{role}.sock", f"127.0.0.1:{ports[role]}"
            )
        if not actual_shibboleth:
            locations = re.sub(r"(?ms)^\s*shib_request_set\b.*?;", "", locations)
            locations = locations.replace("shib_request_use_headers off;", "")
            locations = locations.replace(
                "shib_request /shibauthorizer;", "auth_request /shibauthorizer;"
            )
            locations = re.sub(r"\$oha_shib_[a-z_]+", "synthetic-test-claim", locations)
        port = _free_local_port()
        config = tmp_path / "nginx.conf"
        directives = [
            f"{name} {value};"
            for name in (
                "limit_req_zone",
                "limit_conn_zone",
                "limit_req_status",
                "limit_conn_status",
            )
            for value in _http_level_directives(name)
        ]
        https_server = next(
            server
            for server in _balanced_blocks(_config_text(), re.compile(r"(?m)^\s*server\s*\{"))
            if _direct_directives(server, "client_max_body_size")
        )
        header_budgets = [
            f"{name} {value};"
            for name in (
                "client_max_body_size",
                "client_header_timeout",
                "client_header_buffer_size",
                "large_client_header_buffers",
            )
            for value in _direct_directives(https_server, name)
        ]
        config.write_text(
            "\n".join(
                [
                    f'load_module "{module}";' if actual_shibboleth and module != "builtin" else "",
                    "user root;" if os.geteuid() == 0 else "",
                    "worker_processes 2;",
                    "daemon off;",
                    f'error_log "{tmp_path / "error.log"}" error;',
                    f'pid "{tmp_path / "nginx.pid"}";',
                    "events { worker_connections 256; }",
                    "http {",
                    "access_log off;",
                    *[
                        f'{kind}_temp_path "{tmp_path / kind}";'
                        for kind in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
                    ],
                    *directives,
                    f"upstream oralhistarchiv {{ server 127.0.0.1:{ports['application']}; }}",
                    "server {",
                    f"listen 127.0.0.1:{port};",
                    "server_name archive.example.org;",
                    *header_budgets,
                    locations,
                    "}",
                    "}",
                ]
            ),
            encoding="utf-8",
        )
        checked = subprocess.run(
            [nginx, "-p", f"{tmp_path}/", "-c", str(config), "-T"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert checked.returncode == 0, checked.stderr
        assert checked.stdout.count("limit_conn oralhistarchiv_sso_global_conn 16;") == 2
        process = subprocess.Popen(
            [nginx, "-p", f"{tmp_path}/", "-c", str(config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_until_listening(process, port)
            yield port, calls
        finally:
            calls.release.set()
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)


def _request(port, path, address="127.0.0.1", *, body=None, headers=None):
    """Issue an eight-second loopback GET (POST when body is not None), return status, and always
    close.
    """
    connection = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=8, source_address=(address, 0)
    )
    try:
        connection.request(
            "POST" if body is not None else "GET", path, body=body, headers=headers or {}
        )
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


@pytest.mark.parametrize(
    "actual_shibboleth",
    [False, True]
    if os.environ.get("NGINX_SHIBBOLETH_MODULE")
    or os.environ.get("REQUIRE_NGINX_SHIBBOLETH") == "1"
    else [False],
    ids=lambda enabled: "shibboleth" if enabled else "access-stand-in",
)
def test_rate_rejections_precede_both_sp_backends_and_preserve_small_nat_bursts(
    tmp_path, actual_shibboleth
):
    """Check rate rejections precede both sp backends and preserve small nat bursts."""
    with _edge(tmp_path, actual_shibboleth=actual_shibboleth) as (port, calls):
        paths = ["/Shibboleth.sso/Login", "/auth/shibboleth/callback"]
        # Four users behind one university NAT can begin a small burst.
        assert [_request(port, paths[index % 2]) for index in range(4)] == [200] * 4
        statuses = [_request(port, paths[index % 2]) for index in range(30)]
        assert 429 in statuses
        assert calls.counts["responder"] + calls.counts["authorizer"] == 4 + statuses.count(200)
        assert calls.counts["application"] == calls.counts["authorizer"]
        before = dict(calls.counts)
        assert _request(port, "/shibauthorizer", "127.0.0.2") == 404
        assert calls.counts == before


def test_aggregate_budget_is_shared_across_locations_and_rotating_addresses(tmp_path):
    """Check aggregate budget is shared across locations and rotating addresses."""
    with _edge(tmp_path) as (port, calls):
        statuses = [
            _request(
                port,
                "/Shibboleth.sso/Login" if index % 2 else "/auth/shibboleth/callback",
                f"127.0.1.{index + 1}",
            )
            for index in range(60)
        ]
        assert 200 in statuses and 429 in statuses
        assert calls.counts["responder"] + calls.counts["authorizer"] == statuses.count(200)
        assert calls.counts["application"] == calls.counts["authorizer"]


@pytest.mark.parametrize("aggregate", [False, True], ids=["per-client", "aggregate"])
def test_concurrency_rejections_precede_sp_work_and_capacity_recovers(tmp_path, aggregate):
    """Check concurrency rejections precede sp work and capacity recovers."""
    with _edge(tmp_path) as (port, calls), ThreadPoolExecutor(max_workers=16) as workers:
        calls.release.clear()
        count = 16 if aggregate else 8
        futures = [
            workers.submit(
                _request,
                port,
                "/Shibboleth.sso/Login" if index % 2 else "/auth/shibboleth/callback",
                f"127.0.2.{1 + index // 4}" if aggregate else "127.0.0.1",
            )
            for index in range(count)
        ]
        try:
            calls.wait_for_sp_calls(count)
            address = "127.0.2.9" if aggregate else "127.0.0.1"
            before = dict(calls.counts)
            assert _request(port, "/Shibboleth.sso/Login", address) == 429
            assert calls.counts == before
        finally:
            calls.release.set()
        assert [future.result(timeout=5) for future in futures] == [200] * count
        assert _request(port, "/auth/shibboleth/callback", "127.0.3.1") == 200


def test_oversized_responder_body_never_reaches_fastcgi(tmp_path):
    """Check oversized responder body never reaches fastcgi."""
    with _edge(tmp_path) as (port, calls):
        assert _request(port, "/Shibboleth.sso/SAML2/POST", body=b"x" * (64 * 1024 + 1)) == 413
        assert calls.counts == {"responder": 0, "authorizer": 0, "application": 0}


@pytest.mark.parametrize("path", ["/Shibboleth.sso/Login", "/auth/shibboleth/callback"])
@pytest.mark.parametrize("unrelated_probe", [False, True], ids=["quiet", "unrelated-root-probe"])
def test_stalled_fastcgi_fails_closed_and_capacity_recovers(tmp_path, path, unrelated_probe):
    """Check stalled fastcgi fails closed and capacity recovers."""
    with _edge(tmp_path) as (port, calls):
        marker = secrets.token_hex(16)
        attempt = f"{path}?probe={marker}"
        if unrelated_probe:
            assert _request(calls.application_port, "/") == 200
        calls.release.clear()
        try:
            # The shipped five-second FastCGI read bound must beat the client's
            # eight-second socket deadline; no fixed sleep stands in for it.
            assert _request(port, attempt, headers={"Cookie": f"oha_test_probe={marker}"}) in {
                500,
                504,
            }
            assert not any(
                marker in target or marker in cookie
                for target, cookie in calls.application_requests
            ), calls.application_requests
        finally:
            calls.release.set()
        recovery = f"{path}?probe=recovery-{marker}"
        assert _request(port, recovery, "127.0.4.1") == 200
        assert not any(
            target == attempt or cookie == f"oha_test_probe={marker}"
            for target, cookie in calls.application_requests
        ), calls.application_requests
        if path == "/auth/shibboleth/callback":
            assert any(target == recovery for target, _ in calls.application_requests)

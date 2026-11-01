"""Authenticated bytes through real TLS and the terminating spawned boundary.

No adapter or JSON/replay interpretation is claimed by these transport tests.
"""

import base64
import contextlib
import hashlib
import hmac
import ipaddress
import multiprocessing
import os
import re
import signal
import ssl
import struct
import threading
import time
import traceback
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
import requests.adapters
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import SecretBytes, SecretStr

from app.sources import JsonFeedConfig, prepare_json_feed_startup
from app.sources import json_feed_process as process_boundary
from app.sources import json_feed_transport as transport
from tests.feed_worker_deadline import TEST_FETCH_DEADLINE_SECONDS, deadline_after_worker_ready

_REAL_PAGE_WORKER = transport._page_worker
_BEARER = "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8"
_KEY_BYTES = hashlib.sha256(b"synthetic transport signing material").digest()
_BODY = b'{"unparsed":"caf\xc3\xa9"}\n'


def _ca_page_worker(connection, config, credentials, request, max_bytes, deadline):
    """Test-only trust anchor; the production HTTPS/stream/signature worker runs."""
    requests.adapters.DEFAULT_CA_BUNDLE_PATH = os.environ["TEST_FEED_CA_FILE"]
    _REAL_PAGE_WORKER(connection, config, credentials, request, max_bytes, deadline)


def _certificate(tmp_path):
    """Write localhost CA/key PEM files and return certificate/key paths."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Feed transport test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "ca.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@dataclass
class _Replay:
    """Hold mutable response bytes, fault settings and recorded HTTPS requests."""

    endpoint: str = ""
    body: bytes = _BODY
    status: int = 200
    content_type: str = "application/json"
    encoding: str | None = None
    signature_mode: str = "valid"
    stall: str | None = None
    queries: list[dict[str, list[str]]] = field(default_factory=list)
    headers: list[dict[str, str]] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)


@pytest.fixture
def https_feed(tmp_path, monkeypatch):
    """Yield a localhost HTTPS feed; release stalls and stop the server/thread afterwards."""
    cert, key = _certificate(tmp_path)
    replay = _Replay()
    endpoint_path = f"/feed/{uuid4().hex}"

    class Handler(BaseHTTPRequestHandler):
        """Serve configurable signed responses and record feed requests."""

        def do_GET(self):
            """Record feed requests and send the configured signed response or stall."""
            request = urlsplit(self.path)
            if request.path != endpoint_path:
                with contextlib.suppress(BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                return
            replay.queries.append(parse_qs(request.query))
            replay.headers.append({key.lower(): value for key, value in self.headers.items()})
            if replay.stall == "headers":
                replay.release.wait(5)
            self.send_response(replay.status)
            self.send_header("Content-Type", replay.content_type)
            self.send_header("Content-Length", str(len(replay.body)))
            self.send_header("Set-Cookie", "unrequested=must-not-return")
            if replay.status == 302:
                self.send_header("Location", replay.endpoint + "/redirect-target")
            if replay.encoding is not None:
                self.send_header("Content-Encoding", replay.encoding)
            digest = hmac.digest(_KEY_BYTES, replay.body, "sha256").hex()
            if replay.signature_mode == "wrong":
                digest = "0" * 64
            elif replay.signature_mode == "uppercase":
                digest = digest.upper()
            if replay.signature_mode != "missing":
                self.send_header("X-Feed-Signature", "v1=" + digest)
            if replay.signature_mode == "duplicate":
                self.send_header("X-Feed-Signature", "v1=" + digest)
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError, ssl.SSLError):
                if replay.stall == "body":
                    self.wfile.write(replay.body[:1])
                    self.wfile.flush()
                    replay.release.wait(5)
                    self.wfile.write(replay.body[1:])
                else:
                    self.wfile.write(replay.body)

        def log_message(self, _format, *_args):
            """Suppress the HTTP server request log."""
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    replay.endpoint = f"https://127.0.0.1:{server.server_port}{endpoint_path}"
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    monkeypatch.setenv("TEST_FEED_CA_FILE", str(cert))
    monkeypatch.setattr(transport, "_page_worker", _ca_page_worker)
    try:
        yield replay
    finally:
        replay.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert not [
            child
            for child in multiprocessing.active_children()
            if child.name.startswith("oralhistarchiv-json-feed")
        ], "feed transport left a spawned worker alive"


def _inputs(replay, **changes):
    """Return an overridden feed configuration and matching development credentials."""
    config = JsonFeedConfig.model_validate(
        {
            "name": "transport_test",
            "display": {"label": "Transport test"},
            "endpoint": replay.endpoint,
            "credential_env": "FEED_BEARER",
            "signing_key_env": "FEED_SIGNING_KEY",
            **changes,
        }
    )
    credentials = prepare_json_feed_startup(
        [config],
        environment="dev",
        environ={
            "FEED_BEARER": _BEARER,
            "FEED_SIGNING_KEY": base64.urlsafe_b64encode(_KEY_BYTES).decode().rstrip("="),
        },
    )[0]
    return config, credentials


def _client(replay, **changes):
    """Construct a transport bound to the replay endpoint and matching credentials."""
    return transport.JsonFeedTransport(*_inputs(replay, **changes))


def test_real_tls_worker_preserves_exact_bytes_and_every_request_has_a_fresh_nonce(
    https_feed, monkeypatch, tmp_path
):
    """SB-VIS-005 and SB-TRANS-001: verified HTTPS, exact-byte HMAC, fixed request origin."""
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "does-not-exist.pem"))
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login unexpected password not-the-bearer\n")
    monkeypatch.setenv("NETRC", str(netrc))
    with requests.Session() as probe:
        probe.trust_env = False
        root_url = urlsplit(https_feed.endpoint)._replace(path="/").geturl()
        response = probe.get(root_url, verify=os.environ["TEST_FEED_CA_FILE"], timeout=5)
        assert response.status_code == 404
    assert not https_feed.queries
    client = _client(https_feed)
    first = client.read_page(since=None)
    boundary = datetime(2030, 1, 2, 5, 4, 5, 123456, tzinfo=timezone(timedelta(hours=2)))
    second = client.read_page(since=boundary, cursor="page_2-safe")
    assert first.body == second.body == _BODY
    assert "unparsed" not in repr(first)
    assert first.request.nonce != second.request.nonce
    assert all(re.fullmatch(r"[0-9a-f]{64}", page.request.nonce) for page in (first, second))
    assert https_feed.queries == [
        {"nonce": [first.request.nonce]},
        {
            "nonce": [second.request.nonce],
            "since": ["2030-01-02T03:04:05Z"],
            "cursor": ["page_2-safe"],
        },
    ]
    for headers in https_feed.headers:
        assert headers["authorization"] == "Bearer " + _BEARER
        assert headers["accept"] == "application/json"
        assert headers["accept-encoding"] == "identity"
        assert "cookie" not in headers
    assert client.pages_requested == 2 and client.response_bytes == 2 * len(_BODY)


def test_authenticated_bytes_are_not_decoded_as_utf8_or_json(https_feed):
    """Authenticated bytes are not decoded as UTF-8 or JSON."""
    https_feed.body = b"\xffnot JSON"
    assert _client(https_feed).read_page(since=None).body == https_feed.body


def test_tls_verification_cannot_be_disabled_by_ambient_configuration(https_feed, monkeypatch):
    """TLS verification cannot be disabled by ambient configuration."""
    monkeypatch.setattr(transport, "_page_worker", _REAL_PAGE_WORKER)
    with pytest.raises(transport.FeedTransportError) as error:
        _client(https_feed).read_page(since=None)
    assert error.value.error_code == "transport"
    assert not https_feed.queries


@pytest.mark.parametrize("status", [204, 302, 304, 401, 404, 429, 500])
def test_non200_status_is_not_followed_retried_or_returned_as_empty_success(https_feed, status):
    """SB-TRANS-001 and SB-TRANS-004: even an otherwise signed response cannot authorize a redirect."""
    https_feed.status = status
    with pytest.raises(transport.FeedTransportError) as error:
        _client(https_feed).read_page(since=None)
    assert error.value.error_code == "http_status"
    assert len(https_feed.queries) == 1


@pytest.mark.parametrize(
    "mode,code",
    [
        ("wrong", "signature"),
        ("uppercase", "signature"),
        ("missing", "headers"),
        ("duplicate", "headers"),
    ],
)
def test_signature_is_exactly_one_canonical_matching_mac(https_feed, mode, code):
    """SB-VIS-005: no decoded or unauthenticated body escapes the boundary."""
    https_feed.signature_mode = mode
    with pytest.raises(transport.FeedTransportError) as error:
        _client(https_feed).read_page(since=None)
    assert error.value.error_code == code


@pytest.mark.parametrize(
    "field,value",
    [
        ("encoding", "gzip"),
        ("encoding", "identity, identity"),
        ("content_type", "text/json"),
        ("content_type", "application/json; charset=latin-1"),
        ("content_type", "application/json; charset=utf-8; charset=utf-8"),
    ],
)
def test_unaccepted_encoding_or_media_type_is_a_whole_call_failure(https_feed, field, value):
    """Unaccepted encoding or media type is a whole call failure."""
    setattr(https_feed, field, value)
    client = _client(https_feed)
    with pytest.raises(transport.FeedTransportError) as error:
        client.read_page(since=None)
    assert error.value.error_code == "headers"
    with pytest.raises(transport.FeedTransportError):
        client.read_page(since=None)
    assert len(https_feed.queries) == 1


@pytest.mark.parametrize("limit", ["page", "total", "pages"])
def test_page_aggregate_and_pagecount_budgets_share_one_transport_lifetime(https_feed, limit):
    """SB-TRANS-002 and SB-TRANS-004: exceeded budgets return no page and poison the transport."""
    changes = {
        "page": {"max_page_bytes": len(_BODY) - 1},
        "total": {"max_total_bytes": 2 * len(_BODY) - 1},
        "pages": {"max_pages": 1},
    }[limit]
    client = _client(https_feed, **changes)
    if limit != "page":
        assert client.read_page(since=None).body == _BODY
    with pytest.raises(transport.FeedTransportError) as error:
        client.read_page(since=None)
    assert error.value.error_code == "resource_limit"
    calls = len(https_feed.queries)
    with pytest.raises(transport.FeedTransportError):
        client.read_page(since=None)
    assert len(https_feed.queries) == calls


@pytest.mark.parametrize("stall", ["headers", "body"])
def test_real_stalled_https_worker_is_terminated_and_reaped_at_total_deadline(
    https_feed, monkeypatch, stall
):
    """SB-TRANS-003: socket inactivity is not the terminating wall-clock boundary."""
    https_feed.stall = stall
    monkeypatch.setattr(process_boundary, "_WORKER_SHUTDOWN_SECONDS", 0.2)
    client = _client(https_feed, fetch_deadline_seconds=1)
    started = time.monotonic()
    with pytest.raises(transport.FeedTransportError) as error:
        client.read_page(since=None)
    assert error.value.error_code == "resource_limit"
    assert time.monotonic() - started < 4
    assert not [
        child
        for child in multiprocessing.active_children()
        if child.name.startswith("oralhistarchiv-json-feed")
    ]


@pytest.mark.parametrize(
    "arguments,error_type",
    [
        ({"since": "2030-01-02"}, TypeError),
        ({"since": datetime(2030, 1, 2)}, ValueError),  # noqa: DTZ001
        ({"since": None, "cursor": "https://other.example.org/page"}, ValueError),
        ({"since": None, "cursor": "page\n"}, ValueError),
        ({"since": None, "cursor": "x" * 513}, ValueError),
    ],
)
def test_invalid_request_binding_fails_before_io_and_does_not_poison_client(
    https_feed, arguments, error_type
):
    """Invalid request binding fails before I/O and does not poison client."""
    client = _client(https_feed)
    with pytest.raises(error_type):
        client.read_page(**arguments)
    assert not https_feed.queries
    assert client.read_page(since=None).body == _BODY


def _partial_frame_worker(connection, _config, _credentials, _request, _max_bytes, _deadline):
    """A hostile worker exposes a partial IPC frame and ignores graceful termination."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(connection.fileno(), struct.pack("!i", 1024) + b"S")
    Path(os.environ["TEST_FEED_STAGE_MARKER"]).write_text("partial")
    threading.Event().wait()


def _invalid_error_worker(connection, _config, _credentials, _request, _max_bytes, _deadline):
    """Send an unrecognized private error payload and close the child pipe."""
    connection.send_bytes(b"Eprivate-credential-body-canary")
    connection.close()


def test_partial_ipc_cannot_escape_deadline_and_sigterm_is_escalated_to_reaping(
    monkeypatch, tmp_path
):
    """SB-TRANS-003: readiness is not completion; terminate a stalled result receiver."""
    real_receive = process_boundary._receive
    receive = create_autospec(real_receive, side_effect=real_receive)
    monkeypatch.setattr(process_boundary, "_receive", receive)
    monkeypatch.setattr(transport, "_page_worker", _partial_frame_worker)
    monkeypatch.setattr(process_boundary, "_WORKER_SHUTDOWN_SECONDS", 0.2)
    marker = tmp_path / "partial-frame-entered"
    monkeypatch.setenv("TEST_FEED_STAGE_MARKER", str(marker))
    timing = deadline_after_worker_ready(monkeypatch, marker.is_file)
    client = _client(
        _Replay(endpoint="https://archive.example.edu/feed"),
        fetch_deadline_seconds=TEST_FETCH_DEADLINE_SECONDS,
    )
    with pytest.raises(transport.FeedTransportError) as error:
        client.read_page(since=None)
    assert error.value.error_code == "resource_limit"
    assert marker.read_text() == "partial"
    timing.assert_terminated_after_readiness()
    receive.assert_called_once()
    assert not [
        child
        for child in multiprocessing.active_children()
        if child.name.startswith("oralhistarchiv-json-feed")
    ]
    assert not [
        thread
        for thread in threading.enumerate()
        if thread.name.startswith("json-feed-page-receiver")
    ]


def test_unrecognized_worker_diagnostics_cannot_disclose_credentials_or_body(monkeypatch, caplog):
    """Unrecognized worker diagnostics cannot disclose credentials or body."""
    monkeypatch.setattr(transport, "_page_worker", _invalid_error_worker)
    client = _client(_Replay(endpoint="https://archive.example.edu/feed"))
    with pytest.raises(transport.FeedTransportError) as error:
        client.read_page(since=None)
    assert error.value.error_code == "worker"
    assert "private-credential-body-canary" not in "".join(traceback.format_exception(error.value))
    assert not caplog.records


def test_shared_deadline_is_not_reset_after_a_successful_page(https_feed, monkeypatch):
    """SB-TRANS-003: one absolute cutoff includes the time between page reads."""
    client = _client(https_feed)
    assert client.read_page(since=None).body == _BODY
    real_monotonic = process_boundary.time.monotonic
    expired_clock = create_autospec(real_monotonic, return_value=real_monotonic() + 121)
    monkeypatch.setattr(process_boundary, "time", SimpleNamespace(monotonic=expired_clock))
    with pytest.raises(transport.FeedTransportError) as error:
        client.read_page(since=None)
    assert error.value.error_code == "resource_limit"
    assert len(https_feed.queries) == 1
    assert client.pages_requested == 1


@pytest.mark.parametrize(
    "change,error_type",
    [
        ("source", ValueError),
        ("bearer_wrapper", TypeError),
        ("key_wrapper", TypeError),
        ("weak_bearer", ValueError),
        ("short_key", ValueError),
        ("copied_budget", ValueError),
    ],
)
def test_constructor_revalidates_source_binding_wrappers_and_direct_secret_inputs(
    change, error_type
):
    """Constructor revalidates source binding wrappers and direct secret inputs."""
    config, credentials = _inputs(_Replay(endpoint="https://archive.example.edu/feed"))
    if change == "source":
        credentials = replace(credentials, source_name="different_source")
    elif change == "bearer_wrapper":
        credentials = replace(credentials, bearer_token=_BEARER)
    elif change == "key_wrapper":
        credentials = replace(credentials, signing_key=_KEY_BYTES)
    elif change == "weak_bearer":
        credentials = replace(credentials, bearer_token=SecretStr("a" * 43))
    elif change == "short_key":
        credentials = replace(credentials, signing_key=SecretBytes(b"short"))
    else:
        config = config.model_copy(update={"max_pages": 0})
    with pytest.raises(error_type):
        transport.JsonFeedTransport(config, credentials)


def _framing_worker(connection, _config, _credentials, _request, max_bytes, _deadline):
    """Send the IPC fault selected by TEST_FEED_IPC_CASE and always close the pipe."""
    mode = os.environ["TEST_FEED_IPC_CASE"]
    frames = {"empty": b"", "unknown": b"?untrusted", "error": b"Esignature"}
    try:
        if mode == "oversized":
            connection.send_bytes(b"S" + b"x" * (max_bytes + 33))
        elif mode != "eof":
            connection.send_bytes(frames[mode])
    except (BrokenPipeError, OSError):
        pass
    finally:
        connection.close()


@pytest.mark.parametrize(
    "mode,code",
    [
        ("empty", "worker"),
        ("unknown", "worker"),
        ("oversized", "worker"),
        ("eof", "worker"),
        ("error", "signature"),
    ],
)
def test_real_worker_framing_failures_are_bounded_and_return_no_page(monkeypatch, mode, code):
    """Real worker framing failures are bounded and return no page."""
    monkeypatch.setenv("TEST_FEED_IPC_CASE", mode)
    monkeypatch.setattr(transport, "_page_worker", _framing_worker)
    client = _client(_Replay(endpoint="https://archive.example.edu/feed"))
    with pytest.raises(transport.FeedTransportError) as error:
        client.read_page(since=None)
    assert error.value.error_code == code
    assert client.response_bytes == 0
    assert not [
        child
        for child in multiprocessing.active_children()
        if child.name.startswith("oralhistarchiv-json-feed")
    ]


def test_real_page_worker_replaces_unexpected_downloader_errors_with_a_fixed_frame(
    monkeypatch, caplog
):
    """SB-TRANS-004: deliberately isolate download failure to prove worker diagnostic redaction."""
    config, credentials = _inputs(_Replay(endpoint="https://archive.example.edu/feed"))
    real_download = transport.download_authenticated_page
    download = create_autospec(
        real_download, spec_set=True, side_effect=RuntimeError("download-private-body-canary")
    )
    monkeypatch.setattr(transport, "download_authenticated_page", download)
    receive, send = multiprocessing.get_context("spawn").Pipe(duplex=False)
    request = transport.FeedRequest("a" * 64, None, None)
    try:
        _REAL_PAGE_WORKER(send, config, credentials, request, 1024, time.monotonic() + 10)
        assert receive.recv_bytes(32) == b"Eworker"
        assert send.closed
    finally:
        receive.close()
        send.close()
    download.assert_called_once()
    assert not caplog.records


@pytest.mark.parametrize("failure", ["factory", "start", "post_start"])
def test_process_setup_failure_closes_real_pipes_and_unstarted_process(
    monkeypatch, caplog, failure
):
    """SB-TRANS-004: failed spawn setup leaks no handles or original exception details."""
    context = multiprocessing.get_context("spawn")
    real_get_context = process_boundary.multiprocessing.get_context
    real_pipe, real_process = context.Pipe, context.Process
    connections, processes = [], []
    canary = "process-setup-private-credential-canary"

    def open_pipe(*args, **kwargs):
        """Create real pipes and retain both ends for closure assertions."""
        pair = real_pipe(*args, **kwargs)
        connections.extend(pair)
        return pair

    def make_process(*args, **kwargs):
        """Create a tracked process whose factory/start raises at the configured stage."""
        if failure == "factory":
            raise OSError(canary)
        if failure == "post_start":
            kwargs["target"] = _partial_frame_worker
        process = real_process(*args, **kwargs)
        processes.append(process)
        real_start = process.start

        def fail_start():
            """Optionally start the real child, then raise the private setup OSError."""
            if failure == "post_start":
                real_start()
            raise OSError(canary)

        monkeypatch.setattr(process, "start", create_autospec(real_start, side_effect=fail_start))
        return process

    pipe = create_autospec(real_pipe, side_effect=open_pipe)
    factory = create_autospec(real_process, side_effect=make_process)
    monkeypatch.setattr(context, "Pipe", pipe)
    monkeypatch.setattr(context, "Process", factory)
    monkeypatch.setattr(
        process_boundary.multiprocessing,
        "get_context",
        create_autospec(real_get_context, return_value=context),
    )
    client = _client(_Replay(endpoint="https://archive.example.edu/feed"))
    with pytest.raises(transport.FeedTransportError) as error:
        client.read_page(since=None)
    assert error.value.error_code == "worker"
    assert canary not in "".join(traceback.format_exception(error.value))
    assert len(connections) == 2 and all(connection.closed for connection in connections)
    if failure in {"start", "post_start"}:
        assert len(processes) == 1
        with pytest.raises(ValueError, match="process object is closed"):
            processes[0].is_alive()
    else:
        assert not processes
    factory.assert_called_once()
    with pytest.raises(transport.FeedTransportError) as poisoned:
        client.read_page(since=None)
    assert poisoned.value.error_code == "transport"
    factory.assert_called_once()
    assert not caplog.records


def test_control_signal_propagates_and_poisoned_transport_cannot_start_more_io(monkeypatch):
    """Control signal propagates and poisoned transport cannot start more I/O."""
    real_run = transport._run_page_isolated
    interrupt = KeyboardInterrupt()
    run = create_autospec(real_run, spec_set=True, side_effect=interrupt)
    monkeypatch.setattr(transport, "_run_page_isolated", run)
    client = _client(_Replay(endpoint="https://archive.example.edu/feed"))
    with pytest.raises(KeyboardInterrupt) as error:
        client.read_page(since=None)
    assert error.value is interrupt
    run.assert_called_once()
    with pytest.raises(transport.FeedTransportError) as poisoned:
        client.read_page(since=None)
    assert poisoned.value.error_code == "transport"
    run.assert_called_once()

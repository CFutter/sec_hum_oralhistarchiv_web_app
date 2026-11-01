"""Real signed HTTPS chains and one terminating full-pipeline worker."""

import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import multiprocessing
import os
import signal
import ssl
import struct
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import create_autospec
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
import requests.adapters
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.paths import PROJECT_ROOT
from app.sources import (
    JsonFeedConfig,
    json_feed_harvest,
    json_feed_pages,
    json_feed_transport,
    prepare_json_feed_startup,
)
from app.sources import json_feed_fetch as fetch
from app.sources import json_feed_process as process
from app.sources.json_feed_http import FeedTransportError
from app.sources.json_feed_protocol import FeedInternalError, FeedProtocolError
from tests.feed_worker_deadline import TEST_FETCH_DEADLINE_SECONDS, deadline_after_worker_ready

_REAL_FETCH_WORKER = fetch._fetch_worker
_BEARER = "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8"
_KEY = hashlib.sha256(b"synthetic full fetch signing material").digest()
_PUBLIC = "11111111-1111-4111-8111-111111111111"
_REGISTERED = "22222222-2222-4222-8222-222222222222"
_VETTED = "33333333-3333-4333-8333-333333333333"
_WITHDRAWN = "44444444-4444-4444-8444-444444444444"
_TIER_BAD = "55555555-5555-4555-8555-555555555555"
_DUPLICATE = "66666666-6666-4666-8666-666666666666"


def _utc(value):
    """Format the supplied timestamp with Z in place of a UTC offset."""
    return value.isoformat().replace("+00:00", "Z")


def _certificates(tmp_path):
    """Write localhost CA/key PEM files and return certificate/key paths."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic feed TLS")])
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


def _ca_fetch_worker(connection, config, credentials, since, deadline):
    """Only the test CA and selected hostile stage differ from production."""
    requests.adapters.DEFAULT_CA_BUNDLE_PATH = os.environ["TEST_FEED_CA_FILE"]
    real_page_read = json_feed_transport.JsonFeedTransport.read_page
    json_feed_transport.JsonFeedTransport.read_page = create_autospec(
        real_page_read, side_effect=AssertionError("Nested page workers are forbidden")
    )
    stage = os.environ.get("TEST_FEED_BLOCK_STAGE")
    if stage and stage != "post_result":

        def block(*_args, **_kwargs):
            """Write the selected stage marker and block indefinitely for worker-termination tests."""
            Path(os.environ["TEST_FEED_STAGE_MARKER"]).write_text(stage)
            threading.Event().wait()

        if stage == "json":
            real = json_feed_pages.decode_feed_document
            json_feed_pages.decode_feed_document = create_autospec(real, side_effect=block)
        elif stage == "metadata":
            real = json_feed_harvest.classify_feed_record
            json_feed_harvest.classify_feed_record = create_autospec(real, side_effect=block)
        else:
            real = json_feed_harvest.harvest_contract.encode_harvest_result
            json_feed_harvest.harvest_contract.encode_harvest_result = create_autospec(
                real, side_effect=block
            )
    sent = None
    if stage == "post_result":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        real_send = connection.send_bytes
        sent = create_autospec(real_send, side_effect=real_send)
        connection.send_bytes = sent
    _REAL_FETCH_WORKER(connection, config, credentials, since, deadline)
    if stage == "post_result" and sent is not None:
        if sent.call_args is None or not sent.call_args.args[0].startswith(b"S"):
            return
        Path(os.environ["TEST_FEED_STAGE_MARKER"]).write_text(stage)
        threading.Event().wait()


@dataclass
class _Replay:
    """Hold mutable signed-feed pages, fault modes and observed requests."""

    endpoint: str = ""
    cutoff: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))
    snapshot: str = field(default_factory=lambda: str(uuid4()))
    records: list[dict[str, Any]] = field(default_factory=list)
    mode: str = "mixed"
    calls: list[dict[str, list[str]]] = field(default_factory=list)
    headers: list[dict[str, str]] = field(default_factory=list)
    connections: list[tuple[str, int]] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)
    body_started: threading.Event = field(default_factory=threading.Event)

    def body(self, query):
        """Build the requested example page, injecting the configured JSON/chain fault."""
        if self.mode in {"bad_json", "bad_signature"}:
            return b"{private-source-body-canary-not-json"
        second = query.get("cursor") == ["page_2"]
        records = self.records[2:] if second else self.records[:2]
        if self.mode == "empty":
            records = []
        else:
            extra = dict(self.records[0])
            extra.update(
                uuid=_DUPLICATE if second else _TIER_BAD,
                title="duplicate-title" if second else "Synthetic rejected record",
            )
            if not second:
                extra["visibility_tier"] = "invalid"
            records = [*records, extra]
        echo = {
            "nonce": query["nonce"][0],
            "since": query.get("since", [None])[0],
            "cursor": query.get("cursor", [None])[0],
        }
        if second and self.mode == "echo":
            echo["nonce"] = "0" * 64
        document = {
            "feed_version": 1,
            "snapshot_id": self.snapshot,
            "generated_at": _utc(self.cutoff),
            "request": echo,
            "records": records,
            "withdrawn": [_WITHDRAWN] if second else [],
            "next_cursor": None if second or self.mode == "empty" else "page_2",
            "complete": second or self.mode == "empty",
        }
        if second and self.mode == "snapshot":
            document["snapshot_id"] = str(uuid4())
        elif second and self.mode == "identity":
            document["records"][0]["uuid"] = _PUBLIC
        elif second and self.mode == "loop":
            document.update(complete=False, next_cursor="page_2")
        body = json.dumps(document, separators=(",", ":")).encode()
        return body.replace(
            b'"title":"duplicate-title"', b'"title":"duplicate-title","title":"duplicate-title"'
        )


def _assert_reaped():
    """Require no remaining feed worker processes or page-receiver threads."""
    assert not [
        child
        for child in multiprocessing.active_children()
        if child.name.startswith("oralhistarchiv-json-feed")
    ]
    assert not [
        thread for thread in threading.enumerate() if thread.name == "json-feed-page-receiver"
    ]


@pytest.fixture
def signed_feed(tmp_path, monkeypatch):
    """Yield a localhost signed HTTPS feed; stop its server and require worker cleanup afterwards."""
    cert, key = _certificates(tmp_path)
    replay = _Replay()
    for name in ("feed-v1-full-page-1.json", "feed-v1-full-page-2.json"):
        document = json.loads((PROJECT_ROOT / "docs" / "sources" / "examples" / name).read_text())
        replay.records.extend(document["records"])
    for record in replay.records:
        record["modified_at"] = _utc(replay.cutoff - timedelta(seconds=30))
    endpoint_path = f"/feed/{uuid4().hex}"

    class Handler(BaseHTTPRequestHandler):
        """Serve the synthetic feed over HTTP/1.1 and record requests."""

        protocol_version = "HTTP/1.1"

        def do_GET(self):
            """Record feed requests and send signed pages with configured header, signature or stall
            faults.
            """
            request = urlsplit(self.path)
            if request.path != endpoint_path:
                with contextlib.suppress(BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                return
            query = parse_qs(request.query)
            replay.calls.append(query)
            replay.headers.append(dict(self.headers))
            replay.connections.append(self.client_address)
            body = replay.body(query)
            self.send_response(200)
            self.send_header(
                "Content-Type",
                ("text/plain" if replay.mode == "bad_headers" else "application/json"),
            )
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Set-Cookie",
                "feed-session=ignored-canary; Path=/; Secure",
            )
            digest = hmac.digest(_KEY, body, "sha256").hex()
            self.send_header(
                "X-Feed-Signature", "v1=" + ("0" * 64 if replay.mode == "bad_signature" else digest)
            )
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError, ssl.SSLError):
                if replay.mode == "stall":
                    self.wfile.write(body[:1])
                    self.wfile.flush()
                    replay.body_started.set()
                    replay.release.wait(90)
                    self.wfile.write(body[1:])
                else:
                    self.wfile.write(body)

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
    monkeypatch.setattr(fetch, "_fetch_worker", _ca_fetch_worker)
    try:
        yield replay
    finally:
        replay.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        _assert_reaped()


def _inputs(replay=None, **changes):
    """Return an overridden feed configuration and matching development credentials."""
    config = JsonFeedConfig.model_validate(
        {
            "name": "fetch_test",
            "display": {"label": "Fetch test"},
            "endpoint": replay.endpoint if replay else "https://archive.example.edu/feed",
            "credential_env": "FEED_BEARER",
            "signing_key_env": "FEED_SIGNING_KEY",
            **changes,
        }
    )
    credential = prepare_json_feed_startup(
        [config],
        environment="dev",
        environ={
            "FEED_BEARER": _BEARER,
            "FEED_SIGNING_KEY": base64.urlsafe_b64encode(_KEY).decode().rstrip("="),
        },
    )[0]
    return config, credential


def test_spawned_verified_tls_chain_returns_all_tiers_withdrawal_and_fixed_quarantine(signed_feed):
    """SB-VIS-001 and SB-VIS-005: signed metadata stays bound to its authenticated page chain."""
    result = fetch.fetch_json_feed_isolated(*_inputs(signed_feed), since=None)
    assert result.validate() == signed_feed.cutoff
    assert [record["uuid"] for record in result.matching_records] == [_PUBLIC, _REGISTERED, _VETTED]
    assert [record["visibility_tier"] for record in result.matching_records] == [
        "public",
        "registered",
        "vetted",
    ]
    assert result.deleted_uuids == {_WITHDRAWN} and not result.nonmatching_uuids
    assert result.uncertain_records == {
        _TIER_BAD: "record_tier",
        _DUPLICATE: "duplicate_record_key",
    }
    assert len(signed_feed.calls) == 2
    assert "cursor" not in signed_feed.calls[0] and signed_feed.calls[1]["cursor"] == ["page_2"]
    assert len({call["nonce"][0] for call in signed_feed.calls}) == 2
    assert len(set(signed_feed.connections)) == 1
    for headers in signed_feed.headers:
        assert headers["Authorization"] == "Bearer " + _BEARER
        assert headers["Accept-Encoding"] == "identity"
        assert not any(name.casefold() == "cookie" for name in headers)
    _assert_reaped()


def test_empty_incremental_keeps_inclusive_since_and_new_nonce_for_every_fetch(signed_feed):
    """Empty incremental keeps inclusive since and new nonce for every fetch."""
    signed_feed.mode = "empty"
    since = signed_feed.cutoff - timedelta(seconds=60)
    for _ in range(2):
        result = fetch.fetch_json_feed_isolated(*_inputs(signed_feed), since=since)
        assert result.validate() == signed_feed.cutoff
        assert (
            not result.matching_records
            and not result.deleted_uuids
            and not result.uncertain_records
        )
    assert len(set(signed_feed.connections)) == 2
    assert all(call["since"] == [_utc(since)] for call in signed_feed.calls)
    assert len({call["nonce"][0] for call in signed_feed.calls}) == 2


@pytest.mark.parametrize(
    "mode,error_type,code",
    [
        ("bad_signature", FeedTransportError, "signature"),
        ("bad_json", FeedProtocolError, "json"),
        ("echo", FeedProtocolError, "request"),
        ("snapshot", FeedProtocolError, "pagination"),
        ("loop", FeedProtocolError, "pagination"),
        ("identity", FeedProtocolError, "identity"),
    ],
)
def test_signed_or_untrusted_chain_failures_return_no_harvest_or_body_details(
    signed_feed, mode, error_type, code
):
    """SB-TRANS-004: a valid earlier page cannot turn an aborted chain into a partial result."""
    signed_feed.mode = mode
    with pytest.raises(error_type) as error:
        fetch.fetch_json_feed_isolated(*_inputs(signed_feed), since=None)
    assert error.value.error_code == code
    assert "private-source-body-canary" not in "".join(traceback.format_exception(error.value))
    _assert_reaped()


@pytest.mark.parametrize(
    "budget",
    [
        "max_page_bytes",
        "max_total_bytes",
        "max_record_bytes",
        "max_records",
        "max_pages",
        "max_result_bytes",
    ],
)
def test_every_configured_size_count_budget_encloses_the_full_pipeline(signed_feed, budget):
    """SB-TRANS-002 and SB-TRANS-004: no budget breach produces candidate data."""
    if budget == "max_total_bytes":
        first = signed_feed.body({"nonce": ["a" * 64]})
        second = signed_feed.body({"nonce": ["b" * 64], "cursor": ["page_2"]})
        limit = len(first) + len(second) - 1
    else:
        limit = 1
    with pytest.raises((FeedTransportError, FeedProtocolError)) as error:
        fetch.fetch_json_feed_isolated(*_inputs(signed_feed, **{budget: limit}), since=None)
    assert error.value.error_code == "resource_limit"
    _assert_reaped()


@pytest.mark.parametrize("stage", ["json", "metadata", "serialization", "post_result"])
def test_untrusted_processing_and_serialization_stalls_are_killed_inside_the_same_worker(
    signed_feed, monkeypatch, tmp_path, stage
):
    """SB-TRANS-003: the terminating deadline covers JSON, metadata and serialization."""
    marker = tmp_path / "stage-entered"
    monkeypatch.setenv("TEST_FEED_BLOCK_STAGE", stage)
    monkeypatch.setenv("TEST_FEED_STAGE_MARKER", str(marker))
    monkeypatch.setattr(process, "_WORKER_SHUTDOWN_SECONDS", 0.2)
    timing = deadline_after_worker_ready(monkeypatch, marker.is_file)
    with pytest.raises(FeedTransportError) as error:
        fetch.fetch_json_feed_isolated(
            *_inputs(signed_feed, fetch_deadline_seconds=TEST_FETCH_DEADLINE_SECONDS), since=None
        )
    assert error.value.error_code == "resource_limit"
    assert marker.read_text() == stage
    timing.assert_terminated_after_readiness()
    _assert_reaped()


def test_real_slow_body_is_terminated_before_socket_inactivity_can_extend_the_fetch(
    signed_feed, monkeypatch
):
    """Real slow body is terminated before socket inactivity can extend the fetch."""
    signed_feed.mode = "stall"
    monkeypatch.setattr(process, "_WORKER_SHUTDOWN_SECONDS", 0.2)
    timing = deadline_after_worker_ready(monkeypatch, signed_feed.body_started.is_set)
    with pytest.raises(FeedTransportError) as error:
        fetch.fetch_json_feed_isolated(
            *_inputs(signed_feed, fetch_deadline_seconds=TEST_FETCH_DEADLINE_SECONDS), since=None
        )
    assert error.value.error_code == "resource_limit" and signed_feed.calls
    timing.assert_terminated_after_readiness()
    _assert_reaped()


def _partial_worker(connection, _config, _credentials, _since, _deadline):
    """Ignore SIGTERM, write an incomplete IPC frame and block for forced-kill tests."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(connection.fileno(), struct.pack("!i", 1024) + b"S")
    Path(os.environ["TEST_FEED_STAGE_MARKER"]).write_text("partial")
    threading.Event().wait()


def test_partial_result_ipc_is_killed_and_reaped_even_when_sigterm_is_ignored(
    monkeypatch, tmp_path
):
    """Partial result IPC is killed and reaped even when sigterm is ignored."""
    marker = tmp_path / "partial-frame-entered"
    monkeypatch.setenv("TEST_FEED_STAGE_MARKER", str(marker))
    timing = deadline_after_worker_ready(monkeypatch, marker.is_file)
    real_receive = process._receive
    receive = create_autospec(real_receive, side_effect=real_receive)
    monkeypatch.setattr(process, "_receive", receive)
    monkeypatch.setattr(process, "_WORKER_SHUTDOWN_SECONDS", 0.2)
    monkeypatch.setattr(fetch, "_fetch_worker", _partial_worker)
    with pytest.raises(FeedTransportError) as error:
        fetch.fetch_json_feed_isolated(
            *_inputs(fetch_deadline_seconds=TEST_FETCH_DEADLINE_SECONDS), since=None
        )
    assert error.value.error_code == "resource_limit"
    receive.assert_called_once()
    assert marker.read_text() == "partial"
    timing.assert_terminated_after_readiness()
    _assert_reaped()


def _frame_worker(connection, config, _credentials, _since, _deadline):
    """Send the IPC frame selected by TEST_FEED_FRAME and close the connection."""
    mode = os.environ["TEST_FEED_FRAME"]
    frames = {
        "transport": b"Tsignature",
        "protocol": b"Prequest",
        "unknown": b"Tprivate-credential-canary",
        "malformed": b"Snot-json",
        "kind": b"?unknown",
    }
    with contextlib.suppress(BrokenPipeError, OSError):
        connection.send_bytes(
            b"S" + b"x" * (config.max_result_bytes + 33) if mode == "oversized" else frames[mode]
        )
    connection.close()


@pytest.mark.parametrize(
    "mode,error_type,code",
    [
        ("transport", FeedTransportError, "signature"),
        ("protocol", FeedProtocolError, "request"),
        ("unknown", FeedTransportError, "worker"),
        ("malformed", FeedTransportError, "worker"),
        ("kind", FeedTransportError, "worker"),
        ("oversized", FeedTransportError, "worker"),
    ],
)
def test_parent_accepts_only_bounded_fixed_worker_protocol(monkeypatch, mode, error_type, code):
    """Parent accepts only bounded fixed worker protocol."""
    monkeypatch.setenv("TEST_FEED_FRAME", mode)
    monkeypatch.setattr(fetch, "_fetch_worker", _frame_worker)
    with pytest.raises(error_type) as error:
        fetch.fetch_json_feed_isolated(*_inputs(max_result_bytes=64), since=None)
    assert error.value.error_code == code
    assert "private-credential-canary" not in "".join(traceback.format_exception(error.value))
    _assert_reaped()


def test_direct_verified_collector_returns_only_a_complete_bounded_candidate(
    signed_feed, monkeypatch
):
    """SB-TRANS-004: the direct worker-owned operation releases no partial page result."""
    monkeypatch.setattr(
        requests.adapters, "DEFAULT_CA_BUNDLE_PATH", os.environ["TEST_FEED_CA_FILE"]
    )
    config, credentials = _inputs(signed_feed)
    payload = fetch.collect_feed_payload(
        config, credentials, since=None, deadline=time.monotonic() + 5
    )
    candidate = json.loads(payload)
    assert len(payload) <= config.max_result_bytes
    assert set(candidate) == {
        "matching_records",
        "deleted_uuids",
        "nonmatching_uuids",
        "uncertain_records",
        "source_cursor",
    }
    assert [record["uuid"] for record in candidate["matching_records"]] == [
        _PUBLIC,
        _REGISTERED,
        _VETTED,
    ]
    assert candidate["deleted_uuids"] == [_WITHDRAWN] and not candidate["nonmatching_uuids"]
    assert candidate["uncertain_records"] == {
        _TIER_BAD: "record_tier",
        _DUPLICATE: "duplicate_record_key",
    }
    assert datetime.fromisoformat(candidate["source_cursor"]) == signed_feed.cutoff
    assert len(signed_feed.calls) == 2


@pytest.mark.parametrize("kind", ["transport", "protocol", "internal", "unexpected"])
def test_real_fetch_worker_sends_fixed_failure_frames_and_closes_its_pipe(
    monkeypatch, caplog, kind
):
    """SB-VIS-005 and SB-TRANS-004: diagnostics cannot carry upstream exception values."""
    failure, expected = {
        "transport": (FeedTransportError("signature"), b"Tsignature"),
        "protocol": (FeedProtocolError("request"), b"Prequest"),
        "internal": (FeedInternalError(), b"Tworker"),
        "unexpected": (ValueError("private-worker-credential-canary"), b"Tworker"),
    }[kind]
    real_collect = fetch.collect_feed_payload
    collect = create_autospec(real_collect, spec_set=True, side_effect=failure)
    monkeypatch.setattr(fetch, "collect_feed_payload", collect)
    config, credentials = _inputs()
    receive, send = multiprocessing.get_context("spawn").Pipe(duplex=False)
    try:
        _REAL_FETCH_WORKER(send, config, credentials, None, time.monotonic() + 5)
        frame = receive.recv_bytes(32)
        assert frame == expected and send.closed
        assert b"private-worker-credential-canary" not in frame
    finally:
        receive.close()
        send.close()
    collect.assert_called_once()
    assert not caplog.records


@pytest.mark.parametrize(
    "mode,failure_stage,error_type,error_code",
    [
        ("mixed", None, None, None),
        ("bad_headers", None, FeedTransportError, "headers"),
        ("bad_signature", None, FeedTransportError, "signature"),
        ("bad_json", None, FeedProtocolError, "json"),
        ("snapshot", None, FeedProtocolError, "pagination"),
        ("mixed", "finish", FeedProtocolError, "state"),
    ],
    ids=[
        "success",
        "headers",
        "signature",
        "decode",
        "pagination",
        "finish",
    ],
)
def test_complete_collector_owns_one_session_and_closes_it_on_every_exit(
    signed_feed,
    monkeypatch,
    mode,
    failure_stage,
    error_type,
    error_code,
):
    """Complete collector owns one session and closes it on every exit."""
    monkeypatch.setattr(
        requests.adapters,
        "DEFAULT_CA_BUNDLE_PATH",
        os.environ["TEST_FEED_CA_FILE"],
    )
    signed_feed.mode = mode
    real_factory = fetch.feed_http_session
    closes = []

    @contextlib.contextmanager
    def owned_session():
        """Yield a real HTTP session with a close spy retained for cleanup assertions."""
        with real_factory() as session:
            real_close = session.close
            close = create_autospec(
                real_close,
                spec_set=True,
                side_effect=real_close,
            )
            monkeypatch.setattr(session, "close", close)
            closes.append(close)
            yield session

    factory = create_autospec(
        real_factory,
        spec_set=True,
        side_effect=owned_session,
    )
    monkeypatch.setattr(
        fetch,
        "feed_http_session",
        factory,
    )

    if failure_stage == "finish":
        real_finish = json_feed_harvest.JsonFeedHarvestBuilder.finish
        monkeypatch.setattr(
            json_feed_harvest.JsonFeedHarvestBuilder,
            "finish",
            create_autospec(
                real_finish,
                spec_set=True,
                side_effect=FeedProtocolError("state"),
            ),
        )

    config, credentials = _inputs(signed_feed)

    if error_type is None:
        payload = fetch.collect_feed_payload(
            config,
            credentials,
            since=None,
            deadline=time.monotonic() + 5,
        )
        assert json.loads(payload)["matching_records"]
    else:
        with pytest.raises(error_type) as error:
            fetch.collect_feed_payload(
                config,
                credentials,
                since=None,
                deadline=time.monotonic() + 5,
            )
        assert error.value.error_code == error_code

    factory.assert_called_once_with()
    assert len(closes) == 1
    closes[0].assert_called_once_with()
    assert len(set(signed_feed.connections)) == 1
    assert all(
        not any(name.casefold() == "cookie" for name in headers) for headers in signed_feed.headers
    )


def test_collector_rechecks_deadline_after_the_owned_session_closes(
    signed_feed,
    monkeypatch,
):
    """Collector rechecks deadline after the owned session closes."""
    monkeypatch.setattr(
        requests.adapters,
        "DEFAULT_CA_BUNDLE_PATH",
        os.environ["TEST_FEED_CA_FILE"],
    )
    signed_feed.mode = "empty"
    real_factory = fetch.feed_http_session
    real_check = fetch.check_feed_deadline
    closed = False

    @contextlib.contextmanager
    def closing_session():
        """Yield a real HTTP session and record when its context has closed."""
        nonlocal closed
        with real_factory() as session:
            yield session
        closed = True

    def check(deadline):
        """Raise resource_limit after session closure; otherwise delegate deadline checking."""
        if closed:
            # Simulate expiry during shutdown without changing the
            # clocks used by TLS, sockets or server teardown.
            raise FeedTransportError("resource_limit")
        return real_check(deadline)

    monkeypatch.setattr(
        fetch,
        "feed_http_session",
        create_autospec(
            real_factory,
            spec_set=True,
            side_effect=closing_session,
        ),
    )
    monkeypatch.setattr(
        fetch,
        "check_feed_deadline",
        create_autospec(
            real_check,
            spec_set=True,
            side_effect=check,
        ),
    )

    config, credentials = _inputs(signed_feed)
    with pytest.raises(FeedTransportError) as error:
        fetch.collect_feed_payload(
            config,
            credentials,
            since=None,
            deadline=time.monotonic() + 5,
        )

    assert closed
    assert error.value.error_code == "resource_limit"

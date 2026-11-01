"""Raw transport: real byte streams and HMAC, with an isolated HTTP boundary."""

import hashlib
import hmac
import io
import time
import traceback
from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest
import requests
from pydantic import SecretBytes, SecretStr
from urllib3._collections import HTTPHeaderDict
from urllib3.exceptions import HTTPError
from urllib3.response import HTTPResponse

from app.sources import JsonFeedConfig, JsonFeedCredentials
from app.sources import json_feed_http as transport

_KEY = hashlib.sha256(b"synthetic page signing material").digest()
_BEARER = "synthetic-bearer-private-canary"
_BODY = b'{"confidential":"synthetic"}\xff'
_REQUEST = transport.FeedRequest("a" * 64, None, None)


def _signature(body):
    """Return the v1 lowercase-hex HMAC-SHA256 signature over body."""
    return "v1=" + hmac.new(_KEY, body, hashlib.sha256).hexdigest()


@pytest.fixture
def boundary(monkeypatch):
    """Only session.get is isolated; streams, close, mounts and HMAC remain real."""
    real_session = requests.Session

    def create(body=_BODY, headers=None, *, status=200):
        """Build a real byte-stream response with strict session/read spies and configurable
        headers/status.
        """
        config = JsonFeedConfig.model_validate(
            {
                "name": "private_archive",
                "display": {"label": "Private archive"},
                "endpoint": "https://archive.example.edu/feed",
                "credential_env": "FEED_BEARER",
                "signing_key_env": "FEED_SIGNING_KEY",
            }
        )
        credentials = JsonFeedCredentials(config.name, SecretStr(_BEARER), SecretBytes(_KEY))
        raw = HTTPResponse(
            body=io.BytesIO(body),
            preload_content=False,
            enforce_content_length=False,
            headers=HTTPHeaderDict(
                headers
                if headers is not None
                else [
                    ("Content-Type", "application/json"),
                    ("X-Feed-Signature", _signature(body)),
                ]
            ),
        )
        read = create_autospec(raw.read, spec_set=True, side_effect=raw.read)
        monkeypatch.setattr(raw, "read", read)
        response = requests.Response()
        response.status_code, response.raw = status, raw
        json = create_autospec(
            response.json, spec_set=True, side_effect=AssertionError("JSON decoded")
        )
        monkeypatch.setattr(response, "json", json)
        session = real_session()
        get = create_autospec(session.get, spec_set=True, return_value=response)
        close = create_autospec(session.close, spec_set=True, side_effect=session.close)
        monkeypatch.setattr(session, "get", get)
        monkeypatch.setattr(session, "close", close)
        factory = create_autospec(real_session, spec_set=True, return_value=session)
        monkeypatch.setattr(transport.requests, "Session", factory)
        return SimpleNamespace(
            config=config,
            credentials=credentials,
            raw=raw,
            response=response,
            read=read,
            session=session,
            get=get,
            close=close,
            factory=factory,
            json=json,
        )

    return create


def _download(state, **changes):
    """Download through an owned session, defaulting to 1,024 bytes and a 60-second deadline."""
    deadline = changes.pop("deadline") if "deadline" in changes else time.monotonic() + 60

    with transport.feed_http_session() as session:
        return transport.download_authenticated_page(
            state.config,
            state.credentials,
            changes.pop("request", _REQUEST),
            session=session,
            max_bytes=changes.pop("max_bytes", 1024),
            deadline=deadline,
        )


@pytest.mark.parametrize("since,cursor", [(None, None), ("2030-01-02T03:04:05Z", "page-two")])
def test_authenticated_bytes_and_explicit_request_survive_without_parsing(boundary, since, cursor):
    """SB-TRANS-001 / SB-VIS-005: fixed TLS endpoint and exact-byte authentication."""
    state = boundary()
    request = transport.FeedRequest("b" * 64, since, cursor)
    assert _download(state, request=request) == _BODY  # Intentionally invalid UTF-8/JSON.
    state.factory.assert_called_once_with()
    state.get.assert_called_once()
    assert state.get.call_args.args == (state.config.endpoint,)
    options = state.get.call_args.kwargs
    expected = {"nonce": request.nonce}
    if since is not None:
        expected["since"] = since
    if cursor is not None:
        expected["cursor"] = cursor
    assert options["params"] == expected
    assert options["headers"] == {
        "Authorization": f"Bearer {_BEARER}",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    assert options["verify"] is True and options["stream"] is True
    assert options["allow_redirects"] is False and state.session.trust_env is False
    assert all(0 < timeout <= 10 for timeout in options["timeout"])
    assert state.session.adapters["https://"].max_retries.total == 0
    assert all(call.kwargs == {"decode_content": False} for call in state.read.call_args_list)
    state.json.assert_not_called()
    state.close.assert_called_once_with()
    assert state.raw.closed


@pytest.mark.parametrize("status", [201, 204, 301, 302, 303, 304, 307, 308, 401, 404, 500])
def test_every_non_200_status_aborts_without_reading_or_following(boundary, status):
    """Every non 200 status aborts without reading or following."""
    state = boundary(status=status)
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "http_status"
    state.get.assert_called_once()
    state.read.assert_not_called()
    assert state.raw.closed
    state.close.assert_called_once()


@pytest.mark.parametrize(
    "name", ["Content-Type", "Content-Encoding", "Content-Length", "X-Feed-Signature"]
)
def test_duplicate_security_relevant_headers_are_not_folded(boundary, name):
    """Duplicate security relevant headers are not folded."""
    values = {
        "Content-Type": "application/json",
        "Content-Encoding": "identity",
        "Content-Length": str(len(_BODY)),
        "X-Feed-Signature": _signature(_BODY),
    }
    headers = [*values.items(), (name, values[name])]
    state = boundary(headers=headers)
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "headers"
    state.read.assert_not_called()


@pytest.mark.parametrize(
    "name,value",
    [
        ("Content-Type", "text/json"),
        ("Content-Type", "application/json; charset=latin1"),
        ("Content-Type", "application/json; charset=utf-8; other=x"),
        ("Content-Encoding", "gzip"),
        ("Content-Encoding", "identity,gzip"),
        ("Content-Length", "-1"),
        ("Content-Length", "+1"),
        ("Content-Length", " 1"),
        ("Content-Length", "1,1"),
        ("Content-Length", "٣"),
        ("Content-Length", ""),
    ],
)
def test_invalid_header_values_abort_before_body_read(boundary, name, value):
    """Invalid header values abort before body read."""
    headers = {
        "Content-Type": "application/json",
        "X-Feed-Signature": _signature(_BODY),
        name: value,
    }
    state = boundary(headers=list(headers.items()))
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "headers"
    state.read.assert_not_called()


@pytest.mark.parametrize("name", ["Content-Type", "X-Feed-Signature"])
def test_required_headers_cannot_be_missing(boundary, name):
    """Required headers cannot be missing."""
    headers = {"Content-Type": "application/json", "X-Feed-Signature": _signature(_BODY)}
    del headers[name]
    state = boundary(headers=list(headers.items()))
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "headers"
    state.read.assert_not_called()


@pytest.mark.parametrize(
    "content_type",
    ["APPLICATION/JSON", "application/json; charset=UTF-8", 'application/json; charset="utf-8"'],
)
def test_only_json_with_optional_utf8_and_identity_encoding_is_accepted(boundary, content_type):
    """Only JSON with optional UTF-8 and identity encoding is accepted."""
    state = boundary(
        headers=[
            ("Content-Type", content_type),
            ("Content-Encoding", "identity"),
            ("X-Feed-Signature", _signature(_BODY)),
            ("Content-Length", str(len(_BODY))),
        ]
    )
    assert _download(state) == _BODY


@pytest.mark.parametrize(
    "signature",
    [
        "v2=" + "a" * 64,
        "v1=" + "A" * 64,
        "v1=" + "0" * 64,
        "v1=" + "a" * 63,
        _signature(_BODY) + " ",
        "private-signature-canary\r\nInjected: yes",
    ],
)
def test_malformed_or_wrong_signature_is_refused_without_disclosure(boundary, signature, caplog):
    """Malformed or wrong signature is refused without disclosure."""
    state = boundary(
        headers=[("Content-Type", "application/json"), ("X-Feed-Signature", signature)]
    )
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "signature"
    assert "private-signature-canary" not in str(error.value)
    assert not caplog.records and state.raw.closed
    state.json.assert_not_called()


def test_signature_authenticates_original_bytes_and_uses_constant_time_comparison(
    boundary, monkeypatch
):
    """Signature authenticates original bytes and uses constant time comparison."""
    state = boundary(
        body=_BODY + b" ",
        headers=[("Content-Type", "application/json"), ("X-Feed-Signature", _signature(_BODY))],
    )
    real_compare = hmac.compare_digest
    compare = create_autospec(real_compare, spec_set=True, side_effect=real_compare)
    monkeypatch.setattr(transport.hmac, "compare_digest", compare)
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "signature"
    compare.assert_called_once()
    state.json.assert_not_called()


@pytest.mark.parametrize("extra", [0, 1])
def test_stream_limit_accepts_exact_boundary_and_reads_only_one_extra_probe_byte(boundary, extra):
    """SB-TRANS-002: unknown-length bodies consume the remaining aggregate allowance."""
    state = boundary(body=b"x" * (40 + extra))
    if extra:
        with pytest.raises(transport.FeedTransportError) as error:
            _download(state, max_bytes=40)
        assert error.value.error_code == "resource_limit"
    else:
        assert _download(state, max_bytes=40) == b"x" * 40
    assert all(0 < call.args[0] <= 41 for call in state.read.call_args_list)
    assert state.raw.closed


@pytest.mark.parametrize("length", ["1025", "9" * 10000])
def test_unbounded_declared_length_aborts_before_body_read(boundary, length):
    """Unbounded declared length aborts before body read."""
    state = boundary(
        headers=[
            ("Content-Type", "application/json"),
            ("X-Feed-Signature", _signature(_BODY)),
            ("Content-Length", length),
        ]
    )
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "resource_limit"
    state.read.assert_not_called()


def test_truncated_declared_body_is_not_accepted_even_with_matching_signature(boundary):
    """Truncated declared body is not accepted even with matching signature."""
    state = boundary(
        headers=[
            ("Content-Type", "application/json"),
            ("X-Feed-Signature", _signature(_BODY)),
            ("Content-Length", str(len(_BODY) + 1)),
        ]
    )
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "transport"


@pytest.mark.parametrize(
    "stage,error_type", [("get", requests.RequestException), ("read", HTTPError), ("read", OSError)]
)
def test_transport_failures_are_fixed_and_close_owned_resources(
    boundary, stage, error_type, caplog
):
    """Transport failures are fixed and close owned resources."""
    state = boundary()
    getattr(state, stage).side_effect = error_type(f"{_BEARER} https://private-url.example.org")
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "transport"
    rendered = "".join(traceback.format_exception(error.value))
    assert _BEARER not in rendered and "private-url" not in rendered
    assert not caplog.records
    state.close.assert_called_once()
    if stage == "read":
        assert state.raw.closed


def test_deadline_expiry_during_streaming_discards_partial_body(boundary, monkeypatch):
    """SB-TRANS-003: cooperative checks supplement the terminating parent watchdog."""
    state = boundary()
    monotonic = create_autospec(time.monotonic, side_effect=[0.0, 0.0, 0.0, 2.0])
    monkeypatch.setattr(transport.time, "monotonic", monotonic)
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state, deadline=1.0)
    assert error.value.error_code == "resource_limit" and state.read.call_count == 1
    assert state.raw.closed


@pytest.mark.parametrize("budget", [0, -1, True, 1_048_577])
def test_invalid_internal_budget_fails_before_io(boundary, budget):
    """Invalid internal budget fails before I/O."""
    state = boundary()
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state, max_bytes=budget)
    assert error.value.error_code == "worker"
    state.get.assert_not_called()
    state.close.assert_called_once_with()


def test_expired_deadline_fails_before_io(boundary):
    """Expired deadline fails before I/O."""
    state = boundary()
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state, deadline=time.monotonic() - 1)
    assert error.value.error_code == "resource_limit"
    state.get.assert_not_called()
    state.close.assert_called_once_with()


def test_credentials_for_another_source_fail_before_io(boundary):
    """Credentials for another source fail before I/O."""
    state = boundary()
    state.credentials = JsonFeedCredentials("another_source", SecretStr(_BEARER), SecretBytes(_KEY))
    with pytest.raises(transport.FeedTransportError) as error:
        _download(state)
    assert error.value.error_code == "worker"
    state.get.assert_not_called()
    state.close.assert_called_once_with()


def test_downloader_requires_an_explicit_session_before_any_io(boundary):
    """Downloader requires an explicit session before any I/O."""
    state = boundary()
    try:
        with pytest.raises(TypeError, match="session"):
            transport.download_authenticated_page(
                state.config,
                state.credentials,
                _REQUEST,
                max_bytes=1024,
                deadline=time.monotonic() + 60,
            )

        state.factory.assert_not_called()
        state.get.assert_not_called()
    finally:
        state.session.close()


def test_two_pages_close_responses_but_keep_the_owned_session_open(boundary):
    """Two pages close responses but keep the owned session open."""
    first_body = b"first authenticated page"
    second_body = b"second authenticated page"
    state = boundary(body=first_body)

    second_response = requests.Response()
    second_response.status_code = 200
    second_response.raw = HTTPResponse(
        body=io.BytesIO(second_body),
        preload_content=False,
        enforce_content_length=False,
        headers=HTTPHeaderDict(
            [
                ("Content-Type", "application/json"),
                ("X-Feed-Signature", _signature(second_body)),
            ]
        ),
    )

    state.get.side_effect = [
        state.response,
        second_response,
    ]
    deadline = time.monotonic() + 60

    with transport.feed_http_session() as session:
        assert session is state.session

        for request, body, response in (
            (_REQUEST, first_body, state.response),
            (
                transport.FeedRequest(
                    "b" * 64,
                    None,
                    "page-two",
                ),
                second_body,
                second_response,
            ),
        ):
            assert (
                transport.download_authenticated_page(
                    state.config,
                    state.credentials,
                    request,
                    session=session,
                    max_bytes=1024,
                    deadline=deadline,
                )
                == body
            )

            assert response.raw.closed
            state.close.assert_not_called()

    state.factory.assert_called_once_with()
    assert state.get.call_count == 2
    state.close.assert_called_once_with()

"""Exercise the production spawned OAI worker against recorded loopback HTTP."""

import contextlib
import json
import multiprocessing
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest

from app.services import harvest_result_from_document
from app.sources import oai_client
from tests.oai_fixtures import SAMPLE_CMDI_XML, SOURCE_CURSOR

_SINCE = "2026-03-01T00:00:00Z"
_INSTITUTION = "Recorded local archive"
_LIVE = "oai:local:live"
_DELETED = "oai:local:deleted"
_NONMATCHING = "oai:local:nonmatching"
_UNCERTAIN = "oai:local:uncertain"
_TOKEN = "recorded-page-2"
_FIRST_QUERY = {
    "verb": ["ListRecords"],
    "metadataPrefix": ["oai_cmdi12"],
    "from": [_SINCE],
}
_NEXT_QUERY = {"verb": ["ListRecords"], "resumptionToken": [_TOKEN]}


def _record(identifier: str, institution: str | None) -> str:
    """Replace the sample record identity and optionally remove its institution elements."""
    xml = SAMPLE_CMDI_XML.replace("oai:swissubase.ch:test-uuid-xml", identifier)
    for original in ("Universität Beispielstadt", "Example University"):
        element = f"<cmdp:Institution>{original}</cmdp:Institution>"
        replacement = (
            f"<cmdp:Institution>{institution}</cmdp:Institution>" if institution is not None else ""
        )
        xml = xml.replace(element, replacement)
    return xml


def _page(records: str, *, cursor: str, token: str) -> bytes:
    """Encode a ListRecords page with the supplied records, cursor, and resumption token."""
    return (
        f'<OAI-PMH xmlns="{oai_client.OAI_NS}">'
        f"<responseDate>{cursor}</responseDate><ListRecords>{records}"
        f"<resumptionToken>{token}</resumptionToken></ListRecords></OAI-PMH>"
    ).encode()


@dataclass
class _Replay:
    """Hold the replay endpoint and observed OAI queries and errors."""

    endpoint: str
    queries: list[dict[str, list[str]]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@pytest.fixture
def recorded_oai_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Replay]:
    """Serve two fixed pages and keep every observation in the pytest parent."""
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    # This bounds the parent even if its actual spawned worker fails to report.
    monkeypatch.setattr(oai_client, "_OAI_TOTAL_TIMEOUT_SECONDS", 30.0)
    first = _page(
        _record(_LIVE, _INSTITUTION) + _record(_NONMATCHING, "Different archive"),
        cursor="2026-09-10T12:00:00Z",
        token=_TOKEN,
    )
    second = _page(
        f'<record><header status="deleted"><identifier>{_DELETED}</identifier>'
        "<datestamp>2026-03-06T13:38:02Z</datestamp></header></record>" + _record(_UNCERTAIN, None),
        cursor="2026-09-10T12:05:00Z",
        token="",
    )
    replay = _Replay(endpoint="")
    endpoint_path = f"/oai/{uuid4().hex}"

    class Handler(BaseHTTPRequestHandler):
        """Serve the two recorded OAI pages and record request-contract failures."""

        timeout = 5

        def do_GET(self) -> None:
            """Serve recognized OAI queries, recording encoding violations and unexpected requests."""
            request = urlsplit(self.path)
            if request.path != endpoint_path:
                # Other local probes may reach a port reused by this fixture.
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.send_response(HTTPStatus.NOT_FOUND)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                return

            query = parse_qs(request.query, keep_blank_values=True)
            replay.queries.append(query)
            if self.headers.get("Accept-Encoding") != "identity":
                replay.errors.append("The OAI request did not require identity encoding")
            if query == _FIRST_QUERY:
                body, status = first, HTTPStatus.OK
            elif query == _NEXT_QUERY:
                body, status = second, HTTPStatus.OK
            else:
                replay.errors.append(f"Unexpected request: {self.path}")
                body, status = b"Unexpected recorded request", HTTPStatus.BAD_REQUEST
            self.send_response(status)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            """Suppress the HTTP server's default request logging."""
            pass

    class Server(HTTPServer):
        """Capture HTTP handler failures instead of printing server tracebacks."""

        def handle_error(self, _request: object, _client_address: object) -> None:
            """Record a request-handler failure in the replay error list."""
            replay.errors.append("The recorded HTTP request handler failed")

    server = Server(("127.0.0.1", 0), Handler)
    replay.endpoint = f"http://127.0.0.1:{server.server_port}{endpoint_path}"
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        name="recorded-oai-http",
        daemon=True,
    )
    thread.start()
    try:
        yield replay
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "recorded OAI server thread was not stopped"
        assert not replay.errors, replay.errors
        assert not any(
            child.name == "oralhistarchiv-oai-harvest"
            for child in multiprocessing.active_children()
        ), "the isolated OAI call left a harvest worker alive"


def test_replay_server_keeps_unrelated_requests_out_of_the_harvest(
    recorded_oai_server: _Replay,
) -> None:
    """A root probe must not alter the selected endpoint's transcript."""
    port = urlsplit(recorded_oai_server.endpoint).port
    assert port is not None
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/", headers={"Accept-Encoding": "gzip"})
        response = connection.getresponse()
        assert response.status == HTTPStatus.NOT_FOUND
        assert response.read() == b""
    finally:
        connection.close()

    assert recorded_oai_server.queries == []
    assert recorded_oai_server.errors == []


def test_spawned_worker_returns_parsed_classifications_with_a_valid_wire_round_trip(
    recorded_oai_server: _Replay,
) -> None:
    """Check spawned worker returns parsed classifications with a valid wire round trip."""
    result = oai_client.fetch_updates_isolated(
        recorded_oai_server.endpoint,
        _SINCE,
        _INSTITUTION,
        max_pages=2,
        source="test_archive",
        log_level="INFO",
        log_format="json",
    )

    assert recorded_oai_server.queries == [_FIRST_QUERY, _NEXT_QUERY]
    assert result.source_cursor == SOURCE_CURSOR
    assert result.validate() == SOURCE_CURSOR
    assert len(result.matching_records) == 1
    record = result.matching_records[0]
    assert record["uuid"] == _LIVE
    assert record["title"] == "Test Dataset Title"
    assert record["authors"] == ["Müller, Urs", "Keller, Anna"]
    assert record["institutions"] == [_INSTITUTION, _INSTITUTION]
    assert record["upstream_modified_at"] == datetime(2026, 3, 6, 13, 38, 2, tzinfo=UTC)
    assert result.deleted_uuids == {_DELETED}
    assert result.nonmatching_uuids == {_NONMATCHING}
    assert result.uncertain_records == {
        _UNCERTAIN: "missing or unusable institution metadata",
    }
    payload = oai_client.encode_harvest_result(result)
    assert isinstance(payload, bytes) and payload
    assert harvest_result_from_document(json.loads(payload)) == result


def test_spawned_worker_applies_the_selected_page_cap(
    recorded_oai_server: _Replay,
) -> None:
    """Check spawned worker applies the selected page cap."""
    with pytest.raises(oai_client.OAIProtocolError) as failure:
        oai_client.fetch_updates_isolated(
            recorded_oai_server.endpoint,
            _SINCE,
            _INSTITUTION,
            max_pages=1,
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )

    assert failure.value.error_code == "pagination_loop"
    assert recorded_oai_server.queries == [_FIRST_QUERY]

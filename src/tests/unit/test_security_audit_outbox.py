"""Durable event payload boundaries and independently acknowledged delivery."""

import json
import subprocess
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec
from uuid import uuid4

import pytest
import requests
from psycopg import AsyncCursor
from psycopg.pq import TransactionStatus

from app.services import audit_outbox as outbox


async def test_append_uses_the_owning_cursor_without_returning_or_commit():
    """Check append uses the owning cursor without returning or commit."""
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    identifier = await outbox.append_security_event_cur(
        cursor,
        "dataset_hidden",
        {"dataset_id": 7, "source": "archive", "reason": "record_rejected"},
    )
    query, values = cursor.execute.await_args.args
    assert "RETURNING" not in query
    assert values[0] == identifier
    assert values[1] == "dataset_hidden"
    assert values[2].obj == {
        "dataset_id": 7,
        "source": "archive",
        "reason": "record_rejected",
    }
    cursor.fetchone.assert_not_awaited()


@pytest.mark.parametrize(
    "kind,payload",
    [
        ("bad\nkind", {}),
        ("x" * 65, {}),
        ("dataset_hidden", {"description": "sensitive text"}),
        ("dataset_hidden", {"before": {"password": "sensitive text"}}),
        ("dataset_hidden", {"uuid": "x" * 513}),
        ("dataset_hidden", {"dataset_id": True}),
        ("dataset_hidden", {"uuid": ["not-a-scalar"]}),
    ],
)
async def test_invalid_or_unapproved_event_fields_never_reach_storage(kind, payload):
    """Check invalid or unapproved event fields never reach storage (ValueError)."""
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    with pytest.raises(ValueError):
        await outbox.append_security_event_cur(cursor, kind, payload)
    cursor.execute.assert_not_awaited()


class _Response:
    """Stream configured HTTP response bytes without a network connection."""

    def __init__(self, content, *, status=200):
        """Store the response body and status code."""
        self.status_code = status
        self.content = content

    def __enter__(self):
        """Return this fake resource from its context manager."""
        return self

    def __exit__(self, *_args):
        """Leave the fake resource unchanged and propagate exceptions."""
        pass

    def iter_content(self, *, chunk_size):
        """Yield chunk_size-byte slices; zero raises ValueError and negative values yield no chunks."""
        for index in range(0, len(self.content), chunk_size):
            yield self.content[index : index + chunk_size]


class _Session:
    """Record HTTP setup and consume scripted POST replies or exceptions."""

    def __init__(self, replies):
        """Initialize scripted replies, recorded calls, headers, and mounted adapters."""
        self.replies = replies
        self.calls = []
        self.headers = {}
        self.trust_env = True
        self.mounts = {}

    def __enter__(self):
        """Return this fake resource from its context manager."""
        return self

    def __exit__(self, *_args):
        """Leave the fake resource unchanged and propagate exceptions."""
        pass

    def mount(self, prefix, adapter):
        """Record the adapter mounted for the selected URL prefix."""
        self.mounts[prefix] = adapter

    def post(self, url, **kwargs):
        """Record a POST and consume its reply; raise scripted exceptions or IndexError when replies
        run out.
        """
        self.calls.append((url, kwargs))
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


@pytest.mark.parametrize(
    "reply",
    [
        _Response(b"{}"),
        _Response(b"not-json"),
        _Response(b"x" * 4097),
        _Response(b'{"event_id":"another-event","stored":true}'),
        _Response(b"{}", status=302),
        requests.ConnectionError("secret-containing transport exception"),
    ],
)
def test_sink_failure_never_counts_as_a_durable_receipt(reply):
    """Check sink failure never counts as a durable receipt."""
    with pytest.raises(outbox.AuditDeliveryError) as caught:
        outbox._send_event(_Session([reply]), "https://sink.example/events", {"event_id": "event"})
    assert "secret-containing" not in str(caught.value)


def test_matching_receipt_requires_explicit_durable_storage_and_bounded_verified_transport():
    """Check matching receipt requires explicit durable storage and bounded verified transport."""
    event = {"event_id": "event"}
    session = _Session([_Response(b'{"event_id":"event","stored":true}')])
    outbox._send_event(session, "https://sink.example/events", event)
    _, options = session.calls[0]
    assert options == {
        "json": event,
        "timeout": (2, 5),
        "allow_redirects": False,
        "stream": True,
        "verify": True,
    }
    with pytest.raises(outbox.AuditDeliveryError):
        outbox._send_event(
            _Session([_Response(b'{"event_id":"event","stored":false}')]),
            "https://sink.example/events",
            event,
        )


class _Connection:
    """Simulate receipt writes, transaction outcome, and event reads for audit delivery."""

    def __init__(self, events):
        """Initialize events and receipt/transaction state with an idle connection status."""
        self.events = events
        self.receipts = []
        self.committed = False
        self.rolled_back = False
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)

    @contextmanager
    def transaction(self):
        """Record commit on success or clear receipts and propagate rollback on failure."""
        try:
            yield
        except BaseException:
            self.receipts.clear()
            self.rolled_back = True
            raise
        else:
            self.committed = True

    @contextmanager
    def cursor(self, **_kwargs):
        """Yield this connection as its own fake cursor."""
        yield self

    def execute(self, query, values):
        """Record the first bound value only for INSERT statements."""
        if query.startswith("INSERT"):
            self.receipts.append(values[0])

    def fetchone(self):
        """Return a successful advisory-lock acquisition row."""
        return {"acquired": True}

    def fetchall(self):
        """Return the configured audit events."""
        return self.events


def test_a_later_sink_outage_rolls_back_batch_receipts_and_retry_keeps_ids(monkeypatch):
    """Check a later sink outage rolls back batch receipts and retry keeps IDs."""
    identifiers = [uuid4(), uuid4()]
    events = [
        {
            "event_id": identifier,
            "created_at": datetime.now(UTC),
            "event_type": "dataset_hidden",
            "payload": {"dataset_id": number},
        }
        for number, identifier in enumerate(identifiers, 1)
    ]
    session = _Session(
        [
            _Response(json.dumps({"event_id": str(identifiers[0]), "stored": True}).encode()),
            requests.ConnectionError("outage"),
        ]
    )
    monkeypatch.setattr(outbox.requests, "Session", lambda: session)
    connection = _Connection(events)
    with pytest.raises(outbox.AuditDeliveryError):
        outbox.export_security_audit_events(
            connection, sink_url="https://sink.example/events", bearer_token="synthetic-token"
        )
    assert connection.rolled_back and not connection.receipts
    assert not session.trust_env
    assert session.headers["Authorization"] == "Bearer synthetic-token"
    first_ids = [call[1]["json"]["event_id"] for call in session.calls]
    session.replies = [
        _Response(json.dumps({"event_id": str(identifier), "stored": True}).encode())
        for identifier in identifiers
    ]
    assert (
        outbox.export_security_audit_events(
            connection, sink_url="https://sink.example/events", bearer_token="synthetic-token"
        )
        == 2
    )
    assert connection.committed and connection.receipts == identifiers
    assert [call[1]["json"]["event_id"] for call in session.calls[2:]] == first_ids


@pytest.mark.parametrize(
    "url",
    [
        "http://sink.example/events",
        "https://user:password@sink.example/events",
        "https://sink.example/events?capability=private",
        "https://sink.example/events#private",
        "https://sink.example:0/events",
    ],
)
def test_unsafe_sink_configuration_is_rejected_before_database_access(url):
    """Check unsafe sink configuration is rejected before database access (ValueError)."""
    with pytest.raises(ValueError):
        outbox.export_security_audit_events(None, sink_url=url, bearer_token="synthetic-token")


def test_owner_command_import_and_missing_configuration_need_no_application_secrets(tmp_path):
    """Check owner command import and missing configuration need no application secrets."""
    root = Path(__file__).resolve().parents[3]
    code = """
import runpy, sys
sys.path.insert(0, sys.argv[1])
sys.argv = [sys.argv[2]]
try:
    runpy.run_path(sys.argv[0], run_name='__main__')
except SystemExit as error:
    assert error.code == 1
else:
    raise AssertionError('missing protected configuration must fail')
assert 'config' not in sys.modules
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            code,
            str(root / "src"),
            str(root / "scripts/export_security_audit.py"),
        ],
        env={},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""
    assert (
        result.stderr
        == "Security audit export failed; inspect the protected configuration and sink.\n"
    )

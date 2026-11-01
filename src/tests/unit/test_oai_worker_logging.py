"""The actual worker installs source-aware logging in a fresh spawned interpreter."""

import contextlib
import io
import json
import logging
import multiprocessing
import os
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from typing import cast
from unittest.mock import patch

import pytest

from app.ingestion_contracts import HarvestResult
from app.sources import oai_client

_SOURCE = "logging_archive"
_CURSOR = datetime(2026, 1, 1, tzinfo=UTC)
_LOG_CONTEXT = {"source": _SOURCE, "log_level": "INFO", "log_format": "json"}


class _CapturedConnection:
    """Capture worker messages and resource closure without an actual pipe."""

    def __init__(self):
        """Initialize the send/receive observation state."""
        self.messages = []
        self.closed = False

    def send_bytes(self, payload):
        """Retain the bytes submitted by the worker."""
        self.messages.append(payload)

    def close(self):
        """Mark the fake resource closed."""
        self.closed = True


def _logging_probe(connection: Connection, *, log_level: str, log_format: str) -> None:
    """Run the real worker with a signature-checked fetch double and real logging setup."""
    # Keep an unrelated empty-secret startup warning out of the stderr assertion.
    # The probe never connects to this test-owned Redis address.
    os.environ["RATE_LIMIT_REDIS_URL"] = "redis://127.0.0.1:6379/0"
    stdout, stderr = io.StringIO(), io.StringIO()
    captured = _CapturedConnection()
    observed = {}

    def fetch(
        oai_url: str, since: str, institution_filter: str, *, max_pages: int
    ) -> HarvestResult:
        """Check worker fetch arguments, emit one record per level, and return an empty harvest."""
        assert (oai_url, since, institution_filter, max_pages) == (
            "https://oai.example.invalid/endpoint",
            "2026-01-01",
            "Example archive",
            7,
        )
        observed["level"] = logging.getLogger().getEffectiveLevel()
        logger = logging.getLogger(oai_client.__name__)
        logger.debug("worker_debug")
        logger.info("worker_info")
        logger.warning("worker_warning")
        logging.getLogger("audit").info("worker_audit")
        return HarvestResult(source_cursor=_CURSOR)

    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            # A hostile initial policy proves the worker configures its own handlers.
            root = logging.getLogger()
            root.handlers[:] = [logging.StreamHandler(stderr)]
            root.setLevel(logging.CRITICAL)
            with patch.object(oai_client, "fetch_updates", autospec=True, side_effect=fetch):
                oai_client._harvest_worker(
                    cast(Connection, captured),
                    "https://oai.example.invalid/endpoint",
                    "2026-01-01",
                    "Example archive",
                    7,
                    source=_SOURCE,
                    log_level=log_level,
                    log_format=log_format,
                )
        connection.send(
            {
                "stdout": stdout.getvalue(),
                "stderr": stderr.getvalue(),
                "frames": captured.messages,
                "closed": captured.closed,
                "pid": os.getpid(),
                "level": observed.get("level"),
            }
        )
    finally:
        connection.close()


@pytest.mark.parametrize("log_level", ["DEBUG", "INFO", "WARNING"])
@pytest.mark.parametrize("log_format", ["json", "text"])
def test_spawned_worker_installs_requested_logging_and_context(log_level, log_format):
    """Check spawned worker installs requested logging and context."""
    root = logging.getLogger()
    parent_handlers, parent_level = tuple(root.handlers), root.level
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(
        target=_logging_probe,
        args=(send,),
        kwargs={"log_level": log_level, "log_format": log_format},
        name="oai-logging-regression",
    )
    try:
        process.start()
        send.close()
        assert receive.poll(15), "Spawned logging probe did not complete"
        report = receive.recv()
        process.join(5)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
        if process.is_alive():
            process.kill()
            process.join(5)
        process.close()
        receive.close()
        send.close()

    assert tuple(root.handlers) == parent_handlers and root.level == parent_level
    assert report["pid"] != os.getpid()
    assert report["level"] == logging.getLevelNamesMapping()[log_level]
    assert report["closed"] is True
    assert report["stderr"] == ""
    assert len(report["frames"]) == 1
    frame = report["frames"][0]
    assert frame[:1] == oai_client._WORKER_SUCCESS
    assert oai_client._decode_worker_harvest_result(frame[1:]) == HarvestResult(
        source_cursor=_CURSOR
    )

    expected = ["worker_debug", "worker_info", "worker_warning"]
    expected = expected[["DEBUG", "INFO", "WARNING"].index(log_level) :]
    lines = report["stdout"].splitlines()
    assert len(lines) == len(expected) + 1
    if log_format == "json":
        entries = [json.loads(line) for line in lines]
        assert [entry["message"] for entry in entries] == [*expected, "worker_audit"]
        assert [entry["logger"] for entry in entries[:-1]] == [oai_client.__name__] * len(expected)
        for entry in entries:
            assert entry["source"] == _SOURCE
            assert entry["worker_pid"] == report["pid"]
        audit = entries[-1]
    else:
        for line, message in zip(lines[:-1], expected, strict=True):
            assert f"source={_SOURCE} worker_pid={report['pid']} | {message}" in line
        audit = json.loads(lines[-1])
    assert audit["logger"] == "audit"
    assert audit["message"] == "worker_audit"
    assert audit["source"] == _SOURCE
    assert audit["worker_pid"] == report["pid"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", ""),
        ("source", "UPPER"),
        ("source", "a" * 33),
        ("source", "https://endpoint.invalid"),
        ("source", "archive\n"),
        ("source", None),
        ("log_level", "info"),
        ("log_level", "unsupported"),
        ("log_level", None),
        ("log_level", {}),
        ("log_format", "JSON"),
        ("log_format", "unsupported"),
        ("log_format", None),
    ],
)
def test_invalid_logging_context_is_rejected_before_process_setup(field, value):
    """Check invalid logging context is rejected before process setup (ValueError)."""
    arguments = {**_LOG_CONTEXT, field: value}
    with (
        patch.object(oai_client.multiprocessing, "get_context", autospec=True) as context,
        pytest.raises(ValueError),
    ):
        oai_client.fetch_updates_isolated(
            "https://oai.example.invalid/endpoint", "2026-01-01", "Example archive", **arguments
        )
    context.assert_not_called()


@pytest.mark.parametrize("missing", ["source", "log_level", "log_format"])
def test_logging_context_arguments_are_required(missing):
    """Check logging context arguments are required (TypeError)."""
    arguments = dict(_LOG_CONTEXT)
    del arguments[missing]
    with (
        patch.object(oai_client.multiprocessing, "get_context", autospec=True) as context,
        pytest.raises(TypeError),
    ):
        oai_client.fetch_updates_isolated(
            "https://oai.example.invalid/endpoint", "2026-01-01", "Example archive", **arguments
        )
    context.assert_not_called()


def test_logging_initialization_failure_is_framed_and_closes_the_connection():
    """Check logging initialization failure is framed and closes the connection."""
    connection = _CapturedConnection()
    with (
        patch.object(
            oai_client,
            "_configure_worker_logging",
            autospec=True,
            side_effect=RuntimeError("logging initialization failed"),
        ),
        patch.object(oai_client, "fetch_updates", autospec=True) as fetch,
    ):
        oai_client._harvest_worker(
            connection,
            "https://oai.example.invalid/endpoint",
            "2026-01-01",
            "Example archive",
            7,
            **_LOG_CONTEXT,
        )
    fetch.assert_not_called()
    assert connection.closed is True
    assert len(connection.messages) == 1
    frame = connection.messages[0]
    assert frame[:1] == oai_client._WORKER_ERROR
    assert len(frame) <= oai_client._OAI_WORKER_WIRE_OVERHEAD_BYTES
    error = json.loads(frame[1:])
    assert error["error_code"] == "harvest_worker"
    assert error["exception_type"] == "RuntimeError"


def test_logging_setup_precedes_fetch_and_keeps_the_existing_wire_result():
    """Check logging setup precedes fetch and keeps the existing wire result."""
    connection = _CapturedConnection()
    events = []
    expected = HarvestResult(source_cursor=_CURSOR)

    def setup(**_kwargs):
        """Record logging setup before worker fetching."""
        events.append("setup")

    def fetch(*_args, **_kwargs):
        """Require logging setup first, record fetching, and return the expected harvest."""
        assert events == ["setup"]
        events.append("fetch")
        return expected

    with (
        patch.object(
            oai_client, "_configure_worker_logging", autospec=True, side_effect=setup
        ) as configure,
        patch.object(oai_client, "fetch_updates", autospec=True, side_effect=fetch),
    ):
        oai_client._harvest_worker(
            connection,
            "https://oai.example.invalid/endpoint",
            "2026-01-01",
            "Example archive",
            7,
            **_LOG_CONTEXT,
        )
    configure.assert_called_once_with(**_LOG_CONTEXT)
    assert events == ["setup", "fetch"]
    assert connection.messages == [
        oai_client._WORKER_SUCCESS + oai_client.encode_harvest_result(expected)
    ]
    assert connection.closed is True

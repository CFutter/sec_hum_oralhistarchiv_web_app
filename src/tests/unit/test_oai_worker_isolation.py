"""Hard-deadline process boundary for hostile OAI harvests."""

import inspect
import json
import multiprocessing
import signal
import sys
import threading
import time
from datetime import UTC, datetime
from typing import cast
from unittest.mock import patch

import pytest

from app.services.harvest import HarvestResult
from app.sources import oai_client
from app.sources.oai_client import OAIProtocolError
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record


class _FakeReceiveConnection:
    """Simulate a bounded receive pipe with optional blocking and closure tracking."""

    def __init__(
        self,
        *,
        ready: bool,
        message: bytes = b"",
        block_on_receive: bool = False,
    ) -> None:
        """Initialize receive readiness, payload, blocking behavior, and observation state."""
        self.ready = ready
        self.message = message
        self.block_on_receive = block_on_receive
        self.poll_timeout: float | None = None
        self.maxlength: int | None = None
        self.closed = False
        self.receive_started = threading.Event()
        self._release_receive = threading.Event()

    def poll(self, timeout: float) -> bool:
        """Record the polling timeout and return configured readiness without waiting."""
        self.poll_timeout = timeout
        return self.ready

    def recv_bytes(self, maxlength: int) -> bytes:
        """Record receive limits, optionally wait up to ten seconds, and reject closure or oversized data."""
        self.maxlength = maxlength
        self.receive_started.set()
        if self.block_on_receive:
            self._release_receive.wait(timeout=10.0)
        if self.closed:
            raise EOFError
        if len(self.message) > maxlength:
            raise OSError("message too large")
        return self.message

    def close(self) -> None:
        """Mark the receive end closed and release any blocked receive."""
        self.closed = True
        self._release_receive.set()


class _FakeSendConnection:
    """Track closure of the fake send end."""

    def __init__(self) -> None:
        """Initialize the send/receive observation state."""
        self.closed = False

    def close(self) -> None:
        """Mark the fake resource closed."""
        self.closed = True


class _FakeProcess:
    """Simulate process startup and configurable shutdown resistance."""

    def __init__(
        self,
        *,
        exit_on_join: bool,
        survive_terminate: bool = False,
        survive_kill: bool = False,
    ) -> None:
        """Initialize process lifecycle state and configurable resistance to termination."""
        self.exit_on_join = exit_on_join
        self.survive_terminate = survive_terminate
        self.survive_kill = survive_kill
        self.started = False
        self.alive = False
        self.exitcode: int | None = None
        self.terminate_calls = 0
        self.kill_calls = 0
        self.closed = False

    def start(self) -> None:
        """Mark the fake process started and alive."""
        self.started = True
        self.alive = True

    def join(self, timeout: float) -> None:
        """Require the shutdown budget and simulate successful exit only when configured."""
        assert timeout == oai_client._OAI_WORKER_SHUTDOWN_SECONDS
        if self.exit_on_join:
            self.alive = False
            self.exitcode = 0

    def is_alive(self) -> bool:
        """Return the simulated process liveness flag."""
        return self.alive

    def terminate(self) -> None:
        """Count terminate calls and simulate SIGTERM exit unless configured to survive."""
        self.terminate_calls += 1
        if not self.survive_terminate:
            self.alive = False
            self.exitcode = -signal.SIGTERM

    def kill(self) -> None:
        """Count kill calls and simulate SIGKILL exit unless configured to survive."""
        self.kill_calls += 1
        if not self.survive_kill:
            self.alive = False
            self.exitcode = -signal.SIGKILL

    def close(self) -> None:
        """Mark the fake resource closed."""
        self.closed = True


class _FakeContext:
    """Supply the configured fake pipe endpoints and process."""

    def __init__(
        self,
        receive: _FakeReceiveConnection,
        send: _FakeSendConnection,
        process: _FakeProcess,
    ) -> None:
        """Store fake endpoints and process while initializing captured process arguments."""
        self.receive = receive
        self.send = send
        self.process = process
        self.process_kwargs: dict[str, object] | None = None

    def Pipe(self, *, duplex: bool):
        """Require a one-way pipe and return the configured endpoints."""
        assert duplex is False
        return self.receive, self.send

    def Process(self, **kwargs):
        """Capture process construction arguments and return the configured process."""
        self.process_kwargs = kwargs
        return self.process


class _CaptureConnection:
    """Capture worker messages and resource closure without an actual pipe."""

    def __init__(self) -> None:
        """Initialize the send/receive observation state."""
        self.messages: list[bytes] = []
        self.closed = False

    def send_bytes(self, value: bytes) -> None:
        """Retain the bytes submitted by the worker."""
        self.messages.append(value)

    def close(self) -> None:
        """Mark the fake resource closed."""
        self.closed = True


def _forever_worker(
    _connection,
    _oai_url: str,
    _since: str,
    _institution_filter: str,
    _max_pages: int,
    *,
    source: str,
    log_level: str,
    log_format: str,
) -> None:
    """Spawn-safe hostile worker that never writes or exits voluntarily."""
    del source, log_level, log_format
    while True:
        time.sleep(0.01)


def _ignore_terminate_worker(
    connection,
    _oai_url: str,
    _since: str,
    _institution_filter: str,
    _max_pages: int,
    *,
    source: str,
    log_level: str,
    log_format: str,
) -> None:
    """Announce readiness, ignore SIGTERM, and require watchdog SIGKILL."""
    del source, log_level, log_format
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    connection.send_bytes(b"?")
    while True:
        time.sleep(0.01)


@pytest.mark.parametrize("isolated", [False, True], ids=["direct", "isolated"])
@pytest.mark.parametrize("max_pages", [0, -1, True, 1.5, "2", None])
def test_invalid_page_cap_is_rejected_before_transport_or_process_setup(
    isolated: bool,
    max_pages: object,
) -> None:
    """Invalid caller limits cannot open an HTTP session or start process setup."""
    with (
        patch.object(oai_client, "_build_session", autospec=True) as build_session,
        patch.object(multiprocessing, "get_context", autospec=True) as get_context,
        pytest.raises(ValueError, match=r"^max_pages must be a positive integer$"),
    ):
        if isolated:
            oai_client.fetch_updates_isolated(
                "https://oai.example/oai",
                "2026-01-01",
                "Example University",
                source="test_archive",
                log_level="INFO",
                log_format="json",
                max_pages=cast(int, max_pages),
            )
        else:
            oai_client.fetch_updates(
                "https://oai.example/oai",
                "2026-01-01",
                "Example University",
                max_pages=cast(int, max_pages),
            )

    build_session.assert_not_called()
    get_context.assert_not_called()


def test_isolated_harvest_returns_only_a_bounded_typed_result():
    """Check isolated harvest returns only a bounded typed result."""
    expected = HarvestResult(
        source_cursor=SOURCE_CURSOR,
        matching_records=[
            parsed_record(
                "oai:x:live",
                title="Public title",
                upstream_modified_at=datetime(2026, 9, 10, tzinfo=UTC),
            )
        ],
        deleted_uuids={"oai:x:deleted"},
    )
    wire_message = oai_client._WORKER_SUCCESS + oai_client._encode_worker_harvest_result(expected)
    receive = _FakeReceiveConnection(ready=True, message=wire_message)
    send = _FakeSendConnection()
    process = _FakeProcess(exit_on_join=True)
    context = _FakeContext(receive, send, process)

    with patch.object(
        oai_client.multiprocessing, "get_context", autospec=True, return_value=context
    ) as get_ctx:
        result = oai_client.fetch_updates_isolated(
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            max_pages=7,
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )

    assert result == expected
    get_ctx.assert_called_once_with("spawn")
    assert process.started is True
    assert process.terminate_calls == 0
    assert process.kill_calls == 0
    assert process.closed is True
    assert receive.poll_timeout is not None
    assert 0 < receive.poll_timeout <= oai_client._OAI_TOTAL_TIMEOUT_SECONDS
    assert receive.maxlength == (
        oai_client._OAI_MAX_RESULT_BYTES + oai_client._OAI_WORKER_WIRE_OVERHEAD_BYTES
    )
    assert receive.closed is True
    assert send.closed is True
    assert context.process_kwargs is not None
    assert context.process_kwargs["target"] is oai_client._harvest_worker
    assert context.process_kwargs["args"] == (
        send,
        "https://oai.example/oai",
        "2026-01-01",
        "Example University",
        7,
    )
    assert context.process_kwargs["kwargs"] == {
        "source": "test_archive",
        "log_level": "INFO",
        "log_format": "json",
    }
    inspect.signature(oai_client._harvest_worker).bind(
        *context.process_kwargs["args"], **context.process_kwargs["kwargs"]
    )
    assert context.process_kwargs["daemon"] is True


def test_isolated_harvest_terminates_worker_at_hard_deadline():
    """Check isolated harvest terminates worker at hard deadline (OAIProtocolError)."""
    receive = _FakeReceiveConnection(ready=False)
    send = _FakeSendConnection()
    process = _FakeProcess(exit_on_join=False)
    context = _FakeContext(receive, send, process)

    with (
        patch.object(
            oai_client.multiprocessing, "get_context", autospec=True, return_value=context
        ),
        pytest.raises(OAIProtocolError) as exc_info,
    ):
        oai_client.fetch_updates_isolated(
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )

    assert exc_info.value.error_code == "resource_limit"
    assert "hard wall-clock deadline" in str(exc_info.value)
    assert process.terminate_calls == 1
    assert process.kill_calls == 0
    assert process.closed is True


@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_successful_operation_owns_cleanup_even_inside_an_unrelated_except(cleanup_failure):
    """A caller's handled error neither aborts success nor absorbs cleanup faults."""
    expected = HarvestResult(source_cursor=SOURCE_CURSOR)
    receive = _FakeReceiveConnection(
        ready=True,
        message=oai_client._WORKER_SUCCESS + oai_client.encode_harvest_result(expected),
    )
    send = _FakeSendConnection()
    child = _FakeProcess(
        exit_on_join=not cleanup_failure,
        survive_terminate=cleanup_failure,
        survive_kill=cleanup_failure,
    )
    context = _FakeContext(receive, send, child)
    with patch.object(
        oai_client.multiprocessing, "get_context", autospec=True, return_value=context
    ):
        try:
            raise KeyError("unrelated caller failure")  # noqa: TRY301 - establish caller exception
        except KeyError as unrelated:
            if cleanup_failure:
                with pytest.raises(OAIProtocolError, match="could not be terminated"):
                    oai_client.fetch_updates_isolated(
                        "https://oai.example/oai",
                        "2026-01-01",
                        "Example University",
                        source="test_archive",
                        log_level="INFO",
                        log_format="json",
                    )
            else:
                result = oai_client.fetch_updates_isolated(
                    "https://oai.example/oai",
                    "2026-01-01",
                    "Example University",
                    source="test_archive",
                    log_level="INFO",
                    log_format="json",
                )
                assert result == expected
                assert child.terminate_calls == 0
                assert child.closed
            assert not getattr(unrelated, "__notes__", [])
    assert receive.closed and send.closed


def test_cleanup_failure_does_not_mask_the_primary_deadline_error():
    """Check cleanup failure does not mask the primary deadline error (OAIProtocolError)."""
    receive = _FakeReceiveConnection(ready=False)
    send = _FakeSendConnection()
    process = _FakeProcess(
        exit_on_join=False,
        survive_terminate=True,
        survive_kill=True,
    )
    context = _FakeContext(receive, send, process)

    with (
        patch.object(
            oai_client.multiprocessing, "get_context", autospec=True, return_value=context
        ),
        pytest.raises(OAIProtocolError) as exc_info,
    ):
        oai_client.fetch_updates_isolated(
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )

    assert exc_info.value.error_code == "resource_limit"
    assert "hard wall-clock deadline" in str(exc_info.value)
    assert exc_info.value.__notes__ == [
        "OAI-PMH [resource_limit]: OAI harvest worker could not be terminated after SIGKILL"
    ]
    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert process.closed is False


def test_cleanup_failure_without_primary_error_is_controlled():
    """Check cleanup failure without primary error is controlled (OAIProtocolError)."""
    process = _FakeProcess(
        exit_on_join=False,
        survive_terminate=True,
        survive_kill=True,
    )
    process.start()

    with pytest.raises(OAIProtocolError) as exc_info:
        oai_client._abort_harvest_process(process)

    assert exc_info.value.error_code == "resource_limit"
    assert "could not be terminated after SIGKILL" in str(exc_info.value)
    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert process.closed is False


def test_poll_readiness_cannot_bypass_deadline_with_partial_message(monkeypatch):
    """Check poll readiness cannot bypass deadline with partial message (OAIProtocolError)."""
    receive = _FakeReceiveConnection(ready=True, block_on_receive=True)
    send = _FakeSendConnection()
    process = _FakeProcess(exit_on_join=False)
    context = _FakeContext(receive, send, process)
    monkeypatch.setattr(oai_client, "_OAI_TOTAL_TIMEOUT_SECONDS", 0.01)

    with (
        patch.object(
            oai_client.multiprocessing, "get_context", autospec=True, return_value=context
        ),
        pytest.raises(OAIProtocolError) as exc_info,
    ):
        oai_client.fetch_updates_isolated(
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )

    assert exc_info.value.error_code == "resource_limit"
    assert receive.receive_started.is_set()
    assert receive.closed is True
    assert process.terminate_calls == 1
    assert process.closed is True


class _FakeMonotonicClock:
    """A test-driven stand-in for time.monotonic(): the value only moves
    when the test calls advance_to, never with the wall clock."""

    def __init__(self, start: float) -> None:
        """Store the fixed timestamp returned by this clock."""
        self.value = start

    def __call__(self) -> float:
        """Return the stored timestamp without advancing it."""
        return self.value

    def advance_to(self, value: float) -> None:
        """Replace the simulated monotonic time with the supplied value."""
        self.value = value


def test_parent_rejects_result_when_bounded_decode_crosses_deadline(monkeypatch):
    """A decode that only completes after the hard deadline has passed must
    still be rejected, even though the worker's message arrived in time."""
    expected = HarvestResult(source_cursor=SOURCE_CURSOR, deleted_uuids={"oai:x:deleted"})
    message = oai_client._WORKER_SUCCESS + oai_client._encode_worker_harvest_result(expected)
    receive = _FakeReceiveConnection(ready=True, message=message)
    send = _FakeSendConnection()
    process = _FakeProcess(exit_on_join=True)
    context = _FakeContext(receive, send, process)
    monkeypatch.setattr(oai_client, "_OAI_TOTAL_TIMEOUT_SECONDS", 0.01)

    clock_start = 1_000_000.0
    deadline = clock_start + 0.01
    clock = _FakeMonotonicClock(clock_start)

    def slow_decode(_payload: bytes) -> HarvestResult:
        """Simulate a decode that finishes after the deadline by advancing
        the injected clock past it — no real sleep."""
        clock.advance_to(deadline + 1.0)
        return expected

    with (
        patch.object(
            oai_client.multiprocessing, "get_context", autospec=True, return_value=context
        ),
        patch.object(time, "monotonic", autospec=True, side_effect=clock),
        patch.object(
            oai_client, "_decode_worker_harvest_result", autospec=True, side_effect=slow_decode
        ),
        pytest.raises(OAIProtocolError) as exc_info,
    ):
        oai_client.fetch_updates_isolated(
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )

    assert exc_info.value.error_code == "resource_limit"
    assert "hard wall-clock deadline" in str(exc_info.value)


def test_real_spawned_worker_is_reaped_at_hard_deadline(monkeypatch):
    """The real spawn boundary must terminate and reap a permanently stuck child."""
    monkeypatch.setattr(oai_client, "_harvest_worker", _forever_worker)
    monkeypatch.setattr(oai_client, "_OAI_TOTAL_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(oai_client, "_OAI_WORKER_SHUTDOWN_SECONDS", 0.2)

    started = time.monotonic()
    with pytest.raises(OAIProtocolError) as exc_info:
        oai_client.fetch_updates_isolated(
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )
    elapsed = time.monotonic() - started

    assert exc_info.value.error_code == "resource_limit"
    assert "hard wall-clock deadline" in str(exc_info.value)
    assert elapsed < 3.0
    assert not [
        child
        for child in multiprocessing.active_children()
        if child.name == "oralhistarchiv-oai-harvest"
    ]


@pytest.mark.skipif(sys.platform != "linux", reason="systemd target is Linux")
def test_real_spawned_worker_escalates_to_kill_and_is_reaped(monkeypatch):
    """A worker that ignores SIGTERM must still be killed and reaped."""
    monkeypatch.setattr(oai_client, "_harvest_worker", _ignore_terminate_worker)
    monkeypatch.setattr(oai_client, "_OAI_TOTAL_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(oai_client, "_OAI_WORKER_SHUTDOWN_SECONDS", 0.5)

    started = time.monotonic()
    with pytest.raises(OAIProtocolError) as exc_info:
        oai_client.fetch_updates_isolated(
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )
    elapsed = time.monotonic() - started

    assert exc_info.value.error_code == "harvest_worker"
    assert "did not exit cleanly" in str(exc_info.value)
    assert elapsed < 15
    assert not [
        child
        for child in multiprocessing.active_children()
        if child.name == "oralhistarchiv-oai-harvest"
    ]


def test_worker_serializes_success_and_closes_connection():
    """Check worker serializes success and closes connection."""
    connection = _CaptureConnection()
    expected = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:elsewhere"})

    with (
        patch.object(oai_client, "_configure_worker_logging", autospec=True),
        patch.object(oai_client, "fetch_updates", autospec=True, return_value=expected) as fetch,
    ):
        oai_client._harvest_worker(
            connection,
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            7,
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )

    fetch.assert_called_once_with(
        "https://oai.example/oai",
        "2026-01-01",
        "Example University",
        max_pages=7,
    )
    assert connection.closed is True
    assert len(connection.messages) == 1
    message = connection.messages[0]
    assert message[:1] == oai_client._WORKER_SUCCESS
    assert oai_client._decode_worker_harvest_result(message[1:]) == expected


def test_worker_sends_one_bounded_message_built_from_exactly_one_encode_call():
    """The worker must not build a second full-size copy of the harvest: one
    success frame, one canonical JSON body, one call to the encoder."""
    connection = _CaptureConnection()
    expected = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:elsewhere"})
    real_encode = oai_client._encode_worker_harvest_result

    with (
        patch.object(oai_client, "_configure_worker_logging", autospec=True),
        patch.object(oai_client, "fetch_updates", autospec=True, return_value=expected),
        patch.object(
            oai_client, "_encode_worker_harvest_result", autospec=True, side_effect=real_encode
        ) as encode_spy,
    ):
        oai_client._harvest_worker(
            connection,
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            7,
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )

    assert encode_spy.call_count == 1
    assert len(connection.messages) == 1
    message = connection.messages[0]
    assert message == oai_client._WORKER_SUCCESS + real_encode(expected)


def test_worker_preserves_resource_limit_failure_without_a_result():
    """Check worker preserves resource limit failure without a result."""
    connection = _CaptureConnection()
    failure = OAIProtocolError("resource_limit", "page exceeded")

    with (
        patch.object(oai_client, "_configure_worker_logging", autospec=True),
        patch.object(oai_client, "fetch_updates", autospec=True, side_effect=failure),
    ):
        oai_client._harvest_worker(
            connection,
            "https://oai.example/oai",
            "2026-01-01",
            "Example University",
            7,
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )

    assert connection.closed is True
    assert len(connection.messages) == 1
    message = connection.messages[0]
    assert message[:1] == oai_client._WORKER_ERROR
    payload = json.loads(message[1:].decode("utf-8"))
    assert payload == {
        "error_code": "resource_limit",
        "exception_type": "OAIProtocolError",
        "message": "OAI-PMH [resource_limit]: page exceeded",
    }


def test_worker_payload_decode_rejects_a_record_missing_a_parser_key():
    """Check worker payload decode rejects a record missing a parser key."""
    harvest = HarvestResult(source_cursor=SOURCE_CURSOR, matching_records=[parsed_record("id")])
    wire = json.loads(oai_client._encode_worker_harvest_result(harvest))
    del wire["matching_records"][0]["authors"]

    with pytest.raises((ValueError, OAIProtocolError)):
        oai_client._decode_worker_harvest_result(json.dumps(wire).encode())


@pytest.mark.parametrize("exit_mode", ["nonzero", "hang"])
def test_success_frame_requires_clean_real_child_exit(monkeypatch, exit_mode):
    """Neither a crash nor forced termination may turn a frame into success."""
    monkeypatch.setattr(oai_client, "_harvest_worker", _success_then_abnormal_worker)
    monkeypatch.setattr(oai_client, "_OAI_WORKER_SHUTDOWN_SECONDS", 0.2)
    monkeypatch.setattr(oai_client, "_OAI_TOTAL_TIMEOUT_SECONDS", 10.0)
    with pytest.raises(OAIProtocolError, match="did not exit cleanly"):
        oai_client.fetch_updates_isolated(
            "https://oai.example/oai",
            exit_mode,
            "Example University",
            source="test_archive",
            log_level="INFO",
            log_format="json",
        )
    assert not any(
        child.name == "oralhistarchiv-oai-harvest" for child in multiprocessing.active_children()
    )


def _success_then_abnormal_worker(
    connection, _url, exit_mode, _institution, _max_pages, **_logging
):
    """Send valid harvest output, then exit nonzero or block forever to test cleanup."""
    result = HarvestResult(source_cursor=SOURCE_CURSOR)
    connection.send_bytes(b"S" + oai_client._encode_worker_harvest_result(result))
    connection.close()
    if exit_mode == "nonzero":
        raise SystemExit(7)
    threading.Event().wait()


def test_cleanup_oserror_keeps_primary_failure(monkeypatch):
    """Cleanup's OS-level errors must not replace an existing protocol failure."""
    primary = OAIProtocolError("resource_limit", "primary deadline")

    def fail_cleanup(_process):
        """Raise OSError during worker cleanup."""
        raise OSError("cleanup failed")

    monkeypatch.setattr(oai_client, "_abort_harvest_process", fail_cleanup)
    oai_client._cleanup_harvest_process(object(), completed=False, primary_exception=primary)
    assert primary.__notes__ == ["cleanup failed"]

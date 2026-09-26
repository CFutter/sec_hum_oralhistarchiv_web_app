"""Hard-deadline process boundary for hostile OAI harvests."""

import json
import multiprocessing
import signal
import sys
import threading
import time
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from app.services import oai_client
from app.services.oai_client import HarvestResult, OAIProtocolError
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record


class _FakeReceiveConnection:
    def __init__(
        self,
        *,
        ready: bool,
        message: bytes = b"",
        block_on_receive: bool = False,
    ) -> None:
        self.ready = ready
        self.message = message
        self.block_on_receive = block_on_receive
        self.poll_timeout: float | None = None
        self.maxlength: int | None = None
        self.closed = False
        self.receive_started = threading.Event()
        self._release_receive = threading.Event()

    def poll(self, timeout: float) -> bool:
        self.poll_timeout = timeout
        return self.ready

    def recv_bytes(self, maxlength: int) -> bytes:
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
        self.closed = True
        self._release_receive.set()


class _FakeSendConnection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeProcess:
    def __init__(
        self,
        *,
        exit_on_join: bool,
        survive_terminate: bool = False,
        survive_kill: bool = False,
    ) -> None:
        self.exit_on_join = exit_on_join
        self.survive_terminate = survive_terminate
        self.survive_kill = survive_kill
        self.started = False
        self.alive = False
        self.terminate_calls = 0
        self.kill_calls = 0
        self.closed = False

    def start(self) -> None:
        self.started = True
        self.alive = True

    def join(self, timeout: float) -> None:
        assert timeout == oai_client._OAI_WORKER_SHUTDOWN_SECONDS
        if self.exit_on_join:
            self.alive = False

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        self.terminate_calls += 1
        if not self.survive_terminate:
            self.alive = False

    def kill(self) -> None:
        self.kill_calls += 1
        if not self.survive_kill:
            self.alive = False

    def close(self) -> None:
        self.closed = True


class _FakeContext:
    def __init__(
        self,
        receive: _FakeReceiveConnection,
        send: _FakeSendConnection,
        process: _FakeProcess,
    ) -> None:
        self.receive = receive
        self.send = send
        self.process = process
        self.process_kwargs: dict[str, object] | None = None

    def Pipe(self, *, duplex: bool):
        assert duplex is False
        return self.receive, self.send

    def Process(self, **kwargs):
        self.process_kwargs = kwargs
        return self.process


class _CaptureConnection:
    def __init__(self) -> None:
        self.messages: list[bytes] = []
        self.closed = False

    def send_bytes(self, value: bytes) -> None:
        self.messages.append(value)

    def close(self) -> None:
        self.closed = True


def _forever_worker(
    _connection,
    _oai_url: str,
    _since: str,
    _institution_filter: str,
) -> None:
    """Spawn-safe hostile worker that never writes or exits voluntarily."""
    while True:
        time.sleep(0.01)


def _ignore_terminate_worker(
    connection,
    _oai_url: str,
    _since: str,
    _institution_filter: str,
) -> None:
    """Announce readiness, ignore SIGTERM, and require watchdog SIGKILL."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    connection.send_bytes(b"?")
    while True:
        time.sleep(0.01)


def test_isolated_harvest_returns_only_a_bounded_typed_result():
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
            "University of Zurich",
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
    assert context.process_kwargs["daemon"] is True


def test_isolated_harvest_terminates_worker_at_hard_deadline():
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
            "University of Zurich",
        )

    assert exc_info.value.error_code == "resource_limit"
    assert "hard wall-clock deadline" in str(exc_info.value)
    assert process.terminate_calls == 1
    assert process.kill_calls == 0
    assert process.closed is True


def test_cleanup_failure_does_not_mask_the_primary_deadline_error():
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
            "University of Zurich",
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
            "University of Zurich",
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
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance_to(self, value: float) -> None:
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
            "University of Zurich",
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
            "University of Zurich",
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
            "University of Zurich",
        )
    elapsed = time.monotonic() - started

    assert exc_info.value.error_code == "harvest_worker"
    assert "unknown message type" in str(exc_info.value)
    assert elapsed < 15
    assert not [
        child
        for child in multiprocessing.active_children()
        if child.name == "oralhistarchiv-oai-harvest"
    ]


def test_worker_serializes_success_and_closes_connection():
    connection = _CaptureConnection()
    expected = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:elsewhere"})

    with patch.object(oai_client, "fetch_updates", autospec=True, return_value=expected):
        oai_client._harvest_worker(
            connection,
            "https://oai.example/oai",
            "2026-01-01",
            "University of Zurich",
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
        patch.object(oai_client, "fetch_updates", autospec=True, return_value=expected),
        patch.object(
            oai_client, "_encode_worker_harvest_result", autospec=True, side_effect=real_encode
        ) as encode_spy,
    ):
        oai_client._harvest_worker(
            connection,
            "https://oai.example/oai",
            "2026-01-01",
            "University of Zurich",
        )

    assert encode_spy.call_count == 1
    assert len(connection.messages) == 1
    message = connection.messages[0]
    assert message == oai_client._WORKER_SUCCESS + real_encode(expected)


def test_worker_preserves_resource_limit_failure_without_a_result():
    connection = _CaptureConnection()
    failure = OAIProtocolError("resource_limit", "page exceeded")

    with patch.object(oai_client, "fetch_updates", autospec=True, side_effect=failure):
        oai_client._harvest_worker(
            connection,
            "https://oai.example/oai",
            "2026-01-01",
            "University of Zurich",
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
    """The wire codec that crosses the subprocess boundary is exactly as
    strict as the parser contract: dropping one parser-owned key (here
    'authors') from an encoded matching record must fail decode instead of
    silently handing the parent a record with a missing field."""
    harvest = HarvestResult(source_cursor=SOURCE_CURSOR, matching_records=[parsed_record("id")])
    wire = json.loads(oai_client._encode_worker_harvest_result(harvest))
    del wire["matching_records"][0]["authors"]

    with pytest.raises((ValueError, OAIProtocolError)):
        oai_client._decode_worker_harvest_result(json.dumps(wire).encode())

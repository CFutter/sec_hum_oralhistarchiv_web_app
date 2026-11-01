"""Real spawned IPC cleanup and safe failure contracts for both feed workers."""

import multiprocessing
import threading
import time
import traceback
from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest

from app.sources import json_feed_process as process
from app.sources.json_feed_http import FeedTransportError

_CANARY = "process-cleanup-private-credential-canary"
_NAME = "oralhistarchiv-json-feed-process-test"
_REAL_STOP = process._stop_worker


def _success(connection):
    """Send a success frame and close the child connection."""
    connection.send_bytes(b"Sok")
    connection.close()


def _nonzero(connection):
    """Send success, close the connection and exit with status 2."""
    _success(connection)
    raise SystemExit(2)


def _waiting(connection):
    """Send success, close the connection and block indefinitely."""
    _success(connection)
    threading.Event().wait()


@pytest.fixture
def observed(monkeypatch):
    """Spy on real spawn pipes and child cleanup; return the recorded handles and doubles."""
    context = multiprocessing.get_context("spawn")
    real_context, real_pipe = process.multiprocessing.get_context, context.Pipe
    pipes, children = [], []

    def pipe(*args, **kwargs):
        """Create real pipes and retain both ends for closure assertions."""
        pair = real_pipe(*args, **kwargs)
        pipes.extend(pair)
        return pair

    def stop(child):
        """Retain the child handle and invoke real worker cleanup."""
        children.append(child)
        _REAL_STOP(child)

    choose = create_autospec(real_context, return_value=context)
    stop_spy = create_autospec(_REAL_STOP, side_effect=stop)
    monkeypatch.setattr(process.multiprocessing, "get_context", choose)
    monkeypatch.setattr(context, "Pipe", create_autospec(real_pipe, side_effect=pipe))
    monkeypatch.setattr(process, "_stop_worker", stop_spy)
    return SimpleNamespace(pipes=pipes, children=children, choose=choose, stop=stop_spy)


def _run(worker=_success, *, max_bytes=32):
    """Run the selected worker with max_bytes and a ten-second monotonic deadline."""
    end = time.monotonic() + 10
    return process.run_feed_process(
        worker, (), max_bytes=max_bytes, deadline=end, process_name=_NAME
    )


def _closed(observed):
    """Require closed pipes/process handles and no active child with the test name."""
    assert all(connection.closed for connection in observed.pipes)
    for child in observed.children:
        with pytest.raises(ValueError, match="process object is closed"):
            child.is_alive()
    assert not any(child.name == _NAME for child in multiprocessing.active_children())


def _cleanup_fault(observed, monkeypatch):
    """Patch cleanup to stop the child before raising a private OSError."""

    def stop_then_fail(child):
        """Stop the observed child, then raise the cleanup OSError."""
        observed.stop(child)
        raise OSError(_CANARY)

    monkeypatch.setattr(
        process, "_stop_worker", create_autospec(_REAL_STOP, side_effect=stop_then_fail)
    )


@pytest.mark.parametrize("budget", [0, -1, True, "1"])
def test_invalid_byte_budget_never_opens_a_process_context(observed, budget):
    """Invalid byte budget never opens a process context."""
    with pytest.raises(ValueError):
        _run(max_bytes=budget)
    observed.choose.assert_not_called()
    assert not observed.pipes and not observed.children


def test_success_frame_cannot_override_a_nonzero_child_exit(observed):
    """Success frame cannot override a nonzero child exit."""
    with pytest.raises(FeedTransportError) as error:
        _run(_nonzero)
    assert error.value.error_code == "worker"
    assert len(observed.pipes) == 2 and len(observed.children) == 1
    _closed(observed)


def test_cleanup_fault_is_fixed_and_redacted_after_real_reaping(observed, monkeypatch):
    """Cleanup fault is fixed and redacted after real reaping."""
    _cleanup_fault(observed, monkeypatch)
    with pytest.raises(FeedTransportError) as error:
        _run()
    assert error.value.error_code == "worker"
    assert _CANARY not in "".join(traceback.format_exception(error.value))
    _closed(observed)


def test_unrelated_handled_exception_cannot_absorb_cleanup_failure(observed, monkeypatch):
    """Unrelated handled exception cannot absorb cleanup failure."""
    _cleanup_fault(observed, monkeypatch)
    try:
        raise KeyError("unrelated caller failure")  # noqa: TRY301 - establish caller exception
    except KeyError as unrelated:
        with pytest.raises(FeedTransportError) as error:
            _run()
        assert error.value.error_code == "worker"
        assert not getattr(unrelated, "__notes__", [])
    _closed(observed)


def test_converted_local_failure_owns_cleanup_note(observed, monkeypatch):
    """Cleanup records the public error actually propagated by the supervisor."""

    def fail_after_frame(*args, **kwargs):
        """Wait for a frame, then raise a private ValueError."""
        real_wait(*args, **kwargs)
        raise ValueError(_CANARY)

    real_wait = process._wait_for_frame
    monkeypatch.setattr(
        process, "_wait_for_frame", create_autospec(real_wait, side_effect=fail_after_frame)
    )
    _cleanup_fault(observed, monkeypatch)
    with pytest.raises(FeedTransportError) as error:
        _run()
    assert error.value.error_code == "worker"
    assert error.value.__notes__ == ["JSON feed worker cleanup failed"]
    assert _CANARY not in "".join(traceback.format_exception(error.value))
    _closed(observed)


@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_parent_control_signal_survives_real_child_reaping(observed, monkeypatch, cleanup_failure):
    """Parent control signal survives real child reaping."""
    interrupt, real_wait = KeyboardInterrupt("operator cancelled"), process._wait_for_frame

    def interrupt_after_frame(_child, connection, _state, *, max_bytes, deadline, cancel_event):
        """Consume the success frame, then raise the selected process-control exception."""
        assert cancel_event is None
        assert connection.poll(min(5, deadline - time.monotonic()))
        assert connection.recv_bytes(max_bytes) == b"Sok"
        raise interrupt

    monkeypatch.setattr(
        process,
        "_wait_for_frame",
        create_autospec(real_wait, side_effect=interrupt_after_frame),
    )
    if cleanup_failure:
        _cleanup_fault(observed, monkeypatch)
    with pytest.raises(KeyboardInterrupt) as error:
        _run(_waiting)
    assert error.value is interrupt
    expected = ["JSON feed worker cleanup failed"] if cleanup_failure else []
    assert getattr(interrupt, "__notes__", []) == expected
    assert _CANARY not in "".join(traceback.format_exception(interrupt))
    _closed(observed)

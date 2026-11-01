"""Real server processes owned and cleaned up by integration tests."""

import contextlib
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

import redis as redis_lib


def free_port() -> int:
    """Return a currently unused loopback TCP port; the socket is released before return."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_redis_ping(port: int, *, timeout: float = 5.0) -> None:
    """Poll loopback Redis for PING; raise RuntimeError after the timeout in seconds."""
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            client = redis_lib.Redis(
                host="127.0.0.1", port=port, socket_connect_timeout=0.5, socket_timeout=0.5
            )
            try:
                if client.ping():
                    return
            finally:
                client.close()
        except Exception as exc:
            last_exc = exc
        time.sleep(0.05)
    raise RuntimeError(f"private redis-server on port {port} never answered PING: {last_exc}")


def terminate_process(proc: subprocess.Popen[bytes], *, timeout: float = 5.0) -> None:
    """Terminate and reap the child, then SIGKILL its process group.

    The child must have its own session, as start_private_redis creates. timeout is
    the wait in seconds for each terminate/kill attempt; TimeoutExpired can propagate.
    """
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=timeout)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)


def start_private_redis(directory: Path, port: int, *extra_args: str) -> subprocess.Popen[bytes]:
    """Start Redis on loopback; clean up the process if readiness fails."""
    proc = subprocess.Popen(
        [
            "redis-server",
            "--port",
            str(port),
            "--bind",
            "127.0.0.1",
            "--save",
            "",
            "--dir",
            str(directory),
            *extra_args,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        _wait_for_redis_ping(port)
    except Exception:
        terminate_process(proc)
        raise
    return proc

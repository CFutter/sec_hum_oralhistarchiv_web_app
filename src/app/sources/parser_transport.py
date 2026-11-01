"""Bounded transport to a separately privileged, socket-activated parser.

This module deliberately does not import application settings. Production and
staging never fall back to a child of the scheduler. The only local mode is an
explicit development choice; the service runs one request per fresh identity.
"""

import json
import os
import socket
import stat
import struct
import threading
import time
from pathlib import Path
from typing import Any

from app.ingestion_contracts import check_harvest_cancellation

MAX_REQUEST_BYTES = 65536
MAX_RESPONSE_BYTES = 16 * 1024 * 1024 + 4096
DEFAULT_SOCKET = "/run/oralhistarchiv-parser.sock"
_POLL_SECONDS = 0.1
_CREDENTIALS = struct.Struct("3i")
_LENGTH = struct.Struct("!I")
_runtime_selection: tuple[str, str] | None = None


class ParserServiceError(RuntimeError):
    """Fixed diagnostic without request, credential or remote exception contents."""


def use_parser_service() -> bool:
    """Return the frozen startup mode, or read ENV_STATE/PARSER_EXECUTION_MODE.

    Defaults are dev/service. service is accepted for any environment; local is allowed
    only for dev. Other modes raise ParserServiceError. validate_parser_service freezes
    subsequent selection.
    """
    environment, mode = _runtime_selection or (
        os.environ.get("ENV_STATE", "dev"),
        os.environ.get("PARSER_EXECUTION_MODE", "service"),
    )
    return _uses_service(environment, mode)


def _uses_service(environment: str, mode: str) -> bool:
    """Select service mode or dev-only local mode; reject other pairs with ParserServiceError."""
    if mode == "service":
        return True
    if mode == "local" and environment == "dev":
        return False
    raise ParserServiceError("Parser isolation configuration is invalid")


def _socket_path() -> str:
    """Validate ORALHISTARCHIV_PARSER_SOCKET or its default as a protected root-owned endpoint.

    Require a canonical absolute path, root-owned nonwritable parent directories
    and a socket without other-user access; validation/I/O errors propagate.
    """
    value = os.environ.get("ORALHISTARCHIV_PARSER_SOCKET", DEFAULT_SOCKET)
    path = Path(value)
    if not path.is_absolute() or str(path) != value or any(p == ".." for p in path.parts):
        raise ParserServiceError("Parser socket path is invalid")
    # No writable path component may allow a scheduler/worker to replace the
    # root-owned endpoint with a same-authority impersonator.
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ParserServiceError("Parser socket directory is not protected")
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o007:
        raise ParserServiceError("Parser socket is not protected")
    return value


def _remaining(deadline: float, cancel_event: threading.Event | None) -> float:
    """Check cancellation/deadline and return a socket timeout capped at 0.1 seconds."""
    check_harvest_cancellation(cancel_event)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ParserServiceError("Parser service deadline exceeded")
    return min(remaining, _POLL_SECONDS)


def send_bytes(
    connection: socket.socket,
    payload: bytes,
    *,
    deadline: float,
    cancel_event: threading.Event | None = None,
) -> None:
    """Send a length-prefixed frame with bounded cancellation latency."""
    pending = memoryview(_LENGTH.pack(len(payload)) + payload)
    while pending:
        connection.settimeout(_remaining(deadline, cancel_event))
        try:
            count = connection.send(pending)
        except TimeoutError:
            continue
        if count == 0:
            raise ParserServiceError("Parser service disconnected")
        pending = pending[count:]


def _receive_exactly(
    connection: socket.socket,
    count: int,
    *,
    deadline: float,
    cancel_event: threading.Event | None,
) -> bytes:
    """Read count bytes by the absolute monotonic deadline; reject EOF and honor cancellation."""
    output = bytearray()
    while len(output) < count:
        connection.settimeout(_remaining(deadline, cancel_event))
        try:
            chunk = connection.recv(min(count - len(output), 65536))
        except TimeoutError:
            continue
        if not chunk:
            raise ParserServiceError("Parser service disconnected")
        output.extend(chunk)
    return bytes(output)


def receive_bytes(
    connection: socket.socket,
    *,
    maximum: int,
    deadline: float,
    cancel_event: threading.Event | None = None,
) -> bytes:
    """Reject the announced length before allocating or reading its payload."""
    header = _receive_exactly(
        connection, _LENGTH.size, deadline=deadline, cancel_event=cancel_event
    )
    (length,) = _LENGTH.unpack(header)
    if not 0 < length <= maximum:
        raise ParserServiceError("Parser service frame exceeds its bound")
    return _receive_exactly(connection, length, deadline=deadline, cancel_event=cancel_event)


def _verify_worker_identity(
    connection: socket.socket, *, deadline: float, cancel_event: threading.Event | None
) -> None:
    # SO_PEERCRED describes systemd's listener. SCM_CREDENTIALS instead binds
    # this first byte to the actual service sender, checked by the kernel.
    """Require a kernel-authenticated hello from a separate nonroot UID before sending secrets."""
    while True:
        connection.settimeout(_remaining(deadline, cancel_event))
        try:
            hello, ancillary, flags, _address = connection.recvmsg(
                1, socket.CMSG_SPACE(_CREDENTIALS.size)
            )
            break
        except TimeoutError:
            continue
    credentials = [
        _CREDENTIALS.unpack(data)
        for level, kind, data in ancillary
        if level == socket.SOL_SOCKET
        and kind == socket.SCM_CREDENTIALS
        and len(data) == _CREDENTIALS.size
    ]
    if hello != b"P" or flags & socket.MSG_CTRUNC or len(credentials) != 1:
        raise ParserServiceError("Parser service identity is unavailable")
    pid, uid, _gid = credentials[0]
    if pid <= 0 or uid in {0, os.getuid()}:
        raise ParserServiceError("Parser service must have a separate unprivileged identity")


def request_parser(
    request: dict[str, Any],
    *,
    maximum: int,
    deadline: float,
    cancel_event: threading.Event | None = None,
) -> bytes:
    """Send explicit JSON job inputs to the authenticated parser and return its bounded frame.

    Use ORALHISTARCHIV_PARSER_SOCKET or DEFAULT_SOCKET. deadline is absolute monotonic
    seconds; maximum is 1..MAX_RESPONSE_BYTES. Socket timeouts are changed; the owned
    connection is closed. Framing, identity, socket and deadline failures raise
    ParserServiceError; JSON serialization errors and HarvestCancelled propagate.
    """
    payload = json.dumps(request, ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(payload) > MAX_REQUEST_BYTES or not 0 < maximum <= MAX_RESPONSE_BYTES:
        raise ParserServiceError("Parser service request exceeds its bound")
    try:
        path = _socket_path()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            connection.settimeout(_remaining(deadline, cancel_event))
            connection.connect(path)
            _verify_worker_identity(connection, deadline=deadline, cancel_event=cancel_event)
            send_bytes(connection, payload, deadline=deadline, cancel_event=cancel_event)
            return receive_bytes(
                connection, maximum=maximum, deadline=deadline, cancel_event=cancel_event
            )
    except OSError:
        raise ParserServiceError("Parser service is unavailable") from None


def validate_parser_service(*, environment: str, mode: str) -> None:
    """Validate the selected mode, ping service mode, then replace the process-global selection.

    Local is permitted only for dev. Failure raises ParserServiceError without updating
    the snapshot. Call once during startup; concurrent reconfiguration is unsupported.
    """
    global _runtime_selection  # noqa: PLW0603 - one explicit startup-owned immutable snapshot.
    if _uses_service(environment, mode):
        result = request_parser({"operation": "ping"}, maximum=32, deadline=time.monotonic() + 10)
        if result != b"ready":
            raise ParserServiceError("Parser service readiness failed")
    # Freeze explicitly supplied runtime settings. This honors dev dotenv
    # without importing settings in source/worker code or mutating the env.
    _runtime_selection = (environment, mode)

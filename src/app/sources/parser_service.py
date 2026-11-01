"""One bounded parser request under a fresh, separately privileged service UID.

Started through run_parser.py, never by the scheduler. This supervisor receives
only one source's explicit inputs, owns the existing terminating child watchdog,
and cancels/reaps that child if the scheduler closes its connection. systemd
also bounds the lifetime and resources of the complete per-request cgroup.
"""

import base64
import json
import os
import select
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from typing import Any

from pydantic import SecretBytes, SecretStr

from .json_feed_config import JsonFeedConfig, JsonFeedCredentials, snapshot_json_feed_credentials
from .json_feed_fetch import _fetch_worker
from .json_feed_process import run_feed_process
from .oai_client import _fetch_updates_local, _worker_error_bytes, encode_harvest_result
from .parser_sandbox import validate_effective_sandbox
from .parser_transport import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    receive_bytes,
    send_bytes,
)


def _watch_disconnect(
    connection: socket.socket, cancellation: threading.Event, finished: threading.Event
) -> None:
    """Set cancellation on EOF, extra client data or socket failure until finished is set."""
    while not finished.wait(0.05):
        try:
            readable, _, _ = select.select([connection], [], [], 0)
            if readable:
                # No additional client data is part of this one-request protocol.
                # EOF or a protocol violation both revoke the work's ownership.
                cancellation.set()
                return
        except (OSError, ValueError):
            cancellation.set()
            return


def _json_job(request: dict[str, Any], cancellation: threading.Event) -> bytes:
    """Validate explicit JSON-feed inputs, then return one bounded worker frame with
    cancellation.
    """
    if set(request) != {"operation", "config", "bearer", "signing_key", "since"}:
        raise ValueError("Invalid JSON parser request")
    config = JsonFeedConfig.model_validate_json(json.dumps(request["config"]))
    if not isinstance(request["bearer"], str) or not isinstance(request["signing_key"], str):
        raise TypeError("Invalid JSON parser credentials")
    credentials = snapshot_json_feed_credentials(
        config,
        JsonFeedCredentials(
            source_name=config.name,
            bearer_token=SecretStr(request["bearer"]),
            signing_key=SecretBytes(base64.b64decode(request["signing_key"], validate=True)),
        ),
    )
    since = request["since"]
    if since is not None:
        if not isinstance(since, str):
            raise ValueError("Invalid JSON parser checkpoint")
        since = datetime.fromisoformat(since)
    deadline = time.monotonic() + config.fetch_deadline_seconds
    return run_feed_process(
        _fetch_worker,
        (config, credentials, since, deadline),
        max_bytes=config.max_result_bytes,
        deadline=deadline,
        process_name="oralhistarchiv-json-feed-fetch",
        cancel_event=cancellation,
    )


def _oai_job(request: dict[str, Any], cancellation: threading.Event) -> bytes:
    """Validate explicit OAI inputs; return an encoded harvest or bounded exception frame."""
    required = {"operation", "url", "since", "institution", "source", "max_pages"}
    if set(request) != required or any(
        not isinstance(request[key], str) for key in required - {"max_pages"}
    ):
        raise ValueError("Invalid OAI parser request")
    try:
        result = _fetch_updates_local(
            request["url"],
            request["since"],
            request["institution"],
            source=request["source"],
            log_level="WARNING",
            log_format="json",
            max_pages=request["max_pages"],
            cancel_event=cancellation,
        )
        return b"S" + encode_harvest_result(result)
    except Exception as error:
        return b"E" + _worker_error_bytes(error)


def serve(connection: socket.socket) -> None:
    """Validate the sandbox and serve one ping, JSON-feed or OAI job on a caller-owned socket.

    Send kernel credentials, read a bounded request within five seconds and run its
    worker with disconnect-triggered cancellation. Send the bounded result within
    five seconds and stop the watcher thread; change socket timeouts but do not close
    the socket. Bootstrap, decoding, validation, worker and transport errors propagate.
    """
    validate_effective_sandbox(connection)
    connection.settimeout(5)
    connection.sendmsg(
        [b"P"],
        [
            (
                socket.SOL_SOCKET,
                socket.SCM_CREDENTIALS,
                struct.pack("3i", os.getpid(), os.getuid(), os.getgid()),
            )
        ],
    )
    payload = receive_bytes(connection, maximum=MAX_REQUEST_BYTES, deadline=time.monotonic() + 5)
    request = json.loads(payload)
    if not isinstance(request, dict):
        raise TypeError("Invalid parser request")
    operation = request.get("operation")
    cancellation, finished = threading.Event(), threading.Event()
    watcher = threading.Thread(
        target=_watch_disconnect, args=(connection, cancellation, finished), daemon=True
    )
    watcher.start()
    try:
        if operation == "ping" and set(request) == {"operation"}:
            result = b"ready"
        elif operation == "json":
            result = _json_job(request, cancellation)
        elif operation == "oai":
            result = _oai_job(request, cancellation)
        else:
            raise ValueError("Invalid parser operation")
        if not result or len(result) > MAX_RESPONSE_BYTES:
            raise ValueError("Invalid parser result")
        send_bytes(connection, result, deadline=time.monotonic() + 5, cancel_event=cancellation)
    finally:
        finished.set()
        watcher.join(timeout=1)


def main() -> None:
    """Use systemd's connected stdin socket; errors never echo credential inputs."""
    with socket.socket(fileno=0) as connection:
        try:
            serve(connection)
        except Exception:
            print("Parser service refused bootstrap or failed its bounded job", file=sys.stderr)


if __name__ == "__main__":
    main()

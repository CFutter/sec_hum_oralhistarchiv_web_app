"""One terminating worker for the complete authenticated feed processing chain."""

import base64
import contextlib
import json
import secrets
import time
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from threading import Event

from app.ingestion_contracts import (
    HarvestResult,
    harvest_result_from_document,
)
from app.ingestion_contracts.cancellation import HarvestCancelled, check_harvest_cancellation

from .base import normalize_harvest_since
from .json_feed_config import (
    JsonFeedConfig,
    JsonFeedCredentials,
    snapshot_json_feed_credentials,
)
from .json_feed_harvest import JsonFeedHarvestBuilder
from .json_feed_http import (
    FeedRequest,
    FeedTransportError,
    download_authenticated_page,
    feed_http_session,
)
from .json_feed_process import check_feed_deadline, run_feed_process
from .json_feed_protocol import FeedProtocolCode, FeedProtocolError
from .json_feed_transport import AuthenticatedFeedPage
from .json_feed_worker_protocol import TRANSPORT_ERROR_FRAMES, encode_transport_error
from .parser_transport import ParserServiceError, request_parser, use_parser_service

_PROTOCOL_FRAMES: dict[bytes, FeedProtocolCode] = {
    b"json": "json",
    b"envelope": "envelope",
    b"request": "request",
    b"freshness": "freshness",
    b"pagination": "pagination",
    b"identity": "identity",
    b"resource_limit": "resource_limit",
    b"state": "state",
}


def _utc_now() -> datetime:
    """Return the current aware UTC time for snapshot freshness checks."""
    return datetime.now(UTC)


def collect_feed_payload(
    config: JsonFeedConfig,
    credentials: JsonFeedCredentials,
    *,
    since: datetime | None,
    deadline: float,
) -> bytes:
    """Collect a complete chain inside the caller's terminating worker.

    One private HTTP session serves every page. Downloads, decoding,
    classification, serialization and session cleanup share the same
    absolute monotonic deadline.
    """
    config = JsonFeedConfig.model_validate(config)
    credentials = snapshot_json_feed_credentials(
        config,
        credentials,
    )
    normalized = normalize_harvest_since(since)
    since_text = (
        normalized.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        if normalized is not None
        else None
    )

    builder = JsonFeedHarvestBuilder(config, since=normalized)
    pages = total_bytes = 0

    check_feed_deadline(deadline)

    with feed_http_session() as session:
        while not builder.complete:
            check_feed_deadline(deadline)

            allowance = min(
                config.max_page_bytes,
                config.max_total_bytes - total_bytes,
            )
            if pages >= config.max_pages or allowance <= 0:
                raise FeedTransportError("resource_limit")

            request = FeedRequest(
                secrets.token_hex(32),
                since_text,
                builder.next_cursor,
            )
            pages += 1

            body = download_authenticated_page(
                config,
                credentials,
                request,
                session=session,
                max_bytes=allowance,
                deadline=deadline,
            )

            check_feed_deadline(deadline)
            total_bytes += len(body)

            builder.accept(
                AuthenticatedFeedPage(request, body),
                now=_utc_now(),
            )
            check_feed_deadline(deadline)

        payload = builder.finish()

    # Session cleanup must finish before accepting a successful candidate.
    check_feed_deadline(deadline)
    return payload


def _error_frame(error: BaseException) -> bytes:
    """Encode a declared transport/protocol failure; hide other exception contents."""
    if isinstance(error, FeedTransportError):
        return b"T" + encode_transport_error(error)
    if isinstance(error, FeedProtocolError):
        for encoded, protocol_code in _PROTOCOL_FRAMES.items():
            if error.error_code == protocol_code:
                return b"P" + encoded
    return b"Tworker"


def _fetch_worker(
    connection: Connection,
    config: JsonFeedConfig,
    credentials: JsonFeedCredentials,
    since: datetime | None,
    deadline: float,
) -> None:
    """Send one candidate or fixed error frame and close the pipe, catching BaseException."""
    try:
        payload = collect_feed_payload(config, credentials, since=since, deadline=deadline)
        connection.send_bytes(b"S" + payload)
    except BaseException as error:
        with contextlib.suppress(Exception):
            connection.send_bytes(_error_frame(error))
    finally:
        connection.close()


def _candidate_payload(frame: bytes, maximum: int) -> bytes:
    """Return bounded nonempty success bytes; raise the encoded or generic worker error."""
    prefix, payload = frame[:1], frame[1:]
    if prefix == b"T" and payload in TRANSPORT_ERROR_FRAMES:
        raise FeedTransportError(TRANSPORT_ERROR_FRAMES[payload])
    if prefix == b"P" and payload in _PROTOCOL_FRAMES:
        raise FeedProtocolError(_PROTOCOL_FRAMES[payload])
    if prefix != b"S" or not payload or len(payload) > maximum:
        raise FeedTransportError("worker")
    return payload


def fetch_json_feed_isolated(
    config: JsonFeedConfig,
    credentials: JsonFeedCredentials,
    *,
    since: datetime | None,
    cancel_event: Event | None = None,
) -> "HarvestResult":
    """Fetch and reconstruct one complete harvest within config.fetch_deadline_seconds.

    since=None selects all; aware boundaries become inclusive UTC whole seconds.
    Use the separate parser service unless dev local mode is selected; local mode
    requires an import-safe, non-daemon caller. Workers fetch HTTPS, authenticate,
    validate and serialize; parent reconstruction is bounded in size but only checked
    cooperatively for time. Cleanup has bounded extra grace. Invalid inputs raise
    TypeError/ValueError, feed failures FeedTransportError/FeedProtocolError, and a
    set cancel_event HarvestCancelled. Invalid mode selection raises ParserServiceError;
    workers are reaped before return.
    """
    check_harvest_cancellation(cancel_event)
    started = time.monotonic()
    if not isinstance(config, JsonFeedConfig):
        raise TypeError("JSON feed fetching requires JsonFeedConfig")
    config = JsonFeedConfig.model_validate(config)
    deadline = started + config.fetch_deadline_seconds
    credentials = snapshot_json_feed_credentials(config, credentials)
    normalized = normalize_harvest_since(since)
    check_feed_deadline(deadline)
    if use_parser_service():
        try:
            frame = request_parser(
                {
                    "operation": "json",
                    "config": config.model_dump(mode="json"),
                    "bearer": credentials.bearer_token.get_secret_value(),
                    "signing_key": base64.b64encode(
                        credentials.signing_key.get_secret_value()
                    ).decode("ascii"),
                    "since": normalized.isoformat() if normalized is not None else None,
                },
                maximum=max(config.max_result_bytes + 1, 32),
                deadline=deadline,
                cancel_event=cancel_event,
            )
        except ParserServiceError:
            raise FeedTransportError("worker") from None
    else:
        frame = run_feed_process(
            _fetch_worker,
            (config, credentials, normalized, deadline),
            max_bytes=config.max_result_bytes,
            deadline=deadline,
            process_name="oralhistarchiv-json-feed-fetch",
            cancel_event=cancel_event,
        )
    payload = _candidate_payload(frame, config.max_result_bytes)
    try:
        check_feed_deadline(deadline)
        result = harvest_result_from_document(json.loads(payload))
        check_feed_deadline(deadline)
        check_harvest_cancellation(cancel_event)
        return result
    except (FeedTransportError, HarvestCancelled):
        raise
    except (MemoryError, RecursionError):
        raise FeedTransportError("resource_limit") from None
    except Exception:
        raise FeedTransportError("worker") from None

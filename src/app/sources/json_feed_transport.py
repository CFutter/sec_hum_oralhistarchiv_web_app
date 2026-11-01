"""Authenticated page bytes with shared budgets and a terminating process boundary.

This lower-level page API remains independent of the complete adapter. The B6
fetch worker uses direct HTTP and does not nest these per-page workers.
"""

import contextlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from multiprocessing.connection import Connection

from .base import normalize_harvest_since
from .json_feed_config import (
    JsonFeedConfig,
    JsonFeedCredentials,
    snapshot_json_feed_credentials,
)
from .json_feed_http import (
    FeedRequest,
    FeedTransportError,
    download_authenticated_page,
    feed_http_session,
)
from .json_feed_lexical import FEED_CURSOR_PATTERN
from .json_feed_process import check_feed_deadline, run_feed_process
from .json_feed_worker_protocol import TRANSPORT_ERROR_FRAMES, encode_transport_error


@dataclass(frozen=True, slots=True)
class AuthenticatedFeedPage:
    """Exact authenticated bytes and their actual request; no JSON acceptance yet."""

    request: FeedRequest
    body: bytes = field(repr=False)


def _page_worker(
    connection: Connection,
    config: JsonFeedConfig,
    credentials: JsonFeedCredentials,
    request: FeedRequest,
    max_bytes: int,
    deadline: float,
) -> None:
    """Download/authenticate one page, send a success/fixed error frame and close the pipe."""
    try:
        check_feed_deadline(deadline)

        with feed_http_session() as session:
            body = download_authenticated_page(
                config,
                credentials,
                request,
                session=session,
                max_bytes=max_bytes,
                deadline=deadline,
            )

        check_feed_deadline(deadline)
        connection.send_bytes(b"S" + body)

    except BaseException as exc:
        with contextlib.suppress(
            BrokenPipeError,
            EOFError,
            OSError,
        ):
            connection.send_bytes(b"E" + encode_transport_error(exc))

    finally:
        connection.close()


def _run_page_isolated(
    config: JsonFeedConfig,
    credentials: JsonFeedCredentials,
    request: FeedRequest,
    *,
    max_bytes: int,
    deadline: float,
) -> bytes:
    """Spawn/reap one page worker and return authenticated bytes; reject error or invalid frames."""
    message = run_feed_process(
        _page_worker,
        (config, credentials, request, max_bytes, deadline),
        max_bytes=max_bytes,
        deadline=deadline,
        process_name="oralhistarchiv-json-feed-page",
    )
    if not message:
        raise FeedTransportError("worker")
    kind, body = message[:1], message[1:]
    if kind == b"E":
        raise FeedTransportError(TRANSPORT_ERROR_FRAMES.get(body, "worker"))
    if kind != b"S" or len(body) > max_bytes:
        raise FeedTransportError("worker")
    return body


class JsonFeedTransport:
    """Read authenticated pages sequentially under shared deadline, byte and page caps.

    Each read spawns/reaps a worker; callers still own chain/metadata validation.
    Request failures invalidate the instance; invalid caller arguments and overlapping
    calls do not. Cleanup may outlast the operation deadline by bounded shutdown grace.
    """

    def __init__(self, config: JsonFeedConfig, credentials: JsonFeedCredentials) -> None:
        """Snapshot config/secrets and start the shared monotonic deadline without I/O."""
        if not isinstance(config, JsonFeedConfig):
            raise TypeError("JSON feed transport requires JsonFeedConfig")
        self._config = JsonFeedConfig.model_validate(config)
        self._credentials = snapshot_json_feed_credentials(self._config, credentials)
        self._deadline = time.monotonic() + self._config.fetch_deadline_seconds
        self._pages = 0
        self._total_bytes = 0
        self._failed = False
        self._lock = threading.Lock()

    @property
    def pages_requested(self) -> int:
        """Return attempted page requests, including an attempt that failed."""
        return self._pages

    @property
    def response_bytes(self) -> int:
        """Return the total authenticated byte count from successful reads."""
        return self._total_bytes

    def _page_allowance(self) -> int:
        """Return remaining page bytes; raise resource_limit for expired or exhausted budgets."""
        check_feed_deadline(self._deadline)
        remaining = self._config.max_total_bytes - self._total_bytes
        if self._pages >= self._config.max_pages or remaining <= 0:
            raise FeedTransportError("resource_limit")
        return min(self._config.max_page_bytes, remaining)

    def read_page(
        self, *, since: datetime | None, cursor: str | None = None
    ) -> AuthenticatedFeedPage:
        """Return one authenticated page, without JSON/chain validation, and update request/byte
        counts.

        since=None selects all; aware boundaries become inclusive UTC whole seconds.
        cursor=None starts a chain; otherwise require 1..512 base64url characters.
        Invalid arguments raise TypeError/ValueError; overlapping calls raise RuntimeError.
        Worker, deadline and budget failures raise FeedTransportError and invalidate the
        instance.
        """
        normalized = normalize_harvest_since(since)
        since_text = (
            normalized.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            if normalized is not None
            else None
        )
        if cursor is not None:
            if not isinstance(cursor, str):
                raise TypeError("JSON feed cursor must be text or None")
            if FEED_CURSOR_PATTERN.fullmatch(cursor) is None:
                raise ValueError("JSON feed cursor is outside the v1 profile")
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("JSON feed page reads must be sequential")
        try:
            if self._failed:
                raise FeedTransportError("transport")
            try:
                allowance = self._page_allowance()
                self._pages += 1
                request = FeedRequest(secrets.token_hex(32), since_text, cursor)
                body = _run_page_isolated(
                    self._config,
                    self._credentials,
                    request,
                    max_bytes=allowance,
                    deadline=self._deadline,
                )
                check_feed_deadline(self._deadline)
                self._total_bytes += len(body)
                return AuthenticatedFeedPage(request, body)
            except FeedTransportError:
                self._failed = True
                raise
            except Exception:
                self._failed = True
                raise FeedTransportError("worker") from None
            except BaseException:
                self._failed = True
                raise
        finally:
            self._lock.release()

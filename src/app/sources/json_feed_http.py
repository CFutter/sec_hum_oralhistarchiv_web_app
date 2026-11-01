"""Bounded raw HTTPS download and exact-byte authentication for a single page.

The caller owns the terminating worker deadline and the complete harvest budget.
This module neither decodes JSON nor makes a response into an accepted harvest.
"""

import hashlib
import hmac
import math
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http import HTTPStatus
from http.cookiejar import DefaultCookiePolicy
from typing import Literal

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import HTTPError

from .json_feed_config import JsonFeedConfig, JsonFeedCredentials

FeedErrorCode = Literal[
    "transport", "http_status", "headers", "signature", "resource_limit", "worker"
]
_ERROR_MESSAGES: dict[FeedErrorCode, str] = {
    "transport": "JSON feed transport failed",
    "http_status": "JSON feed response status was refused",
    "headers": "JSON feed response headers were refused",
    "signature": "JSON feed response signature was refused",
    "resource_limit": "JSON feed resource budget was exceeded",
    "worker": "JSON feed worker failed",
}
_JSON_TYPE = re.compile(
    r'application/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8"))?', re.IGNORECASE
)
_SIGNATURE = re.compile(r"v1=[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"[0-9]+\Z")
_CHUNK_BYTES = 65_536
_MAX_LENGTH_DIGITS = 20


class FeedTransportError(Exception):
    """A fixed, credential-free diagnostic suitable for a worker boundary."""

    def __init__(self, error_code: FeedErrorCode) -> None:
        """Store a declared code and its fixed message; unknown codes raise KeyError."""
        self.error_code = error_code
        super().__init__(_ERROR_MESSAGES[error_code])


@dataclass(frozen=True, slots=True)
class FeedRequest:
    """Unvalidated fields: expected nonce is 64 lowercase hex, since UTC seconds or None, cursor
    opaque or None.
    """

    nonce: str
    since: str | None
    cursor: str | None


def _remaining(deadline: float) -> float:
    """Return seconds until an absolute monotonic deadline; raise resource_limit if expired."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise FeedTransportError("resource_limit")
    return remaining


def _single_header(response: requests.Response, name: str, *, required: bool = False) -> str | None:
    # Response.headers folds duplicate values and loses their original cardinality.
    """Return one raw header or None; reject duplicates and missing required headers."""
    values = response.raw.headers.getlist(name)
    if len(values) > 1 or (required and not values):
        raise FeedTransportError("headers")
    return values[0] if values else None


def _response_headers(response: requests.Response, max_bytes: int) -> tuple[str, int | None]:
    """Return signature and optional length; reject unsafe headers and oversized bodies."""
    content_type = _single_header(response, "Content-Type", required=True)
    encoding = _single_header(response, "Content-Encoding")
    signature = _single_header(response, "X-Feed-Signature", required=True)
    length = _single_header(response, "Content-Length")
    if content_type is None or _JSON_TYPE.fullmatch(content_type.strip(" \t")) is None:
        raise FeedTransportError("headers")
    if encoding is not None and encoding.strip(" \t").casefold() != "identity":
        raise FeedTransportError("headers")
    if signature is None or _SIGNATURE.fullmatch(signature) is None:
        raise FeedTransportError("signature")
    expected_length = None
    if length is not None:
        if len(length) > _MAX_LENGTH_DIGITS:
            raise FeedTransportError("resource_limit")
        if _DECIMAL.fullmatch(length) is None:
            raise FeedTransportError("headers")
        expected_length = int(length)
        if expected_length > max_bytes:
            raise FeedTransportError("resource_limit")
    return signature, expected_length


@contextmanager
def feed_http_session() -> Iterator[requests.Session]:
    """Own one isolated connection pool for a complete feed or one-page worker."""
    try:
        with requests.Session() as session:
            session.trust_env = False

            # An empty allowlist intentionally rejects all response cookies.
            session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=()))

            session.mount(
                "https://",
                HTTPAdapter(max_retries=0),
            )
            yield session
    except (requests.RequestException, HTTPError, OSError):
        raise FeedTransportError("transport") from None


def download_authenticated_page(
    config: JsonFeedConfig,
    credentials: JsonFeedCredentials,
    request: FeedRequest,
    *,
    session: requests.Session,
    max_bytes: int,
    deadline: float,
) -> bytes:
    """Return bounded, authenticated bytes using a caller-owned feed session.

    session must come from feed_http_session(). This function closes only
    its response, leaving connection-pool ownership with the caller.

    deadline is an absolute monotonic cutoff owned by the parent watchdog.
    Socket inactivity timeouts and cooperative checks supplement that
    terminating boundary. max_bytes includes the remaining aggregate allowance.
    """
    if (
        type(max_bytes) is not int
        or not 1
        <= max_bytes
        <= min(
            config.max_page_bytes,
            config.max_total_bytes,
        )
        or not math.isfinite(deadline)
        or credentials.source_name != config.name
    ):
        raise FeedTransportError("worker")

    remaining = _remaining(deadline)

    params = {"nonce": request.nonce}
    if request.since is not None:
        params["since"] = request.since
    if request.cursor is not None:
        params["cursor"] = request.cursor

    headers = {
        "Authorization": (f"Bearer {credentials.bearer_token.get_secret_value()}"),
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }

    try:
        with session.get(
            config.endpoint,
            params=params,
            headers=headers,
            allow_redirects=False,
            stream=True,
            verify=True,
            timeout=(
                min(10.0, remaining),
                min(10.0, remaining),
            ),
        ) as response:
            _remaining(deadline)

            if response.status_code != HTTPStatus.OK:
                raise FeedTransportError("http_status")

            signature, expected_length = _response_headers(
                response,
                max_bytes,
            )

            body = bytearray()
            while True:
                _remaining(deadline)
                chunk = response.raw.read(
                    min(
                        _CHUNK_BYTES,
                        max_bytes + 1 - len(body),
                    ),
                    decode_content=False,
                )
                _remaining(deadline)

                if not chunk:
                    break

                body.extend(chunk)
                if len(body) > max_bytes:
                    raise FeedTransportError("resource_limit")

            if expected_length is not None and len(body) != expected_length:
                raise FeedTransportError("transport")

            _remaining(deadline)
            digest = hmac.new(
                credentials.signing_key.get_secret_value(),
                body,
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(
                signature,
                f"v1={digest}",
            ):
                raise FeedTransportError("signature")

            _remaining(deadline)
            return bytes(body)

    except (requests.RequestException, HTTPError, OSError):
        raise FeedTransportError("transport") from None

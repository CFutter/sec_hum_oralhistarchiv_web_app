"""Fixed protocol failures and immutable page inputs, without feed activation."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Final, Literal

from .json_feed_http import FeedRequest

FEED_CONTRACT_VERSION: Final = 1
FEED_ACCESS_LABELS: Final[Mapping[str, str]] = MappingProxyType(
    {"Public access": "public", "Restricted access": "restricted"}
)

FeedProtocolCode = Literal[
    "json", "envelope", "request", "freshness", "pagination", "identity", "resource_limit", "state"
]
FeedRecordReason = Literal[
    "duplicate_record_key", "record_shape", "record_metadata", "record_tier", "record_timestamp"
]
_MESSAGES: dict[FeedProtocolCode, str] = {
    "json": "JSON feed document was refused",
    "envelope": "JSON feed envelope was refused",
    "request": "JSON feed request binding was refused",
    "freshness": "JSON feed snapshot freshness was refused",
    "pagination": "JSON feed page chain was refused",
    "identity": "JSON feed record identity was refused",
    "resource_limit": "JSON feed resource budget was exceeded",
    "state": "JSON feed validation state is unavailable",
}


class FeedProtocolError(Exception):
    """A fixed diagnostic containing no incoming values or body fragments."""

    def __init__(self, error_code: FeedProtocolCode) -> None:
        """Store a declared code and its fixed message; unknown codes raise KeyError."""
        self.error_code = error_code
        super().__init__(_MESSAGES[error_code])


class FeedInternalError(RuntimeError):
    """A local implementation failure, transported as a fixed worker fault.

    Unlike FeedProtocolError this never blames a publisher envelope. Exception
    values remain suppressed because they may contain submitted metadata.
    """

    def __init__(self) -> None:
        """Use a fixed message that omits submitted metadata and exception contents."""
        super().__init__("JSON feed processing failed internally")


@dataclass(frozen=True, slots=True)
class FeedRecordInput:
    """Identifiable original record bytes; metadata still requires validation."""

    uuid: str
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class FeedRecordRejection:
    """A quarantined identity and fixed reason; incoming metadata is discarded."""

    uuid: str
    reason: FeedRecordReason = "duplicate_record_key"


@dataclass(frozen=True, slots=True)
class ValidatedFeedPage:
    """Checked envelope and identities, with record metadata awaiting classification."""

    request: FeedRequest
    snapshot_id: str
    generated_at: datetime
    records: tuple[FeedRecordInput, ...] = field(repr=False)
    quarantined: tuple[FeedRecordRejection, ...]
    withdrawn: tuple[str, ...]
    next_cursor: str | None
    complete: bool

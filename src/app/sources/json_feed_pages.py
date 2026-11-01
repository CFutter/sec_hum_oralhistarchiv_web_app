"""Pure envelope, identity and page-chain validation for authenticated feed bytes.

Record metadata classification and the complete-fetch process deadline belong
to the next integration boundary. This module performs no I/O or persistence.
"""

import re
import threading
from datetime import UTC, datetime

from .base import normalize_harvest_since
from .json_feed_config import JsonFeedConfig
from .json_feed_http import FeedRequest
from .json_feed_json import JSONObject, RawJSONRecord, decode_feed_document
from .json_feed_lexical import FEED_CURSOR_PATTERN, FEED_UTC_SECOND_PATTERN, FEED_UUID_PATTERN
from .json_feed_protocol import (
    FEED_CONTRACT_VERSION,
    FeedInternalError,
    FeedProtocolCode,
    FeedProtocolError,
    FeedRecordInput,
    FeedRecordRejection,
    ValidatedFeedPage,
)
from .json_feed_transport import AuthenticatedFeedPage

_FIELDS = {
    "feed_version",
    "snapshot_id",
    "generated_at",
    "request",
    "records",
    "withdrawn",
    "next_cursor",
    "complete",
}
_REQUEST_FIELDS = {"nonce", "since", "cursor"}
_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_FRESHNESS_SECONDS = 600


def _object_fields(value: object, expected: set[str], code: FeedProtocolCode) -> dict[str, object]:
    """Return exactly the expected unique fields; otherwise raise the supplied protocol code."""
    if not isinstance(value, JSONObject):
        raise FeedProtocolError(code)
    values = dict(value.pairs)
    if len(values) != len(value.pairs) or set(values) != expected:
        raise FeedProtocolError(code)
    return values


def _uuid(value: object, code: FeedProtocolCode) -> str:
    """Return a canonical lowercase UUIDv4 string; otherwise raise the supplied protocol code."""
    if not isinstance(value, str) or FEED_UUID_PATTERN.fullmatch(value) is None:
        raise FeedProtocolError(code)
    return value


def _timestamp(value: object) -> datetime:
    """Parse YYYY-MM-DDTHH:MM:SSZ into UTC; reject invalid values as envelope failures."""
    if not isinstance(value, str) or FEED_UTC_SECOND_PATTERN.fullmatch(value) is None:
        raise FeedProtocolError("envelope")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise FeedProtocolError("envelope") from None


def _current_utc(now: datetime) -> datetime:
    """Normalize aware now to UTC; wrong types raise TypeError and naive values ValueError."""
    if not isinstance(now, datetime):
        raise TypeError("JSON feed acceptance requires a current datetime")
    if now.utcoffset() is None:
        raise ValueError("JSON feed acceptance requires an aware current datetime")
    return now.astimezone(UTC)


def _record_uuid(value: object) -> str:
    """Return the sole canonical UUIDv4 field; malformed identity raises FeedProtocolError."""
    if not isinstance(value, JSONObject):
        raise FeedProtocolError("identity")
    values = [item for key, item in value.pairs if key == "uuid"]
    if len(values) != 1:
        raise FeedProtocolError("identity")
    return _uuid(values[0], "identity")


def _has_duplicate_keys(value: object) -> bool:
    """Find duplicate object keys at any depth without recursive calls."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, JSONObject):
            keys: set[str] = set()
            for key, child in item.pairs:
                if key in keys:
                    return True
                keys.add(key)
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
    return False


class JsonFeedPageValidator:
    """Validate one authenticated page chain; use sequentially.

    Record bodies still need metadata validation. Guarded accept failures invalidate
    the chain; invalid caller arguments and overlapping calls fail before that guard.
    finish returns the cutoff only for a complete chain and invalidates incomplete
    chains; successful finish may be repeated.
    """

    def __init__(self, config: JsonFeedConfig, *, since: datetime | None) -> None:
        """Snapshot config and initialize chain state; truncate aware since to UTC seconds, or
        select all.
        """
        if not isinstance(config, JsonFeedConfig):
            raise TypeError("JSON feed page validation requires JsonFeedConfig")
        self._config = JsonFeedConfig.model_validate(config)
        normalized = normalize_harvest_since(since)
        self._since = normalized.replace(microsecond=0) if normalized is not None else None
        self._since_text = self._since.isoformat().replace("+00:00", "Z") if self._since else None
        self._snapshot_id: str | None = None
        self._generated_at: datetime | None = None
        self._expected_cursor: str | None = None
        self._seen_ids: set[str] = set()
        self._seen_cursors: set[str] = set()
        self._seen_nonces: set[str] = set()
        self._pages = 0
        self._total_bytes = 0
        self._complete = False
        self._failed = False
        self._lock = threading.Lock()

    @property
    def complete(self) -> bool:
        """Return whether an unfailed final page has been accepted."""
        return self._complete and not self._failed

    @property
    def next_cursor(self) -> str | None:
        """Return the required next request cursor, rejecting failed state."""
        if self._failed:
            raise FeedProtocolError("state")
        return self._expected_cursor

    def _check_page_budget(self, body: bytes) -> None:
        """Reject failed/completed chains or exhausted page/aggregate-byte budgets without
        mutation.
        """
        if self._failed or self._complete:
            raise FeedProtocolError("state")
        if self._pages >= self._config.max_pages or (
            self._total_bytes + len(body) > self._config.max_total_bytes
        ):
            raise FeedProtocolError("resource_limit")

    def _check_request(self, request: FeedRequest, value: object) -> None:
        """Check expected cursor, fresh nonce, second-precision since and the exact request echo."""
        if request.cursor != self._expected_cursor:
            raise FeedProtocolError("pagination")
        if (
            not isinstance(request.nonce, str)
            or _NONCE.fullmatch(request.nonce) is None
            or request.nonce in self._seen_nonces
            or request.since != self._since_text
        ):
            raise FeedProtocolError("request")
        echo = _object_fields(value, _REQUEST_FIELDS, "request")
        if echo != {"nonce": request.nonce, "since": request.since, "cursor": request.cursor}:
            raise FeedProtocolError("request")

    def _check_snapshot(self, snapshot_id: str, cutoff: datetime, now: datetime) -> None:
        """Require a stable snapshot/cutoff within 600 seconds of now and at or after since."""
        if self._pages and (snapshot_id != self._snapshot_id or cutoff != self._generated_at):
            raise FeedProtocolError("pagination")
        if abs((cutoff - now).total_seconds()) > _FRESHNESS_SECONDS:
            raise FeedProtocolError("freshness")
        if self._since is not None and cutoff < self._since:
            raise FeedProtocolError("envelope")

    def _completion(self, values: dict[str, object]) -> tuple[str | None, bool]:
        """Return (next_cursor, complete), rejecting invalid or repeated cursors."""
        complete = values["complete"]
        cursor = values["next_cursor"]
        if not isinstance(complete, bool):
            raise FeedProtocolError("envelope")
        if cursor is not None and (
            not isinstance(cursor, str) or FEED_CURSOR_PATTERN.fullmatch(cursor) is None
        ):
            raise FeedProtocolError("pagination")
        if complete != (cursor is None) or cursor in self._seen_cursors:
            raise FeedProtocolError("pagination")
        return cursor, complete

    def _claim_identity(self, identity: str, found: set[str]) -> None:
        """Add a new identity to found; reject repetition within or across pages."""
        if identity in found or identity in self._seen_ids:
            raise FeedProtocolError("identity")
        found.add(identity)

    def _record_inputs(
        self, values: dict[str, object]
    ) -> tuple[
        tuple[FeedRecordInput, ...], tuple[FeedRecordRejection, ...], tuple[str, ...], set[str]
    ]:
        """Return records, duplicate-key quarantines, withdrawals and new IDs; reject
        limits/identity errors.
        """
        raw_records, raw_withdrawn = values["records"], values["withdrawn"]
        if not isinstance(raw_records, list) or not isinstance(raw_withdrawn, list):
            raise FeedProtocolError("envelope")
        if len(self._seen_ids) + len(raw_records) + len(raw_withdrawn) > self._config.max_records:
            raise FeedProtocolError("resource_limit")
        records: list[FeedRecordInput] = []
        quarantined: list[FeedRecordRejection] = []
        withdrawn: list[str] = []
        found: set[str] = set()
        for raw in raw_records:
            if not isinstance(raw, RawJSONRecord):
                raise FeedProtocolError("identity")
            identity = _record_uuid(raw.value)
            self._claim_identity(identity, found)
            if _has_duplicate_keys(raw.value):
                quarantined.append(FeedRecordRejection(identity))
            else:
                records.append(FeedRecordInput(identity, raw.body))
        for value in raw_withdrawn:
            identity = _uuid(value, "identity")
            self._claim_identity(identity, found)
            withdrawn.append(identity)
        return tuple(records), tuple(quarantined), tuple(withdrawn), found

    def _accept(self, page: AuthenticatedFeedPage, now: datetime) -> ValidatedFeedPage:
        """Validate a page and commit chain counters/identities before returning its record
        inputs.
        """
        self._check_page_budget(page.body)
        document = decode_feed_document(
            page.body,
            max_page_bytes=self._config.max_page_bytes,
            max_record_bytes=self._config.max_record_bytes,
            max_records=self._config.max_records,
        )
        values = _object_fields(document, _FIELDS, "envelope")
        if (
            type(values["feed_version"]) is not int
            or values["feed_version"] != FEED_CONTRACT_VERSION
        ):
            raise FeedProtocolError("envelope")
        snapshot_id = _uuid(values["snapshot_id"], "envelope")
        cutoff = _timestamp(values["generated_at"])
        self._check_snapshot(snapshot_id, cutoff, now)
        self._check_request(page.request, values["request"])
        next_cursor, complete = self._completion(values)
        records, quarantined, withdrawn, found = self._record_inputs(values)
        self._seen_ids.update(found)
        self._seen_nonces.add(page.request.nonce)
        if next_cursor is not None:
            self._seen_cursors.add(next_cursor)
        self._snapshot_id, self._generated_at = snapshot_id, cutoff
        self._expected_cursor, self._complete = next_cursor, complete
        self._pages += 1
        self._total_bytes += len(page.body)
        return ValidatedFeedPage(
            page.request,
            snapshot_id,
            cutoff,
            records,
            quarantined,
            withdrawn,
            next_cursor,
            complete,
        )

    def accept(self, page: AuthenticatedFeedPage, *, now: datetime) -> ValidatedFeedPage:
        """Validate and retain chain state; return identifiable records awaiting metadata
        validation.

        now must be aware. Invalid input types raise TypeError; naive now raises ValueError.
        Overlapping calls raise RuntimeError. Guarded failures invalidate the chain and
        raise FeedProtocolError or FeedInternalError; process-control BaseExceptions
        propagate.
        No partial result is returned.
        """
        current = _current_utc(now)
        if not isinstance(page, AuthenticatedFeedPage) or (
            not isinstance(page.body, bytes) or not isinstance(page.request, FeedRequest)
        ):
            raise TypeError("JSON feed validation requires an authenticated byte page")
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("JSON feed page validation must be sequential")
        try:
            return self._accept(page, current)
        except (FeedProtocolError, FeedInternalError):
            self._failed = True
            raise
        except (MemoryError, RecursionError):
            self._failed = True
            raise FeedProtocolError("resource_limit") from None
        except Exception:
            self._failed = True
            raise FeedInternalError() from None
        except BaseException:
            self._failed = True
            raise
        finally:
            self._lock.release()

    def finish(self) -> datetime:
        """Return the cutoff only after completion; an incomplete finish aborts the chain."""
        if self._failed:
            raise FeedProtocolError("state")
        if not self._complete or self._generated_at is None:
            self._failed = True
            raise FeedProtocolError("pagination")
        return self._generated_at

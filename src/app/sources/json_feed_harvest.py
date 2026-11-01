"""Complete-chain metadata classification and bounded candidate serialization.

This pure builder performs no I/O and supplies no terminating deadline. The
full-fetch worker must enclose transport, this builder and result serialization.
"""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from app.ingestion_contracts import harvest as harvest_contract

from .base import normalize_harvest_since
from .json_feed_config import JsonFeedConfig
from .json_feed_http import FeedRequest
from .json_feed_pages import JsonFeedPageValidator
from .json_feed_protocol import FeedInternalError, FeedProtocolError, FeedRecordRejection
from .json_feed_records import classify_feed_record
from .json_feed_transport import AuthenticatedFeedPage


class JsonFeedHarvestBuilder:
    """Build one complete harvest sequentially from authenticated pages.

    Failures inside accept/finish discard metadata and invalidate the builder; caller
    argument checks before the guard leave state usable. Overlapping guarded calls
    raise RuntimeError. Successful finish is single-use and clears retained metadata.
    """

    def __init__(self, config: JsonFeedConfig, *, since: datetime | None) -> None:
        """Snapshot config and initialize a chain; truncate aware since to UTC seconds, or select
        all.
        """
        if not isinstance(config, JsonFeedConfig):
            raise TypeError("JSON feed harvest building requires JsonFeedConfig")
        self._config = JsonFeedConfig.model_validate(config)
        normalized = normalize_harvest_since(since)
        self._since = normalized.replace(microsecond=0) if normalized is not None else None
        self._pages = JsonFeedPageValidator(self._config, since=self._since)
        self._records: list[dict[str, Any]] = []
        self._withdrawn: set[str] = set()
        self._uncertain: dict[str, str] = {}
        self._failed = False
        self._finished = False
        self._lock = threading.Lock()

    @property
    def complete(self) -> bool:
        """Return whether the page chain is complete and no fatal failure occurred."""
        return self._pages.complete and not self._failed

    @property
    def next_cursor(self) -> str | None:
        """Return the next request cursor while the builder is still active."""
        self._ensure_active()
        return self._pages.next_cursor

    def _ensure_active(self) -> None:
        """Raise FeedProtocolError(state) after failure or successful finish."""
        if self._failed or self._finished:
            raise FeedProtocolError("state")

    def _discard(self) -> None:
        """Clear retained records, withdrawals and quarantine reasons."""
        self._records.clear()
        self._withdrawn.clear()
        self._uncertain.clear()

    @contextmanager
    def _operation(self) -> Iterator[None]:
        """Reject overlapping operations; invalidate and discard state on guarded failures.

        Preserve protocol/internal errors and BaseException; map resource exhaustion to
        FeedProtocolError and other exceptions to FeedInternalError; always unlock.
        """
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("JSON feed harvest building must be sequential")
        try:
            self._ensure_active()
            yield
        except (FeedProtocolError, FeedInternalError):
            self._failed = True
            self._discard()
            raise
        except (MemoryError, RecursionError):
            self._failed = True
            self._discard()
            raise FeedProtocolError("resource_limit") from None
        except Exception:
            self._failed = True
            self._discard()
            raise FeedInternalError() from None
        except BaseException:
            self._failed = True
            self._discard()
            raise
        finally:
            self._lock.release()

    def accept(self, page: AuthenticatedFeedPage, *, now: datetime) -> None:
        """Validate/classify one authenticated page and retain its records or quarantine reasons.

        now must be aware. Caller TypeError/ValueError leaves state unchanged; overlapping
        calls raise RuntimeError. Guarded failures invalidate and discard the harvest.
        """
        current = normalize_harvest_since(now)
        if current is None:
            raise TypeError("JSON feed harvest building requires an aware current time")
        if not isinstance(page, AuthenticatedFeedPage) or (
            not isinstance(page.body, bytes) or not isinstance(page.request, FeedRequest)
        ):
            raise TypeError("JSON feed harvest building requires an authenticated byte page")
        with self._operation():
            validated = self._pages.accept(page, now=current)
            for record in validated.records:
                classified = classify_feed_record(
                    record,
                    cutoff=validated.generated_at,
                    since=self._since,
                    max_record_bytes=self._config.max_record_bytes,
                    max_project_title_chars=self._config.max_project_title_chars,
                )
                if isinstance(classified, FeedRecordRejection):
                    self._uncertain[classified.uuid] = classified.reason
                else:
                    self._records.append(classified)
            self._uncertain.update((item.uuid, item.reason) for item in validated.quarantined)
            self._withdrawn.update(validated.withdrawn)

    def finish(self) -> bytes:
        """Return serialized HarvestResult bytes once after the final page, then clear retained
        metadata.

        Incomplete/failed state or size exhaustion raises FeedProtocolError; shared-schema
        validation failures raise FeedInternalError and discard the harvest.
        Concurrent operations raise RuntimeError. Persistence and cursor advancement belong
        to the caller; no partial result is returned.
        """
        with self._operation():
            cutoff = self._pages.finish()
            result = harvest_contract.HarvestResult(
                matching_records=self._records,
                deleted_uuids=self._withdrawn,
                uncertain_records=self._uncertain,
                source_cursor=cutoff,
            )
            try:
                payload = harvest_contract.encode_harvest_result(
                    result, max_bytes=self._config.max_result_bytes
                )
            except harvest_contract.HarvestResultSizeError:
                raise FeedProtocolError("resource_limit") from None
            self._finished = True
            self._discard()
            return payload

"""Metadata-free ingestion events persisted with their catalogue transactions.

Buffers follow their caller's transaction/savepoint lifetime. Persist before
commit; optional local log copies are emitted only after the commit succeeds.
"""

import logging
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal

from psycopg import AsyncCursor

from app.sources import AccessTier

from .access_tiers import tier_rank
from .audit_outbox import append_security_event_cur

logger = logging.getLogger("audit")
WithdrawalReason = Literal["explicit", "inferred"]


@dataclass(frozen=True, slots=True)
class DatasetTierState:
    """Only persisted identity and restrictions, without catalogue metadata."""

    dataset_id: int
    source: str
    uuid: str
    stored_tier: AccessTier
    admin_tier: AccessTier | None

    @property
    def effective_tier(self) -> AccessTier:
        """Return the stricter stored/administrator tier, or the stored tier without an override."""
        if self.admin_tier is None:
            return self.stored_tier
        return max((self.stored_tier, self.admin_tier), key=tier_rank)


@dataclass(frozen=True, slots=True)
class DatasetWriteState:
    """Identity and stored restriction returned by the actual catalogue upsert."""

    dataset_id: int
    source: str
    uuid: str
    stored_tier: AccessTier


@dataclass(frozen=True, slots=True)
class _TierChanged:
    """A dataset tier transition queued for transactional audit."""

    dataset_id: int
    source: str
    uuid: str
    old_tier: AccessTier
    new_tier: AccessTier


@dataclass(frozen=True, slots=True)
class _DatasetWithdrawn:
    """A dataset withdrawal and its stable reason queued for audit emission."""

    dataset_id: int
    source: str
    uuid: str
    reason: WithdrawalReason


async def read_tier_state_cur(
    cur: AsyncCursor[Any], *, source: str, uuid: str
) -> DatasetTierState | None:
    """Lock/read an existing row and its durable administrator tier floor."""
    await cur.execute(
        """SELECT dataset.id, dataset.source, dataset.uuid,
                  dataset.visibility_tier, admin.visibility_tier AS admin_tier
           FROM oral_history_datasets AS dataset
           LEFT JOIN dataset_admin_state AS admin
             ON admin.source = dataset.source AND admin.uuid = dataset.uuid
           WHERE dataset.source = %s AND dataset.uuid = %s
           FOR UPDATE OF dataset""",
        (source, uuid),
    )
    row = await cur.fetchone()
    if row is None:
        return None
    return DatasetTierState(
        row["id"], row["source"], row["uuid"], row["visibility_tier"], row["admin_tier"]
    )


class IngestionAudit:
    """A transaction-local buffer; merge successful savepoints and persist before commit."""

    def __init__(self) -> None:
        """Start an empty event buffer with no persisted events."""
        self._changes: list[_TierChanged | _DatasetWithdrawn] = []
        self._persisted_count = 0

    def merge(self, child: "IngestionAudit") -> None:
        """Transfer a successful child savepoint's changes without emitting them."""
        self._changes.extend(child._changes)
        child._changes.clear()

    def record_tier_change(
        self,
        before: DatasetTierState | None,
        after: DatasetWriteState,
    ) -> None:
        """Compare persisted tiers without another query; inserts emit no event.

        The caller holds the common catalogue transaction lock, keeping the
        captured administrator floor stable until this transaction ends.
        """
        if not isinstance(after, DatasetWriteState):
            raise RuntimeError(  # noqa: TRY004 - internal writer contract failure.
                "Catalogue upsert returned an invalid persisted state"
            )

        if before is None:
            return

        if (after.dataset_id, after.source, after.uuid) != (
            before.dataset_id,
            before.source,
            before.uuid,
        ):
            raise RuntimeError("Persisted ingestion audit state is unavailable")

        effective_after = DatasetTierState(
            after.dataset_id,
            after.source,
            after.uuid,
            after.stored_tier,
            before.admin_tier,
        ).effective_tier

        if before.effective_tier != effective_after:
            self._changes.append(
                _TierChanged(
                    after.dataset_id,
                    after.source,
                    after.uuid,
                    before.effective_tier,
                    effective_after,
                )
            )

    def record_withdrawals(
        self,
        rows: Sequence[Mapping[str, Any]],
        *,
        source: str,
        reason: WithdrawalReason,
    ) -> None:
        """Collect only actual DELETE RETURNING identities, never requested absent IDs."""
        self._changes.extend(
            _DatasetWithdrawn(row["id"], source, row["uuid"], reason) for row in rows
        )

    def emit(self) -> None:
        """Drain optional local log copies after the owning transaction commits."""
        changes, self._changes = self._changes, []
        self._persisted_count = 0
        for change in changes:
            event_type, fields = _event(change)
            logger.info(event_type, extra={"event_type": event_type, **fields})

    async def persist_cur(self, cur: AsyncCursor[Any]) -> None:
        """Append buffered events with the mutation cursor; failures abort its transaction.

        Repeated calls in the same transaction append only newly buffered work.
        Discard the complete buffer if that transaction or a commit fails.
        """
        while self._persisted_count < len(self._changes):
            event_type, fields = _event(self._changes[self._persisted_count])
            await append_security_event_cur(cur, event_type, fields)
            self._persisted_count += 1


def _event(change: _TierChanged | _DatasetWithdrawn) -> tuple[str, dict[str, object]]:
    """Return the event name and pseudonymous dataset/restriction payload."""
    fields: dict[str, object] = {
        "dataset_id": change.dataset_id,
        "source": change.source,
        "uuid": change.uuid,
    }
    if isinstance(change, _TierChanged):
        fields.update(old_tier=change.old_tier, new_tier=change.new_tier)
        return "tier_changed", fields
    fields["reason"] = change.reason
    return "dataset_withdrawn", fields


@contextmanager
def audit_savepoint(parent: IngestionAudit | None) -> Iterator[IngestionAudit | None]:
    """Discard on savepoint failure; merge only after the caller's savepoint exits."""
    if parent is None:
        yield None
        return
    child = IngestionAudit()
    yield child
    parent.merge(child)

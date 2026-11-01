"""Commit authorized dataset restrictions and audit each durable change.

Catalogue writes cooperate with ingestion's advisory lock. The service owns
its transaction; callers must not wrap it in another mutation transaction.
Routes supply trusted runtime sources and request correlation, never a source
policy chosen by submitted form fields. No upstream fetch is performed.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, cast, get_args

from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool

from app.federation_contract import valid_federated_identity
from app.sources import AccessTier, SourceMetadata
from config import settings

from .access_tiers import (
    SourceVisibilityTierError,
    resolve_required_source_tier,
    resolve_tier,
    tier_rank,
)
from .audit import append_dataset_admin_action_cur, audit_dataset_admin_action
from .catalogue_lock import acquire_catalogue_write_lock_cur
from .db import get_db_cursor
from .federated_session_policy import federation_policy_is_current_cur
from .users import AdminActionRejected, guard_current_admin_session_cur

DatasetAdminAction = Literal["raise_tier", "hide", "restore"]
DatasetAdminReason = Literal[
    "invalid_action",
    "invalid_tier",
    "dataset_not_found",
    "source_unavailable",
    "source_configuration",
    "tier_below_floor",
    "invalid_source_tier",
]


class DatasetAdminRejected(ValueError):
    """A sanitized domain rejection; HTTP callers map reason to fixed feedback."""

    def __init__(self, reason: DatasetAdminReason):
        """Retain the stable rejection reason as both reason and the exception message."""
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class DatasetAdminContext:
    """Exact acting credential plus server-resolved request correlation."""

    actor_id: int
    actor_session_id: str = field(repr=False)
    request_id: str | None = None
    client_ip: str | None = None

    def __post_init__(self) -> None:
        """Raise AdminActionRejected unless the actor ID is positive and session ID nonempty."""
        if type(self.actor_id) is not int or self.actor_id <= 0:
            raise AdminActionRejected("Your administrator access is invalid.")
        if not isinstance(self.actor_session_id, str) or not self.actor_session_id:
            raise AdminActionRejected("Your administrator session is no longer valid.")


@dataclass(frozen=True, slots=True)
class DatasetAdminState:
    """Stored classification and durable administrator restrictions at one boundary."""

    stored_tier: AccessTier
    admin_tier: AccessTier | None
    hidden_at: datetime | None

    @property
    def effective_tier(self) -> AccessTier:
        """Return the same stricter classification used by catalogue reads."""
        if self.admin_tier is None:
            return self.stored_tier
        return max((self.stored_tier, self.admin_tier), key=tier_rank)


@dataclass(frozen=True, slots=True)
class DatasetAdminChange:
    """Committed result; identities and classification state contain no metadata."""

    dataset_id: int
    source: str
    uuid: str
    action: DatasetAdminAction
    before: DatasetAdminState
    after: DatasetAdminState

    @property
    def changed(self) -> bool:
        """Include establishing a durable floor even if today's effective tier is equal."""
        return self.before != self.after


async def _authorize_cur(
    cur: AsyncCursor[Any], context: DatasetAdminContext, *, federation_current: bool
) -> None:
    """Revalidate the locked administrator session and local or federated eligibility.

    Require federation_current for federated actors; raise AdminActionRejected
    when the actor, session or authentication policy is no longer eligible.
    """
    await guard_current_admin_session_cur(
        cur, actor_id=context.actor_id, actor_session_id=context.actor_session_id
    )
    await cur.execute(
        "SELECT auth_method, email_verified, totp_recovery_required, federated_status, "
        "shibboleth_issuer, shibboleth_subject_id FROM users WHERE id = %s",
        (context.actor_id,),
    )
    actor = await cur.fetchone()
    if actor is None:
        raise AdminActionRejected("Your administrator access changed. Please log in again.")
    if actor["auth_method"] == "local":
        if actor["email_verified"] and not actor["totp_recovery_required"]:
            return
    elif (
        actor["auth_method"] == "shibboleth"
        and actor["federated_status"] == "approved"
        and settings.shibboleth_enabled
        and federation_current
        and valid_federated_identity(actor["shibboleth_issuer"], actor["shibboleth_subject_id"])
        and actor["shibboleth_issuer"] in settings.shibboleth_trusted_issuers
    ):
        return
    raise AdminActionRejected("Your administrator access changed. Please log in again.")


def _required_tier(
    target: dict[str, Any], configured_sources: Sequence[SourceMetadata]
) -> AccessTier:
    """Resolve the stored record tier against its uniquely selected source policy.

    Raise DatasetAdminRejected for absent/duplicate source configuration or a
    missing/invalid record tier required by that source.
    """
    selected = [source for source in configured_sources if source.name == target["source"]]
    if not selected:
        raise DatasetAdminRejected("source_unavailable")
    if len(selected) != 1:
        raise DatasetAdminRejected("source_configuration")
    policy = selected[0].policy
    data = target["data"]
    record_tier = data.get("visibility_tier") if isinstance(data, dict) else None
    try:
        if policy.requires_record_tier:
            return resolve_required_source_tier(record_tier, policy)
        return resolve_tier(record_tier, policy)
    except SourceVisibilityTierError:
        raise DatasetAdminRejected("invalid_source_tier") from None


async def _write_state_cur(
    cur: AsyncCursor[Any],
    target: dict[str, Any],
    before: DatasetAdminState,
    action: DatasetAdminAction,
    new_tier: AccessTier | None,
    *,
    exists: bool,
) -> DatasetAdminState:
    """Write the requested tier/hidden state in the caller's transaction.

    Return before for an unchanged state; exists selects UPDATE versus INSERT.
    A new hide uses database wall time. Raise RuntimeError if no row is returned.
    """
    admin_tier = new_tier if action == "raise_tier" else before.admin_tier
    hidden_at = None if action == "restore" else before.hidden_at
    if admin_tier == before.admin_tier and (
        (action == "hide" and before.hidden_at is not None)
        or (action != "hide" and hidden_at == before.hidden_at)
    ):
        return before
    values = {
        "source": target["source"],
        "uuid": target["uuid"],
        "tier": admin_tier,
        "hidden_at": hidden_at,
        "stamp_hide": action == "hide",
    }
    if exists:
        statement = """UPDATE dataset_admin_state
            SET visibility_tier = %(tier)s,
                hidden_at = CASE WHEN %(stamp_hide)s THEN clock_timestamp() ELSE %(hidden_at)s END
            WHERE source = %(source)s AND uuid = %(uuid)s
            RETURNING visibility_tier, hidden_at"""
    else:
        statement = """INSERT INTO dataset_admin_state (source, uuid, visibility_tier, hidden_at)
            VALUES (%(source)s, %(uuid)s, %(tier)s,
                    CASE WHEN %(stamp_hide)s THEN clock_timestamp() ELSE %(hidden_at)s END)
            RETURNING visibility_tier, hidden_at"""
    await cur.execute(statement, values)
    state = await cur.fetchone()
    if state is None:
        raise RuntimeError("Dataset administrator state write returned no row")
    return DatasetAdminState(before.stored_tier, state["visibility_tier"], state["hidden_at"])


async def change_dataset_admin_state(
    pool: AsyncConnectionPool,
    dataset_id: int,
    action: DatasetAdminAction,
    *,
    context: DatasetAdminContext,
    new_tier: AccessTier | None = None,
    configured_sources: Sequence[SourceMetadata],
) -> DatasetAdminChange:
    """Authorize, commit and audit a raise/hide/restore without mutating source metadata.

    configured_sources must be explicit; () intentionally permits hide/restore
    for retained unselected sources but cannot authorize a tier raise.
    Raising requires the matching selected policy and cannot lower the stored,
    administrator or resolved current-source floor. Hide/restore permit retained
    unselected sources. Repeated actions are no-ops; restore retains the floor.
    Rejections and rollback retain no change event. The restriction and its
    durable security event commit together; local logging follows commit.
    """
    if action not in get_args(DatasetAdminAction):
        raise DatasetAdminRejected("invalid_action")
    if (action == "raise_tier" and new_tier not in get_args(AccessTier)) or (
        action != "raise_tier" and new_tier is not None
    ):
        raise DatasetAdminRejected("invalid_tier")
    if type(dataset_id) is not int or dataset_id <= 0:
        raise DatasetAdminRejected("dataset_not_found")
    selected = tuple(configured_sources)
    async with get_db_cursor(pool) as cur:
        await acquire_catalogue_write_lock_cur(cur)
        # Take policy state before actor/session locks, as federation does.
        federation_current = await federation_policy_is_current_cur(cur)
        await _authorize_cur(cur, context, federation_current=federation_current)
        await cur.execute(
            "SELECT id, source, uuid, stored_tier AS visibility_tier, record_tier "
            "FROM dataset_admin_catalogue "
            "WHERE id = %s",
            (dataset_id,),
        )
        target = await cur.fetchone()
        if target is None:
            raise DatasetAdminRejected("dataset_not_found")
        target["data"] = {"visibility_tier": target["record_tier"]}
        await cur.execute(
            "SELECT visibility_tier, hidden_at FROM dataset_admin_state "
            "WHERE source = %s AND uuid = %s FOR UPDATE",
            (target["source"], target["uuid"]),
        )
        state = await cur.fetchone()
        before = DatasetAdminState(
            target["visibility_tier"],
            state["visibility_tier"] if state is not None else None,
            state["hidden_at"] if state is not None else None,
        )
        # Recheck expiry and authority after the last potentially blocking state lock.
        await _authorize_cur(cur, context, federation_current=federation_current)
        if action == "raise_tier":
            minimum = max((before.effective_tier, _required_tier(target, selected)), key=tier_rank)
            if tier_rank(cast(AccessTier, new_tier)) < tier_rank(minimum):
                raise DatasetAdminRejected("tier_below_floor")
        after = await _write_state_cur(
            cur, target, before, action, new_tier, exists=state is not None
        )
        change = DatasetAdminChange(
            dataset_id, target["source"], target["uuid"], action, before, after
        )
        await append_dataset_admin_action_cur(cur, change, context)
    if change.changed:
        audit_dataset_admin_action(change, context)
    return change

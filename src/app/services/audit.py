"""Log account events and persist dataset restriction changes.

Local events use the audit logger; dataset changes can also be appended to
the mutation transaction for delivery by audit_outbox.
"""

import logging
from typing import TYPE_CHECKING, Any

from fastapi import Request

from ..request_utils import get_client_ip
from .audit_outbox import append_security_event_cur

if TYPE_CHECKING:
    from psycopg import AsyncCursor

    from .dataset_admin import DatasetAdminChange, DatasetAdminContext

audit_logger = logging.getLogger("audit")


def audit_user_event(
    level: int,
    request: Request,
    event_type: str,
    user_id: int | None,
    exc_info: bool = False,
    **fields: Any,
) -> None:
    """Log an account event with request IP and optional request ID.

    user_id may be None for an unidentified actor. fields override the default
    extra fields; logging-reserved keys raise KeyError. exc_info passes the
    active exception to the configured formatter.
    """
    audit_logger.log(
        level,
        event_type,
        exc_info=exc_info,
        stacklevel=2,
        extra={
            "event_type": event_type,
            "user_id": user_id,
            "client_ip": get_client_ip(request),
            "request_id": getattr(request.state, "request_id", None),
            **fields,
        },
    )


def audit_admin_action(
    level: int,
    request: Request,
    event_type: str,
    target_user_id: int,
    exc_info: bool = False,
    **fields: Any,
) -> None:
    """Log an administrator event using request.state.user as the actor.

    The user attribute must exist; None logs a critical missing-actor event
    instead. fields override default extra fields; logging-reserved keys raise
    KeyError. exc_info passes the active exception to the configured formatter.
    """
    admin = request.state.user
    if admin is None:
        audit_logger.critical(
            "admin_action_no_actor",
            stacklevel=2,
            extra={
                "event_type": "admin_action_no_actor",
                "attempted_event": event_type,
                "target_user_id": target_user_id,
                "client_ip": get_client_ip(request),
                "request_id": getattr(request.state, "request_id", None),
            },
        )
        return

    audit_logger.log(
        level,
        event_type,
        exc_info=exc_info,
        stacklevel=2,
        extra={
            "event_type": event_type,
            "actor_admin_id": admin.id,
            "target_user_id": target_user_id,
            "client_ip": get_client_ip(request),
            "request_id": getattr(request.state, "request_id", None),
            **fields,
        },
    )


def _dataset_admin_event(
    change: "DatasetAdminChange", context: "DatasetAdminContext"
) -> tuple[str, dict[str, object]]:
    """Return the action event name and identity/restriction payload without logging."""
    event_type = {
        "raise_tier": "admin_dataset_tier_raised",
        "hide": "admin_dataset_hidden",
        "restore": "admin_dataset_restored",
    }[change.action]
    states: dict[str, object] = {}
    for name, state in (("before", change.before), ("after", change.after)):
        states[name] = {
            "stored_tier": state.stored_tier,
            "admin_tier": state.admin_tier,
            "effective_tier": state.effective_tier,
            "hidden_at": state.hidden_at.isoformat() if state.hidden_at is not None else None,
        }
    return event_type, {
        "actor_admin_id": context.actor_id,
        "dataset_id": change.dataset_id,
        "dataset_source": change.source,
        "dataset_uuid": change.uuid,
        "request_id": context.request_id,
        "client_ip": context.client_ip,
        **states,
    }


async def append_dataset_admin_action_cur(
    cur: "AsyncCursor[Any]", change: "DatasetAdminChange", context: "DatasetAdminContext"
) -> None:
    """Append one restriction change with the owning mutation transaction."""
    if change.changed:
        event_type, fields = _dataset_admin_event(change, context)
        await append_security_event_cur(cur, event_type, fields)


def audit_dataset_admin_action(
    change: "DatasetAdminChange", context: "DatasetAdminContext"
) -> None:
    """Emit an optional local copy of one already committed restriction change."""
    if change.changed:
        event_type, fields = _dataset_admin_event(change, context)
        audit_logger.info(event_type, stacklevel=2, extra={"event_type": event_type, **fields})

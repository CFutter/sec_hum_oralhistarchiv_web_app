"""Structured audit logging helpers for security-relevant events.

The application has an audit log channel separate from the regular
application log. This module provides two helpers that emit structured
records to that channel:

  - audit_user_event:  events about the acting user's own account
                       (login, password reset, TOTP change, etc.)
  - audit_admin_action: events about an admin acting on another user's
                       account (tier change, deactivation, etc.)

Both helpers ensure events carry consistent fields (event_type,
request_id, IP, timestamps via the log formatter) so downstream
SIEM/analytics queries can filter and group reliably.
"""

import logging
from typing import Any

from fastapi import Request

from ..request_utils import get_client_ip

audit_logger = logging.getLogger("audit")


def audit_user_event(
    level: int,
    request: Request,
    event_type: str,
    user_id: int | None,
    exc_info: bool = False,
    **fields: Any,
) -> None:
    """Record an audit event for an action a user performs on their own account.

    Examples:
        login_success, login_failed, password_reset_requested,
        totp_configured, email_verified.

    Args:
        level: The log level the event should be logged as.
        request: The current request, used for IP and request_id.
        event_type: A stable, machine-readable event name (snake_case).
            Used by SIEM rules to filter; never change for an
            existing event without a migration plan.
        user_id: The user being acted on. May be None for failed events
            where the email didn't match a registered user.
        exc_info: If True, appends the active exception context (error type,
            message, and full traceback) to the log output. Defaults to False.
        **fields: Additional structured fields specific to this event
            (e.g., reason="wrong_password", failed_count=3).
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
    """Record an audit event for an admin action on another user's account.

    Examples: admin_user_active_changed, admin_user_tier_changed,
    admin_user_admin_changed.

    Args:
        level: The level, the event should be loged as.
        request: The current request — request.state.user must be the
                 acting admin.
        event_type: A stable event name (snake_case, prefixed admin_).
        target_user_id: The user whose account was modified. Distinct
                        from request.state.user.id, which is the admin.
        exc_info: Defaults to False, if set to True, exception information
                  can be added to the logging message.
        **fields: Additional structured fields, typically including
                  old_value and new_value for the modified attribute.
    """
    admin = request.state.user
    if admin is None:
        # Shouldn't happen — admin routes are gated by require_admin.
        # If it does, log a critical-level event for investigation.
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

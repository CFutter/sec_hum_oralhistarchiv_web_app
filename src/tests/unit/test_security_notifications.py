"""Owner notice builders accept fixed transitions, never credential payloads."""

from unittest.mock import create_autospec

import pytest

from app.services import security_notifications
from app.services.email import build_security_change_notice
from tests.fixtures import make_async_cursor

_CHANGES = (
    "totp_enrolled",
    "totp_rotated",
    "totp_recovery_authorized",
    "totp_recovery_redeemed",
    "totp_recovery_completed",
    "admin_promotion_accepted",
)


@pytest.mark.parametrize("change", _CHANGES)
def test_fixed_security_notices_contain_no_action_credentials(change):
    """Check fixed security notices contain no action credentials."""
    message = build_security_change_notice("owner@example.org", change=change)
    assert message.message_type == f"{change}_notice"
    assert message.recipient == "owner@example.org"
    assert "contact" in message.body.lower()
    assert "otpauth:" not in message.body
    assert "/reset-password" not in message.body
    assert "/verify-email" not in message.body


def test_arbitrary_notification_content_is_rejected():
    """Check arbitrary notification content is rejected (ValueError)."""
    with pytest.raises(ValueError, match="Unsupported"):
        build_security_change_notice("owner@example.org", change="seed=untrusted-secret")


async def test_queue_uses_locked_account_address_and_the_existing_transaction(monkeypatch):
    """Check queue uses locked account address and the existing transaction."""
    cur = make_async_cursor(fetchone={"email": "owner@example.org"})
    enqueue = create_autospec(security_notifications.enqueue_outbound_email_cur, spec_set=True)
    monkeypatch.setattr(security_notifications, "enqueue_outbound_email_cur", enqueue)
    await security_notifications.queue_security_change_notice_cur(
        cur, user_id=7, change="totp_rotated"
    )
    enqueue.assert_awaited_once()
    assert enqueue.await_args.args == (cur,)
    assert enqueue.await_args.kwargs["user_id"] == 7
    assert enqueue.await_args.kwargs["action"] is None
    assert enqueue.await_args.kwargs["email"].recipient == "owner@example.org"


async def test_queue_failure_propagates_to_the_owning_transaction(monkeypatch):
    """Check queue failure propagates to the owning transaction (RuntimeError)."""
    cur = make_async_cursor(fetchone={"email": "owner@example.org"})
    enqueue = create_autospec(
        security_notifications.enqueue_outbound_email_cur,
        side_effect=RuntimeError("Queue unavailable"),
        spec_set=True,
    )
    monkeypatch.setattr(security_notifications, "enqueue_outbound_email_cur", enqueue)
    with pytest.raises(RuntimeError, match="Queue unavailable"):
        await security_notifications.queue_security_change_notice_cur(
            cur, user_id=7, change="totp_rotated"
        )

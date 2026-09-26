"""Delivery worker for the transactional email outbox.

Claims committed outbox rows, performs SMTP delivery without holding a
database transaction, and then records success, retry, or terminal failure.
"""

import logging
import time
from datetime import timedelta
from typing import Literal

from psycopg.errors import LockNotAvailable
from psycopg_pool import AsyncConnectionPool

from .email import DeliveryResult
from .email_outbox import (
    ClaimedEmail,
    OutboundEmail,
    OutboxBodyDecryptionError,
    OutboxLeaseLostError,
    claim_due_emails,
    decrypt_claimed_email_body,
    defer_contended_email,
    mark_email_dead,
    mark_email_sent,
    prepare_email_delivery,
    retry_email_later,
)
from .smtp_process import SMTP_OPERATION_BUDGET, SMTP_SEND_SECONDS, send_claimed_email

logger = logging.getLogger(__name__)

_DELIVERY_BATCH_SIZE = 10
_DELIVERY_LEASE_TIMEOUT = timedelta(minutes=10)
_MIN_ACTION_LIFETIME = timedelta(minutes=2)
_MAX_DELIVERY_ATTEMPTS = 7
_RETRY_BASE_SECONDS = 30
_RETRY_MAX_SECONDS = 15 * 60

_DeliveryDisposition = Literal["sent", "retried", "dead"]


def _retry_delay(attempt_count: int) -> timedelta:
    """Return 30-second exponential backoff from attempt one, capped at 15 minutes."""
    exponent = max(0, attempt_count - 1)
    seconds = min(
        _RETRY_BASE_SECONDS * (2**exponent),
        _RETRY_MAX_SECONDS,
    )
    return timedelta(seconds=seconds)


def _delivery_error(result: DeliveryResult) -> str:
    """Return the bounded diagnostic persisted on the outbox row."""
    if result.smtp_code is None:
        return result.reason
    return f"{result.reason} (SMTP {result.smtp_code})"


async def _deliver_claimed_email(
    pool: AsyncConnectionPool,
    message: ClaimedEmail,
) -> _DeliveryDisposition:
    """Deliver one lease and persist sent, retried, or dead status.

    Decrypt and check current account/token state before a 60-second SMTP
    deadline. Retry temporary failures with backoff up to seven claims;
    require two minutes of remaining action lifetime. Contention defers
    delivery. Lease and database failures propagate; SMTP Exceptions are
    converted to temporary failures, while cancellation propagates.
    """
    try:
        body = decrypt_claimed_email_body(message)
    except OutboxBodyDecryptionError:
        await mark_email_dead(
            pool,
            message_id=message.id,
            lock_token=message.lock_token,
            error="Outbox body decryption failed",
            outcome="body_unreadable",
        )
        logger.exception(
            "Email outbox message %d is undecryptable and was marked dead",
            message.id,
            extra={
                "event_type": "email_outbox_body_undecryptable",
                "message_id": message.id,
                "message_type": message.message_type,
            },
        )
        return "dead"

    email = OutboundEmail(
        message_type=message.message_type,
        recipient=message.recipient,
        subject=message.subject,
        body=body,
    )

    smtp_deadline = time.monotonic() + SMTP_SEND_SECONDS
    try:
        ready = await prepare_email_delivery(
            pool,
            message,
            lease_timeout=_DELIVERY_LEASE_TIMEOUT,
            min_remaining_lifetime=_MIN_ACTION_LIFETIME,
        )
    except LockNotAvailable:
        await defer_contended_email(pool, message)
        return "retried"
    if not ready:
        logger.info("Outbox message %d discarded before SMTP", message.id)
        return "dead"

    try:
        result = await send_claimed_email(message, email, deadline=smtp_deadline)
    except Exception:
        # Process startup and transport failures can raise before SMTP starts.
        logger.exception(
            "Unexpected email-delivery exception for outbox message %d",
            message.id,
        )
        result = DeliveryResult(
            status="temporary_failure",
            reason="smtp_process_exception",
        )

    if result.status == "sent":
        await mark_email_sent(
            pool,
            message_id=message.id,
            lock_token=message.lock_token,
        )
        return "sent"

    delivery_error = _delivery_error(result)
    if result.status == "permanent_failure":
        await mark_email_dead(
            pool,
            message_id=message.id,
            lock_token=message.lock_token,
            error=delivery_error,
        )
        logger.warning(
            "Email outbox message %d failed permanently",
            message.id,
            extra={
                "event_type": "email_outbox_delivery_permanent_failure",
                "message_id": message.id,
                "message_type": message.message_type,
                "delivery_reason": result.reason,
                "smtp_code": result.smtp_code,
            },
        )
        return "dead"

    if message.attempt_count >= _MAX_DELIVERY_ATTEMPTS:
        await mark_email_dead(
            pool,
            message_id=message.id,
            lock_token=message.lock_token,
            error=delivery_error,
        )
        logger.error(
            "Email outbox message %d exhausted its delivery attempts",
            message.id,
            extra={
                "event_type": "email_outbox_delivery_dead",
                "message_id": message.id,
                "message_type": message.message_type,
                "attempt_count": message.attempt_count,
                "delivery_reason": result.reason,
                "smtp_code": result.smtp_code,
            },
        )
        return "dead"

    delay = _retry_delay(message.attempt_count)
    try:
        disposition = await retry_email_later(
            pool,
            message=message,
            delay=delay,
            error=delivery_error,
            lease_timeout=_DELIVERY_LEASE_TIMEOUT,
            min_remaining_lifetime=_MIN_ACTION_LIFETIME,
        )
    except LockNotAvailable:
        await defer_contended_email(pool, message, smtp_attempted=True)
        return "retried"
    if disposition == "dead":
        logger.info("Outbox message %d is no longer retryable", message.id)
        return "dead"
    logger.warning(
        "Email outbox message %d scheduled for retry",
        message.id,
        extra={
            "event_type": "email_outbox_delivery_retry",
            "message_id": message.id,
            "message_type": message.message_type,
            "attempt_count": message.attempt_count,
            "retry_delay_seconds": int(delay.total_seconds()),
            "delivery_reason": result.reason,
            "smtp_code": result.smtp_code,
        },
    )
    return "retried"


async def deliver_email_outbox_batch(pool: AsyncConnectionPool) -> None:
    """Process at most ten messages sequentially, claiming each only when ready.

    Claims last ten minutes. Log per-message failures and leave abandoned
    leases reclaimable; claim-query failures and cancellation propagate.
    Raise RuntimeError if the lease does not exceed the SMTP budget. SMTP
    is at-least-once: acceptance before a failed sent update can duplicate mail.
    """
    if _DELIVERY_LEASE_TIMEOUT <= SMTP_OPERATION_BUDGET:
        raise RuntimeError("Outbox lease must exceed the complete SMTP operation budget")

    counts = {"sent": 0, "retried": 0, "dead": 0, "lease_lost": 0, "abandoned": 0}
    claimed = 0
    for _ in range(_DELIVERY_BATCH_SIZE):
        messages = await claim_due_emails(
            pool,
            limit=1,
            lease_timeout=_DELIVERY_LEASE_TIMEOUT,
        )
        if not messages:
            break
        message = messages[0]
        claimed += 1
        try:
            disposition = await _deliver_claimed_email(pool, message)
            counts[disposition] += 1
        except OutboxLeaseLostError:
            counts["lease_lost"] += 1
            logger.warning("Outbox lease lost for message %d", message.id)
        except Exception:
            counts["abandoned"] += 1
            logger.exception("Outbox processing failed for message %d", message.id)

    if claimed:
        logger.info(
            "Email outbox batch complete",
            extra={"event_type": "email_outbox_batch_complete", "claimed": claimed, **counts},
        )

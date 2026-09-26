"""The transactional email outbox: claiming, delivery, encryption at rest,
the SMTP child process boundary, and retention/maintenance policy.

Covers ``app.services.email_delivery``, ``app.services.email_outbox``
encryption helpers (via ``app.services.crypto``), ``app.services.smtp_process``,
and ``app.services.outbox_maintenance``.
"""

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import ANY, create_autospec, patch
from uuid import UUID

import pytest
from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool
from pydantic import SecretStr, ValidationError

from app.services import crypto, email_delivery, smtp_process
from app.services._smtp_child import _OutboxContext
from app.services.cache import CatalogueStatsCache
from app.services.email import DeliveryResult
from app.services.email_outbox import (
    ClaimedEmail,
    OutboundEmail,
    OutboxBodyDecryptionError,
    OutboxLeaseLostError,
)
from app.services.outbox_maintenance import get_outbox_metrics_cur, outbox_is_degraded
from app.services.scheduler import RunningJobTracker, create_scheduler
from config import settings
from config.settings import Settings

_LOCK_TOKEN = UUID("12345678-1234-5678-1234-567812345678")
_REAL = {
    name: getattr(email_delivery, name)
    for name in (
        "claim_due_emails",
        "decrypt_claimed_email_body",
        "prepare_email_delivery",
        "send_claimed_email",
        "mark_email_sent",
        "retry_email_later",
        "mark_email_dead",
    )
}

_SENT_RESULT = DeliveryResult(status="sent", reason="smtp_accepted")
_FAILURE_RESULT = DeliveryResult(status="temporary_failure", reason="smtp_transport_error")


def _claimed_email(*, message_id=1, attempt_count=1):
    """Build a claimed outbox row, as returned by ``claim_due_emails``."""
    return ClaimedEmail(
        id=message_id,
        user_id=7,
        message_type="account_locked_notice",
        recipient=f"user-{message_id}@example.org",
        subject="Notice",
        body_ciphertext=f"encrypted-{message_id}",
        attempt_count=attempt_count,
        lock_token=_LOCK_TOKEN,
        action_token_hash=None,
        expires_at=None,
    )


def _install_worker_mocks(monkeypatch, *, messages, delivered=True):
    send_result = _SENT_RESULT if delivered else _FAILURE_RESULT
    mocks = SimpleNamespace(
        claim=create_autospec(
            _REAL["claim_due_emails"], side_effect=[[m] for m in messages] + [[]]
        ),
        decrypt=create_autospec(_REAL["decrypt_claimed_email_body"], return_value="Body"),
        prepare=create_autospec(_REAL["prepare_email_delivery"], return_value=True),
        send=create_autospec(_REAL["send_claimed_email"], return_value=send_result),
        mark_sent=create_autospec(_REAL["mark_email_sent"]),
        retry=create_autospec(_REAL["retry_email_later"], return_value="retried"),
        mark_dead=create_autospec(_REAL["mark_email_dead"]),
    )
    for name, mock_name in (
        ("claim_due_emails", "claim"),
        ("decrypt_claimed_email_body", "decrypt"),
        ("prepare_email_delivery", "prepare"),
        ("send_claimed_email", "send"),
        ("mark_email_sent", "mark_sent"),
        ("retry_email_later", "retry"),
        ("mark_email_dead", "mark_dead"),
    ):
        monkeypatch.setattr(email_delivery, name, getattr(mocks, mock_name))
    return mocks


class TestBatchClaiming:
    """``deliver_email_outbox_batch`` claims one message at a time, up to a
    bounded batch, and never claims when the configured lease budget is
    invalid."""

    async def test_claims_only_after_previous_delivery_finishes(self, monkeypatch):
        messages = [_claimed_email(message_id=i) for i in (1, 2)]
        mocks = _install_worker_mocks(monkeypatch, messages=messages)
        events = []
        remaining = iter(messages)

        async def claim(_pool, *, limit, lease_timeout):
            assert limit == 1
            assert lease_timeout == timedelta(minutes=10)
            events.append("claim")
            message = next(remaining, None)
            return [message] if message else []

        async def send(message, _email, **_kwargs):
            events.append(f"start-{message.id}")
            await asyncio.sleep(0)
            events.append(f"end-{message.id}")
            return _SENT_RESULT

        mocks.claim.side_effect = claim
        mocks.send.side_effect = send
        await email_delivery.deliver_email_outbox_batch(object())
        assert events == ["claim", "start-1", "end-1", "claim", "start-2", "end-2", "claim"]
        assert mocks.mark_sent.await_count == 2

    async def test_batch_has_bounded_work(self, monkeypatch):
        mocks = _install_worker_mocks(
            monkeypatch, messages=[_claimed_email(message_id=i) for i in range(12)]
        )
        await email_delivery.deliver_email_outbox_batch(object())
        assert mocks.claim.await_count == 10
        assert mocks.send.await_count == 10

    async def test_empty_claim_returns_without_delivery(self, monkeypatch):
        mocks = _install_worker_mocks(monkeypatch, messages=[])
        await email_delivery.deliver_email_outbox_batch(object())
        mocks.send.assert_not_awaited()

    async def test_invalid_lease_budget_fails_before_claim(self, monkeypatch):
        mocks = _install_worker_mocks(monkeypatch, messages=[])
        monkeypatch.setattr(email_delivery, "_DELIVERY_LEASE_TIMEOUT", timedelta(seconds=10))
        with pytest.raises(RuntimeError, match="budget"):
            await email_delivery.deliver_email_outbox_batch(object())
        mocks.claim.assert_not_awaited()


class TestDeliveryAttempts:
    """``_deliver_claimed_email`` decrypts, preflights, sends and records
    the outcome of a single claimed message."""

    async def test_successful_delivery_marks_message_sent(self, monkeypatch):
        message = _claimed_email()
        pool = object()
        mocks = _install_worker_mocks(monkeypatch, messages=[message])
        assert await email_delivery._deliver_claimed_email(pool, message) == "sent"
        mocks.send.assert_awaited_once_with(
            message,
            OutboundEmail(message.message_type, message.recipient, message.subject, "Body"),
            deadline=ANY,
        )
        mocks.mark_sent.assert_awaited_once_with(
            pool, message_id=message.id, lock_token=message.lock_token
        )
        mocks.retry.assert_not_awaited()

    async def test_failed_delivery_is_scheduled_for_retry(self, monkeypatch):
        message = _claimed_email(attempt_count=3)
        pool = object()
        mocks = _install_worker_mocks(monkeypatch, messages=[message], delivered=False)
        assert await email_delivery._deliver_claimed_email(pool, message) == "retried"
        mocks.retry.assert_awaited_once_with(
            pool,
            message=message,
            delay=timedelta(seconds=120),
            error="smtp_transport_error",
            lease_timeout=timedelta(minutes=10),
            min_remaining_lifetime=timedelta(minutes=2),
        )

    async def test_final_failed_attempt_marks_message_dead(self, monkeypatch):
        message = _claimed_email(attempt_count=7)
        mocks = _install_worker_mocks(monkeypatch, messages=[message], delivered=False)
        assert await email_delivery._deliver_claimed_email(object(), message) == "dead"
        mocks.mark_dead.assert_awaited_once()
        mocks.retry.assert_not_awaited()

    async def test_undecryptable_body_is_marked_dead_without_sending(self, monkeypatch):
        message = _claimed_email()
        mocks = _install_worker_mocks(monkeypatch, messages=[message])
        mocks.decrypt.side_effect = OutboxBodyDecryptionError(message.id)
        assert await email_delivery._deliver_claimed_email(object(), message) == "dead"
        mocks.send.assert_not_awaited()
        mocks.mark_dead.assert_awaited_once()

    @pytest.mark.parametrize(
        "error",
        [RuntimeError("DB unavailable"), OutboxLeaseLostError(1)],
        ids=["database_unavailable", "lease_lost"],
    )
    async def test_preflight_error_never_calls_smtp(self, monkeypatch, error):
        message = _claimed_email()
        mocks = _install_worker_mocks(monkeypatch, messages=[message])
        mocks.prepare.side_effect = error
        with pytest.raises(type(error)):
            await email_delivery._deliver_claimed_email(object(), message)
        mocks.send.assert_not_awaited()

    async def test_blocked_preflight_never_calls_smtp(self, monkeypatch):
        message = _claimed_email()
        mocks = _install_worker_mocks(monkeypatch, messages=[message])
        mocks.prepare.return_value = False
        assert await email_delivery._deliver_claimed_email(object(), message) == "dead"
        mocks.send.assert_not_awaited()

    async def test_retry_rejection_is_reported_as_dead(self, monkeypatch):
        message = _claimed_email()
        mocks = _install_worker_mocks(monkeypatch, messages=[message], delivered=False)
        mocks.retry.return_value = "dead"
        assert await email_delivery._deliver_claimed_email(object(), message) == "dead"

    async def test_lease_loss_does_not_stop_remaining_messages(self, monkeypatch):
        messages = [_claimed_email(message_id=i) for i in (1, 2)]
        mocks = _install_worker_mocks(monkeypatch, messages=messages)
        mocks.prepare.side_effect = [OutboxLeaseLostError(1), True]
        await email_delivery.deliver_email_outbox_batch(object())
        mocks.send.assert_awaited_once()
        assert mocks.send.await_args.args[0].id == 2

    async def test_cancellation_propagates_and_leaves_lease_for_recovery(self, monkeypatch):
        message = _claimed_email()
        mocks = _install_worker_mocks(monkeypatch, messages=[message])
        mocks.send.side_effect = asyncio.CancelledError
        with pytest.raises(asyncio.CancelledError):
            await email_delivery.deliver_email_outbox_batch(object())
        mocks.mark_sent.assert_not_awaited()
        mocks.retry.assert_not_awaited()
        mocks.mark_dead.assert_not_awaited()

    async def test_preflight_runs_after_decryption_and_before_smtp(self, monkeypatch):
        message = _claimed_email()
        mocks = _install_worker_mocks(monkeypatch, messages=[message])
        events = []

        def decrypt(_message):
            events.append("decrypt")
            return "Body"

        async def prepare(*_args, **_kwargs):
            events.append("preflight")
            return True

        async def send(_message, _email, **_kwargs):
            events.append("smtp")
            return _SENT_RESULT

        mocks.decrypt.side_effect = decrypt
        mocks.prepare.side_effect = prepare
        mocks.send.side_effect = send
        assert await email_delivery._deliver_claimed_email(object(), message) == "sent"
        assert events == ["decrypt", "preflight", "smtp"]

    async def test_delivery_survives_signing_key_change(self, monkeypatch):
        monkeypatch.setattr(settings, "outbox_encryption_keys", [SecretStr("test-outbox-key")])
        monkeypatch.setattr(crypto, "_outbox_body_fernet", crypto._get_outbox_body_fernet())
        message = replace(_claimed_email(), body_ciphertext=crypto.encrypt_outbox_body("Notice"))
        monkeypatch.setattr(settings, "secret_key", SecretStr("new-signing-key"))
        mocks = _install_worker_mocks(monkeypatch, messages=[message])
        monkeypatch.setattr(
            email_delivery, "decrypt_claimed_email_body", _REAL["decrypt_claimed_email_body"]
        )
        assert await email_delivery._deliver_claimed_email(object(), message) == "sent"
        assert mocks.send.await_args.args[1].body == "Notice"


def _use_outbox_keys(monkeypatch, *keys):
    monkeypatch.setattr(
        settings,
        "outbox_encryption_keys",
        [SecretStr(key) for key in keys],
    )
    # Rebuild the cached ring to simulate startup with this configuration.
    monkeypatch.setattr(
        crypto,
        "_outbox_body_fernet",
        crypto._get_outbox_body_fernet(),
    )


class TestEncryptionAtRest:
    """Outbox bodies survive independent signing and encryption key
    rotation, and reject ciphertext that does not decrypt."""

    def test_outbox_body_survives_signing_key_change(self, monkeypatch):
        _use_outbox_keys(monkeypatch, "test-outbox-key")
        ciphertext = crypto.encrypt_outbox_body("A queued notification.")

        monkeypatch.setattr(
            settings,
            "secret_key",
            SecretStr("new-signing-key"),
        )
        _use_outbox_keys(monkeypatch, "test-outbox-key")

        assert crypto.decrypt_outbox_body(ciphertext) == "A queued notification."

    def test_outbox_ring_reads_old_bodies_and_encrypts_with_first_key(self, monkeypatch):
        _use_outbox_keys(monkeypatch, "old-outbox-key")
        old_ciphertext = crypto.encrypt_outbox_body("Old message.")

        _use_outbox_keys(monkeypatch, "new-outbox-key", "old-outbox-key")
        assert crypto.decrypt_outbox_body(old_ciphertext) == "Old message."
        new_ciphertext = crypto.encrypt_outbox_body("New message.")

        _use_outbox_keys(monkeypatch, "new-outbox-key")
        assert crypto.decrypt_outbox_body(new_ciphertext) == "New message."
        assert crypto.decrypt_outbox_body(old_ciphertext) is None

        _use_outbox_keys(monkeypatch, "old-outbox-key")
        assert crypto.decrypt_outbox_body(new_ciphertext) is None

    def test_outbox_invalid_ciphertext_returns_none(self, monkeypatch):
        _use_outbox_keys(monkeypatch, "test-outbox-key")

        assert crypto.decrypt_outbox_body("invalid-ciphertext") is None


class TestRetentionAndMaintenance:
    """Retention settings are bounded, and the retention job is registered
    on the scheduler with its own bounded, coalesced cadence."""

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("outbox_sent_retention_days", 0),
            ("outbox_dead_retention_days", -1),
            ("outbox_retention_batch_size", 0),
            ("outbox_retention_batch_size", 5001),
            ("outbox_stale_after_seconds", 59),
        ],
        ids=[
            "sent_retention_days_must_be_positive",
            "dead_retention_days_must_be_nonnegative",
            "retention_batch_size_must_be_positive",
            "retention_batch_size_has_a_ceiling",
            "stale_after_seconds_has_a_floor",
        ],
    )
    def test_retention_configuration_is_bounded(self, name, value):
        with pytest.raises(ValidationError):
            Settings(**{name: value})

    def test_retention_job_is_tracked_bounded_and_uses_independent_cadence(self):
        pool = create_autospec(AsyncConnectionPool, instance=True, spec_set=True)
        pool.max_size = 2
        stats_cache = create_autospec(CatalogueStatsCache, instance=True, spec_set=True)
        tracker = RunningJobTracker()
        scheduler = create_scheduler(pool, stats_cache, tracker)
        job = next(job for job in scheduler.get_jobs() if job.id == "outbox_retention")
        assert job.func.__self__ is tracker
        assert job.args[0] == "outbox_retention"
        assert job.args[1].__name__ == "purge_terminal_emails"
        assert job.args[2] is pool
        assert job.trigger.interval.total_seconds() == settings.outbox_retention_interval_seconds
        assert job.max_instances == 1
        assert job.coalesce is True


class TestOutboxMetrics:
    """Outbox diagnostics narrow driver-reported values and flag a
    degraded outbox from an aging pending/sending queue or an overdue
    retention count."""

    async def test_metrics_narrow_driver_values_and_clamp_future_timestamps(self):
        cur = create_autospec(AsyncCursor, instance=True, spec_set=True)
        cur.fetchone.return_value = {
            "pending_count": 2,
            "sending_count": 1,
            "dead_count": 4,
            "recent_failure_count": 0,
            "pending_age": Decimal("1.5"),
            "sending_age": Decimal("-2"),
            "retention_overdue_count": 0,
        }
        result = await get_outbox_metrics_cur(cur)
        assert result == {
            "counts_capped_at": 1000,
            "pending_count": 2,
            "sending_count": 1,
            "dead_count": 4,
            "recent_failure_count": 0,
            "oldest_pending_age_seconds": 1.5,
            "oldest_sending_age_seconds": 0.0,
            "retention_overdue_count": 0,
        }
        assert outbox_is_degraded(result) is False

    @pytest.mark.parametrize(
        "reason",
        ["pending", "sending", "retention"],
        ids=["stale_pending_queue", "stale_sending_queue", "retention_overdue"],
    )
    def test_outbox_becomes_degraded_when_queue_ages_or_retention_is_overdue(self, reason):
        metrics = {
            "pending_count": 0,
            "sending_count": 0,
            "dead_count": 0,
            "recent_failure_count": 0,
            "oldest_pending_age_seconds": None,
            "oldest_sending_age_seconds": None,
            "retention_overdue_count": 0,
        }
        if reason == "retention":
            metrics["retention_overdue_count"] = 1
        else:
            metrics[f"oldest_{reason}_age_seconds"] = settings.outbox_stale_after_seconds
        assert outbox_is_degraded(metrics) is True


# Mirrors the result document the real SMTP child writes: argv[1] is the
# result file descriptor (see _smtp_child.py:86-95), and the child's exit
# code and self-reported status must agree for _run_process to trust it.
_RESULT_WRITER_SCRIPT = (
    "import json, os, sys\n"
    "data = json.load(sys.stdin)\n"
    "ok = data['value'] == 7\n"
    "status = 'sent' if ok else 'temporary_failure'\n"
    "os.write(int(sys.argv[1]), json.dumps("
    "{'status': status, 'reason': 'test_case', 'smtp_code': None}).encode())\n"
    "sys.exit(0 if ok else 1)\n"
)


class TestSmtpChildProcess:
    """Exercise the real ``_smtp_child`` subprocess lifetime, without an
    SMTP server: exit status, timeouts, cancellation, and deadlines."""

    async def test_process_exit_status_and_stdin_are_respected(self):
        command = (sys.executable, "-c", _RESULT_WRITER_SCRIPT)

        sent = await smtp_process._run_process(command, b'{"value": 7}', timeout_seconds=2)
        assert sent.status == "sent"

        failed = await smtp_process._run_process(command, b'{"value": 8}', timeout_seconds=2)
        assert failed.status == "temporary_failure"

    async def test_timeout_stops_and_reaps_the_real_child(self, monkeypatch):
        real_spawn = asyncio.create_subprocess_exec
        processes = []

        async def spawn(*args, **kwargs):
            process = await real_spawn(*args, **kwargs)
            processes.append(process)
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        monkeypatch.setattr(smtp_process, "_TERMINATE_GRACE_SECONDS", 0.05)
        command = (
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
        )
        result = await smtp_process._run_process(command, b"", timeout_seconds=0.15)
        assert result.status == "temporary_failure"
        assert result.reason == "smtp_process_timeout"
        assert len(processes) == 1
        assert processes[0].returncode is not None

    async def test_cancellation_stops_child_before_returning(self, monkeypatch):
        real_spawn = asyncio.create_subprocess_exec
        started = asyncio.Event()
        processes = []

        async def spawn(*args, **kwargs):
            process = await real_spawn(*args, **kwargs)
            processes.append(process)
            started.set()
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        command = (sys.executable, "-c", "import time; time.sleep(30)")
        task = asyncio.create_task(smtp_process._run_process(command, b"", timeout_seconds=2))
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert processes[0].returncode is not None

    async def test_real_smtp_child_works_with_smtp_disabled(self, monkeypatch):
        monkeypatch.setenv("SMTP_ENABLED", "false")
        message = _claimed_email()
        email = OutboundEmail("account_locked_notice", "a@example.test", "Notice", "Body")
        result = await smtp_process.send_claimed_email(
            message, email, deadline=time.monotonic() + 60
        )
        assert result.status == "sent"

    async def test_expired_deadline_does_not_start_a_process(self):
        message = _claimed_email()
        email = OutboundEmail("account_locked_notice", "a@example.test", "Notice", "Body")
        with patch.object(smtp_process, "_run_process", autospec=True) as run:
            result = await smtp_process.send_claimed_email(
                message, email, deadline=time.monotonic() - 1
            )
        assert result.status == "temporary_failure"
        assert result.reason == "smtp_delivery_deadline_elapsed"
        run.assert_not_awaited()

    async def test_child_refuses_expired_deadline_even_if_parent_was_delayed(self, monkeypatch):
        monkeypatch.setenv("SMTP_ENABLED", "false")
        child = smtp_process.Path(smtp_process.__file__).with_name("_smtp_child.py")
        payload = json.dumps(
            {
                "outbox_id": 1,
                "deadline": time.monotonic() - 1,
                "email": {
                    "message_type": "account_locked_notice",
                    "recipient": "a@example.test",
                    "subject": "Notice",
                    "body": "Body",
                },
            }
        ).encode()
        result = await smtp_process._run_process(
            (sys.executable, str(child), "60"), payload, timeout_seconds=5
        )
        assert result.status == "temporary_failure"
        assert result.reason == "smtp_delivery_deadline_elapsed"

    async def test_cancellation_during_cleanup_is_propagated_after_reaping(self, monkeypatch):
        real_stop = smtp_process._stop_process
        cleaning = asyncio.Event()
        release = asyncio.Event()
        processes = []

        async def stop(process):
            processes.append(process)
            cleaning.set()
            await release.wait()
            await real_stop(process)

        monkeypatch.setattr(smtp_process, "_stop_process", stop)
        task = asyncio.create_task(
            smtp_process._run_process(
                (sys.executable, "-c", "pass"),
                b"",
                timeout_seconds=2,
            )
        )
        try:
            await asyncio.wait_for(cleaning.wait(), timeout=2)
            task.cancel()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2)
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert processes[0].returncode is not None

    async def test_smtp_child_saves_private_dev_email(self, monkeypatch, tmp_path):
        monkeypatch.setenv("DEV_MAILBOX_DIR", str(tmp_path / "mailbox"))
        monkeypatch.setenv("SMTP_ENABLED", "false")
        monkeypatch.setenv("ENV_STATE", "dev")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("LOG_FORMAT", "text")

        child = smtp_process.Path(smtp_process.__file__).with_name("_smtp_child.py")
        payload = json.dumps(
            {
                "outbox_id": 1,
                "deadline": time.monotonic() + 30,
                "email": {
                    "message_type": "email_verification",
                    "recipient": "test@example.test",
                    "subject": "Verify your email",
                    "body": "Click here: http://127.0.0.1:5000/verify/test-token",
                },
            }
        ).encode()

        result_read_fd, result_write_fd = os.pipe()
        try:
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                str(child),
                "30",
                str(result_write_fd),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                pass_fds=(result_write_fd,),
            )
            os.close(result_write_fd)
            result_write_fd = -1
            stdout, stderr = await process.communicate(payload)
            result_payload = os.read(result_read_fd, 512)
        finally:
            if result_write_fd >= 0:
                os.close(result_write_fd)
            os.close(result_read_fd)

        output = (stdout + stderr).decode()
        assert process.returncode == 0
        assert "Development email saved" in output
        assert "http://127.0.0.1:5000/verify/test-token" not in output
        assert len(list((tmp_path / "mailbox").glob("*.eml"))) == 1

        result = json.loads(result_payload)
        assert result["status"] == "sent"
        assert result["reason"] == "development_mailbox_saved"


class TestOutboxLoggingCorrelation:
    """``_OutboxContext`` stamps every log record from the SMTP child process
    with the durable outbox row id, so the parent process can correlate a
    failed-send log line back to the exact queued email that produced it.
    """

    def test_filter_stamps_log_records_with_the_durable_outbox_id(self):
        record = logging.makeLogRecord({"msg": "smtp failed"})
        assert _OutboxContext(42).filter(record)
        assert record.outbox_id == 42

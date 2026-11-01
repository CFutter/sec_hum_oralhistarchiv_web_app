"""Finite password admission preserves thread ownership and credential outcomes."""

import asyncio
import threading
from collections.abc import AsyncIterator
from unittest.mock import create_autospec, patch

import anyio
import pytest
from pydantic import ValidationError

from app.services import authentication, password_verification, password_work
from app.services.crypto import password_hasher
from app.services.password_work import PasswordWorkAdmissionTimeout, run_password_work
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool, make_sample_user_row
from tests.unit.settings_builders import base_kwargs, make_settings


def test_default_password_admission_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """Check default password admission budget."""
    monkeypatch.delenv("PASSWORD_WORK_ADMISSION_TIMEOUT_SECONDS", raising=False)
    values = base_kwargs()
    values.pop("password_work_admission_timeout_seconds")
    assert make_settings(**values).password_work_admission_timeout_seconds == 1.0


@pytest.mark.parametrize("value", [0.01, 0.25, 1, 5, "0.25", "5"])
def test_password_admission_budget_accepts_documented_values(value: float | str) -> None:
    """Check password admission budget accepts documented values."""
    configured = make_settings(**base_kwargs(password_work_admission_timeout_seconds=value))
    assert configured.password_work_admission_timeout_seconds == float(value)


@pytest.mark.parametrize(
    "value",
    [
        0,
        -1,
        0.009,
        5.001,
        float("inf"),
        float("-inf"),
        float("nan"),
        None,
        True,
        False,
        "forever",
        "true",
        "inf",
        "NaN",
    ],
)
def test_password_admission_budget_rejects_invalid_values(value: object) -> None:
    """Check password admission budget rejects invalid values (ValidationError)."""
    with pytest.raises(ValidationError) as failure:
        make_settings(**base_kwargs(password_work_admission_timeout_seconds=value))
    assert any(
        error["loc"] == ("password_work_admission_timeout_seconds",)
        for error in failure.value.errors()
    )


def test_password_admission_budget_reads_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Check password admission budget reads the environment."""
    values = base_kwargs()
    values.pop("password_work_admission_timeout_seconds")
    monkeypatch.setenv("PASSWORD_WORK_ADMISSION_TIMEOUT_SECONDS", "0.25")
    assert make_settings(**values).password_work_admission_timeout_seconds == 0.25


@pytest.fixture
async def password_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[anyio.CapacityLimiter]:
    """Install one password-work slot and a 20ms admission budget, restoring the context on exit."""
    limiter = anyio.CapacityLimiter(1)
    token = password_work._limiter.set(limiter)
    monkeypatch.setattr(settings, "password_work_admission_timeout_seconds", 0.02)
    try:
        yield limiter
    finally:
        password_work._limiter.reset(token)


async def test_timeout_starts_no_work_and_leaves_capacity_reusable(password_capacity) -> None:
    """Check timeout starts no work and leaves capacity reusable (PasswordWorkAdmissionTimeout)."""
    holder = object()
    await password_capacity.acquire_on_behalf_of(holder)

    def combine(value: int, *, label: str) -> tuple[int, str]:
        """Return the positional value paired with the keyword-only label."""
        return value, label

    work = create_autospec(combine, side_effect=combine)
    try:
        with anyio.fail_after(1), pytest.raises(PasswordWorkAdmissionTimeout) as failure:
            await run_password_work(work, 7, label="done")
        assert failure.value.timeout_seconds == 0.02
        work.assert_not_called()
        assert password_capacity.statistics().borrowed_tokens == 1
        assert password_capacity.statistics().tasks_waiting == 0
    finally:
        password_capacity.release_on_behalf_of(holder)
    assert await run_password_work(work, 7, label="done") == (7, "done")
    work.assert_called_once_with(7, label="done")
    assert password_capacity.statistics().borrowed_tokens == 0


async def test_queued_cancellation_removes_the_waiter(password_capacity, monkeypatch) -> None:
    """Check queued cancellation removes the waiter."""
    monkeypatch.setattr(settings, "password_work_admission_timeout_seconds", 5.0)
    holder = object()
    await password_capacity.acquire_on_behalf_of(holder)
    work = create_autospec(lambda: None)
    queued = asyncio.create_task(run_password_work(work))
    try:
        with anyio.fail_after(1):
            while password_capacity.statistics().tasks_waiting != 1:
                await anyio.lowlevel.checkpoint()
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued
        work.assert_not_called()
        assert password_capacity.statistics().tasks_waiting == 0
        assert password_capacity.statistics().borrowed_tokens == 1
    finally:
        queued.cancel()
        await asyncio.gather(queued, return_exceptions=True)
        password_capacity.release_on_behalf_of(holder)


async def test_admission_budget_does_not_release_running_or_cancelled_work(
    password_capacity,
) -> None:
    """Check admission budget does not release running or cancelled work
    (PasswordWorkAdmissionTimeout).
    """
    started = threading.Event()
    release = threading.Event()

    def slow_work() -> None:
        """Signal worker entry and wait up to five seconds for test release."""
        started.set()
        release.wait(timeout=5)

    running = asyncio.create_task(run_password_work(slow_work))
    rejected = create_autospec(lambda: None)
    try:
        with anyio.fail_after(2):
            assert await anyio.to_thread.run_sync(started.wait, 1)
            with pytest.raises(PasswordWorkAdmissionTimeout):
                await run_password_work(rejected)
            assert not running.done()
            running.cancel()
            with pytest.raises(PasswordWorkAdmissionTimeout):
                await run_password_work(rejected)
            assert not running.done()
            assert password_capacity.statistics().borrowed_tokens == 1
            rejected.assert_not_called()
    finally:
        release.set()
        await asyncio.gather(running, return_exceptions=True)
    assert running.cancelled()
    assert password_capacity.statistics().borrowed_tokens == 0


@pytest.mark.parametrize("error_type", [ValueError, RuntimeError, TimeoutError])
async def test_callable_errors_are_not_capacity_errors(password_capacity, error_type) -> None:
    """Check callable errors are not capacity errors (error_type)."""
    error = error_type("synthetic worker error")

    def fail() -> None:
        """Raise the injected failure unchanged."""
        raise error

    with pytest.raises(error_type) as failure:
        await run_password_work(fail)
    assert failure.value is error
    assert not isinstance(error, PasswordWorkAdmissionTimeout)
    assert password_capacity.statistics().borrowed_tokens == 0


@pytest.mark.parametrize("phase", ["verify", "rehash", "dummy"])
async def test_login_capacity_failures_propagate_before_credential_writes(phase: str) -> None:
    """Check login capacity failures propagate before credential writes (PasswordWorkAdmissionTimeout)."""
    row = make_sample_user_row(password_hash="stored", locked_until=None, auth_revision=3)
    cursor = make_async_cursor(fetchone=[None if phase == "dummy" else row])
    capacity = PasswordWorkAdmissionTimeout(0.02)
    hasher = create_autospec(password_hasher, spec_set=True)
    hasher.check_needs_rehash.return_value = True
    work = create_autospec(
        run_password_work,
        spec_set=True,
        side_effect=[True, capacity] if phase == "rehash" else capacity,
    )
    with (
        patch.object(
            authentication, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cursor)
        ) as connection,
        patch.object(authentication, "run_password_work", work),
        patch.object(password_verification, "run_password_work", work),
        patch.object(authentication, "password_hasher", hasher),
        patch.object(password_verification, "password_hasher", hasher),
        patch.object(password_verification, "_DUMMY_HASH", "cached dummy hash"),
        pytest.raises(PasswordWorkAdmissionTimeout) as failure,
    ):
        await authentication.verify_password(make_mock_pool(), "alice@example.org", "password")
    assert failure.value is capacity
    assert work.await_count == (2 if phase == "rehash" else 1)
    assert connection.call_count == 1
    assert cursor.execute.await_count == 1

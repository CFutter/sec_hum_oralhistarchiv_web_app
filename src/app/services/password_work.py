"""Bound Argon2 working memory independently of the general thread pool."""

from collections.abc import Callable
from functools import partial
from typing import ParamSpec, TypeVar

from anyio import CapacityLimiter
from anyio.lowlevel import RunVar

from app.thread_work import ThreadWorkAdmissionTimeout, run_thread_work
from config import settings

P = ParamSpec("P")
R = TypeVar("R")
_limiter: RunVar[CapacityLimiter] = RunVar("password_work_limiter")


class PasswordWorkAdmissionTimeout(ThreadWorkAdmissionTimeout):
    """Password work could not acquire a slot within its configured wait budget."""


async def run_password_work(function: Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> R:
    """Run a blocking callable in a thread with an event-loop-local limiter.

    The first call fixes that loop's limit from PASSWORD_WORK_CONCURRENCY.
    Admission waits at most PASSWORD_WORK_ADMISSION_TIMEOUT_SECONDS, raising
    PasswordWorkAdmissionTimeout without starting the callable when saturated.
    Return the callable's result or propagate its exception. Queued cancellation
    is immediate; admitted work keeps its slot until its thread finishes.
    """
    try:
        limiter = _limiter.get()
    except LookupError:
        limiter = CapacityLimiter(settings.password_work_concurrency)
        _limiter.set(limiter)
    try:
        return await run_thread_work(
            partial(function, *args, **kwargs),
            limiter,
            admission_timeout_seconds=settings.password_work_admission_timeout_seconds,
        )
    except ThreadWorkAdmissionTimeout as exc:
        raise PasswordWorkAdmissionTimeout(exc.timeout_seconds) from exc

"""Bound Argon2 working memory independently of the general thread pool."""

from collections.abc import Callable
from functools import partial
from typing import ParamSpec, TypeVar

from anyio import CapacityLimiter
from anyio.lowlevel import RunVar

from app.thread_work import run_thread_work
from config import settings

P = ParamSpec("P")
R = TypeVar("R")
_limiter: RunVar[CapacityLimiter] = RunVar("password_work_limiter")


async def run_password_work(function: Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> R:
    """Run a blocking callable in a thread with an event-loop-local limiter.

    The first call fixes that loop's limit from PASSWORD_WORK_CONCURRENCY.
    Return its result or propagate its exception. Cancellation waits for thread
    completion before releasing capacity.
    """
    try:
        limiter = _limiter.get()
    except LookupError:
        limiter = CapacityLimiter(settings.password_work_concurrency)
        _limiter.set(limiter)
    return await run_thread_work(partial(function, *args, **kwargs), limiter)

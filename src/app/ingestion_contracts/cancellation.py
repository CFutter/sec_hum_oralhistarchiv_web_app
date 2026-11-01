"""Parent-side cancellation for bounded, synchronous source fetching."""

import threading
import time
from collections.abc import Callable

_CANCEL_POLL_SECONDS = 0.05


class HarvestCancelled(Exception):
    """The fetch owner cancelled; its supervisor must reap before propagating."""


def check_harvest_cancellation(cancel_event: threading.Event | None) -> None:
    """Raise HarvestCancelled if cancel_event is set; None disables the check."""
    if cancel_event is not None and cancel_event.is_set():
        raise HarvestCancelled("Source fetch was cancelled")


def wait_for_harvest_step(
    wait: Callable[[float], bool],
    *,
    deadline: float,
    cancel_event: threading.Event | None,
) -> bool:
    """Return wait success before a monotonic deadline; poll cancellation every 50 ms.

    ``deadline`` uses time.monotonic() seconds. The callback must honor its
    timeout and return whether the step completed. Without cancel_event call
    wait once; otherwise raise HarvestCancelled when cancellation is observed.
    The caller retains child-process and pipe ownership.
    """
    if cancel_event is None:
        return wait(max(0.0, deadline - time.monotonic()))
    while True:
        check_harvest_cancellation(cancel_event)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        if wait(min(_CANCEL_POLL_SECONDS, remaining)):
            check_harvest_cancellation(cancel_event)
            return True

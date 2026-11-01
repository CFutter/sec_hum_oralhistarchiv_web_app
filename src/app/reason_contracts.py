"""Exhaustiveness checks for routes that present typed service refusals."""

from collections.abc import Collection, Mapping
from typing import get_args


def require_reason_coverage(
    reason_type: object,
    messages: Mapping[str, object],
    *,
    separately_handled: Collection[str] = (),
) -> None:
    """Raise RuntimeError unless Literal reasons exactly equal the handled keys.

    Include separately_handled reasons for explicit branches without messages;
    the check also rejects stale keys and remains active under python -O.
    """
    expected = set(get_args(reason_type))
    handled = set(messages) | set(separately_handled)
    if not expected or expected != handled:
        raise RuntimeError(
            "Service reason presentation is incomplete: "
            f"missing={sorted(expected - handled)!r}, extra={sorted(handled - expected)!r}"
        )

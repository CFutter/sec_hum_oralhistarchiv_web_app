"""Rank access tiers and enforce source-specific minimum restrictions."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, TypeGuard, get_args

from psycopg import sql

AccessTier = Literal["public", "registered", "vetted"]

_TIER_RANK = {"public": 0, "registered": 1, "vetted": 2}


class SourceVisibilityTierError(ValueError):
    """A source that requires per-record visibility supplied no valid tier."""


def _is_access_tier(value: object) -> TypeGuard[AccessTier]:
    """Return whether the value is a declared access tier."""
    return value in get_args(AccessTier)


def tier_case_sql(table: str | None = None) -> sql.Composed:
    """Build a visibility rank expression using the shared tier hierarchy.

    Args:
        table: Optional table or alias qualifying the visibility column.

    Returns:
        A SQL CASE expression with a fail-closed rank for unknown tiers.
    """
    whens = " ".join(f"WHEN '{t}' THEN {r}" for t, r in _TIER_RANK.items())
    column = (
        sql.Identifier(table, "visibility_tier") if table else sql.Identifier("visibility_tier")
    )
    return sql.SQL("(CASE {column} {whens} ELSE 99 END)").format(
        column=column, whens=sql.SQL(whens)
    )


TIER_CASE_SQL = tier_case_sql()


def assert_tier_rank_complete() -> None:
    """Raise AssertionError unless declared and ranked tiers match exactly."""
    declared = set(get_args(AccessTier))
    ranked = set(_TIER_RANK)
    if declared != ranked:
        raise AssertionError(
            f"AccessTier/_TIER_RANK drift — unranked: {sorted(declared - ranked)}; "
            f"ranked but not declared: {sorted(ranked - declared)}"
        )


@dataclass(frozen=True)
class SourcePolicy:
    """Source restriction and classifier for raw access labels.

    max_visibility is the least restrictive permitted tier; classify_access
    maps a raw label or None to an access classification.
    """

    name: str
    max_visibility: AccessTier
    classify_access: Callable[[str | None], str]


def can_access(user_tier: AccessTier, required_tier: AccessTier) -> bool:
    """Return whether user_tier meets required_tier; reject unknown tiers.

    Raises:
        ValueError: Either tier is unknown.
    """
    try:
        return _TIER_RANK[user_tier] >= _TIER_RANK[required_tier]
    except KeyError as e:
        raise ValueError(f"Unknown access tier: {e}") from e


def tier_rank(tier: AccessTier) -> int:
    """Return the tier rank (public=0, registered=1, vetted=2).

    Raises:
        ValueError: The tier is unknown.
    """
    try:
        return _TIER_RANK[tier]
    except KeyError as e:
        raise ValueError(f"Unknown access tier: {e}") from e


def resolve_tier(record_tier: str | None, policy: SourcePolicy) -> AccessTier:
    """Return the stricter tier; missing or unknown record tiers use the policy."""
    ceiling = policy.max_visibility
    if record_tier is None or not _is_access_tier(record_tier):
        return ceiling
    return record_tier if tier_rank(record_tier) >= tier_rank(ceiling) else ceiling


def resolve_required_source_tier(
    record_tier: object,
    policy: SourcePolicy,
) -> AccessTier:
    """Apply the source restriction to an explicitly recognized record tier.

    Raises:
        SourceVisibilityTierError: The tier is missing or unknown; the error
            omits the supplied value to keep sensitive data out of logs.
    """
    if record_tier is None:
        raise SourceVisibilityTierError(f"{policy.name} record is missing required visibility_tier")
    if not _is_access_tier(record_tier):
        raise SourceVisibilityTierError(
            f"{policy.name} record has invalid required visibility_tier"
        )
    return resolve_tier(record_tier, policy)

"""Access-tier hierarchy and gating.

Three tiers — public, registered, vetted — control how much metadata a
user sees. The ranking is strict and total: vetted > registered >
public. A vetted user can access everything a registered user can; a
public viewer sees only the public subset.

can_access() is the single comparison primitive. The service layer uses
it via datasets.can_view_full() to gate redaction; tier_rank() supplies
the numeric rank that SQL queries compare against; and resolve_tier()
clamps a record's tier to its source's SourcePolicy ceiling at ingest.
Tier strings are validated through the AccessTier Literal, so unknown
values get caught at the Pydantic / dataclass boundary, not here.
"""

from typing import Literal, get_args, TypeGuard
from dataclasses import dataclass


AccessTier = Literal["public", "registered", "vetted"]

# Tier hierarchy: vetted > registered > public
_TIER_RANK = {"public": 0, "registered": 1, "vetted": 2}

def _is_access_tier(value: str) -> TypeGuard[AccessTier]:
    return value in get_args(AccessTier)


@dataclass(frozen=True)
class SourcePolicy:
    """Binds an ingest source to the most permissive tier its metadata may
    be published at. `max_visibility` has no default: adding a source forces
    an explicit sensitivity decision at the call site, in reviewed code."""
    name: str
    max_visibility: AccessTier

def can_access(user_tier: AccessTier, required_tier: AccessTier) -> bool:
    """Check if a user's access tier meets the required minimum.

    A vetted user can access everything. A public user can only
    access public content.

    Raises:
        ValueError: If either tier is not a recognized value.
    """
    try:
        return _TIER_RANK[user_tier] >= _TIER_RANK[required_tier]
    except KeyError as e:
        raise ValueError(f"Unknown access tier: {e}") from e

def tier_rank(tier: AccessTier) -> int:
    """Numeric rank for SQL comparison; raises on unknown tiers."""
    try:
        return _TIER_RANK[tier]
    except KeyError as e:
        raise ValueError(f"Unknown access tier: {e}") from e


def resolve_tier(record_tier: str | None, policy: SourcePolicy) -> AccessTier:
    """Return the more restrictive of (record's own tier, source ceiling).

    - No per-record tier, or an unknown/garbage value -> the ceiling.
    - A record claiming a tier more permissive than the ceiling is clamped up to it.
    - A record already at or above the ceiling keeps its own tier.
    """
    ceiling = policy.max_visibility
    if record_tier is None or not _is_access_tier(record_tier):
        return ceiling
    return record_tier if tier_rank(record_tier) >= tier_rank(ceiling) else ceiling
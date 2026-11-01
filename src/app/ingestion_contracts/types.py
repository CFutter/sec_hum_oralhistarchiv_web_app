"""Shared metadata access tiers without source or service imports."""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal, TypeAlias

AccessTier: TypeAlias = Literal["public", "registered", "vetted"]


ACCESS_TIER_RANK: Final[Mapping[AccessTier, int]] = MappingProxyType(
    {"public": 0, "registered": 1, "vetted": 2}
)

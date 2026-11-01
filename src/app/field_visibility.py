"""Static metadata disclosure contract shared by sources and catalogue services.

This module performs no runtime imports from either package. Non-discovery
fields additionally inherit the effective source/stored/administrator record
tier when catalogue services resolve their disclosure requirements.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.ingestion_contracts import AccessTier

__all__ = [
    "FIELD_VISIBILITY",
    "PUBLIC_DISCOVERY_FIELDS",
    "PUBLIC_SEARCH_FIELDS",
    "RESOURCE_URL_FIELDS",
    "FrozenFieldVisibility",
]


@dataclass(frozen=True, slots=True, eq=False)
class FrozenFieldVisibility(Mapping[str, "AccessTier"]):
    """An immutable, pickleable source-configuration mapping for worker spawn."""

    entries: tuple[tuple[str, AccessTier], ...] = ()

    def __getitem__(self, key: str) -> AccessTier:
        """Return the first matching tier; raise KeyError if the field is absent."""
        for name, minimum in self.entries:
            if name == key:
                return minimum
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        """Iterate field names in entry order, including duplicates."""
        return (name for name, _minimum in self.entries)

    def __len__(self) -> int:
        """Return the entry count, including duplicate field names."""
        return len(self.entries)


PUBLIC_DISCOVERY_FIELDS = frozenset(
    {"id", "uuid", "title", "access_level", "version", "source", "visibility_tier"}
)
PUBLIC_SEARCH_FIELDS = frozenset({"title", "access_level"})
RESOURCE_URL_FIELDS = frozenset({"resource_proxies", "resource_access_url", "landing_page_url"})

FIELD_VISIBILITY: Mapping[str, AccessTier] = MappingProxyType(
    {
        "id": "public",
        "uuid": "public",
        "title": "public",
        "project_title": "public",
        "description": "public",
        "resource_description": "public",
        "languages": "public",
        "project_description": "public",
        "authors": "public",
        "keywords": "public",
        "resource_proxies": "public",
        "resource_access_url": "public",
        "landing_page_url": "public",
        "license_val": "public",
        "license_url": "public",
        "access_level": "public",
        "version": "public",
        "doi": "public",
        "resource_type": "public",
        "bibliographical_citation": "public",
        "source": "public",
        "visibility_tier": "public",
    }
)

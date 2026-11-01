"""Compile immutable catalogue field rules; record/admin tiers are always live."""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TypeGuard, get_args

from psycopg import sql
from psycopg.sql import Composable

from app import FIELD_VISIBILITY, PUBLIC_DISCOVERY_FIELDS
from app import search_mask_contract as search_masks
from app.sources import AccessTier, SourceMetadata

from .access_tiers import TIER_CASE_SQL, tier_rank
from .policy_digest import cursor_context_digest


@dataclass(frozen=True, slots=True, eq=False)
class CataloguePolicy:
    """A validated source snapshot and its derived rules, owned by one app lifespan.

    Nested derived mappings are read-only. No dataset, viewer, database row or
    administrator decision is retained here. Source replacement requires a
    freshly compiled policy; raw source sequences remain accepted by services.
    """

    sources: tuple[SourceMetadata, ...]
    code_visibility: Mapping[str, AccessTier] = field(repr=False)
    discovery_fields: frozenset[str]
    field_names: tuple[str, ...]
    source_by_name: Mapping[str, SourceMetadata] = field(repr=False)
    code_minima: Mapping[str, AccessTier] = field(repr=False)
    source_minima: Mapping[str | None, Mapping[str, AccessTier]] = field(repr=False)
    full_minima: Mapping[str | None, AccessTier] = field(repr=False)
    field_sql: Mapping[str, Composable] = field(repr=False)
    document_masks_json: Mapping[int, str] = field(repr=False)
    page_masks: Mapping[int, Mapping[str, int]] = field(repr=False)
    fingerprint: str

    def minimum(self, field_name: str, source_name: str | None) -> AccessTier:
        """Look up a field minimum, retaining vetted fallback for unknown sources."""
        self.validate_field(field_name)
        return self.source_minima.get(source_name, self.source_minima[None])[field_name]

    def validate_field(self, field_name: str) -> None:
        """Reject unknown and non-string fields before indexing a policy mapping."""
        if type(field_name) is not str or field_name not in self.code_minima:
            raise ValueError(f"Unknown Dataset field: {field_name}")

    def validate_rank(self, rank: int) -> None:
        """Require a real integer rank from the application's tier contract."""
        if type(rank) is not int or rank not in self.page_masks:
            raise ValueError("Unknown catalogue viewer rank")


CataloguePolicyInput = Sequence[SourceMetadata] | CataloguePolicy


def compile_default_catalogue_policy(
    configured_sources: Sequence[SourceMetadata],
) -> CataloguePolicy:
    """Compile the shipped field contract without authentication settings or keys."""
    return compile_catalogue_policy(
        configured_sources,
        field_names=tuple(FIELD_VISIBILITY),
        visibility=FIELD_VISIBILITY,
        discovery_fields=PUBLIC_DISCOVERY_FIELDS,
    )


def _is_minimum(value: object) -> TypeGuard[AccessTier]:
    """Check canonical values even when a caller has bypassed static annotations."""
    return type(value) is str and value in get_args(AccessTier)


def _code_minima(
    field_names: tuple[str, ...],
    visibility: Mapping[str, AccessTier],
    discovery_fields: frozenset[str],
) -> dict[str, AccessTier]:
    """Validate the code matrix once, before deriving source-specific rules."""
    if not isinstance(visibility, Mapping) or set(visibility) != set(field_names):
        raise ValueError("Field visibility matrix must match Dataset fields")
    minima = dict(visibility)
    for name, minimum in minima.items():
        if not _is_minimum(minimum):
            raise ValueError(f"Invalid field visibility minimum: {name}")
        if name in discovery_fields and minimum != "public":
            raise ValueError(f"Public discovery field requires a public minimum: {name}")
    return minima


def _visible_sql(
    field_name: str,
    source_names: Sequence[str],
    source_minima: Mapping[str | None, Mapping[str, AccessTier]],
    discovery_fields: frozenset[str],
) -> Composable:
    """Compile static source cases while leaving the effective record floor in SQL."""
    if field_name in discovery_fields:
        return sql.SQL("TRUE")
    minimum = (
        sql.SQL("CASE source {sources} ELSE 2 END").format(
            sources=sql.SQL(" ").join(
                sql.SQL("WHEN {source} THEN {rank}").format(
                    source=sql.Literal(name),
                    rank=sql.Literal(tier_rank(source_minima[name][field_name])),
                )
                for name in source_names
            )
        )
        if source_names
        else sql.Literal(2)
    )
    return sql.SQL("({record_rank} <= %(rank)s AND {minimum} <= %(rank)s)").format(
        record_rank=TIER_CASE_SQL, minimum=minimum
    )


def compile_catalogue_policy(
    configured_sources: Sequence[SourceMetadata],
    *,
    field_names: tuple[str, ...],
    visibility: Mapping[str, AccessTier],
    discovery_fields: frozenset[str],
) -> CataloguePolicy:
    """Resolve field rules, SQL and all viewer masks once for an immutable selection."""
    sources = tuple(configured_sources)
    code_minima = _code_minima(field_names, visibility, discovery_fields)
    source_by_name: dict[str, SourceMetadata] = {}
    source_minima: dict[str | None, Mapping[str, AccessTier]] = {
        None: MappingProxyType(
            {name: "public" if name in discovery_fields else "vetted" for name in field_names}
        )
    }
    for source in sources:
        if source.name in source_by_name:
            raise ValueError(f"Duplicate source name: {source.name}")
        source_by_name[source.name] = source
        overrides = dict(source.config.field_visibility)
        if overrides.keys() - code_minima.keys():
            raise ValueError(f"Unknown field visibility override for source: {source.name}")
        for name, minimum in overrides.items():
            if not _is_minimum(minimum):
                raise ValueError(f"Invalid field visibility override: {name}")
            if name in discovery_fields and minimum != "public":
                raise ValueError(f"Public discovery field requires a public minimum: {name}")
        source_minima[source.name] = MappingProxyType(
            {
                # A tightened source floor applies immediately, including to
                # rows harvested under an earlier source configuration.
                name: (
                    "public"
                    if name in discovery_fields
                    else max(
                        (minimum, overrides.get(name, minimum), source.policy.max_visibility),
                        key=tier_rank,
                    )
                )
                for name, minimum in code_minima.items()
            }
        )

    page_masks: dict[int, Mapping[str, int]] = {}
    document_masks_json: dict[int, str] = {}
    for tier in get_args(AccessTier):
        rank = tier_rank(tier)
        masks = {
            name if name is not None else "*": sum(
                int(item.bit)
                for item in search_masks.SEARCH_FILTER_FIELDS
                if tier_rank(minima[item.name]) <= rank
            )
            for name, minima in source_minima.items()
        }
        page_masks[rank] = MappingProxyType(masks)
        document_masks_json[rank] = json.dumps(
            {name: mask & search_masks.SEARCH_DOCUMENT_MASK for name, mask in masks.items()},
            sort_keys=True,
            separators=(",", ":"),
        )

    fingerprint = cursor_context_digest(
        {
            "search_mask_protocol": search_masks.SEARCH_MASK_PROTOCOL_TAG,
            "code_field_minima": code_minima,
            "source_field_minima": {
                name if name is not None else "*": dict(minima)
                for name, minima in source_minima.items()
            },
            "source_policy": [
                {
                    "name": name,
                    "adapter": source_by_name[name].config.adapter,
                    "max_visibility": source_by_name[name].policy.max_visibility,
                    "requires_record_tier": source_by_name[name].policy.requires_record_tier,
                }
                for name in sorted(source_by_name)
            ],
        }
    )
    return CataloguePolicy(
        sources=sources,
        code_visibility=visibility,
        discovery_fields=discovery_fields,
        field_names=field_names,
        source_by_name=MappingProxyType(source_by_name),
        code_minima=MappingProxyType(code_minima),
        source_minima=MappingProxyType(source_minima),
        full_minima=MappingProxyType(
            {name: max(minima.values(), key=tier_rank) for name, minima in source_minima.items()}
        ),
        field_sql=MappingProxyType(
            {
                name: _visible_sql(name, tuple(source_by_name), source_minima, discovery_fields)
                for name in field_names
            }
        ),
        document_masks_json=MappingProxyType(document_masks_json),
        page_masks=MappingProxyType(page_masks),
        fingerprint=fingerprint,
    )

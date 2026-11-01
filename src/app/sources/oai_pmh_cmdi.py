"""OAI-PMH/CMDI adapter with source-owned, bounded isolated transport.

Service APIs and transport imports remain inside methods so source construction
does not initialize runtime services or load settings.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from threading import Event
from types import MappingProxyType
from typing import Final, Literal

from pydantic import Field, field_validator

from app.ingestion_contracts import HarvestResult
from app.ingestion_contracts.cancellation import check_harvest_cancellation
from app.url_safety import parse_http_url

from .base import SourceConfig, SourcePolicy, normalize_harvest_since

# Generation 1 is the legacy parser without this fingerprint field.
# Increment when CMDI interpretation changes and stored records need rebuilding.
OAI_CMDI_PARSER_CONTRACT_VERSION: Final = 2

_OAI_RECORD_TIER_ERROR = (
    "oai_pmh_cmdi does not provide per-record visibility_tier; requires_record_tier must be false"
)


class OaiPmhCmdiConfig(SourceConfig):
    """OAI construction fields; environment-specific startup gates are separate."""

    adapter: Literal["oai_pmh_cmdi"] = "oai_pmh_cmdi"
    endpoint: str
    institution_filter: str
    max_pages: int = Field(default=500, ge=1)

    requires_record_tier: bool = False

    @field_validator("requires_record_tier")
    @classmethod
    def reject_required_record_tier(cls, value: bool) -> bool:
        """Reject a requirement that the native CMDI parser cannot satisfy."""
        if value:
            raise ValueError(_OAI_RECORD_TIER_ERROR)
        return value

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        """Validate structure without rewriting the fingerprint input."""
        parse_http_url(value)
        return value

    @field_validator("institution_filter")
    @classmethod
    def validate_institution_filter(cls, value: str) -> str:
        """Reject an unscoped harvest without rewriting its binding input."""
        if not value.strip():
            raise ValueError("Source institution_filter must not be blank")
        return value


OAI_ACCESS_LABELS: Mapping[str, str] = MappingProxyType(
    {
        "Public access": "public",
        "License CC BY": "public",
        "CC BY 4.0": "public",
        "Restricted access": "restricted",
    }
)
OAI_UNKNOWN_ACCESS_LEVEL = "restricted"


def classify_oai_access(raw: str | None) -> str:
    """Map exact local contract labels; missing and unknown labels are restricted.

    Do not normalize case/whitespace or infer access from prefixes. The mapping
    preserves explicitly supported local spellings; it is not provider or source
    owner approval. Reject wrong types without echoing upstream values.
    """
    if raw is None:
        return OAI_UNKNOWN_ACCESS_LEVEL
    if not isinstance(raw, str):
        raise TypeError("OAI access label must be text or None")
    return OAI_ACCESS_LABELS.get(raw, OAI_UNKNOWN_ACCESS_LEVEL)


@dataclass(frozen=True, slots=True)
class OaiPmhCmdiAdapter:
    """Hold source settings and policy without fetching; callers must validate direct inputs.

    Fetch imports runtime settings and selects parser service or explicit dev local mode.
    Only local workers use its configured log level/format; service workers use WARNING/json.
    """

    policy: SourcePolicy
    oai_url: str
    institution_filter: str
    max_pages: int

    def __post_init__(self) -> None:
        """Enforce the same restriction for direct construction and unvalidated models."""
        if self.policy.requires_record_tier is not False:
            raise ValueError(_OAI_RECORD_TIER_ERROR)

    @classmethod
    def from_config(cls, config: SourceConfig) -> OaiPmhCmdiAdapter:
        """Construct an adapter without fetching or loading global settings."""
        if not isinstance(config, OaiPmhCmdiConfig):
            raise TypeError("oai_pmh_cmdi requires OaiPmhCmdiConfig")

        return cls(
            policy=SourcePolicy(
                name=config.name,
                max_visibility=config.max_visibility,
                classify_access=classify_oai_access,
                requires_record_tier=config.requires_record_tier,
            ),
            oai_url=config.endpoint,
            institution_filter=config.institution_filter,
            max_pages=config.max_pages,
        )

    @property
    def name(self) -> str:
        """Derive source identity from the policy used for its records."""
        return self.policy.name

    def config_fingerprint(self) -> str:
        """Bind source selection, parser semantics and the exact resource-access mapping."""
        document = {
            "source": self.name,
            "oai_url": self.oai_url,
            "institution_filter": self.institution_filter,
            "max_visibility": self.policy.max_visibility,
            "requires_record_tier": self.policy.requires_record_tier,
            "cmdi_parser_contract_version": OAI_CMDI_PARSER_CONTRACT_VERSION,
            "access_labels": dict(OAI_ACCESS_LABELS),
            "unknown_access_level": OAI_UNKNOWN_ACCESS_LEVEL,
        }
        canonical = json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def fetch(self, *, since: datetime | None, cancel_event: Event | None = None) -> HarvestResult:
        """Fetch a complete harvest after widening an aware boundary to its inclusive UTC date.

        None uses 1900-01-01. Import runtime logging settings; read parser-mode/socket
        configuration and perform network/service or process I/O. Boundary errors raise
        TypeError/ValueError, harvest failures OAIProtocolError and cancellation
        HarvestCancelled; no database writes occur.
        """
        check_harvest_cancellation(cancel_event)
        normalized = normalize_harvest_since(since)
        transport_since = normalized.date().isoformat() if normalized is not None else "1900-01-01"

        from config import settings  # noqa: PLC0415 - fetch-time runtime logging policy

        from .oai_client import fetch_updates_isolated  # noqa: PLC0415

        return fetch_updates_isolated(
            oai_url=self.oai_url,
            since=transport_since,
            institution_filter=self.institution_filter,
            max_pages=self.max_pages,
            source=self.name,
            log_level=settings.log_level,
            log_format=settings.log_format,
            cancel_event=cancel_event,
        )

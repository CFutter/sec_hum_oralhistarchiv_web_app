"""Deterministic bundled metadata for offline development and source tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.resources import files
from threading import Event
from typing import Literal

from pydantic import Field

from app.ingestion_contracts import HarvestResult, harvest_result_from_document
from app.ingestion_contracts.cancellation import check_harvest_cancellation

from .base import SourceConfig, SourcePolicy, normalize_harvest_since

_MAX_FIXTURE_BYTES = 1048576


class FixtureConfig(SourceConfig):
    """Allowlisted package data; no endpoint or arbitrary filesystem path."""

    adapter: Literal["fixture"] = "fixture"
    dataset: Literal["catalogue_v1"] = "catalogue_v1"
    max_bytes: int = Field(default=65536, ge=1, le=_MAX_FIXTURE_BYTES)
    requires_record_tier: bool = True


def classify_fixture_access(raw: str | None) -> str:
    """Map the exact fixture public label; otherwise classify as restricted."""
    return "public" if raw == "Public access" else "restricted"


@dataclass(frozen=True, slots=True)
class FixtureAdapter:
    """Bind and fetch the same immutable, bounded package-data snapshot."""

    policy: SourcePolicy
    dataset: str
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Keep direct construction bounded and reject mutable payloads."""
        if not isinstance(self.payload, bytes):
            raise TypeError("Fixture payload must be immutable bytes")
        if len(self.payload) > _MAX_FIXTURE_BYTES:
            raise ValueError("Fixture payload exceeds the 1 MiB hard limit")

    @classmethod
    def from_config(cls, config: SourceConfig) -> FixtureAdapter:
        """Read bundled bytes without loading settings/services or fetching."""
        if not isinstance(config, FixtureConfig):
            raise TypeError("fixture requires FixtureConfig")

        resource = files("app.sources").joinpath("fixture_data", f"{config.dataset}.json")
        with resource.open("rb") as handle:
            payload = handle.read(config.max_bytes + 1)
        if len(payload) > config.max_bytes:
            raise ValueError("Fixture data exceeds max_bytes")

        return cls(
            policy=SourcePolicy(
                name=config.name,
                max_visibility=config.max_visibility,
                classify_access=classify_fixture_access,
                requires_record_tier=config.requires_record_tier,
            ),
            dataset=config.dataset,
            payload=payload,
        )

    @property
    def name(self) -> str:
        """Return the policy's persistent source identity."""
        return self.policy.name

    def config_fingerprint(self) -> str:
        """Bind content and interpretation; exclude presentation and budgets."""
        document = {
            "adapter": "fixture",
            "fixture_contract_version": 1,
            "dataset": self.dataset,
            "content_sha256": hashlib.sha256(self.payload).hexdigest(),
            "source": self.name,
            "max_visibility": self.policy.max_visibility,
            "requires_record_tier": self.policy.requires_record_tier,
        }
        canonical = json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def fetch(self, *, since: datetime | None, cancel_event: Event | None = None) -> HarvestResult:
        """Decode fresh records, widening aware boundaries to inclusive UTC days.

        None selects the complete validated catalogue. The fixed source
        cursor never uses wall-clock time; later UTC days are rejected.
        """
        check_harvest_cancellation(cancel_event)
        normalized = normalize_harvest_since(since)
        boundary = normalized.date() if normalized is not None else None

        result = harvest_result_from_document(json.loads(self.payload.decode("utf-8")))
        cursor = result.validate().astimezone(UTC)
        if result.deleted_uuids or result.nonmatching_uuids or result.uncertain_records:
            raise ValueError("Static fixture data supports matching records only")
        if boundary is not None and boundary > cursor.date():
            raise ValueError("Fixture since is later than its fixed source cursor")

        selected = []
        for record in result.matching_records:
            modified = record["upstream_modified_at"]
            if not isinstance(modified, datetime) or modified > cursor:
                raise ValueError(
                    "Fixture records require modification timestamps within the cursor"
                )
            if self.policy.requires_record_tier and record.get("visibility_tier") is None:
                raise ValueError("Fixture record is missing required visibility_tier")
            if boundary is None or modified.astimezone(UTC).date() >= boundary:
                selected.append(record)
        result.matching_records = selected
        result.validate()
        check_harvest_cancellation(cancel_event)
        return result

"""Independent bounded package-data adapter used for the extensibility proof."""

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

_MAX_STATIC_JSON_BYTES = 1048576
_STATIC_JSON_CONTRACT_VERSION = 1


class StaticJsonConfig(SourceConfig):
    """Select allowlisted bundled JSON; no URL or arbitrary path is accepted."""

    adapter: Literal["static_json"] = "static_json"
    dataset: Literal["proof_v1"] = "proof_v1"
    max_bytes: int = Field(default=65536, ge=1, le=_MAX_STATIC_JSON_BYTES)
    requires_record_tier: bool = True


def classify_static_json_access(raw: str | None) -> str:
    """Recognize the exact public label; classify every other value as restricted."""
    return "public" if raw == "Public access" else "restricted"


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous duplicate fields in every native JSON object."""
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("Static JSON data contains duplicate object fields")
        document[key] = value
    return document


@dataclass(frozen=True, slots=True)
class StaticJsonAdapter:
    """Snapshot a native cursor/items document and translate fresh results per fetch."""

    policy: SourcePolicy
    dataset: str
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Keep direct construction immutable and within the hard input budget."""
        if not isinstance(self.payload, bytes):
            raise TypeError("Static JSON payload must be immutable bytes")
        if len(self.payload) > _MAX_STATIC_JSON_BYTES:
            raise ValueError("Static JSON payload exceeds the 1 MiB hard limit")

    @classmethod
    def from_config(cls, config: SourceConfig) -> StaticJsonAdapter:
        """Read one bounded package snapshot without fetching or global settings."""
        if not isinstance(config, StaticJsonConfig):
            raise TypeError("static_json requires StaticJsonConfig")

        resource = files("app.sources").joinpath("static_json_data", f"{config.dataset}.json")
        with resource.open("rb") as handle:
            payload = handle.read(config.max_bytes + 1)
        if len(payload) > config.max_bytes:
            raise ValueError("Static JSON data exceeds max_bytes")

        return cls(
            policy=SourcePolicy(
                name=config.name,
                max_visibility=config.max_visibility,
                classify_access=classify_static_json_access,
                requires_record_tier=config.requires_record_tier,
            ),
            dataset=config.dataset,
            payload=payload,
        )

    @property
    def name(self) -> str:
        """Return the persistent identity supplied by the actual write policy."""
        return self.policy.name

    def config_fingerprint(self) -> str:
        """Bind exact native bytes and interpretation, excluding operational metadata."""
        document = {
            "adapter": "static_json",
            "static_json_contract_version": _STATIC_JSON_CONTRACT_VERSION,
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
        """Validate all native input before selecting inclusive UTC-day records.

        None selects the complete catalogue. A boundary on the fixed cursor's
        UTC day can return an empty result; later UTC days are rejected.
        Every call decodes a fresh result and retains no mutable harvest state.
        """
        check_harvest_cancellation(cancel_event)
        normalized = normalize_harvest_since(since)
        boundary = normalized.date() if normalized is not None else None
        native = json.loads(self.payload.decode("utf-8"), object_pairs_hook=_unique_json_object)
        if not isinstance(native, dict) or set(native) != {"cursor", "items"}:
            raise ValueError("Static JSON data requires exactly cursor and items")
        cursor_text = native["cursor"]
        if not isinstance(cursor_text, str):
            raise TypeError("Static JSON cursor must be a string")
        if not isinstance(native["items"], list):
            raise TypeError("Static JSON items must be a list")

        result = harvest_result_from_document(
            {
                "matching_records": native["items"],
                "deleted_uuids": [],
                "nonmatching_uuids": [],
                "uncertain_records": {},
                "source_cursor": cursor_text,
            }
        )
        cursor = result.validate().astimezone(UTC)
        for record in result.matching_records:
            modified = record["upstream_modified_at"]
            if not isinstance(modified, datetime) or modified > cursor:
                raise ValueError(
                    "Static JSON records require modification timestamps within the cursor"
                )
            if self.policy.requires_record_tier and record.get("visibility_tier") is None:
                raise ValueError("Static JSON record is missing required visibility_tier")

        if boundary is not None and boundary > cursor.date():
            raise ValueError("Static JSON since is later than its fixed source cursor")
        result.matching_records = [
            record
            for record in result.matching_records
            if boundary is None or record["upstream_modified_at"].astimezone(UTC).date() >= boundary
        ]
        result.validate()
        check_harvest_cancellation(cancel_event)
        return result

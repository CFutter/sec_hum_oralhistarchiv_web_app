"""Runnable sensitive-feed adapter with pure construction and stable binding."""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from threading import Event

from app.ingestion_contracts import HarvestResult
from app.ingestion_contracts.cancellation import check_harvest_cancellation

from .base import SourceConfig, SourcePolicy, normalize_harvest_since
from .json_feed_config import (
    JsonFeedConfig,
    JsonFeedCredentials,
    snapshot_json_feed_credentials,
)
from .json_feed_protocol import FEED_ACCESS_LABELS, FEED_CONTRACT_VERSION

_JSON_FEED_INTERPRETATION_VERSION = 2


def classify_json_feed_access(raw: str | None) -> str:
    """Map the two reviewed wire labels; reject invalid input without echoing it."""
    if not isinstance(raw, str):
        raise TypeError("JSON feed access label must be text")
    classification = FEED_ACCESS_LABELS.get(raw)
    if classification is None:
        raise ValueError("JSON feed access label is outside the reviewed mapping")
    return classification


@dataclass(frozen=True, slots=True)
class JsonFeedAdapter:
    """Snapshot validated config and secrets without fetching or ambient reads.

    Credential values can rotate at the same references without rebuilding the
    catalogue. Reference names are source bindings. Display, schedule and resource
    budgets are operational and excluded from the interpretation fingerprint.
    Wire/public-policy changes require review and an interpretation-version
    increment.
    """

    config: JsonFeedConfig
    credentials: JsonFeedCredentials = field(repr=False)

    def __post_init__(self) -> None:
        """Revalidate and snapshot config and source-bound secrets; reject mismatched inputs."""
        if not isinstance(self.config, JsonFeedConfig):
            raise TypeError("JSON feed adapter requires JsonFeedConfig")
        snapshot = JsonFeedConfig.model_validate(self.config)
        credentials = snapshot_json_feed_credentials(snapshot, self.credentials)
        object.__setattr__(self, "config", snapshot)
        object.__setattr__(self, "credentials", credentials)

    @classmethod
    def from_config(
        cls, config: SourceConfig, credentials: JsonFeedCredentials | None = None
    ) -> "JsonFeedAdapter":
        """Construct only with explicitly prepared, source-bound credentials."""
        if not isinstance(config, JsonFeedConfig):
            raise TypeError("json_feed requires JsonFeedConfig")
        if credentials is None:
            raise ValueError("JSON feed requires prepared credentials")
        return cls(config, credentials)

    @property
    def name(self) -> str:
        """Return the configured persistent source identity."""
        return self.config.name

    @property
    def policy(self) -> SourcePolicy:
        """Return the strict source floor and exact material-access classifier."""
        return SourcePolicy(
            name=self.name,
            max_visibility=self.config.max_visibility,
            classify_access=classify_json_feed_access,
            requires_record_tier=True,
        )

    def config_fingerprint(self) -> str:
        """Bind interpretation without secret values, I/O or service imports."""
        document = {
            "adapter": "json_feed",
            "source": self.name,
            "endpoint": self.config.endpoint,
            "credential_env": self.config.credential_env,
            "signing_key_env": self.config.signing_key_env,
            "feed_contract_version": FEED_CONTRACT_VERSION,
            "json_feed_interpretation_version": _JSON_FEED_INTERPRETATION_VERSION,
            "max_visibility": self.config.max_visibility,
            "requires_record_tier": True,
            "max_project_title_chars": self.config.max_project_title_chars,
            "public_discovery_mapping": {
                "uuid": "uuid",
                "title": "title",
                "license_val": "access_level",
                "version": "version",
                "visibility_tier": "visibility_tier",
                "source": "configured_source_name",
                "id": "application_generated",
            },
            "access_labels": dict(FEED_ACCESS_LABELS),
        }
        canonical = json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def fetch(
        self, *, since: datetime | None, cancel_event: Event | None = None
    ) -> "HarvestResult":
        """Normalize the caller boundary before starting complete isolated work."""
        check_harvest_cancellation(cancel_event)
        normalized = normalize_harvest_since(since)
        from .json_feed_fetch import fetch_json_feed_isolated  # noqa: PLC0415

        return fetch_json_feed_isolated(
            self.config, self.credentials, since=normalized, cancel_event=cancel_event
        )

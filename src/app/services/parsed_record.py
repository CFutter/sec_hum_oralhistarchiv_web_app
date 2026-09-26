"""Validated metadata contract shared by ingestion, worker decoding and writes."""

from typing import Any, Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from .access_tiers import AccessTier

FACET_LABEL_MAX_CHARS = 256

# Increment whenever persisted ParsedRecord fields or their meaning change.
# A release changing this value must retain a decoder or support conservative
# pending-harvest reset and refetch.
PARSED_RECORD_CONTRACT_VERSION: Final = 1


class ResourceProxy(BaseModel):
    """Strict resource type/reference pair; ref may be None and extra fields fail validation."""

    model_config = ConfigDict(strict=True, extra="forbid")
    type: str
    ref: str | None


class ParsedRecord(BaseModel):
    """Strict parser record; extra fields and coercible wrong types fail validation.

    Every field except visibility_tier is required. uuid and title must be
    nonblank; keyword/language labels contain 1-256 characters. Nullable
    fields and lists may be empty. Datetimes must have a timezone.
    Source classification separately rejects missing institutions.
    """

    model_config = ConfigDict(strict=True, extra="forbid")
    uuid: str = Field(min_length=1)
    title: str = Field(min_length=1)
    project_title: str | None
    description: str | None
    resource_description: str | None
    languages: list[str]
    project_description: str | None
    authors: list[str]
    keywords: list[str]
    resource_proxies: list[ResourceProxy]
    license_val: str | None
    license_url: str | None
    version: str | None
    doi: str | None
    resource_type: str | None
    institutions: list[str]
    main_disciplines: list[str]
    bibliographical_citation: str | None
    upstream_modified_at: AwareDatetime | None
    visibility_tier: AccessTier | None = None

    @field_validator("uuid", "title")
    @classmethod
    def nonblank(cls, value: str) -> str:
        """Return value unchanged, raising ValueError if it contains only whitespace."""
        if not value.strip():
            raise ValueError("identity and discovery title must not be blank")
        return value

    @field_validator("keywords", "languages")
    @classmethod
    def facet_labels(cls, values: list[str]) -> list[str]:
        """Return labels unchanged, raising ValueError for empty or over-256-character labels."""
        if any(not value or len(value) > FACET_LABEL_MAX_CHARS for value in values):
            raise ValueError(f"facet labels must contain 1-{FACET_LABEL_MAX_CHARS} characters")
        return values


def validate_parsed_record(record: dict[str, Any]) -> None:
    """Validate without mutating record; raise pydantic.ValidationError on contract violations."""
    ParsedRecord.model_validate(record)

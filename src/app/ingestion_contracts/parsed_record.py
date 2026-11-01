"""Validated metadata contract shared by ingestion, worker decoding and writes."""

from typing import Any, Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from .types import AccessTier

FACET_LABEL_MAX_CHARS = 256
# At most 2048 UTF-8 bytes per value, leaving room for the ASCII source
# component and tuple overhead in the reviewed PostgreSQL btree indexes.
IDENTITY_MAX_CHARS: Final = 512
DOI_MAX_CHARS: Final = 512
RECORD_MAX_COLLECTION_ITEMS: Final = 512
RECORD_MAX_LABEL_CHARS: Final = 4096
PROJECT_TITLE_MAX_CHARS: Final = 16_384
RECORD_MAX_TEXT_CHARS: Final = 262_144
RECORD_MAX_URL_CHARS: Final = 4096

# Increment whenever persisted ParsedRecord fields or their meaning change.
# A release changing this value must retain a decoder or support conservative
# pending-harvest reset and refetch.
PARSED_RECORD_CONTRACT_VERSION: Final = 4


class ResourceProxy(BaseModel):
    """Strict resource type/reference pair; ref may be None and extra fields fail validation."""

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)
    type: str = Field(max_length=RECORD_MAX_LABEL_CHARS)
    ref: str | None = Field(max_length=RECORD_MAX_URL_CHARS)


class ParsedRecord(BaseModel):
    """Strict parser record; extra fields and coercible wrong types fail validation.

    Every field except visibility_tier is required. uuid and title must be
    nonblank; uuid and DOI contain at most 512 characters. Keyword/language
    labels contain 1-256 characters. Collections contain at most 512 entries;
    project_title contains at most 16384 characters, other labels/URLs at most
    4096 and long text at most 262144.
    Nullable fields and lists may be empty.
    Datetimes must have a timezone.
    Source classification separately rejects missing institutions.
    """

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)
    uuid: str = Field(min_length=1, max_length=IDENTITY_MAX_CHARS)
    title: str = Field(min_length=1, max_length=RECORD_MAX_LABEL_CHARS)
    project_title: str | None = Field(max_length=PROJECT_TITLE_MAX_CHARS)
    description: str | None = Field(max_length=RECORD_MAX_TEXT_CHARS)
    resource_description: str | None = Field(max_length=RECORD_MAX_TEXT_CHARS)
    languages: list[str] = Field(max_length=RECORD_MAX_COLLECTION_ITEMS)
    project_description: str | None = Field(max_length=RECORD_MAX_TEXT_CHARS)
    authors: list[str] = Field(max_length=RECORD_MAX_COLLECTION_ITEMS)
    keywords: list[str] = Field(max_length=RECORD_MAX_COLLECTION_ITEMS)
    resource_proxies: list[ResourceProxy] = Field(max_length=RECORD_MAX_COLLECTION_ITEMS)
    license_val: str | None = Field(max_length=RECORD_MAX_LABEL_CHARS)
    license_url: str | None = Field(max_length=RECORD_MAX_URL_CHARS)
    version: str | None = Field(max_length=RECORD_MAX_LABEL_CHARS)
    doi: str | None = Field(max_length=DOI_MAX_CHARS)
    resource_type: str | None = Field(max_length=RECORD_MAX_LABEL_CHARS)
    institutions: list[str] = Field(max_length=RECORD_MAX_COLLECTION_ITEMS)
    main_disciplines: list[str] = Field(max_length=RECORD_MAX_COLLECTION_ITEMS)
    bibliographical_citation: str | None = Field(max_length=RECORD_MAX_TEXT_CHARS)
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

    @field_validator("authors", "institutions", "main_disciplines")
    @classmethod
    def collection_labels(cls, values: list[str], info: ValidationInfo) -> list[str]:
        """Return labels unchanged; raise ValueError if any exceeds 4096 characters."""
        if any(len(value) > RECORD_MAX_LABEL_CHARS for value in values):
            raise ValueError(f"{info.field_name} members exceed the label length limit")
        return values


def validate_parsed_record(record: dict[str, Any]) -> None:
    """Validate without mutating record; raise pydantic.ValidationError on contract violations."""
    ParsedRecord.model_validate(record)

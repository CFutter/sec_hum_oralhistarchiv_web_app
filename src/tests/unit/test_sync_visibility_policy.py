"""Source tier requirements are enforced at the catalogue write boundary."""

from unittest.mock import AsyncMock, Mock, create_autospec

import pytest

from app.services import ingestion
from app.services.access_tiers import SourceVisibilityTierError
from app.services.schema import DATASET_INSERT_COLUMNS
from app.sources.base import SourcePolicy
from tests.ingestion_doubles import dataset_write_state_from_params
from tests.oai_fixtures import parsed_record


@pytest.mark.parametrize("record_tier", [None, "private-tier-value"], ids=["missing", "unknown"])
async def test_required_tier_is_checked_before_classification_or_writes(
    monkeypatch: pytest.MonkeyPatch, record_tier: str | None
) -> None:
    """Reject missing or unknown mandatory tiers before classification or persistence."""
    classifier = Mock(return_value="public")
    policy = SourcePolicy(
        name="test_source",
        max_visibility="registered",
        classify_access=classifier,
        requires_record_tier=True,
    )
    cursor = AsyncMock()
    upsert = create_autospec(
        ingestion.upsert_dataset,
        spec_set=True,
        side_effect=dataset_write_state_from_params,
    )
    monkeypatch.setattr(ingestion, "upsert_dataset", upsert)
    record = parsed_record("record-1", visibility_tier=record_tier)

    with pytest.raises(SourceVisibilityTierError) as error:
        await ingestion._upsert_public_catalogue_record(cursor, record, policy)

    assert str(record_tier) not in str(error.value)
    classifier.assert_not_called()
    upsert.assert_not_awaited()
    assert cursor.mock_calls == []


@pytest.mark.parametrize(
    ("requires_record_tier", "record_tier", "expected"),
    [
        (False, None, "registered"),
        (True, "public", "registered"),
        (True, "registered", "registered"),
        (True, "vetted", "vetted"),
    ],
)
async def test_ingestion_applies_the_source_tier_policy(
    monkeypatch: pytest.MonkeyPatch,
    requires_record_tier: bool,
    record_tier: str | None,
    expected: str,
) -> None:
    """Optional missing tiers still work; valid mandatory tiers are clamped only upward."""
    policy = SourcePolicy(
        name="test_source",
        max_visibility="registered",
        classify_access=lambda _value: "public",
        requires_record_tier=requires_record_tier,
    )
    cursor = AsyncMock()
    upsert = create_autospec(
        ingestion.upsert_dataset,
        spec_set=True,
        side_effect=dataset_write_state_from_params,
    )
    monkeypatch.setattr(ingestion, "upsert_dataset", upsert)
    record = parsed_record("record-1", visibility_tier=record_tier)

    await ingestion._upsert_public_catalogue_record(cursor, record, policy)

    upsert.assert_awaited_once()
    assert upsert.await_args is not None
    passed_cursor, params = upsert.await_args.args
    assert passed_cursor is cursor
    assert params[DATASET_INSERT_COLUMNS.index("visibility_tier")] == expected
    assert params[DATASET_INSERT_COLUMNS.index("source")] == policy.name

"""Administrative discovery adds only nonhidden public titles to identity/controls."""

from dataclasses import asdict
from datetime import UTC, datetime

import pytest
from psycopg.types.json import Jsonb

from app.services.dataset_admin_queries import (
    ADMIN_DATASET_MAX_ID,
    ADMIN_DATASET_UUID_MAX_CHARS,
    DatasetAdminPage,
    get_admin_dataset_by_id,
    search_admin_datasets,
)
from tests.source_fixtures import fixture_source, legacy_source


async def test_admin_search_includes_hidden_and_unselected_sources_with_bounded_keyset_pages(
    db_pool, sync_conn, dataset_factory
):
    """Verify admin search includes hidden and unselected sources with bounded keyset pages."""
    hidden_at = datetime(2026, 10, 18, tzinfo=UTC)
    hidden_id = dataset_factory(source="archive_alpha", uuid="shared", title="private-only-title")
    foreign_id = dataset_factory(source="archive_beta", uuid="shared", visibility_tier="vetted")
    other_id = dataset_factory(source="archive_alpha", uuid="other")
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, visibility_tier, hidden_at) "
        "VALUES ('archive_alpha', 'shared', 'registered', %s), "
        "('orphan_archive', 'absent-record', 'vetted', %s)",
        (hidden_at, hidden_at),
    )
    sync_conn.commit()
    selected = (legacy_source(name="archive_alpha", max_visibility="public"),)
    first_page = await search_admin_datasets(db_pool, page_size=2, configured_sources=selected)
    first = first_page.records
    assert [row.dataset_id for row in first] == [other_id, foreign_id]
    assert first_page.newer_id is None and first_page.older_id == foreign_id
    second_page = await search_admin_datasets(
        db_pool, after_id=first_page.older_id, page_size=2, configured_sources=selected
    )
    second = second_page.records
    assert [row.dataset_id for row in second] == [hidden_id]
    assert second_page.newer_id == hidden_id and second_page.older_id is None
    back = await search_admin_datasets(
        db_pool, before_id=second_page.newer_id, page_size=2, configured_sources=selected
    )
    assert back == first_page
    assert await search_admin_datasets(
        db_pool, after_id=hidden_id, page_size=2, configured_sources=selected
    ) == DatasetAdminPage([])
    hidden = await get_admin_dataset_by_id(db_pool, hidden_id, configured_sources=selected)
    assert hidden == second[0] and hidden is not None
    assert hidden.state.hidden_at == hidden_at
    assert hidden.state.admin_tier == hidden.required_tier == "registered"
    assert hidden.public_title is None
    assert hidden.allowed_raise_tiers == ("registered", "vetted")
    foreign = first[1]
    assert foreign.source == "archive_beta" and foreign.state.admin_tier is None
    assert foreign.state.hidden_at is None and foreign.raise_block_reason == "source_unavailable"
    assert foreign.allowed_raise_tiers == ()
    for row in (*first, *second):
        assert set(asdict(row)) == {
            "dataset_id",
            "source",
            "uuid",
            "state",
            "required_tier",
            "raise_block_reason",
            "public_title",
            "quarantined_at",
            "quarantine_reason",
        }
        assert "private-only" not in repr(row)
    for filters, expected in (
        ({"source": "archive_alpha"}, [other_id, hidden_id]),
        ({"uuid": "shared"}, [foreign_id, hidden_id]),
        ({"source": "archive_alpha", "uuid": "shared"}, [hidden_id]),
    ):
        result = await search_admin_datasets(db_pool, **filters, configured_sources=selected)
        assert [row.dataset_id for row in result.records] == expected
        assert result.newer_id is None and result.older_id is None
        assert await search_admin_datasets(
            db_pool, after_id=expected[-1], **filters, configured_sources=selected
        ) == DatasetAdminPage([])
    assert await search_admin_datasets(
        db_pool, source="archive_beta", uuid="other", configured_sources=selected
    ) == DatasetAdminPage([])
    assert await search_admin_datasets(
        db_pool, source="orphan_archive", configured_sources=selected
    ) == DatasetAdminPage([])
    assert await get_admin_dataset_by_id(db_pool, other_id + 1, configured_sources=selected) is None


async def test_uuid_search_is_exact_and_does_not_match_metadata(db_pool, dataset_factory):
    """Verify UUID search is exact and does not match metadata."""
    literal = "literal%_\\identity"
    exact_id = dataset_factory(source="archive_alpha", uuid=literal)
    dataset_factory(source="archive_alpha", uuid=f"prefix-{literal}")
    dataset_factory(
        source="archive_alpha",
        uuid="unrelated",
        title="title-needle",
        description="description-needle",
        keywords=["keyword-needle"],
    )
    result = await search_admin_datasets(db_pool, uuid=literal, configured_sources=())
    assert [row.dataset_id for row in result.records] == [exact_id]
    assert result.older_id is None
    for needle in ("literal", "title-needle", "description-needle", "keyword-needle"):
        assert await search_admin_datasets(
            db_pool, uuid=needle, configured_sources=()
        ) == DatasetAdminPage([])


async def test_public_titles_remain_bound_to_nonhidden_source_identities(
    db_pool, sync_conn, dataset_factory
):
    """Verify public titles remain bound to nonhidden source identities."""
    hidden_id = dataset_factory(source="archive_alpha", uuid="shared", title="Hidden title needle")
    visible_id = dataset_factory(
        source="archive_beta",
        uuid="shared",
        title="Public title needle",
        visibility_tier="vetted",
        description="protected description needle",
    )
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, hidden_at) "
        "VALUES ('archive_alpha', 'shared', clock_timestamp())"
    )
    sync_conn.commit()
    result = await search_admin_datasets(db_pool, uuid="shared", configured_sources=())
    records = {record.dataset_id: record for record in result.records}
    assert records[hidden_id].public_title is None
    assert records[visible_id].public_title == "Public title needle"
    assert "protected description needle" not in repr(result)
    for needle in ("Hidden title needle", "Public title needle", "protected description needle"):
        assert await search_admin_datasets(
            db_pool, uuid=needle, configured_sources=()
        ) == DatasetAdminPage([])


@pytest.mark.parametrize(
    ("selection", "stored", "policy", "mandatory", "data", "admin", "minimum", "reason", "choices"),
    [
        ("selected", "public", "vetted", False, None, None, "vetted", None, ("vetted",)),
        (
            "selected",
            "public",
            "public",
            True,
            {"visibility_tier": "registered", "upstream_modified_at": "2026-10-18T00:00:00+00:00"},
            None,
            "registered",
            None,
            ("registered", "vetted"),
        ),
        (
            "selected",
            "public",
            "public",
            True,
            {"visibility_tier": "unknown"},
            None,
            None,
            "invalid_source_tier",
            (),
        ),
        ("selected", "public", "public", True, None, None, None, "invalid_source_tier", ()),
        ("selected", "public", "public", False, {}, "vetted", "vetted", None, ("vetted",)),
        ("selected", "vetted", "public", False, {}, None, "vetted", None, ("vetted",)),
        ("missing", "public", "public", False, {}, None, None, "source_unavailable", ()),
        ("duplicate", "public", "public", False, {}, None, None, "source_configuration", ()),
    ],
)
async def test_list_and_detail_share_the_action_service_policy_floor(
    db_pool,
    sync_conn,
    dataset_factory,
    selection,
    stored,
    policy,
    mandatory,
    data,
    admin,
    minimum,
    reason,
    choices,
):
    """Verify list and detail share the action service policy floor."""
    target_id = dataset_factory(
        source="archive_alpha", uuid="policy-record", visibility_tier=stored, data=Jsonb(data)
    )
    if admin is not None:
        sync_conn.execute(
            "INSERT INTO dataset_admin_state (source, uuid, visibility_tier) "
            "VALUES ('archive_alpha', 'policy-record', %s)",
            (admin,),
        )
        sync_conn.commit()
    configured = fixture_source(
        name="archive_alpha", max_visibility=policy, requires_record_tier=mandatory
    )
    selected = (
        () if selection == "missing" else (configured,) * (2 if selection == "duplicate" else 1)
    )
    detail = await get_admin_dataset_by_id(db_pool, target_id, configured_sources=selected)
    result = await search_admin_datasets(db_pool, configured_sources=selected)
    assert detail is not None and result.records == [detail]
    assert result.older_id is None
    assert detail.required_tier == minimum and detail.raise_block_reason == reason
    assert detail.allowed_raise_tiers == choices


@pytest.mark.parametrize(
    "filters",
    [
        {"uuid": "x" * (ADMIN_DATASET_UUID_MAX_CHARS + 1)},
        {"uuid": "\x00"},
        {"source": "Upper"},
        {"source": "a" * 33},
        {"after_id": 0},
        {"after_id": ADMIN_DATASET_MAX_ID + 1},
        {"after_id": True},
        {"before_id": True},
        {"before_id": -1},
        {"after_id": 1, "before_id": 2},
        {"page_size": 0},
        {"page_size": 101},
        {"page_size": True},
    ],
)
async def test_admin_search_rejects_invalid_bounded_inputs(db_pool, filters):
    """Verify admin search rejects invalid bounded inputs."""
    with pytest.raises(ValueError):
        await search_admin_datasets(db_pool, **filters, configured_sources=())


@pytest.mark.parametrize("dataset_id", [0, -1, True])
async def test_admin_detail_rejects_invalid_ids(db_pool, dataset_id):
    """Verify admin detail rejects invalid IDs."""
    with pytest.raises(ValueError):
        await get_admin_dataset_by_id(db_pool, dataset_id, configured_sources=())


async def test_keyset_continuation_does_not_shift_after_insert_or_boundary_delete(
    db_pool, sync_conn, dataset_factory
):
    """Verify keyset continuation does not shift after insert or boundary delete."""
    ids = [dataset_factory(source="archive_alpha", uuid=f"keyset-{n}") for n in range(5)]
    first = await search_admin_datasets(db_pool, page_size=2, configured_sources=())
    assert [row.dataset_id for row in first.records] == ids[-2:][::-1]
    dataset_factory(source="archive_alpha", uuid="arrived-after-first-page")
    sync_conn.execute("DELETE FROM oral_history_datasets WHERE id = %s", (first.older_id,))
    sync_conn.commit()
    second = await search_admin_datasets(
        db_pool, after_id=first.older_id, page_size=2, configured_sources=()
    )
    assert [row.dataset_id for row in second.records] == [ids[2], ids[1]]
    third = await search_admin_datasets(
        db_pool, after_id=second.older_id, page_size=2, configured_sources=()
    )
    assert [row.dataset_id for row in third.records] == [ids[0]]
    assert third.older_id is None

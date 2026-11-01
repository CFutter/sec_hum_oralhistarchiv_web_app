"""Public ingestion APIs fence old bindings and preserve disclosure policy."""

import hashlib
import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from app.services import ingestion
from app.services.datasets import get_dataset_by_id, search_datasets
from app.services.stored_harvest import encode_stored_harvest
from app.services.sync_state import ensure_source_status_rows
from app.sources import OaiPmhCmdiConfig, configure_sources
from tests.integration.sync_doubles import FETCH, harvest_result, make_record
from tests.oai_fixtures import SOURCE_CURSOR


def source_config(**overrides):
    """Build an OAI mapping source with supplied configuration overrides."""
    values = {
        "name": "mapping_archive",
        "display": {"label": "Mapping archive"},
        "endpoint": "https://archive.example.org/oai",
        "institution_filter": "Example institution",
        "max_visibility": "registered",
        "requires_record_tier": False,
        "field_visibility": {"description": "vetted"},
    }
    values.update(overrides)
    return configure_sources([OaiPmhCmdiConfig.model_validate(values)])[0]


def pre_k1_binding(source):
    """The accepted five-field format; no source code is imported or duplicated."""
    document = {
        "source": source.name,
        "oai_url": source.config.endpoint,
        "institution_filter": source.config.institution_filter,
        "max_visibility": source.policy.max_visibility,
        "requires_record_tier": source.policy.requires_record_tier,
    }
    return hashlib.sha256(
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
async def test_exact_mapping_changes_no_metadata_or_administrator_authority(
    bind_catalogue_policy, db_pool, sync_conn, dataset_factory, runner
):
    """Verify exact mapping changes no metadata or administrator authority."""
    source = source_config()
    bind_catalogue_policy((source,))
    await ensure_source_status_rows(db_pool, (source.name,))
    sync_conn.execute(
        "UPDATE sync_status SET source_fingerprint = %s WHERE source = %s",
        (source.adapter.config_fingerprint(), source.name),
    )
    sync_conn.commit()
    retained_id = dataset_factory(
        source=source.name, uuid="retained-vetted", visibility_tier="vetted", access_level="public"
    )
    hidden_id = dataset_factory(
        source=source.name, uuid="hidden-record", visibility_tier="registered"
    )
    foreign_id = dataset_factory(
        source="other_archive", uuid="retained-vetted", access_level="public"
    )
    sync_conn.execute(
        """INSERT INTO dataset_admin_state (source, uuid, visibility_tier, hidden_at)
           VALUES (%s, 'hidden-record', 'vetted', clock_timestamp())""",
        (source.name,),
    )
    sync_conn.execute(
        """INSERT INTO dataset_admin_state (source, uuid, visibility_tier)
           VALUES (%s, 'administrator-vetted', 'vetted')""",
        (source.name,),
    )
    sync_conn.commit()
    labels = {
        "exact-public": "Public access",
        "local-cc-alias": "License CC BY",
        "retained-vetted": "CC BY 4.0",
        "exact-restricted": "Restricted access",
        "missing-label": None,
        "unknown-label": "Open Access",
        "hidden-record": "Public access",
        "administrator-vetted": "Public access",
    }
    records = [
        make_record(
            uuid,
            title=f"Mapped {uuid}",
            license_val=label,
            description=f"private-{uuid}-description",
            visibility_tier=None if uuid == "retained-vetted" else "public",
        )
        for uuid, label in labels.items()
    ]
    with patch(FETCH, autospec=True, return_value=harvest_result(records)):
        result = await runner(db_pool, configured_source=source)
    assert result.status == "success"
    rows = dict(
        sync_conn.execute(
            "SELECT uuid, access_level FROM oral_history_datasets WHERE source = %s", (source.name,)
        ).fetchall()
    )
    assert rows == {
        "exact-public": "public",
        "local-cc-alias": "public",
        "retained-vetted": "public",
        "exact-restricted": "restricted",
        "missing-label": "restricted",
        "unknown-label": "restricted",
        "hidden-record": "public",
        "administrator-vetted": "public",
    }
    assert sync_conn.execute(
        "SELECT access_level FROM oral_history_datasets WHERE id = %s", (foreign_id,)
    ).fetchone() == ("public",)
    assert sync_conn.execute(
        "SELECT visibility_tier FROM oral_history_datasets WHERE id = %s", (retained_id,)
    ).fetchone() == ("vetted",)
    identifiers = dict(
        sync_conn.execute(
            "SELECT uuid, id FROM oral_history_datasets WHERE source = %s", (source.name,)
        ).fetchall()
    )
    for tier in ("public", "registered", "vetted"):
        assert (
            await get_dataset_by_id(db_pool, hidden_id, tier, configured_sources=(source,)) is None
        )
    public = await get_dataset_by_id(
        db_pool, identifiers["exact-public"], "public", configured_sources=(source,)
    )
    registered = await get_dataset_by_id(
        db_pool, identifiers["exact-public"], "registered", configured_sources=(source,)
    )
    vetted = await get_dataset_by_id(
        db_pool, identifiers["exact-public"], "vetted", configured_sources=(source,)
    )
    assert public.access_level == registered.access_level == vetted.access_level == "public"
    assert (
        public.visibility_tier
        == registered.visibility_tier
        == vetted.visibility_tier
        == "registered"
    )
    assert public.description is None and registered.description is None
    assert vetted.description == "private-exact-public-description"
    admin_floor = await get_dataset_by_id(
        db_pool, identifiers["administrator-vetted"], "registered", configured_sources=(source,)
    )
    assert admin_floor.visibility_tier == "vetted" and admin_floor.description is None
    private_results, private_count = await search_datasets(
        db_pool,
        "registered",
        search_text="private-exact-public-description",
        configured_sources=(source,),
    )
    assert private_count == 0 and private_results == []


@pytest.mark.parametrize("with_staged", [False, True])
async def test_old_access_binding_requires_rebuild_before_cursor_or_staged_reuse(
    db_pool, sync_conn, dataset_factory, with_staged, approve_source_rebinding
):
    """Verify old access binding requires rebuild before cursor or staged reuse."""
    source = source_config()
    await ensure_source_status_rows(db_pool, (source.name,))
    old_binding = pre_k1_binding(source)
    assert old_binding != source.adapter.config_fingerprint()
    record = make_record(
        "unknown-before-k1",
        title="Unchanged public title",
        license_val="Open Access",
        visibility_tier="public",
    )
    dataset_id = dataset_factory(
        source=source.name, uuid=record["uuid"], access_level="public", visibility_tier="registered"
    )
    old_stage = (
        encode_stored_harvest(harvest_result([record]), source_fingerprint=old_binding)
        if with_staged
        else None
    )
    sync_conn.execute(
        """UPDATE sync_status SET source_fingerprint = %s, source_cursor = %s,
                  incremental_harvest = %s, incremental_started_at = %s,
                  incremental_position = 0, incremental_affected = 0
           WHERE source = %s""",
        (
            old_binding,
            SOURCE_CURSOR,
            old_stage,
            datetime(2026, 9, 10, tzinfo=UTC) if with_staged else None,
            source.name,
        ),
    )
    sync_conn.commit()
    with patch(FETCH, autospec=True) as fetch:
        result = await ingestion.run_sync(db_pool, configured_source=source)
    assert result.status == "failed" and result.requires_source_acknowledgement
    fetch.assert_not_called()
    assert sync_conn.execute(
        "SELECT access_level FROM oral_history_datasets WHERE id = %s", (dataset_id,)
    ).fetchone() == ("public",)
    assert sync_conn.execute(
        "SELECT source_fingerprint, source_cursor, incremental_harvest FROM sync_status WHERE source = %s",
        (source.name,),
    ).fetchone() == (old_binding, SOURCE_CURSOR, old_stage)
    approve_source_rebinding(source)
    with patch(FETCH, autospec=True, return_value=harvest_result([record])):
        rebuilt = await ingestion.run_full_rebuild(db_pool, configured_source=source)
    assert rebuilt.status == "success"
    assert sync_conn.execute(
        "SELECT access_level, visibility_tier FROM oral_history_datasets WHERE id = %s",
        (dataset_id,),
    ).fetchone() == ("restricted", "registered")
    assert sync_conn.execute(
        "SELECT source_fingerprint, incremental_harvest FROM sync_status WHERE source = %s",
        (source.name,),
    ).fetchone() == (source.adapter.config_fingerprint(), None)

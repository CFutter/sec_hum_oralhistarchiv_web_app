"""Administrative visibility restrictions survive both synchronization paths."""

from collections.abc import Awaitable, Callable
from dataclasses import asdict
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from psycopg import Connection
from psycopg_pool import AsyncConnectionPool

from app.services import ingestion
from app.services.datasets import (
    PUBLIC_DISCOVERY_FIELDS,
    get_dataset_by_id,
    search_datasets,
)
from app.sources import ConfiguredSource
from tests.integration.sync_doubles import FETCH, harvest_result, make_record
from tests.source_fixtures import fixture_source, legacy_source


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
@pytest.mark.parametrize("include_null", [False, True], ids=["omitted", "null"])
async def test_required_record_tiers_preserve_rejected_rows_and_progress(
    db_pool: AsyncConnectionPool,
    sync_conn: Connection[tuple[Any, ...]],
    dataset_factory: Callable[..., int],
    runner: Callable[..., Awaitable[ingestion.SyncOutcome]],
    include_null: bool,
    sync_source: ConfiguredSource,
) -> None:
    """Both runners preserve rejected rows while committing valid neighbours."""
    configured_source = fixture_source(
        name=sync_source.name,
        max_visibility="registered",
        requires_record_tier=True,
    )
    policy = configured_source.policy
    sync_conn.execute(
        "UPDATE sync_status SET source_fingerprint = %s WHERE source = %s",
        (configured_source.adapter.config_fingerprint(), configured_source.name),
    )
    sync_conn.commit()
    existing_uuid = "tier-existing"
    new_uuid = "tier-new"
    existing_id = dataset_factory(
        source=policy.name,
        uuid=existing_uuid,
        title="Last accepted title",
        visibility_tier="vetted",
    )
    foreign_id = dataset_factory(
        source="other_archive",
        uuid=existing_uuid,
        title="Other source title",
        visibility_tier="public",
    )
    status_query = """SELECT last_harvest_date, last_full_rebuild_date,
                             source_cursor, source_fingerprint
                      FROM sync_status WHERE source = %s"""
    before = sync_conn.execute(status_query, (configured_source.name,)).fetchone()
    assert before is not None
    sync_conn.commit()

    rejected = [
        make_record(existing_uuid, title="Rejected replacement", visibility_tier=None),
        make_record(new_uuid, title="Rejected new record", visibility_tier=None),
    ]
    if not include_null:
        for record in rejected:
            record.pop("visibility_tier")
    accepted = [
        make_record("tier-public", visibility_tier="public"),
        make_record("tier-vetted", visibility_tier="vetted"),
    ]
    with patch.object(
        type(configured_source.adapter),
        "fetch",
        autospec=True,
        return_value=harvest_result([*rejected, *accepted]),
    ):
        outcome = await runner(db_pool, configured_source=configured_source)

    assert (outcome.status, outcome.affected_count, outcome.failed_count) == ("partial", 2, 2)
    assert sync_conn.execute(
        "SELECT title, visibility_tier FROM oral_history_datasets WHERE id = %s",
        (existing_id,),
    ).fetchone() == ("Last accepted title", "vetted")
    assert (
        sync_conn.execute(
            "SELECT id FROM oral_history_datasets WHERE source = %s AND uuid = %s",
            (policy.name, new_uuid),
        ).fetchone()
        is None
    )
    assert sync_conn.execute(
        "SELECT title, visibility_tier FROM oral_history_datasets WHERE id = %s",
        (foreign_id,),
    ).fetchone() == ("Other source title", "public")
    assert dict(
        sync_conn.execute(
            "SELECT uuid, visibility_tier FROM oral_history_datasets "
            "WHERE source = %s AND uuid = ANY(%s)",
            (policy.name, [record["uuid"] for record in accepted]),
        ).fetchall()
    ) == {"tier-public": "registered", "tier-vetted": "vetted"}
    failures = dict(
        sync_conn.execute(
            "SELECT uuid, message FROM ingestion_failures WHERE source = %s",
            (policy.name,),
        ).fetchall()
    )
    assert set(failures) == {existing_uuid, new_uuid}
    assert all("missing required visibility_tier" in message for message in failures.values())
    assert sync_conn.execute(status_query, (configured_source.name,)).fetchone() == before


@pytest.mark.parametrize("runner", [ingestion._sync_source, ingestion.run_full_rebuild])
@pytest.mark.parametrize(
    ("stored_tier", "incoming_tier", "expected_tier"),
    [
        ("public", "public", "public"),
        ("public", "registered", "registered"),
        ("public", "vetted", "vetted"),
        ("registered", "public", "public"),
        ("registered", "registered", "registered"),
        ("registered", "vetted", "vetted"),
        ("vetted", "public", "public"),
        ("vetted", "registered", "registered"),
        ("vetted", "vetted", "vetted"),
    ],
)
async def test_sync_applies_explicit_upstream_visibility_corrections(
    db_pool,
    sync_conn,
    dataset_factory,
    runner,
    stored_tier,
    incoming_tier,
    expected_tier,
    sync_source: ConfiguredSource,
):
    """Apply fresh assertions while preserving source isolation and identity."""
    configured_source = legacy_source(name=sync_source.name, max_visibility="public")
    sync_conn.execute(
        "UPDATE sync_status SET source_fingerprint = %s WHERE source = %s",
        (configured_source.adapter.config_fingerprint(), configured_source.name),
    )
    sync_conn.commit()
    uuid = "oai:test:admin-visibility"
    neighbour = make_record("oai:test:other-visibility")
    with patch(FETCH, autospec=True, return_value=harvest_result([make_record(uuid), neighbour])):
        await ingestion._sync_source(db_pool, configured_source=configured_source)
    dataset_id = sync_conn.execute(
        "SELECT id FROM oral_history_datasets WHERE source = %s AND uuid = %s",
        (configured_source.name, uuid),
    ).fetchone()[0]
    sync_conn.execute(
        "UPDATE oral_history_datasets SET visibility_tier = %s WHERE id = %s",
        (stored_tier, dataset_id),
    )
    sync_conn.commit()
    foreign_id = dataset_factory(uuid=uuid, source="mock", visibility_tier="vetted")

    updated = make_record(uuid, title="Updated source title", visibility_tier=incoming_tier)
    with patch(FETCH, autospec=True, return_value=harvest_result([updated, neighbour])):
        outcome = await runner(db_pool, configured_source=configured_source)
    assert outcome.status == "success"
    assert sync_conn.execute(
        "SELECT id, title, visibility_tier FROM oral_history_datasets "
        "WHERE source = %s AND uuid = %s",
        (configured_source.name, uuid),
    ).fetchone() == (dataset_id, "Updated source title", expected_tier)
    assert sync_conn.execute(
        "SELECT visibility_tier FROM oral_history_datasets WHERE id = %s", (foreign_id,)
    ).fetchone() == ("vetted",)
    assert sync_conn.execute(
        "SELECT visibility_tier FROM oral_history_datasets WHERE source = %s AND uuid = %s",
        (configured_source.name, neighbour["uuid"]),
    ).fetchone() == ("public",)


async def _assert_anonymous_redaction(
    db_pool: AsyncConnectionPool,
    client: TestClient,
    dataset_id: int,
    title: str,
    marker: str,
    *,
    configured_source: ConfiguredSource,
) -> None:
    """Check complete service redaction and actual anonymous HTTP responses."""
    sources = (configured_source,)

    full = await get_dataset_by_id(
        db_pool,
        dataset_id,
        "vetted",
        configured_sources=sources,
    )
    assert full is not None
    assert full.visibility_tier == "vetted"

    private_values = {
        name: value for name, value in asdict(full).items() if name not in PUBLIC_DISCOVERY_FIELDS
    }
    assert all(private_values.values())

    anonymous = await get_dataset_by_id(
        db_pool,
        dataset_id,
        "public",
        configured_sources=sources,
    )
    results, count = await search_datasets(
        db_pool,
        "public",
        search_text=title,
        configured_sources=sources,
    )
    assert anonymous is not None
    assert count == 1
    assert len(results) == 1
    for dataset in (anonymous, results[0]):
        assert dataset.title == title
        assert dataset.visibility_tier == "vetted"
        assert all(asdict(dataset)[name] in (None, []) for name in private_values)

    for url, params in [(f"/dataset/{dataset_id}", {}), ("/search", {"q": title})]:
        response = client.get(url, params=params)
        assert response.status_code == 200
        assert title in response.text
        assert marker not in response.text
    hidden_search = client.get("/search", params={"q": marker})
    assert hidden_search.status_code == 200
    assert hidden_search.context["result_count"] is None
    assert hidden_search.context["results"] == []
    assert "No datasets found." in hidden_search.text
    assert title not in hidden_search.text


async def test_administrative_visibility_survives_sync_and_anonymous_responses(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    e2e_client,
    monkeypatch,
    sync_source: ConfiguredSource,
):
    """Keep an administrator's vetted tier through updates and rebuilds."""
    configured_source = legacy_source(name=sync_source.name, max_visibility="public")
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (configured_source,))
    sync_conn.execute(
        "UPDATE sync_status SET source_fingerprint = %s WHERE source = %s",
        (configured_source.adapter.config_fingerprint(), configured_source.name),
    )
    sync_conn.commit()
    uuid = "oai:test:restricted-visibility"
    marker = "h01private"
    record = make_record(
        uuid,
        title="Public discovery title",
        project_title=f"{marker} project",
        description=f"{marker} description",
        resource_description=f"{marker} resource description",
        project_description=f"{marker} project description",
        authors=[f"{marker} author"],
        keywords=[f"{marker} keyword"],
        languages=[f"{marker} language"],
        resource_proxies=[
            {"type": "Resource", "ref": f"https://example.org/{marker}/resource"},
            {"type": "LandingPage", "ref": f"https://example.org/{marker}/landing"},
        ],
        license_val=f"{marker} licence",
        license_url=f"https://example.org/{marker}/licence",
        doi=f"10.1234/{marker}",
        resource_type=f"{marker} audio",
        bibliographical_citation=f"{marker} citation",
    )
    with patch(FETCH, autospec=True, return_value=harvest_result([record])):
        await ingestion._sync_source(db_pool, configured_source=configured_source)
    dataset_id, tier = sync_conn.execute(
        "SELECT id, visibility_tier FROM oral_history_datasets WHERE source = %s AND uuid = %s",
        (configured_source.name, uuid),
    ).fetchone()
    assert tier == "public"
    response = e2e_client.get(f"/dataset/{dataset_id}")
    assert response.status_code == 200
    assert marker in response.text

    sync_conn.execute(
        "UPDATE oral_history_datasets SET visibility_tier = 'vetted' WHERE id = %s",
        (dataset_id,),
    )
    sync_conn.commit()
    await _assert_anonymous_redaction(
        db_pool,
        e2e_client,
        dataset_id,
        record["title"],
        marker,
        configured_source=configured_source,
    )

    for runner, title in [
        (ingestion._sync_source, "Updated discovery title"),
        (ingestion.run_full_rebuild, "Rebuilt discovery title"),
    ]:
        record = {**record, "title": title}
        with patch(FETCH, autospec=True, return_value=harvest_result([record])):
            outcome = await runner(db_pool, configured_source=configured_source)
        assert outcome.status == "success"
        await _assert_anonymous_redaction(
            db_pool,
            e2e_client,
            dataset_id,
            title,
            marker,
            configured_source=configured_source,
        )

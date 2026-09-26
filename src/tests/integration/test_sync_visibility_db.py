"""Administrative visibility restrictions survive both synchronization paths."""

from dataclasses import asdict, replace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from psycopg_pool import AsyncConnectionPool

from app.services import sync
from app.services.datasets import (
    PUBLIC_DISCOVERY_FIELDS,
    get_dataset_by_id,
    search_datasets,
)
from tests.integration.sync_doubles import FETCH, harvest_result, make_record


@pytest.mark.parametrize("runner", [sync._sync_source_a, sync.run_full_rebuild])
@pytest.mark.parametrize(
    ("stored_tier", "incoming_tier", "expected_tier"),
    [
        ("public", "public", "public"),
        ("public", "registered", "registered"),
        ("public", "vetted", "vetted"),
        ("registered", "public", "registered"),
        ("registered", "registered", "registered"),
        ("registered", "vetted", "vetted"),
        ("vetted", "public", "vetted"),
        ("vetted", "registered", "vetted"),
        ("vetted", "vetted", "vetted"),
    ],
)
async def test_sync_keeps_the_stricter_visibility(
    db_pool,
    sync_conn,
    dataset_factory,
    monkeypatch,
    runner,
    stored_tier,
    incoming_tier,
    expected_tier,
):
    """Preserve restrictions by source and UUID while refreshing source fields."""
    monkeypatch.setattr(
        sync, "_SWISSUBASE_POLICY", replace(sync._SWISSUBASE_POLICY, max_visibility="public")
    )
    uuid = "oai:test:admin-visibility"
    neighbour = make_record("oai:test:other-visibility")
    with patch(FETCH, autospec=True, return_value=harvest_result([make_record(uuid), neighbour])):
        await sync._sync_source_a(db_pool)
    dataset_id = sync_conn.execute(
        "SELECT id FROM oral_history_datasets WHERE source = 'swissubase' AND uuid = %s",
        (uuid,),
    ).fetchone()[0]
    sync_conn.execute(
        "UPDATE oral_history_datasets SET visibility_tier = %s WHERE id = %s",
        (stored_tier, dataset_id),
    )
    sync_conn.commit()
    foreign_id = dataset_factory(uuid=uuid, source="mock", visibility_tier="vetted")

    updated = make_record(uuid, title="Updated source title", visibility_tier=incoming_tier)
    with patch(FETCH, autospec=True, return_value=harvest_result([updated, neighbour])):
        outcome = await runner(db_pool)
    assert outcome.status == "success"
    assert sync_conn.execute(
        "SELECT id, title, visibility_tier FROM oral_history_datasets "
        "WHERE source = 'swissubase' AND uuid = %s",
        (uuid,),
    ).fetchone() == (dataset_id, "Updated source title", expected_tier)
    assert sync_conn.execute(
        "SELECT visibility_tier FROM oral_history_datasets WHERE id = %s", (foreign_id,)
    ).fetchone() == ("vetted",)
    assert sync_conn.execute(
        "SELECT visibility_tier FROM oral_history_datasets "
        "WHERE source = 'swissubase' AND uuid = %s",
        (neighbour["uuid"],),
    ).fetchone() == ("public",)


async def _assert_anonymous_redaction(
    db_pool: AsyncConnectionPool,
    client: TestClient,
    dataset_id: int,
    title: str,
    marker: str,
) -> None:
    """Check complete service redaction and actual anonymous HTTP responses."""
    full = await get_dataset_by_id(db_pool, dataset_id, "vetted")
    assert full is not None
    assert full.visibility_tier == "vetted"
    private_values = {
        name: value for name, value in asdict(full).items() if name not in PUBLIC_DISCOVERY_FIELDS
    }
    assert all(private_values.values())
    anonymous = await get_dataset_by_id(db_pool, dataset_id, "public")
    results, count = await search_datasets(db_pool, "public", search_text=title)
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
    assert "0 datasets found" in hidden_search.text
    assert title not in hidden_search.text


async def test_administrative_visibility_survives_sync_and_anonymous_responses(
    db_pool,
    sync_conn,
    e2e_client,
    monkeypatch,
):
    """Keep an administrator's vetted tier before and after update and rebuild."""
    monkeypatch.setattr(
        sync, "_SWISSUBASE_POLICY", replace(sync._SWISSUBASE_POLICY, max_visibility="public")
    )
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
        await sync._sync_source_a(db_pool)
    dataset_id, tier = sync_conn.execute(
        "SELECT id, visibility_tier FROM oral_history_datasets "
        "WHERE source = 'swissubase' AND uuid = %s",
        (uuid,),
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
    await _assert_anonymous_redaction(db_pool, e2e_client, dataset_id, record["title"], marker)

    for runner, title in [
        (sync._sync_source_a, "Updated discovery title"),
        (sync.run_full_rebuild, "Rebuilt discovery title"),
    ]:
        record = {**record, "title": title}
        with patch(FETCH, autospec=True, return_value=harvest_result([record])):
            outcome = await runner(db_pool)
        assert outcome.status == "success"
        await _assert_anonymous_redaction(db_pool, e2e_client, dataset_id, title, marker)

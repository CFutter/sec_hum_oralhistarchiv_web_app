"""Rendered facet options retain viewer permissions and contributor audit coverage."""

import logging

import pytest
from lxml import html

from app.services.datasets import get_facets
from app.services.totp_crypto import encrypt_value
from config import settings
from tests.fixtures import sign_session_id
from tests.source_fixtures import fixture_source


@pytest.mark.parametrize("viewer", ["public", "registered", "vetted"])
async def test_authorized_suggestions_audit_only_the_records_and_fields_displayed(
    db_pool,
    dataset_factory,
    e2e_client,
    user_factory,
    session_factory,
    replace_bound_catalogue_sources,
    monkeypatch,
    caplog,
    viewer,
):
    """Verify authorized suggestions audit only the records and fields displayed."""
    source = fixture_source(
        name="facet_archive",
        max_visibility="public",
        field_visibility={"keywords": "registered", "languages": "vetted"},
    )
    policy = replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    ids = {
        tier: dataset_factory(
            source=source.name,
            uuid=f"facet-{tier}",
            visibility_tier=tier,
            keywords=[f"private-{tier}-keyword"] * 2 + [f"unlisted-{tier}-singleton"],
            languages=[f"private-{tier}-language"],
        )
        for tier in ("public", "registered", "vetted")
    }
    contributors = []
    expected = await get_facets(
        db_pool, viewer, configured_sources=policy, disclosures=contributors
    )
    if viewer != "public":
        user = user_factory(access_tier=viewer, totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"))
        e2e_client.cookies.set(
            settings.session_cookie_name, sign_session_id(session_factory(user.id))
        )
    logger = logging.getLogger("audit")
    monkeypatch.setattr(logger, "handlers", [caplog.handler])
    monkeypatch.setattr(logger, "propagate", False)
    caplog.set_level(logging.INFO, logger="audit")
    response = e2e_client.get("/search")
    assert response.status_code == 200
    assert response.context["all_keywords"] == expected["keywords"]
    assert response.context["all_languages"] == expected["languages"]
    events = [event for event in caplog.records if getattr(event, "view", None) == "facets"]
    observed = [record for event in events for record in event.disclosures]
    assert {record["dataset_id"]: record["fields"] for record in observed} == {
        record.dataset_id: list(record.fields) for record in contributors
    }
    expected_ids = (
        set()
        if viewer == "public"
        else {ids["public"], ids["registered"], *([ids["vetted"]] if viewer == "vetted" else [])}
    )
    assert {record["dataset_id"] for record in observed} == expected_ids
    assert all(
        record["fields"] == (["keywords", "languages"] if viewer == "vetted" else ["keywords"])
        for record in observed
    )
    assert "private-" not in repr([vars(event) for event in events])
    options = html.fromstring(response.text).xpath("//datalist/option/@value")
    assert not any("unlisted-" in value for value in options)


async def test_unlisted_keyword_contributors_do_not_create_disclosure_records(
    db_pool,
    dataset_factory,
    bind_catalogue_policy,
):
    """Verify unlisted keyword contributors do not create disclosure records."""
    policy = bind_catalogue_policy((fixture_source(name="facet_archive", max_visibility="public"),))
    dataset_factory(
        source="facet_archive",
        uuid="only-singleton",
        visibility_tier="registered",
        keywords=["not-offered"],
    )
    contributors = []
    assert (
        await get_facets(db_pool, "registered", configured_sources=policy, disclosures=contributors)
    )["keywords"] == []
    assert contributors == []


@pytest.mark.parametrize("distinct_options", [False, True])
async def test_facet_audit_obeys_the_sample_and_displayed_option_limits(
    db_pool,
    sync_conn,
    bind_catalogue_policy,
    distinct_options,
):
    """Verify facet audit obeys the sample and displayed option limits."""
    policy = bind_catalogue_policy((fixture_source(name="facet_archive", max_visibility="public"),))
    sync_conn.execute(
        """INSERT INTO oral_history_datasets
               (source, uuid, title, visibility_tier, keywords, languages)
           SELECT 'facet_archive', 'bounded-' || number::text, 'Public title', 'registered',
                  ARRAY[label, label], ARRAY[label]
           FROM generate_series(1, 201) AS number
           CROSS JOIN LATERAL (
               SELECT CASE WHEN %s THEN lpad(number::text, 3, '0') ELSE 'shared' END AS label
           ) AS options""",
        (distinct_options,),
    )
    first_id = sync_conn.execute("SELECT min(id) FROM oral_history_datasets").fetchone()[0]
    sync_conn.commit()
    contributors = []
    options = await get_facets(
        db_pool, "registered", configured_sources=policy, disclosures=contributors
    )
    assert len(contributors) == (50 if distinct_options else 200)
    assert first_id not in {record.dataset_id for record in contributors}
    assert all(record.fields == ("keywords", "languages") for record in contributors)
    assert len(options["keywords"]) == len(options["languages"]) == (50 if distinct_options else 1)

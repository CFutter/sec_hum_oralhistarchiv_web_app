"""Actual page rendering audits permitted protected fields on public records."""

import logging
from contextlib import ExitStack
from unittest.mock import patch

import pytest

from app.services.datasets import Dataset, SearchPage, filter_for_tier
from tests.fixtures import make_sample_user, replace_test_catalogue_sources
from tests.source_fixtures import fixture_source


@pytest.mark.parametrize(
    "path,view",
    [
        ("/", "home"),
        ("/search?q=private-query-canary&keyword=filter-canary", "search"),
        ("/dataset/7", "detail"),
    ],
)
def test_rendered_public_record_with_protected_fields_has_a_value_free_event(
    monkeypatch, caplog, client_builder, path, view
):
    """Check rendered public record with protected fields has a value free event (HTTP 200)."""
    source = fixture_source(
        name="disclosure_archive",
        max_visibility="public",
        field_visibility={"description": "registered", "keywords": "vetted"},
    )
    client = client_builder(session_user=make_sample_user(access_tier="registered"))
    policy = replace_test_catalogue_sources(monkeypatch, client.app, (source,))
    record = filter_for_tier(
        Dataset(
            id=7,
            uuid="stable-identity",
            title="public title",
            source=source.name,
            visibility_tier="public",
            description="permitted-description-canary",
            keywords=["forbidden-keyword-canary"],
        ),
        "registered",
        configured_sources=policy,
    )
    logger = logging.getLogger("audit")
    monkeypatch.setattr(logger, "handlers", [caplog.handler])
    monkeypatch.setattr(logger, "propagate", False)
    caplog.set_level(logging.INFO, logger="audit")
    with ExitStack() as stack:
        for target, value in (
            ("get_recent_datasets", [record]),
            ("get_dataset_by_id", record),
            ("search_catalogue_page", SearchPage([record], None, 1)),
            ("get_facets", {}),
        ):
            stack.enter_context(
                patch(f"app.routes.pages.{target}", autospec=True, return_value=value)
            )
        response = client.get(path)
    assert response.status_code == 200
    assert "permitted-description-canary" in response.text
    assert "forbidden-keyword-canary" not in response.text
    events = [
        event
        for event in caplog.records
        if getattr(event, "event_type", None) == "metadata_disclosure"
    ]
    assert len(events) == 1 and events[0].view == view
    assert events[0].disclosures == [
        {
            "dataset_id": 7,
            "source": source.name,
            "uuid": "stable-identity",
            "fields": ["description"],
            "denied_fields": ["keywords"],
            "outcome": "partial",
        }
    ]
    assert "canary" not in repr(vars(events[0]))

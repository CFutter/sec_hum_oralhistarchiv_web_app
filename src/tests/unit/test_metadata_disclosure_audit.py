"""Field protection, actual view coverage and metadata-free bounded events."""

import io
import json
import logging
from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest
from starlette.requests import Request

from app.services import audit as event_audit
from app.services import disclosure_audit as audit
from app.services.datasets import (
    Author,
    Dataset,
    FacetDisclosure,
    build_catalogue_policy,
    filter_for_tier,
)
from config import logging as log_config
from tests.source_fixtures import fixture_source


def _dataset(**changes):
    """Build a public dataset with private metadata canaries and caller field overrides."""
    values = {
        "id": 7,
        "uuid": "stable-identity",
        "source": "archive",
        "title": "public discovery",
        "visibility_tier": "public",
        "description": "private-description-canary",
        "authors": [Author("private-author-canary")],
        "keywords": ["private-keyword-canary"],
        "languages": ["private-language-canary"],
        "project_title": "private-project-canary",
    }
    return Dataset(**(values | changes))


def _policy():
    """Build the disclosure policy that restricts sample private metadata fields."""
    return build_catalogue_policy(
        (
            fixture_source(
                name="archive",
                max_visibility="public",
                field_visibility={
                    "description": "registered",
                    "authors": "registered",
                    "keywords": "vetted",
                    "languages": "registered",
                    "project_title": "registered",
                },
            ),
        )
    )


def _capture(monkeypatch):
    """Capture audit-event arguments through a signature-checked replacement."""
    events = []
    monkeypatch.setattr(
        audit,
        "audit_user_event",
        create_autospec(
            audit.audit_user_event,
            spec_set=True,
            side_effect=lambda *args, **kwargs: events.append((args, kwargs)),
        ),
    )
    return events


@pytest.mark.parametrize("view", ["detail", "home", "search"])
def test_public_record_stricter_fields_are_audited_without_metadata_or_query(monkeypatch, view):
    """Check public record stricter fields are audited without metadata or query."""
    events = _capture(monkeypatch)
    policy = _policy()
    request = SimpleNamespace(state=SimpleNamespace(user=SimpleNamespace(id=19)))
    record = filter_for_tier(_dataset(), "registered", configured_sources=policy)
    audit.audit_metadata_disclosures(
        request, [record], user_tier="registered", configured_sources=policy, view=view
    )
    fields = events[0][1]["disclosures"][0]
    assert fields["dataset_id"] == 7
    assert set(fields["fields"]) == {"authors", "description", "languages"} | (
        {"project_title"} if view == "detail" else set()
    )
    assert fields["denied_fields"] == ["keywords"]
    assert fields["outcome"] == "partial"
    assert "canary" not in repr(events)
    assert events[0][0][3] == 19


def test_empty_protected_values_are_not_claimed_as_disclosed(monkeypatch):
    """Check empty protected values are not claimed as disclosed."""
    events = _capture(monkeypatch)
    audit.audit_metadata_disclosures(
        SimpleNamespace(state=SimpleNamespace(user=None)),
        [_dataset(description=None, authors=[], keywords=[], languages=[], project_title=None)],
        user_tier="vetted",
        configured_sources=_policy(),
        view="detail",
    )
    assert events == []


def test_facet_contributors_are_bounded_batched_and_contain_no_option_values(monkeypatch):
    """Check facet contributors are bounded batched and contain no option values (ValueError)."""
    events = _capture(monkeypatch)
    request = SimpleNamespace(state=SimpleNamespace(user=SimpleNamespace(id=19)))
    records = [
        FacetDisclosure(index, "archive", f"identity-{index}", ("keywords", "languages"))
        for index in range(200)
    ]
    audit.audit_facet_disclosures(request, records, user_tier="vetted")
    assert len(events) == 40
    assert all(
        event[1]["view"] == "facets" and len(event[1]["disclosures"]) == 5 for event in events
    )
    assert {row["dataset_id"] for event in events for row in event[1]["disclosures"]} == set(
        range(200)
    )
    with pytest.raises(ValueError, match="record bound"):
        audit.audit_facet_disclosures(request, records + records[:1], user_tier="vetted")
    with pytest.raises(ValueError, match="field"):
        audit.audit_facet_disclosures(
            request,
            [FacetDisclosure(7, "archive", "identity", ("private-value-canary",))],
            user_tier="vetted",
        )
    assert "canary" not in repr(events)


def test_card_keyword_mask_counts_only_the_rendered_slice(monkeypatch):
    """Check card keyword mask counts only the rendered slice."""
    events = _capture(monkeypatch)
    audit.audit_metadata_disclosures(
        SimpleNamespace(state=SimpleNamespace(user=None)),
        [_dataset(description=None, authors=[], languages=[], keywords=["", "", "", "", "later"])],
        user_tier="vetted",
        configured_sources=_policy(),
        view="home",
    )
    assert events == []


def test_public_only_data_produces_no_protected_disclosure_event(monkeypatch):
    """Check public only data produces no protected disclosure event."""
    events = _capture(monkeypatch)
    policy = build_catalogue_policy((fixture_source(name="archive", max_visibility="public"),))
    audit.audit_metadata_disclosures(
        SimpleNamespace(state=SimpleNamespace(user=None)),
        [_dataset()],
        user_tier="public",
        configured_sources=policy,
        view="detail",
    )
    assert events == []


def test_result_auditing_is_bounded_and_has_no_metadata_values(monkeypatch):
    """Check result auditing is bounded and has no metadata values (ValueError)."""
    events = _capture(monkeypatch)
    request = SimpleNamespace(state=SimpleNamespace(user=SimpleNamespace(id=19)))
    audit.audit_metadata_disclosures(
        request,
        [_dataset(id=index) for index in range(1, 101)],
        user_tier="vetted",
        configured_sources=_policy(),
        view="search",
    )
    assert len(events) == 20
    assert all(len(event[1]["disclosures"]) == 5 for event in events)
    assert "canary" not in repr(events)
    with pytest.raises(ValueError, match="record bound"):
        audit.audit_metadata_disclosures(
            request,
            [_dataset()] * 101,
            user_tier="vetted",
            configured_sources=_policy(),
            view="search",
        )


@pytest.mark.parametrize("exposed", [False, True])
def test_detail_records_resource_fields_only_when_the_upstream_target_is_exposed(
    monkeypatch, exposed
):
    """Check detail records resource fields only when the upstream target is exposed."""
    events = _capture(monkeypatch)
    policy = build_catalogue_policy(
        (
            fixture_source(
                name="archive",
                max_visibility="public",
                field_visibility={
                    "resource_proxies": "registered",
                    "resource_access_url": "registered",
                    "landing_page_url": "registered",
                },
            ),
        )
    )
    audit.audit_metadata_disclosures(
        SimpleNamespace(state=SimpleNamespace(user=SimpleNamespace(id=19))),
        [
            _dataset(
                resource_proxies=[{"type": "Resource", "ref": "https://upstream.example/private"}]
            )
        ],
        user_tier="registered",
        configured_sources=policy,
        view="detail",
        resource_exposed=exposed,
    )
    assert bool(events) is exposed
    if exposed:
        assert events[0][1]["disclosures"][0]["fields"] == ["resource_proxies"]
        assert "upstream.example" not in repr(events)


def test_rejected_license_target_is_not_claimed_as_a_disclosed_value(monkeypatch):
    """Check rejected license target is not claimed as a disclosed value."""
    events = _capture(monkeypatch)
    policy = build_catalogue_policy(
        (
            fixture_source(
                name="archive",
                max_visibility="public",
                field_visibility={"license_url": "registered"},
            ),
        )
    )
    audit.audit_metadata_disclosures(
        SimpleNamespace(state=SimpleNamespace(user=SimpleNamespace(id=19))),
        [
            _dataset(
                description=None,
                authors=[],
                keywords=[],
                languages=[],
                project_title=None,
                license_url="javascript:private-url-canary",
            )
        ],
        user_tier="registered",
        configured_sources=policy,
        view="detail",
    )
    assert events == []


def test_maximum_full_field_batches_survive_the_complete_audit_formatter(monkeypatch):
    """Check maximum full field batches survive the complete audit formatter."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(log_config.JSONFormatter(audit=True))
    handler.addFilter(log_config._audit_redactor)
    logger = logging.getLogger("audit.maximum-disclosure-test")
    logger.setLevel(logging.INFO)
    monkeypatch.setattr(event_audit, "audit_logger", logger)
    monkeypatch.setattr(logger, "handlers", [handler])
    monkeypatch.setattr(logger, "filters", [log_config._audit_email_autohash])
    monkeypatch.setattr(logger, "level", logging.INFO)
    monkeypatch.setattr(logger, "propagate", False)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/dataset/7",
            "client": ("127.0.0.1", 12345),
            "headers": [],
        }
    )
    request.state.user = SimpleNamespace(id=19)
    request.state.request_id = "maximum-disclosure-fields"
    policy = build_catalogue_policy((fixture_source(name="archive", max_visibility="vetted"),))
    records = [
        _dataset(
            id=index,
            uuid=f"{index:03d}-" + "u" * 508,
            resource_description="resource-description-canary",
            project_description="project-description-canary",
            bibliographical_citation="citation-canary",
            resource_type="resource-type-canary",
            doi="10.1234/private-doi-canary",
            license_val="private-license-canary",
            license_url="https://upstream.example/private-license-canary",
            resource_proxies=[{"type": "Resource", "ref": "https://upstream.example/private"}],
        )
        for index in range(1, 101)
    ]
    audit.audit_metadata_disclosures(
        request,
        records,
        user_tier="vetted",
        configured_sources=policy,
        view="detail",
        resource_exposed=True,
    )
    output = stream.getvalue()
    batches = [json.loads(line)["disclosures"] for line in output.splitlines()]
    assert len(batches) == 20 and all(len(batch) == 5 for batch in batches)
    descriptions = [description for batch in batches for description in batch]
    assert {description["dataset_id"] for description in descriptions} == set(range(1, 101))
    expected_fields = sorted((*audit._DETAIL_FIELDS, "resource_proxies"))
    assert all(description["fields"] == expected_fields for description in descriptions)
    assert all(description["denied_fields"] == [] for description in descriptions)
    assert all(description["outcome"] == "full" for description in descriptions)
    assert all(len(description["uuid"]) == 512 for description in descriptions)
    assert "<truncated>" not in output and "log_context_truncated" not in output
    assert "canary" not in output

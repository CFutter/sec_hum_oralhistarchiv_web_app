"""Stored resource redirects use metadata authorization and bounded audit fields."""

import logging
from contextlib import contextmanager
from typing import Any, cast
from unittest.mock import create_autospec, patch

import pytest
from fastapi import Request
from lxml import html

from app.services import Dataset
from app.services import audit_user_event as _real_audit_user_event
from app.services import get_dataset_by_id as _real_get_dataset_by_id
from app.sources import ConfiguredSource, FixtureConfig, configure_sources
from tests.fixtures import make_sample_user

_DATASET_ID = 17
_SOURCE_NAME = "resource_archive"
_RESOURCE_URL = "https://records.example.edu/interviews/42?download=1&lang=de#part-2"
_LANDING_URL = "https://records.example.edu/catalogue/42"
_PRIVATE_TITLE = "Private resource title must not enter audit metadata"
_PRIVATE_UUID = "private-resource-uuid"
_TIERS = ("public", "registered", "vetted")
_DETAIL_PATH = f"/dataset/{_DATASET_ID}"
_RESOURCE_PATH = f"{_DETAIL_PATH}/resource"
_RESOURCE = {"type": "Resource", "ref": _RESOURCE_URL}
_LANDING = {"type": "LandingPage", "ref": _LANDING_URL}
_SEARCH = {"type": "Search", "ref": "https://ignored.example.edu/search"}
_UNSAFE = {"type": "Resource", "ref": "javascript:alert(1)"}


def _source(*, log_resource_access: bool | None = None) -> ConfiguredSource:
    """Build a real offline adapter without fetching or changing runtime policy."""
    values: dict[str, object] = {
        "name": _SOURCE_NAME,
        "display": {"label": "Resource archive"},
        "max_visibility": "public",
    }
    if log_resource_access is not None:
        values["log_resource_access"] = log_resource_access
    return configure_sources((FixtureConfig.model_validate(values),))[0]


def _dataset(**overrides: Any) -> Dataset:
    """Keep stored proxies distinct from convenience URLs and audit identifiers."""
    values: dict[str, Any] = {
        "id": _DATASET_ID,
        "uuid": _PRIVATE_UUID,
        "title": _PRIVATE_TITLE,
        "source": _SOURCE_NAME,
        "visibility_tier": "public",
        "access_level": "public",
        "resource_proxies": [_RESOURCE],
        "resource_access_url": _RESOURCE_URL,
        "landing_page_url": _LANDING_URL,
    }
    values.update(overrides)
    return Dataset(**cast("Any", values))


def _proxy(ref: Any) -> dict[str, Any]:
    """Construct a proxy input, including intentionally invalid reference types."""
    return {"type": "Resource", "ref": ref}


@contextmanager
def _boundary(dataset):
    """Replace the query boundary and spy on the real audit implementation."""
    lookup = create_autospec(_real_get_dataset_by_id, return_value=dataset)
    audit = create_autospec(_real_audit_user_event, side_effect=_real_audit_user_event)
    with (
        patch("app.routes.pages.get_dataset_by_id", new=lookup),
        patch("app.routes.pages.audit_user_event", new=audit),
    ):
        yield lookup, audit


@pytest.mark.parametrize("viewer", ("guest", *_TIERS))
@pytest.mark.parametrize("record_tier", _TIERS)
def test_redirect_requires_the_effective_metadata_tier(client_builder, viewer, record_tier, caplog):
    """The real session tier, rather than the resource label, governs every pair."""
    user = None if viewer == "guest" else make_sample_user(access_tier=viewer)
    viewer_tier = "public" if user is None else user.access_tier
    client = client_builder(session_user=user, configured_sources=(_source(),))
    with (
        _boundary(_dataset(visibility_tier=record_tier)) as (lookup, audit),
        caplog.at_level(logging.INFO, logger="audit"),
    ):
        response = client.get(f"{_RESOURCE_PATH}/0", follow_redirects=False)

    lookup.assert_awaited_once_with(
        client.mock_pool,
        _DATASET_ID,
        viewer_tier,
        configured_sources=client.app.state.catalogue_policy,
    )
    permitted = _TIERS.index(viewer_tier) >= _TIERS.index(record_tier)
    if not permitted:
        assert response.status_code == 404
        assert "location" not in response.headers
        audit.assert_not_called()
        assert not [record for record in caplog.records if record.msg == "resource_access"]
        return

    assert response.status_code == 303
    assert response.headers["location"] == _RESOURCE_URL
    audit.assert_called_once()
    fields = audit.call_args.kwargs.copy()
    assert fields.pop("level") == logging.INFO
    assert isinstance(fields.pop("request"), Request)
    assert fields == {
        "event_type": "resource_access",
        "user_id": None if user is None else user.id,
        "dataset_id": _DATASET_ID,
        "source": _SOURCE_NAME,
        "user_tier": viewer_tier,
        "proxy_index": 0,
    }
    events = [record for record in caplog.records if record.msg == "resource_access"]
    assert len(events) == 1
    event = events[0]
    assert {name: getattr(event, name) for name in fields} == fields
    for private in (_RESOURCE_URL, _LANDING_URL, _PRIVATE_TITLE, _PRIVATE_UUID):
        assert private not in repr(event.__dict__)


def test_administrator_status_does_not_raise_the_metadata_tier(client_builder):
    """A public-tier administrator cannot follow a vetted record's resource."""
    client = client_builder(
        session_user=make_sample_user(is_admin=True, access_tier="public"),
        configured_sources=(_source(),),
    )
    with _boundary(_dataset(visibility_tier="vetted")) as (lookup, audit):
        response = client.get(f"{_RESOURCE_PATH}/0", follow_redirects=False)
    assert response.status_code == 404
    assert "location" not in response.headers
    lookup.assert_awaited_once_with(
        client.mock_pool,
        _DATASET_ID,
        "public",
        configured_sources=client.app.state.catalogue_policy,
    )
    audit.assert_not_called()


def test_missing_and_below_tier_records_share_the_same_cloaked_response(guest_client):
    """The redirect endpoint does not reveal whether a refused record exists."""
    responses = []
    for dataset in (None, _dataset(visibility_tier="vetted")):
        with _boundary(dataset) as (_, audit):
            response = guest_client.get(f"{_RESOURCE_PATH}/0", follow_redirects=False)
        assert response.status_code == 404
        assert "location" not in response.headers
        audit.assert_not_called()
        responses.append(response)
    assert responses[0].text == responses[1].text


@pytest.mark.parametrize(
    ("proxy_index", "proxies"),
    [
        pytest.param("-1", [_RESOURCE], id="index-negative"),
        pytest.param("1", [_RESOURCE], id="index-out-of-range"),
        pytest.param("no-index", [_RESOURCE], id="index-text"),
        pytest.param("1.0", [_RESOURCE], id="index-fraction"),
        pytest.param("\u0661", [_RESOURCE], id="index-non-ascii"),
        pytest.param("00000000000", [_RESOURCE], id="index-oversized"),
        pytest.param("0", [None], id="proxy-null"),
        pytest.param("0", ["not-a-proxy"], id="proxy-text"),
        pytest.param("0", [{}], id="proxy-empty"),
        pytest.param("0", [{"type": [], "ref": _RESOURCE_URL}], id="proxy-list-type"),
        pytest.param("0", [{"type": {}, "ref": _RESOURCE_URL}], id="proxy-dict-type"),
        pytest.param("0", [_SEARCH], id="proxy-search-type"),
        pytest.param("0", [{"type": "Resource"}], id="proxy-missing-ref"),
        pytest.param("0", [_proxy(None)], id="url-null"),
        pytest.param("0", [_proxy(42)], id="url-number"),
        pytest.param("0", [_proxy("")], id="url-empty"),
        pytest.param("0", [_UNSAFE], id="url-script"),
        pytest.param("0", [_proxy("//records.example.edu/42")], id="url-relative"),
        pytest.param("0", [_proxy("https://u:p@records.example.edu/42")], id="url-userinfo"),
        pytest.param("0", [_proxy(f" {_RESOURCE_URL}")], id="url-leading-space"),
        pytest.param("0", [_proxy(f"{_RESOURCE_URL} ")], id="url-trailing-space"),
        pytest.param("0", [_proxy(f"{_RESOURCE_URL}\r\nX:y")], id="url-header-control"),
        pytest.param("0", [_proxy(f"{_RESOURCE_URL}\tother")], id="url-tab-control"),
        pytest.param("0", [_proxy("https://records.example.edu:bad/42")], id="url-bad-port"),
        pytest.param("0", None, id="container-null"),
        pytest.param("0", {}, id="container-dict"),
        pytest.param("0", "not-a-list", id="container-text"),
    ],
)
def test_invalid_indexes_or_stored_proxies_never_redirect(client_builder, proxy_index, proxies):
    """Invalid stored input cannot be rescued by valid convenience URLs or emit access events."""
    client = client_builder(configured_sources=(_source(),))
    with _boundary(_dataset(resource_proxies=proxies)) as (_, audit):
        response = client.get(f"{_RESOURCE_PATH}/{proxy_index}", follow_redirects=False)
    assert response.status_code == 404
    assert "location" not in response.headers
    audit.assert_not_called()


@pytest.mark.parametrize("proxy_type", ("Resource", "LandingPage"))
@pytest.mark.parametrize("source_selected", (False, True))
def test_redirect_uses_only_the_indexed_stored_target_and_always_audits(
    client_builder, proxy_type, source_selected
):
    """Neither caller URL parameters nor the display opt-out bypass redirect auditing."""
    client = client_builder(
        session_user=make_sample_user(access_tier="vetted") if not source_selected else None,
        configured_sources=(_source(log_resource_access=False),) if source_selected else (),
    )
    dataset = _dataset(
        resource_proxies=[_SEARCH, {"type": proxy_type, "ref": _RESOURCE_URL}],
        resource_access_url="https://ignored.example.edu/derived",
    )
    with _boundary(dataset) as (_, audit):
        response = client.get(
            f"{_RESOURCE_PATH}/1",
            params={"url": "https://caller.example.edu/override", "proxy_index": "0"},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert response.headers["location"] == _RESOURCE_URL
    audit.assert_called_once()
    assert audit.call_args.kwargs["proxy_index"] == 1


@pytest.mark.parametrize(
    ("stored_url", "expected_location"),
    (
        (
            "https://records.example.edu/caf%C3%A9?q=a%2Fb#part-2",
            "https://records.example.edu/caf%C3%A9?q=a%2Fb#part-2",
        ),
        ("https://records.example.edu/café", "https://records.example.edu/caf%C3%A9"),
    ),
    ids=("preserves-existing-encoding", "encodes-unicode-for-http"),
)
def test_redirect_applies_standard_http_encoding_once(
    client_builder, stored_url, expected_location, caplog
):
    """Header encoding retains the stored target and emits one successful access event."""
    client = client_builder(configured_sources=(_source(),))
    dataset = _dataset(resource_proxies=[{"type": "Resource", "ref": stored_url}])
    with (
        _boundary(dataset) as (_, audit),
        caplog.at_level(logging.INFO, logger="audit"),
    ):
        response = client.get(f"{_RESOURCE_PATH}/0", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == expected_location
    audit.assert_called_once()
    assert len([record for record in caplog.records if record.msg == "resource_access"]) == 1


@pytest.mark.parametrize("source_selected", (False, True))
@pytest.mark.parametrize(
    ("proxies", "expected_index", "expected_label"),
    (
        ([_SEARCH, _LANDING, _RESOURCE], 2, "Open resource"),
        ([_UNSAFE, _LANDING], 1, "View source record"),
        ([_UNSAFE, _RESOURCE, _LANDING], 1, "Open resource"),
    ),
    ids=("resource-first", "safe-landing-fallback", "later-safe-resource"),
)
def test_detail_page_hides_stored_targets_behind_the_original_proxy_index(
    client_builder, source_selected, proxies, expected_index, expected_label
):
    """Selected logging sources and retained sources expose only the local redirect."""
    client = client_builder(
        session_user=make_sample_user(access_tier="vetted") if not source_selected else None,
        configured_sources=(_source(),) if source_selected else (),
    )
    with _boundary(_dataset(resource_proxies=proxies)):
        response = client.get(_DETAIL_PATH)
    assert response.status_code == 200
    tree = html.fromstring(response.text)
    links = tree.xpath("//a[@href=$href]", href=f"{_RESOURCE_PATH}/{expected_index}")
    assert len(links) == 1
    assert links[0].text_content().strip() == expected_label
    assert links[0].get("target") == "_blank"
    assert "noopener" in links[0].get("rel", "").split()
    assert "records.example.edu" not in response.text
    assert "ignored.example.edu" not in response.text
    assert "javascript:" not in response.text


def test_explicit_display_opt_out_links_directly_to_the_safe_stored_proxy(client_builder):
    """An explicit source opt-out keeps the direct resource action and its precedence."""
    client = client_builder(configured_sources=(_source(log_resource_access=False),))
    dataset = _dataset(
        resource_proxies=[_LANDING, _RESOURCE],
        resource_access_url="https://ignored.example.edu/derived",
    )
    with _boundary(dataset):
        response = client.get(_DETAIL_PATH)
    assert response.status_code == 200
    tree = html.fromstring(response.text)
    assert len(tree.xpath("//a[@href=$href]", href=_RESOURCE_URL)) == 1
    assert not tree.xpath("//a[contains(@href, '/resource/')]")
    assert _LANDING_URL not in tree.xpath("//a/@href")
    assert "ignored.example.edu" not in response.text


@pytest.mark.parametrize(
    "dataset",
    [
        pytest.param(_dataset(visibility_tier="registered"), id="registered-tier"),
        pytest.param(_dataset(visibility_tier="vetted"), id="vetted-tier"),
        pytest.param(_dataset(resource_proxies=[_proxy("file:/secret")]), id="unsafe-proxy"),
    ],
)
def test_detail_page_omits_actions_for_restricted_or_unsafe_resources(client_builder, dataset):
    """Unavailable resources reveal neither a local action nor stale convenience URLs."""
    client = client_builder(configured_sources=(_source(),))
    with _boundary(dataset):
        response = client.get(_DETAIL_PATH)
    assert response.status_code == 200
    tree = html.fromstring(response.text)
    assert not tree.xpath("//a[contains(@href, '/resource/')]")
    assert "records.example.edu" not in response.text
    assert "file:/secret" not in response.text

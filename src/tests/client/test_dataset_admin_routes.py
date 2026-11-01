"""Dataset controls through real administrator, form, CSRF and template boundaries."""

from datetime import UTC, datetime
from unittest.mock import create_autospec, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from lxml import html

from app.routes.auth import datasets as routes
from app.services import (
    DatasetAdminChange,
    DatasetAdminPage,
    DatasetAdminRecord,
    DatasetAdminRejected,
    DatasetAdminState,
)
from app.services.users import AdminActionRejected
from app.sources import FixtureConfig, SourceDisplay, catalogue_sources, configure_sources
from tests.fixtures import RAW_SESSION_ID, make_sample_user

_BASE = "/admin/datasets"
_HIDDEN = datetime(2026, 10, 18, tzinfo=UTC)
_SOURCES = configure_sources(
    (
        FixtureConfig(
            name="archive_alpha",
            display=SourceDisplay(label="Selected archive"),
            max_visibility="public",
        ),
    )
)
_CATALOGUE_SOURCES = catalogue_sources(tuple(source.config for source in _SOURCES))
_REAL = {
    name: getattr(routes, name)
    for name in (
        "search_admin_datasets",
        "get_admin_dataset_by_id",
        "change_dataset_admin_state",
    )
}


def _patch(name, **kwargs):
    """Patch a dataset-route collaborator using its saved real specification."""
    return patch.object(routes, name, create_autospec(_REAL[name], spec_set=True, **kwargs))


def _record(
    *,
    hidden=True,
    source="archive_alpha",
    blocked=None,
    uuid="public-identifier",
    title="Public discovery title",
    quarantined=False,
):
    """Build a dataset-admin record with optional withdrawal and quarantine state."""
    return DatasetAdminRecord(
        7,
        source,
        uuid,
        DatasetAdminState("registered", "vetted", _HIDDEN if hidden else None),
        None if blocked else "vetted",
        blocked,
        None if hidden else title,
        _HIDDEN if quarantined else None,
        "record_rejected" if quarantined else None,
    )


@pytest.mark.parametrize("hidden", [False, True])
@pytest.mark.parametrize("page", ["", "/7"])
def test_quarantined_identity_remains_manageable_without_serving_stale_metadata(
    client_builder, hidden, page
):
    """Check quarantined identity remains manageable without serving stale metadata (HTTP 200)."""
    client = client_builder(
        session_user=make_sample_user(is_admin=True, access_tier="vetted"),
        configured_sources=_CATALOGUE_SOURCES,
    )
    record = _record(hidden=hidden, quarantined=True, title="withheld-title-canary")
    with (
        _patch("search_admin_datasets", return_value=DatasetAdminPage([record])),
        _patch("get_admin_dataset_by_id", return_value=record),
    ):
        response = client.get(_BASE + page)
    assert response.status_code == 200
    assert "Awaiting upstream correction" in response.text
    assert "public-identifier" in response.text
    assert "withheld-title-canary" not in response.text
    tree = html.fromstring(response.text)
    assert not tree.xpath('//a[@href="/dataset/7"]')
    assert not tree.xpath('//input[@value="clear_quarantine"]')
    if page:
        assert "until a valid upstream correction is successfully ingested" in response.text
        assert "Restoring an administrator-hidden dataset does not remove" in response.text
        assert tree.xpath('//input[@name="action" and @value="raise_tier"]')


def _change(action, changed=True):
    """Build before/after admin states for withdrawal, restoration, or a tier increase."""
    before = DatasetAdminState("public", None, None)
    after = DatasetAdminState("public", None, _HIDDEN)
    if action == "raise_tier":
        after = DatasetAdminState("public", "registered", None)
    elif action == "restore":
        before = DatasetAdminState("public", "vetted", _HIDDEN)
        after = DatasetAdminState("public", "vetted", None)
    return DatasetAdminChange(
        7, "archive_alpha", "public-identifier", action, before, after if changed else before
    )


@pytest.mark.parametrize("tier", ["public", "registered"])
def test_admin_list_renders_hidden_identity(client_builder, tier):
    """Check admin list renders hidden identity (HTTP 200)."""
    client = client_builder(
        session_user=make_sample_user(is_admin=True, access_tier=tier), configured_sources=_SOURCES
    )
    with _patch("search_admin_datasets", return_value=DatasetAdminPage([_record()])) as search:
        response = client.get(
            _BASE, params={"source": "archive_alpha", "uuid": "public-identifier"}
        )
    assert response.status_code == 200
    assert "public-identifier" in response.text and "Hidden" in response.text
    assert "Selected archive" in response.text
    assert "Hidden — title withheld" in response.text
    assert "Public discovery title" not in response.text
    assert response.headers["cache-control"] == "no-store"
    search.assert_awaited_once_with(
        client.mock_pool,
        uuid="public-identifier",
        source="archive_alpha",
        after_id=None,
        before_id=None,
        page_size=20,
        configured_sources=_CATALOGUE_SOURCES,
    )
    assert html.fromstring(response.text).xpath('//a[@href="/admin/datasets/7"]')


@pytest.mark.parametrize("tier", ["public", "registered", "vetted"])
def test_admin_list_shows_public_title_at_every_metadata_tier(client_builder, tier):
    """Check admin list shows public title at every metadata tier (HTTP 200)."""
    client = client_builder(
        session_user=make_sample_user(is_admin=True, access_tier=tier), configured_sources=_SOURCES
    )
    with _patch("search_admin_datasets", return_value=DatasetAdminPage([_record(hidden=False)])):
        response = client.get(_BASE)
    assert response.status_code == 200
    tree = html.fromstring(response.text)
    assert tree.xpath('//a[@href="/dataset/7"]/text()') == ["Public discovery title"]
    assert "public-identifier" in tree.text_content()


@pytest.mark.parametrize("hidden", [False, True], ids=["visible", "hidden"])
def test_admin_detail_renders_controls(client_builder, hidden):
    """Check admin detail renders controls (HTTP 200)."""
    client = client_builder(
        session_user=make_sample_user(is_admin=True, access_tier="public"),
        configured_sources=_SOURCES,
    )
    with _patch("get_admin_dataset_by_id", return_value=_record(hidden=hidden)) as lookup:
        response = client.get(f"{_BASE}/7")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "Selected archive" in response.text
    lookup.assert_awaited_once_with(client.mock_pool, 7, configured_sources=_CATALOGUE_SOURCES)
    tree = html.fromstring(response.text)
    forms = tree.xpath('//form[@action="/admin/datasets/7/state"]')
    assert {form.xpath('.//input[@name="action"]/@value')[0] for form in forms} == {
        "raise_tier",
        "restore" if hidden else "hide",
    }
    assert all(form.get("method") == "post" for form in forms)
    assert all(
        form.xpath('.//input[@name="csrf_token"]/@value') == [client.csrf_token] for form in forms
    )
    assert tree.xpath('//select[@name="new_tier"]/option/@value') == ["vetted"]
    assert bool(tree.xpath('//a[@href="/dataset/7"]')) is not hidden
    assert ("Public discovery title" in response.text) is not hidden


@pytest.mark.parametrize("path", [_BASE, f"{_BASE}/7"])
def test_public_title_is_escaped(admin_client, path):
    """Check public title is escaped (HTTP 200)."""
    record = _record(hidden=False, title="<script>public title</script>")
    with (
        _patch("get_admin_dataset_by_id", return_value=record),
        _patch("search_admin_datasets", return_value=DatasetAdminPage([record])),
    ):
        response = admin_client.get(path)
    assert response.status_code == 200
    assert "&lt;script&gt;public title&lt;/script&gt;" in response.text
    assert "<script>public title</script>" not in response.text


@pytest.mark.parametrize("hidden", [False, True])
def test_unselected_source_keeps_hide_restore_without_a_raise_control(admin_client, hidden):
    """Check unselected source keeps hide restore without a raise control (HTTP 200)."""
    record = _record(hidden=hidden, source="retired_archive", blocked="source_unavailable")
    with _patch("get_admin_dataset_by_id", return_value=record):
        response = admin_client.get(f"{_BASE}/7")
    assert response.status_code == 200
    tree = html.fromstring(response.text)
    assert "retired_archive" in tree.text_content()
    assert "currently selected source policy" in tree.text_content()
    assert tree.xpath('//input[@name="action"]/@value') == ["restore" if hidden else "hide"]
    assert not tree.xpath('//select[@name="new_tier"]')


@pytest.mark.parametrize(
    ("action", "changed", "notice"),
    [
        ("raise_tier", True, "tier_raised"),
        ("hide", True, "hidden"),
        ("restore", True, "restored"),
        ("hide", False, "unchanged"),
    ],
)
def test_state_change_uses_resolved_authority(client_builder, action, changed, notice):
    """Check state change uses resolved authority (HTTP 303)."""
    client = client_builder(
        session_user=make_sample_user(id=91, is_admin=True, access_tier="public"),
        configured_sources=_SOURCES,
        peer_address="203.0.113.8",
    )
    form = {
        "action": action,
        "csrf_token": client.csrf_token,
        "actor_id": "999",
        "actor_session_id": "planted-session",
        "source": "attacker_source",
    }
    if action == "raise_tier":
        form["new_tier"] = "registered"
    with _patch("change_dataset_admin_state", return_value=_change(action, changed)) as change:
        response = client.post(f"{_BASE}/7/state", data=form, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"{_BASE}/7?notice={notice}"
    change.assert_awaited_once()
    assert change.await_args.args == (client.mock_pool, 7, action)
    values = change.await_args.kwargs
    assert values["configured_sources"] == _CATALOGUE_SOURCES
    assert values["new_tier"] == ("registered" if action == "raise_tier" else None)
    context = values["context"]
    assert (context.actor_id, context.actor_session_id) == (91, RAW_SESSION_ID)
    assert context.request_id == response.headers["x-request-id"]
    assert context.client_ip == "203.0.113.8"


@pytest.mark.parametrize("principal", ["guest", "nonadmin"])
@pytest.mark.parametrize("path", [_BASE, f"{_BASE}/7", f"{_BASE}/7/state"])
def test_nonadministrators_cannot_reach_any_dataset_service(client_builder, principal, path):
    """Check nonadministrators cannot reach any dataset service (HTTP 404)."""
    user = None if principal == "guest" else make_sample_user()
    client = client_builder(session_user=user)
    with (
        _patch("search_admin_datasets") as search,
        _patch("get_admin_dataset_by_id") as read,
        _patch("change_dataset_admin_state") as change,
    ):
        response = client.post(path, json={}) if path.endswith("/state") else client.get(path)
    assert response.status_code == 404
    search.assert_not_awaited()
    read.assert_not_awaited()
    change.assert_not_awaited()


@pytest.mark.parametrize("post", [False, True])
def test_enrollment_session_cannot_reach_dataset_controls(client_builder, post):
    """Check enrollment session cannot reach dataset controls (HTTP 303)."""
    user = make_sample_user(is_admin=True, totp_configured=False)
    client = client_builder(session_user=user, session_purpose="totp_setup")
    with _patch("get_admin_dataset_by_id") as read, _patch("change_dataset_admin_state") as change:
        response = (
            client.post(f"{_BASE}/7/state", data={"action": "hide"}, follow_redirects=False)
            if post
            else client.get(f"{_BASE}/7", follow_redirects=False)
        )
    assert response.status_code == 303 and response.headers["location"] == "/setup-totp"
    read.assert_not_awaited()
    change.assert_not_awaited()


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ("missing-csrf", 403),
        ("wrong-csrf", 403),
        ("json", 415),
        ("invalid-action", 422),
        ("invalid-tier", 422),
    ],
)
def test_rejected_mutation_inputs_never_reach_service(admin_client, body, status):
    """Check rejected mutation inputs never reach service."""
    form = {"action": "hide", "csrf_token": admin_client.csrf_token}
    if body == "missing-csrf":
        form.pop("csrf_token")
    elif body == "wrong-csrf":
        form["csrf_token"] = "wrong"
    elif body == "invalid-action":
        form["action"] = "delete"
    elif body == "invalid-tier":
        form.update(action="raise_tier", new_tier="private-invalid-value")
    with _patch("change_dataset_admin_state") as change:
        response = admin_client.post(
            f"{_BASE}/7/state", **({"json": form} if body == "json" else {"data": form})
        )
    assert response.status_code == status
    change.assert_not_awaited()
    assert "private-invalid-value" not in response.text


@pytest.mark.parametrize(
    ("reason", "status"),
    [
        ("dataset_not_found", 404),
        ("invalid_action", 422),
        ("invalid_tier", 422),
        ("source_unavailable", 409),
        ("source_configuration", 409),
        ("invalid_source_tier", 409),
        ("tier_below_floor", 409),
    ],
)
def test_domain_rejections_are_html_errors_not_success_redirects(admin_client, reason, status):
    """Check domain rejections are html errors not success redirects."""
    with _patch("change_dataset_admin_state", side_effect=DatasetAdminRejected(reason)) as change:
        response = admin_client.post(
            f"{_BASE}/7/state",
            data={"action": "hide", "csrf_token": admin_client.csrf_token},
            follow_redirects=False,
        )
    assert response.status_code == status
    assert response.headers["content-type"].startswith("text/html")
    assert "location" not in response.headers
    change.assert_awaited_once()


def test_authority_rejection_never_reloads_the_dataset(admin_client):
    """Check authority rejection never reloads the dataset (HTTP 403)."""
    with (
        _patch("change_dataset_admin_state", side_effect=AdminActionRejected("private diagnosis")),
        _patch("get_admin_dataset_by_id") as read,
    ):
        response = admin_client.post(
            f"{_BASE}/7/state",
            data={"action": "hide", "csrf_token": admin_client.csrf_token},
            follow_redirects=False,
        )
    assert response.status_code == 403
    assert "private diagnosis" not in response.text
    read.assert_not_awaited()


@pytest.mark.parametrize(
    "query",
    [
        {"source": "UPPER"},
        {"source": "x" * 33},
        {"uuid": "x" * 2049},
        {"uuid": "a\x00b"},
        {"after_id": "0"},
        {"after_id": "2147483648"},
        {"after_id": "1", "before_id": "2"},
    ],
)
def test_search_bounds_fail_before_service(admin_client, query):
    """Check search bounds fail before service (HTTP 422)."""
    with _patch("search_admin_datasets") as search:
        response = admin_client.get(_BASE, params=query)
    assert response.status_code == 422
    search.assert_not_awaited()


def test_empty_continuation_keeps_filters_and_offers_first_page(admin_client):
    """Check empty continuation keeps filters and offers first page (HTTP 200)."""
    with _patch("search_admin_datasets", return_value=DatasetAdminPage([])):
        response = admin_client.get(
            _BASE, params={"source": "archive_alpha", "uuid": "a&b", "after_id": "99"}
        )
    assert response.status_code == 200
    tree = html.fromstring(response.text)
    link = tree.xpath('//nav/a[normalize-space(.)="First page"]/@href')[0]
    assert parse_qs(urlsplit(link).query) == {"source": ["archive_alpha"], "uuid": ["a&b"]}
    assert not tree.xpath('//nav/a[normalize-space(.)="Next"]')


def test_detail_absent_and_invalid_ids_do_not_render_controls(admin_client):
    """Check detail absent and invalid IDs do not render controls."""
    with _patch("get_admin_dataset_by_id", return_value=None) as read:
        missing = admin_client.get(f"{_BASE}/7")
        invalid = admin_client.get(f"{_BASE}/0")
    assert missing.status_code == 404 and invalid.status_code == 422
    read.assert_awaited_once()


def test_identifier_is_escaped_and_unknown_notice_is_not_echoed(admin_client):
    """Check identifier is escaped and unknown notice is not echoed (HTTP 200)."""
    with _patch("get_admin_dataset_by_id", return_value=_record(uuid="<script>identity</script>")):
        response = admin_client.get(f"{_BASE}/7", params={"notice": "<script>notice</script>"})
    assert response.status_code == 200
    assert "&lt;script&gt;identity&lt;/script&gt;" in response.text
    assert "<script>" not in response.text and "notice</script>" not in response.text


@pytest.mark.parametrize(
    ("service", "path", "post"),
    [
        ("search_admin_datasets", _BASE, False),
        ("get_admin_dataset_by_id", f"{_BASE}/7", False),
        ("change_dataset_admin_state", f"{_BASE}/7/state", True),
    ],
)
def test_unexpected_storage_failure_is_not_reported_as_success(admin_client, service, path, post):
    """Check unexpected storage failure is not reported as success (HTTP 500)."""
    with _patch(service, side_effect=RuntimeError("private storage diagnosis")):
        response = (
            admin_client.post(
                path,
                data={"action": "hide", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )
            if post
            else admin_client.get(path)
        )
    assert response.status_code == 500
    assert "location" not in response.headers
    assert "private storage diagnosis" not in response.text


def test_keyset_navigation_preserves_filters_without_counts_or_page_offsets(admin_client):
    """Check keyset navigation preserves filters without counts or page offsets (HTTP 200)."""
    result = DatasetAdminPage([_record()], newer_id=27, older_id=7)
    with _patch("search_admin_datasets", return_value=result) as search:
        response = admin_client.get(
            _BASE, params={"after_id": "31", "source": "archive_alpha", "uuid": "a&b"}
        )
    assert response.status_code == 200
    tree = html.fromstring(response.text)
    links = {
        link.text_content(): parse_qs(urlsplit(link.get("href")).query)
        for link in tree.xpath('//nav[contains(@class,"pagination")]/a')
    }
    assert links["Previous"] == {"before_id": ["27"], "source": ["archive_alpha"], "uuid": ["a&b"]}
    assert links["Next"] == {"after_id": ["7"], "source": ["archive_alpha"], "uuid": ["a&b"]}
    assert "Page 10000" not in tree.text_content()
    assert "Exact totals are omitted" in tree.text_content()
    assert search.await_args.kwargs["after_id"] == 31
    assert search.await_args.kwargs["before_id"] is None


def test_known_notice_displays_fixed_feedback(admin_client):
    """Check known notice displays fixed feedback (HTTP 200)."""
    with _patch("get_admin_dataset_by_id", return_value=_record()):
        response = admin_client.get(f"{_BASE}/7", params={"notice": "hidden"})
    assert response.status_code == 200
    assert html.fromstring(response.text).xpath('string(//*[@role="status"])') == (
        "Dataset hidden from every catalogue viewer."
    )

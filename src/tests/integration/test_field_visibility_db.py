"""E2: source field policies agree across real catalogue SQL and rendered pages."""

import copy
from dataclasses import asdict, fields
from datetime import UTC, datetime

import pytest
from lxml import html

from app.services.datasets import (
    PUBLIC_DISCOVERY_FIELDS,
    Dataset,
    get_dataset_by_id,
    get_facets,
    get_recent_datasets,
    get_total_dataset_count,
    search_datasets,
)
from app.services.totp_crypto import encrypt_value
from app.sources import FixtureConfig, configure_sources
from config import settings
from tests.fixtures import sign_session_id

_TIERS = ("public", "registered", "vetted")
_LINK_FIELDS = ("resource_proxies", "resource_access_url", "landing_page_url")
_MINIMA = {
    "project_title": "public",
    "description": "registered",
    "resource_description": "vetted",
    "languages": "registered",
    "project_description": "vetted",
    "authors": "public",
    "keywords": "vetted",
    "license_val": "public",
    "license_url": "vetted",
    "doi": "registered",
    "resource_type": "vetted",
    "bibliographical_citation": "registered",
    **dict.fromkeys(_LINK_FIELDS, "vetted"),
}
_TEXT_FIELDS = (
    "project_title",
    "description",
    "resource_description",
    "languages",
    "project_description",
    "authors",
    "keywords",
    "license_val",
    "doi",
    "resource_type",
    "bibliographical_citation",
)
_SEARCH_FIELDS = (
    "title",
    "access_level",
    "description",
    "project_title",
    "project_description",
    "keywords",
    "authors",
)


def _source(name="matrix_archive", minima=None):
    """Build a public-floor fixture source with optional field minima and access auditing."""
    config = FixtureConfig.model_validate(
        {
            "name": name,
            "display": {"label": f"Display {name}"},
            "max_visibility": "public",
            "log_resource_access": True,
            "field_visibility": minima or {},
        }
    )
    return configure_sources((config,))[0]


def _record(factory, source, *, tier="public", marker="matrix", uuid=None, **changes):
    """Build a synthetic source record with the requested identity and overrides."""
    values = {
        "uuid": uuid or f"{marker}-uuid-value",
        "title": f"{marker}-title-value",
        "project_title": f"{marker}-project-title-value",
        "description": f"{marker}-description-value",
        "resource_description": f"{marker}-resource-description-value",
        "languages": [f"{marker}-language-value"],
        "project_description": f"{marker}-project-description-value",
        "authors": [f"{marker}-author-value"],
        "keywords": [f"{marker}-keyword-value"] * 2,
        "resource_proxies": [
            {"type": "Resource", "ref": f"https://archive.example.org/{marker}/resource"},
            {"type": "LandingPage", "ref": f"https://archive.example.org/{marker}/landing"},
        ],
        "license_val": f"{marker}-license-value",
        "license_url": f"https://archive.example.org/{marker}/license",
        "access_level": f"{marker}-access-value",
        "version": f"{marker}-version-value",
        "doi": f"10.9999/{marker}-doi-value",
        "resource_type": f"{marker}-type-value",
        "bibliographical_citation": f"{marker}-citation-value",
        "source": source,
        "visibility_tier": tier,
    }
    values.update(changes)
    dataset_id = factory(**values, upstream_modified_at=datetime(2026, 10, 19, tzinfo=UTC))
    expected = copy.deepcopy(values)
    expected.update(
        id=dataset_id,
        authors=[{"name": name} for name in values["authors"]],
        resource_access_url=values["resource_proxies"][0]["ref"],
        landing_page_url=values["resource_proxies"][1]["ref"],
    )
    assert set(expected) == {field.name for field in fields(Dataset)}
    return expected


def _allowed(viewer, record_tier, minimum="public"):
    """Check whether the viewer meets the record and field tier minima."""
    return _TIERS.index(viewer) >= max(_TIERS.index(record_tier), _TIERS.index(minimum))


def _release(record, viewer, minima, *, admin_tier="public", retained=False):
    """Compute the expected detached metadata release for tier and field minima."""
    expected = copy.deepcopy(record)
    effective = max((record["visibility_tier"], admin_tier), key=_TIERS.index)
    expected["visibility_tier"] = effective
    for name, value in expected.items():
        minimum = "vetted" if retained else minima.get(name, "public")
        if name not in PUBLIC_DISCOVERY_FIELDS and not _allowed(viewer, effective, minimum):
            expected[name] = [] if isinstance(value, list) else None
    return expected


def _sign_in(client, viewer, user_factory, session_factory):
    """Replace browser cookies with the selected viewer session and return the effective metadata
    tier.
    """
    client.cookies.clear()
    tier = "public" if viewer == "public_admin" else viewer
    if viewer == "public":
        return tier
    user = user_factory(
        access_tier=tier,
        is_admin=viewer == "public_admin",
        totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"),
    )
    session = session_factory(user.id, purpose="full")
    client.cookies.set(settings.session_cookie_name, sign_session_id(session))
    return tier


def _strings(value):
    """Return a list of strings, extracting author names from dictionary entries."""
    if isinstance(value, list):
        return [item["name"] if isinstance(item, dict) else item for item in value]
    return [value]


def _assert_rendered_release(response, original, expected, *, card=False):
    """Check rendered fields and withheld markers against the expected release."""
    tree = html.fromstring(response.text)
    text = tree.text_content()
    names = ("description", "authors", "keywords", "languages") if card else _TEXT_FIELDS
    for name in names:
        permitted = expected[name] not in (None, [])
        for value in _strings(original[name]):
            assert (value in text) is permitted, name
        record_visible = _allowed(response.context["user_tier"], expected["visibility_tier"])
        if not permitted and (card or record_visible):
            assert tree.xpath(
                "//*[@data-field=$field and contains(concat(' ', normalize-space(@class), ' '),"
                " ' metadata-restricted ')]",
                field=name,
            ), name
    if not card:
        if not _allowed(response.context["user_tier"], expected["visibility_tier"]):
            assert tree.xpath("//div[@class='detail-restricted']")
            assert "vetted" in tree.xpath("string(//div[@class='detail-restricted'])")
        assert (original["license_url"] in tree.xpath("//a/@href")) is (
            expected["license_url"] is not None
        )
        for name in ("resource_access_url", "landing_page_url"):
            assert original[name] not in response.text


@pytest.mark.parametrize("viewer", _TIERS)
@pytest.mark.parametrize("record_tier", _TIERS)
async def test_mixed_source_minima_release_all_fields_and_render_partial_metadata(
    replace_bound_catalogue_sources,
    db_pool,
    dataset_factory,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
    viewer,
    record_tier,
):
    """Verify mixed source minima release all fields and render partial metadata."""
    source = _source(minima=_MINIMA)
    selected = (source,)
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, selected)
    original = _record(dataset_factory, source.name, tier=record_tier)
    expected = _release(original, viewer, _MINIMA)
    _sign_in(e2e_client, viewer, user_factory, session_factory)

    detail = await get_dataset_by_id(db_pool, original["id"], viewer, configured_sources=selected)
    results, count = await search_datasets(
        db_pool, viewer, search_text=original["title"], configured_sources=selected
    )
    recent = await get_recent_datasets(db_pool, viewer, configured_sources=selected)
    assert detail is not None and count == 1 and len(results) == len(recent) == 1
    for dataset in (detail, results[0], recent[0]):
        assert asdict(dataset) == expected

    page = e2e_client.get(f"/dataset/{original['id']}")
    search = e2e_client.get("/search", params={"q": original["title"]})
    home = e2e_client.get("/")
    for response in (page, search, home):
        assert response.status_code == 200 and response.context["user_tier"] == viewer
    assert asdict(page.context["dataset"]) == expected
    assert asdict(search.context["results"][0]) == expected
    assert asdict(home.context["recent"][0]) == expected
    _assert_rendered_release(page, original, expected)
    _assert_rendered_release(search, original, expected, card=True)
    _assert_rendered_release(home, original, expected, card=True)

    full = all(expected[name] == original[name] for name in original)
    resource_path = f"/dataset/{original['id']}/resource/0"
    assert (resource_path in html.fromstring(page.text).xpath("//a/@href")) is full
    resource = e2e_client.get(resource_path, follow_redirects=False)
    assert resource.status_code == (303 if full else 404)
    assert resource.headers.get("location") == (original["resource_access_url"] if full else None)


async def test_an_unrelated_hidden_description_denies_a_resource_with_visible_target_fields(
    replace_bound_catalogue_sources,
    db_pool,
    dataset_factory,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
):
    """Verify an unrelated hidden description denies a resource with visible target fields."""
    source = _source(minima={"description": "vetted"})
    selected = (source,)
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, selected)
    original = _record(dataset_factory, source.name, marker="unrelated")
    path = f"/dataset/{original['id']}/resource/0"
    for viewer in ("public", "vetted"):
        _sign_in(e2e_client, viewer, user_factory, session_factory)
        dataset = await get_dataset_by_id(
            db_pool, original["id"], viewer, configured_sources=selected
        )
        assert dataset is not None
        expected = _release(original, viewer, {"description": "vetted"})
        assert asdict(dataset) == expected
        assert all(asdict(dataset)[name] == original[name] for name in _LINK_FIELDS)
        page = e2e_client.get(f"/dataset/{original['id']}")
        assert page.status_code == 200
        _assert_rendered_release(page, original, expected)
        assert (path in html.fromstring(page.text).xpath("//a/@href")) is (viewer == "vetted")
        resource = e2e_client.get(path, follow_redirects=False)
        assert resource.status_code == (303 if viewer == "vetted" else 404)
        assert resource.headers.get("location") == (
            original["resource_access_url"] if viewer == "vetted" else None
        )


@pytest.mark.parametrize("viewer", _TIERS)
async def test_source_policy_gates_each_search_field_and_the_empty_page_count(
    bind_catalogue_policy, db_pool, dataset_factory, viewer
):
    """Verify source policy gates each search field and the empty page count."""
    source = _source(minima=_MINIMA)
    selected = (source,)
    bind_catalogue_policy(selected)
    original = _record(dataset_factory, source.name, marker="search")
    for name in _SEARCH_FIELDS:
        value = _strings(original[name])[0]
        permitted = name in PUBLIC_DISCOVERY_FIELDS or _allowed(
            viewer, "public", _MINIMA.get(name, "public")
        )
        rows, total = await search_datasets(
            db_pool, viewer, search_text=value, configured_sources=selected
        )
        assert [row.id for row in rows] == ([original["id"]] if permitted else []), name
        assert total == int(permitted), name
        assert await search_datasets(
            db_pool, viewer, search_text=value, page=2, page_size=1, configured_sources=selected
        ) == ([], int(permitted)), name

    # Field policy controls disclosure; it does not expand the search vocabulary.
    for name in (
        "uuid",
        "resource_description",
        "languages",
        "license_val",
        "license_url",
        "version",
        "doi",
        "resource_type",
        "bibliographical_citation",
        "resource_access_url",
        "landing_page_url",
    ):
        assert await search_datasets(
            db_pool, viewer, search_text=_strings(original[name])[0], configured_sources=selected
        ) == ([], 0), name


@pytest.mark.parametrize("viewer", _TIERS)
@pytest.mark.parametrize(
    ("language_minimum", "keyword_minimum"),
    (("registered", "vetted"), ("vetted", "registered")),
)
async def test_language_and_keyword_policies_independently_gate_filters_and_facets(
    replace_bound_catalogue_sources,
    db_pool,
    dataset_factory,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
    viewer,
    language_minimum,
    keyword_minimum,
):
    """Verify language and keyword policies independently gate filters and facets."""
    source = _source(minima={"languages": language_minimum, "keywords": keyword_minimum})
    selected = (source,)
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, selected)
    records = [
        _record(
            dataset_factory,
            source.name,
            tier=tier,
            marker=tier,
            keywords=[f"{tier}-repeat-keyword"] * 2 + [f"{tier}-singleton-keyword"],
        )
        for tier in _TIERS
    ]
    languages, repeated = [], []
    for record in records:
        for field, parameter, minimum in (
            ("languages", "language", language_minimum),
            ("keywords", "keyword", keyword_minimum),
        ):
            permitted = _allowed(viewer, record["visibility_tier"], minimum)
            values = record[field]
            for value in set(values):
                rows, total = await search_datasets(
                    db_pool, viewer, **{parameter: value}, configured_sources=selected
                )
                assert [row.id for row in rows] == ([record["id"]] if permitted else [])
                assert total == int(permitted)
                assert await search_datasets(
                    db_pool,
                    viewer,
                    **{parameter: value},
                    page=2,
                    page_size=1,
                    configured_sources=selected,
                ) == ([], int(permitted))
            if permitted:
                if field == "languages":
                    languages.extend(values)
                else:
                    repeated.append(values[0])
    expected_facets = {
        "languages": sorted(set(languages)),
        "keywords": sorted(repeated),
        "access_levels": sorted(record["access_level"] for record in records),
    }
    assert await get_facets(db_pool, viewer, configured_sources=selected) == expected_facets
    assert await get_total_dataset_count(db_pool) == 3
    _sign_in(e2e_client, viewer, user_factory, session_factory)
    home = e2e_client.get("/")
    search = e2e_client.get("/search")
    assert home.status_code == search.status_code == 200
    assert "total_languages" not in home.context and "total_keywords" not in home.context
    assert search.context["all_languages"] == expected_facets["languages"]
    assert search.context["all_keywords"] == expected_facets["keywords"]
    assert search.context["all_access_levels"] == expected_facets["access_levels"]
    assert search.context["result_count"] is None
    assert len(search.context["results"]) == home.context["total_datasets"] == 3


@pytest.mark.parametrize("viewer", (*_TIERS, "public_admin"))
async def test_source_isolation_retained_fallback_and_durable_floor_hide_restore(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    dataset_factory,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
    viewer,
):
    """Verify source isolation retained fallback and durable floor hide restore."""
    source = _source("matrix_alpha", _MINIMA)
    other = _source("matrix_beta")
    selected = (source, other)
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, selected)
    originals = [
        _record(dataset_factory, name, marker=marker, uuid="shared-matrix-identity")
        for name, marker in (
            (source.name, "alpha"),
            (other.name, "beta"),
            ("retained_matrix", "retained"),
        )
    ]
    tier = _sign_in(e2e_client, viewer, user_factory, session_factory)
    for admin_tier, hidden in (
        ("public", False),
        ("registered", False),
        ("registered", True),
        ("registered", False),
    ):
        sync_conn.execute(
            "INSERT INTO dataset_admin_state (source, uuid, visibility_tier, hidden_at) "
            "VALUES (%s, %s, %s, %s) ON CONFLICT (source, uuid) DO UPDATE "
            "SET visibility_tier = EXCLUDED.visibility_tier, hidden_at = EXCLUDED.hidden_at",
            (
                source.name,
                originals[0]["uuid"],
                admin_tier,
                datetime(2026, 10, 19, tzinfo=UTC) if hidden else None,
            ),
        )
        sync_conn.commit()
        expected = [
            _release(originals[0], tier, _MINIMA, admin_tier=admin_tier),
            _release(originals[1], tier, {}),
            _release(originals[2], tier, {}, retained=True),
        ]
        visible = expected[1:] if hidden else expected
        rows, count = await search_datasets(db_pool, tier, configured_sources=selected)
        recent = await get_recent_datasets(db_pool, tier, limit=10, configured_sources=selected)
        by_id = {row["id"]: row for row in visible}
        assert {row.id: asdict(row) for row in rows} == by_id
        assert {row.id: asdict(row) for row in recent} == by_id
        assert count == await get_total_dataset_count(db_pool) == len(visible)
        for index, original in enumerate(originals):
            detail = await get_dataset_by_id(
                db_pool, original["id"], tier, configured_sources=selected
            )
            page = e2e_client.get(f"/dataset/{original['id']}")
            if index == 0 and hidden:
                assert detail is None and page.status_code == 404
            else:
                assert detail is not None and asdict(detail) == expected[index]
                assert (
                    page.status_code == 200 and asdict(page.context["dataset"]) == expected[index]
                )
        search = e2e_client.get("/search")
        home = e2e_client.get("/")
        assert search.context["result_count"] is None
        assert {row.id: asdict(row) for row in search.context["results"]} == by_id
        assert home.context["total_datasets"] == len(visible)
        assert (originals[0]["title"] in search.text) is not hidden
        assert (originals[0]["title"] in home.text) is not hidden
        assert originals[1]["title"] in home.text and originals[2]["title"] in home.text
        if hidden:
            assert await search_datasets(
                db_pool, tier, search_text=originals[0]["title"], configured_sources=selected
            ) == ([], 0)

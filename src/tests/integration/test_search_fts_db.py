"""Searches match only the complete document permitted to the current viewer."""

import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from app.services.datasets import get_facets, search_datasets
from app.sources import FixtureConfig, configure_sources
from tests.integration.test_deployed_preflight_db import deployed_database

__all__ = ["deployed_database"]

_TIERS = ("public", "registered", "vetted")
_FIELDS = ("description", "project_title", "project_description", "keywords", "authors")


def source(name="fts_archive", minima=None):
    """Build the test's configured public-floor source."""
    return configure_sources(
        [
            FixtureConfig.model_validate(
                {
                    "name": name,
                    "display": {"label": "FTS archive"},
                    "max_visibility": "public",
                    "field_visibility": minima or {},
                }
            )
        ]
    )[0]


@pytest.mark.parametrize(
    "query,expected",
    [
        ("history oral", {"river", "harbor", "recollections"}),
        ("recollect", {"recollections"}),
        ('"oral history"', {"river"}),
        ("river OR harbor", {"river", "harbor"}),
        ("oral -river", {"harbor", "recollections", "apostrophe", "noapostrophe"}),
        ('"oral history" -river', set()),
        ("100%", {"percent"}),
        ("100_", {"underscore"}),
        (r"C:\data", {"path"}),
        ("literal-marker", {"hyphen"}),
        ("O'Brien", {"apostrophe"}),
        ('"walking"', {"walking"}),
        ('"café"', {"accent"}),
    ],
)
async def test_web_search_and_literal_substring_intents(
    bind_catalogue_policy, db_pool, dataset_factory, query, expected
):
    """Verify web search and literal substring intents."""
    selected = (source(),)
    bind_catalogue_policy(selected)
    values = {
        "river": ("river oral history", "patient archive"),
        "harbor": ("history of oral lives", "harbor community"),
        "recollections": ("oral recollections", "history about miners"),
        "percent": ("Yield 100% interview", None),
        "number": ("Yield 100x interview", None),
        "underscore": ("Code 100_ notes", None),
        "path": (r"Archive C:\data set", None),
        "nopath": ("Archive C data set", None),
        "hyphen": ("literal-marker transcription", None),
        "nohyphen": ("literal marker transcription", None),
        "apostrophe": ("O'Brien oral account", None),
        "noapostrophe": ("OBrien oral account", None),
        "walking": ("walking witness", None),
        "walked": ("walked witness", None),
        "accent": ("café meeting", None),
        "noaccent": ("cafe meeting", None),
    }
    identifiers = {
        label: dataset_factory(
            source=selected[0].name, uuid=label, title=title, description=description
        )
        for label, (title, description) in values.items()
    }
    rows, total = await search_datasets(
        db_pool, "vetted", search_text=query, configured_sources=selected
    )
    assert {row.id for row in rows} == {identifiers[label] for label in expected}
    assert total == len(expected)
    assert await search_datasets(
        db_pool, "vetted", search_text=query, page=2, page_size=100, configured_sources=selected
    ) == ([], len(expected))


@pytest.mark.parametrize("viewer", _TIERS)
async def test_independent_field_masks_exclude_hidden_positive_and_negative_terms(
    bind_catalogue_policy, db_pool, dataset_factory, viewer
):
    """Verify independent field masks exclude hidden positive and negative terms."""
    minima = {
        "description": "vetted",
        "project_title": "public",
        "project_description": "registered",
        "keywords": "vetted",
        "authors": "registered",
    }
    mixed = source(minima=minima)
    closed = source("closed_archive", dict.fromkeys(_FIELDS, "vetted"))
    markers = {field: f"private{field.replace('_', '')}token" for field in _FIELDS}
    values = {
        field: [marker] if field in {"keywords", "authors"} else marker
        for field, marker in markers.items()
    }
    identifier = dataset_factory(source=mixed.name, title="publicanchor", **values)
    closed_id = dataset_factory(source=closed.name, title="closedanchor", **values)
    selected = (mixed, closed)
    bind_catalogue_policy(selected)
    for field, marker in markers.items():
        permitted = _TIERS.index(viewer) >= _TIERS.index(minima[field])
        rows, count = await search_datasets(
            db_pool, viewer, search_text=f'"publicanchor" "{marker}"', configured_sources=selected
        )
        assert [row.id for row in rows] == ([identifier] if permitted else []), field
        assert count == int(permitted), field
        excluded, excluded_count = await search_datasets(
            db_pool, viewer, search_text=f'"publicanchor" -{marker}', configured_sources=selected
        )
        assert [row.id for row in excluded] == ([] if permitted else [identifier]), field
        assert excluded_count == int(not permitted), field
        closed_rows, closed_count = await search_datasets(
            db_pool, viewer, search_text=f'"closedanchor" "{marker}"', configured_sources=selected
        )
        assert [row.id for row in closed_rows] == ([closed_id] if viewer == "vetted" else []), field
        assert closed_count == int(viewer == "vetted"), field


@pytest.mark.parametrize("viewer", _TIERS)
async def test_above_record_tier_public_document_remains_searchable_without_private_terms(
    bind_catalogue_policy, db_pool, dataset_factory, viewer
):
    """Verify above record tier public document remains searchable without private terms."""
    selected = (source(),)
    bind_catalogue_policy(selected)
    identifier = dataset_factory(
        source=selected[0].name,
        title="publicanchor",
        access_level="restricted",
        visibility_tier="vetted",
        description="privatedescriptiontoken",
    )
    for term in ('"publicanchor"', '"restricted"'):
        rows, total = await search_datasets(
            db_pool, viewer, search_text=term, configured_sources=selected
        )
        assert [row.id for row in rows] == [identifier] and total == 1
        assert rows[0].description == ("privatedescriptiontoken" if viewer == "vetted" else None)
    rows, total = await search_datasets(
        db_pool,
        viewer,
        search_text='"publicanchor" "privatedescriptiontoken"',
        configured_sources=selected,
    )
    assert [row.id for row in rows] == ([identifier] if viewer == "vetted" else [])
    assert total == int(viewer == "vetted")


@pytest.mark.parametrize("viewer", _TIERS)
async def test_filters_facets_hidden_rows_and_empty_page_counts_keep_their_policy(
    bind_catalogue_policy, db_pool, sync_conn, dataset_factory, viewer
):
    """Verify filters facets hidden rows and empty page counts keep their policy."""
    selected = (source(),)
    bind_catalogue_policy(selected)
    identifiers = {}
    for tier in _TIERS:
        identifiers[tier] = dataset_factory(
            source=selected[0].name,
            uuid=tier,
            title=f"oral {tier}",
            visibility_tier=tier,
            keywords=[f"{tier}keyword"],
            languages=[f"{tier}language"],
            access_level="public",
        )
    hidden_id = dataset_factory(source=selected[0].name, uuid="hidden", title="oral hidden")
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, hidden_at) VALUES (%s, 'hidden', clock_timestamp())",
        (selected[0].name,),
    )
    sync_conn.commit()
    before = await get_facets(db_pool, viewer, configured_sources=selected)
    rows, count = await search_datasets(
        db_pool, viewer, search_text='"oral"', access_level="public", configured_sources=selected
    )
    assert {row.id for row in rows} == set(identifiers.values()) and count == 3
    assert hidden_id not in {row.id for row in rows}
    for tier in _TIERS:
        permitted = _TIERS.index(viewer) >= _TIERS.index(tier)
        for parameter in ("keyword", "language"):
            argument = f"{tier}{parameter}"
            result, total = await search_datasets(
                db_pool,
                viewer,
                search_text='"oral"',
                **{parameter: argument},
                configured_sources=selected,
            )
            assert [row.id for row in result] == ([identifiers[tier]] if permitted else [])
            assert total == int(permitted)
            assert await search_datasets(
                db_pool,
                viewer,
                search_text='"oral"',
                **{parameter: argument},
                page=2,
                page_size=100,
                configured_sources=selected,
            ) == ([], int(permitted))
    assert await get_facets(db_pool, viewer, configured_sources=selected) == before


async def test_vectors_follow_trigger_insert_update_and_never_publish_private_lexemes(
    sync_conn, dataset_factory
):
    """Verify vectors follow trigger insert update and never publish private lexemes."""
    identifier = dataset_factory(
        title="originalpublictoken", access_level="public", description="originalprivatetoken"
    )
    probe = """SELECT search_vector_public @@ websearch_to_tsquery('pg_catalog.simple', %s),
                      search_vector_full @@ websearch_to_tsquery('pg_catalog.simple', %s)
               FROM oral_history_datasets WHERE id = %s"""
    assert sync_conn.execute(
        probe, ("originalpublictoken", "originalprivatetoken", identifier)
    ).fetchone() == (True, True)
    assert sync_conn.execute(
        probe, ("originalprivatetoken", "originalprivatetoken", identifier)
    ).fetchone() == (False, True)
    sync_conn.execute(
        "UPDATE oral_history_datasets SET title = 'replacementpublictoken', description = 'replacementprivatetoken' WHERE id = %s",
        (identifier,),
    )
    assert sync_conn.execute(
        probe, ("originalpublictoken", "originalprivatetoken", identifier)
    ).fetchone() == (False, False)
    assert sync_conn.execute(
        probe, ("replacementpublictoken", "replacementprivatetoken", identifier)
    ).fetchone() == (True, True)
    assert sync_conn.execute(
        probe, ("replacementprivatetoken", "replacementprivatetoken", identifier)
    ).fetchone() == (False, True)
    sync_conn.commit()


@pytest.mark.parametrize("viewer", _TIERS)
async def test_actual_web_role_search_respects_source_field_minima(
    bind_catalogue_policy, deployed_database, viewer
):
    """Verify actual web role search respects source field minima."""
    selected = (source(minima={"description": "vetted"}),)
    bind_catalogue_policy(selected, database_url=deployed_database["oralhistarchiv"])
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        identifier = owner.execute(
            """INSERT INTO oral_history_datasets (source, uuid, title, access_level, visibility_tier, description)
               VALUES (%s, 'web-role-search', 'publicanchor', 'public', 'public', 'privatecanary') RETURNING id""",
            (selected[0].name,),
        ).fetchone()[0]
    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_web"], min_size=1, max_size=1, open=False
    ) as pool:
        await pool.wait(timeout=5)
        async with pool.connection() as connection:
            assert await (
                await connection.execute(
                    "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
                )
            ).fetchone() == ("oralhistarchiv_web", False, False)
        rows, total = await search_datasets(
            pool, viewer, search_text='"publicanchor" "privatecanary"', configured_sources=selected
        )
        assert [row.id for row in rows] == ([identifier] if viewer == "vetted" else [])
        assert total == int(viewer == "vetted")
        negative, negative_count = await search_datasets(
            pool, viewer, search_text='"publicanchor" -privatecanary', configured_sources=selected
        )
        assert [row.id for row in negative] == ([] if viewer == "vetted" else [identifier])
        assert negative_count == int(viewer != "vetted")
        assert await search_datasets(
            pool,
            viewer,
            search_text='"publicanchor" "privatecanary"',
            page=2,
            page_size=100,
            configured_sources=selected,
        ) == ([], int(viewer == "vetted"))

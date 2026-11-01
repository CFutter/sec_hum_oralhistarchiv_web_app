"""Policy maintenance is explicit and query SQL sees only audience projections."""

import importlib.util
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import pytest
from psycopg.errors import ObjectNotInPrerequisiteState

from app import catalogue_sql, search_projection_sql
from app.paths import ALEMBIC_DIR
from app.services import SearchUnavailable, build_catalogue_policy
from app.services import search_projection as service
from tests.source_fixtures import legacy_source


@pytest.fixture
def cursor(monkeypatch):
    """Install an asynchronous database cursor scope and return its mock cursor."""
    cursor = AsyncMock()

    @asynccontextmanager
    async def scope(_pool):
        """Yield the scripted cursor without a real database connection."""
        yield cursor

    monkeypatch.setattr(service, "get_db_cursor", scope)
    return cursor


async def test_worker_initialization_cannot_supply_a_previous_policy_for_replacement(cursor):
    """Check worker initialization cannot supply a previous policy for replacement."""
    policy = build_catalogue_policy((legacy_source(max_visibility="public"),))
    await service.synchronize_search_policy(object(), policy)
    statement, values = cursor.execute.await_args.args
    assert statement == "SELECT public.catalogue_initialize_search_policy(%s, %s)"
    assert values[0] == policy.fingerprint
    assert values[1].obj == {str(rank): dict(masks) for rank, masks in policy.page_masks.items()}


async def test_operator_replacement_binds_the_expected_previous_policy(cursor):
    """Check operator replacement binds the expected previous policy."""
    policy = build_catalogue_policy((legacy_source(max_visibility="public"),))
    await service.replace_search_policy(object(), policy, expected_fingerprint="a" * 64)
    statement, values = cursor.execute.await_args.args
    assert statement == "SELECT public.catalogue_replace_search_policy(%s, %s, %s)"
    assert values[:2] == ("a" * 64, policy.fingerprint)


async def test_serving_policy_check_is_bound_and_sanitizes_refusal(cursor):
    """Check serving policy check is bound and sanitizes refusal (SearchUnavailable)."""
    await service.guard_catalogue_policy_cur(cursor, "a" * 64)
    cursor.execute.assert_awaited_once_with(
        "SELECT public.catalogue_guard_search_policy(%s)", ("a" * 64,)
    )
    cursor.execute.side_effect = ObjectNotInPrerequisiteState("private database detail")
    with pytest.raises(SearchUnavailable) as failure:
        await service.guard_catalogue_policy_cur(cursor, "a" * 64)
    assert "private" not in str(failure.value)


@pytest.mark.parametrize("fingerprint", ["", "A" * 64, "0" * 63, "g" * 64])
async def test_invalid_operator_comparison_is_rejected_before_sql(cursor, fingerprint):
    """Check invalid operator comparison is rejected before SQL (ValueError)."""
    policy = build_catalogue_policy(())
    with pytest.raises(ValueError, match="fingerprint"):
        await service.replace_search_policy(object(), policy, expected_fingerprint=fingerprint)
    cursor.execute.assert_not_awaited()


def test_current_source_floor_and_field_overrides_both_constrain_projection_masks():
    """Check current source floor and field overrides both constrain projection masks."""
    policy = build_catalogue_policy(
        (legacy_source(max_visibility="registered", field_visibility={"description": "vetted"}),)
    )
    source = policy.sources[0].name
    assert policy.page_masks[0][source] == 0
    assert not policy.page_masks[1][source] & 1
    assert policy.page_masks[1][source] & 8
    assert policy.page_masks[2][source] == 63
    assert policy.minimum("title", source) == "public"
    assert policy.minimum("description", source) == "vetted"


def test_user_predicates_do_not_reference_unrestricted_search_storage():
    """Check user predicates do not reference unrestricted search storage."""
    for source in (
        catalogue_sql.CATALOGUE_PAGE_IDS_SOURCE,
        search_projection_sql.SEARCH_MATCH_IDS_SOURCE,
        catalogue_sql.CATALOGUE_SEARCH_CANDIDATES_DEFINITION,
    ):
        assert "oral_history_datasets" not in source
        assert "search_vector_full" not in source
        assert "search_text_full" not in source
    assert set(search_projection_sql.SEARCH_AUDIENCES) == {"public", "registered", "vetted"}
    for audience in search_projection_sql.SEARCH_AUDIENCES:
        assert (
            f"ON public.catalogue_search_{audience} USING gin"
            in search_projection_sql.SEARCH_PROJECTION_TABLE_DDL
        )


def test_frozen_initial_search_schema_matches_runtime_contracts():
    """Check frozen initial search schema matches runtime contracts."""
    path = ALEMBIC_DIR / "versions/4f73ae3ff827_initial_schema.py"
    specification = importlib.util.spec_from_file_location("search_initial_schema", path)
    assert specification is not None and specification.loader is not None
    migration = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(migration)
    assert migration._CATALOGUE_PAGE_IDS_SOURCE == catalogue_sql.CATALOGUE_PAGE_IDS_SOURCE
    assert migration._CATALOGUE_SCAN_CEILING_SOURCE == catalogue_sql.CATALOGUE_SCAN_CEILING_SOURCE
    assert migration._SEARCH_FUNCTION_SOURCES == search_projection_sql.SEARCH_FUNCTION_SOURCES
    assert (
        migration._SEARCH_PROJECTION_TABLE_DDL == search_projection_sql.SEARCH_PROJECTION_TABLE_DDL
    )

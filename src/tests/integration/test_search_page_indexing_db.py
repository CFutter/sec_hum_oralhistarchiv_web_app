"""Page searches expose stored index keys without changing exact field semantics."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.rows import tuple_row
from psycopg_pool import AsyncConnectionPool

from app.ingestion_contracts import AccessTier
from app.services import datasets
from app.services.access_tiers import tier_rank
from app.services.db import get_catalogue_cursor
from app.services.search_query import parse_search_query
from tests.integration import test_deployed_preflight_db
from tests.integration.test_catalogue_ordering_db import _ids
from tests.integration.test_search_plans_db import (
    _assert_audience_search_plan,
    _seed_plan_catalogue,
)
from tests.source_fixtures import legacy_source

deployed_database = test_deployed_preflight_db.deployed_database

_SOURCES = (legacy_source(name="plan_source", max_visibility="public"),)
_SIGNATURE = "integer, integer, boolean, integer, integer, jsonb"


@pytest.fixture
def page_plan_probe(deployed_database: dict[str, str]) -> Iterator[None]:
    """Explain the installed function's generated SQL under its actual owner boundary.

    The copy returns JSON and is VOLATILE so PostgreSQL permits EXPLAIN. Its
    generated page SQL, argument bindings, owner and search_path come from the
    installed definition. The real STABLE function is exercised first.
    """
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        assert owner.execute(
            "SELECT to_regprocedure(%s)", (f"public.test_catalogue_page_plan({_SIGNATURE})",)
        ).fetchone() == (None,)
        row = owner.execute(
            "SELECT pg_get_functiondef(%s::regprocedure)",
            (f"public.catalogue_page_ids({_SIGNATURE})",),
        ).fetchone()
        assert row is not None
        definition = row[0]
        old = "RETURN QUERY EXECUTE page_sql"
        assert definition.count(old) == 1
        definition = definition.replace(
            "FUNCTION public.catalogue_page_ids(", "FUNCTION public.test_catalogue_page_plan(", 1
        ).replace("RETURNS SETOF integer", "RETURNS SETOF json", 1)
        definition = definition.replace(
            old,
            "RETURN QUERY EXECUTE "
            "'EXPLAIN (ANALYZE, BUFFERS, VERBOSE, SETTINGS, FORMAT JSON) ' || page_sql",
            1,
        )
        owner.execute(definition)
        owner.execute(f"ALTER FUNCTION public.test_catalogue_page_plan({_SIGNATURE}) VOLATILE")
        owner.execute(
            f"REVOKE ALL ON FUNCTION public.test_catalogue_page_plan({_SIGNATURE}) FROM PUBLIC"
        )
        owner.execute(
            f"GRANT EXECUTE ON FUNCTION public.test_catalogue_page_plan({_SIGNATURE}) TO oralhistarchiv_web"
        )
        assert owner.execute(
            "SELECT actual.proowner = probe.proowner, actual.prosecdef AND probe.prosecdef, "
            "actual.proconfig = probe.proconfig FROM pg_proc AS actual, pg_proc AS probe "
            "WHERE actual.oid = %s::regprocedure AND probe.oid = %s::regprocedure",
            (
                f"public.catalogue_page_ids({_SIGNATURE})",
                f"public.test_catalogue_page_plan({_SIGNATURE})",
            ),
        ).fetchone() == (True, True, True)
    try:
        yield
    finally:
        with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
            owner.execute(f"DROP FUNCTION public.test_catalogue_page_plan({_SIGNATURE})")


def _removed_rows(node: Any) -> int:
    """Sum rows removed by filters across JSON plan nodes and their loop counts."""
    if isinstance(node, dict):
        own = node.get("Rows Removed by Filter", 0) * node.get("Actual Loops", 1)
        return own + sum(_removed_rows(value) for value in node.values())
    if isinstance(node, list):
        return sum(_removed_rows(value) for value in node)
    return 0


@pytest.mark.usefixtures("page_plan_probe")
async def test_selective_page_search_uses_gin_inside_the_owner_function(
    deployed_database: dict[str, str], tmp_path: Path, bind_catalogue_policy
) -> None:
    """Reuse the same seed and web connection across every read-only audience case."""
    policy = bind_catalogue_policy(_SOURCES, database_url=deployed_database["oralhistarchiv"])
    target_id = _seed_plan_catalogue(deployed_database["oralhistarchiv"])
    cases: list[tuple[AccessTier, str, str, bool]] = [
        ("public", '"K2publicneedle"', "idx_catalogue_search_public_vector", True),
        ("registered", '"K2publicneedle"', "idx_catalogue_search_registered_vector", True),
        ("vetted", '"K2fullneedle"', "idx_catalogue_search_vetted_vector", True),
        ("public", "K2publicneedle", "idx_catalogue_search_public_vector", True),
        ("vetted", "K2fullneedle", "idx_catalogue_search_vetted_vector", True),
        ("public", '"CQ5missingneedle"', "idx_catalogue_search_public_vector", False),
        ("vetted", '"CQ5missingneedle"', "idx_catalogue_search_vetted_vector", False),
        ("public", "CQ5missingneedle%", "idx_catalogue_search_public_public_trgm", False),
        ("registered", "CQ5missingneedle%", "idx_catalogue_search_registered_public_trgm", False),
        ("vetted", "CQ5missingneedle%", "idx_catalogue_search_vetted_public_trgm", False),
    ]
    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_web"], min_size=1, max_size=1, open=False
    ) as pool:
        await pool.wait(timeout=5)
        for case_index, (viewer, term, index_name, matches) in enumerate(cases):
            try:
                await _assert_page_plan_case(
                    pool, tmp_path, policy, target_id, case_index, viewer, term, index_name, matches
                )
            except Exception as exc:
                raise AssertionError(f"Page plan failed for {viewer=}, {term=}") from exc


async def _assert_page_plan_case(
    pool, tmp_path, policy, target_id, case_index, viewer, term, index_name, matches
):
    """Check page results and plans use only the selected audience projection."""
    context = datasets._page_query_context(
        parse_search_query(term),
        tier_rank(viewer),
        {"keyword": "", "language": "", "access_level": ""},
        policy,
    )
    # No search-context scope: p_query must be authoritative on its own.
    async with get_catalogue_cursor(pool, viewer, row_factory=tuple_row) as cursor:
        await cursor.execute(
            "SELECT set_config('app.search_term', 'unrelated', true), "
            "set_config('app.search_mode', 'web', true), "
            "set_config('app.search_pattern', '%unrelated%', true), "
            "set_config('app.search_field_masks', '{\"*\":0}', true)"
        )
        await cursor.execute("SELECT public.catalogue_scan_ceiling()")
        ceiling = await cursor.fetchone()
        assert ceiling is not None
        arguments = (None, ceiling[0], False, 21, 0, context)
        await cursor.execute(
            "SELECT id FROM public.catalogue_page_ids(%s, %s, %s, %s, %s, %s) AS selected(id)",
            arguments,
        )
        assert await cursor.fetchall() == ([(target_id,)] if matches else [])
        await cursor.execute(
            "SELECT plan FROM public.test_catalogue_page_plan(%s, %s, %s, %s, %s, %s) AS probe(plan)",
            arguments,
        )
        explained = await cursor.fetchone()
        assert explained is not None
        plan = explained[0]
    (tmp_path / f"page-plan-{case_index}.json").write_text(
        json.dumps({"viewer": viewer, "term": term, "plan": plan}, indent=2), encoding="utf-8"
    )
    _assert_audience_search_plan(plan, viewer, index_name)
    # Index presence alone must not conceal an additional whole-table fallback.
    assert _removed_rows(plan) < 100, json.dumps(plan, indent=2)


@pytest.mark.parametrize(
    ("mask", "term", "language", "expected"),
    [
        (0, '"oral"', "", ["visible", "above", "phrase"]),
        (32, '"oral"', "English", ["visible", "phrase"]),
        (63, '"history"', "", ["visible", "phrase"]),
        (31, '"history"', "", ["visible", "phrase"]),
        (2, '"oral history"', "", ["visible", "phrase"]),
        (1, "oral -closed", "", ["above", "phrase"]),
        (0, "oral -closed", "", ["visible", "above", "phrase"]),
        (2, "oral -closed", "", ["visible", "above", "phrase"]),
        (63, "oral -closed", "", ["above", "phrase"]),
        (63, "100%", "", ["phrase"]),
    ],
)
def test_page_candidate_branches_preserve_exact_visibility_and_ordering(
    sync_conn,
    dataset_factory,
    bind_catalogue_policy,
    mask: int,
    term: str,
    language: str,
    expected: list[str],
) -> None:
    # Select a real disclosure policy that produces the desired public mask.
    # A caller-supplied mask may no longer override the stored policy binding.
    """Verify page candidate branches preserve exact visibility and ordering."""
    field_bits = {
        "description": 1,
        "project_title": 2,
        "project_description": 4,
        "keywords": 8,
        "authors": 16,
        "languages": 32,
    }
    policy = bind_catalogue_policy(
        (
            legacy_source(
                name="plan_source",
                max_visibility="public",
                field_visibility={
                    name: "public" if mask & bit else "vetted" for name, bit in field_bits.items()
                },
            ),
        )
    )
    assert policy.page_masks[0]["plan_source"] == mask
    identifiers = {}
    for label, values in (
        ("visible", {"title": "oral", "description": "closed", "project_title": "history"}),
        ("above", {"title": "oral", "description": "history", "visibility_tier": "vetted"}),
        ("phrase", {"title": "oral history 100%", "description": "open"}),
        ("hidden", {"title": "oral history"}),
    ):
        identifiers[label] = dataset_factory(
            source="plan_source",
            uuid=label,
            access_level="",
            languages=["English"],
            upstream_modified_at=({"visible": "2026-01-03", "above": "2026-01-02"}.get(label)),
            **values,
        )
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, hidden_at) "
        "VALUES ('plan_source', 'hidden', clock_timestamp())"
    )
    sync_conn.execute("SELECT set_config('app.viewer_tier', 'public', true)")
    query = parse_search_query(term)
    context = datasets._page_query_context(
        query,
        0,
        {"keyword": "", "language": language, "access_level": ""},
        policy,
    )
    ordered = [identifiers[label] for label in expected]
    assert _ids(sync_conn, limit=100, context=context) == ordered
    assert _ids(sync_conn, limit=1, context=context) == ordered[:1]
    assert _ids(sync_conn, limit=100, offset=1, context=context) == ordered[1:]
    for position, anchor in enumerate(ordered):
        assert _ids(sync_conn, anchor=anchor, limit=100, context=context) == ordered[position + 1 :]
        assert _ids(sync_conn, anchor=anchor, backward=True, limit=100, context=context) == list(
            reversed(ordered[:position])
        )

"""Natural GIN plans for separately requested exact counts under the web role."""

import json
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row, tuple_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.services import datasets
from app.services.db import get_catalogue_search_cursor
from tests.integration import test_deployed_preflight_db
from tests.source_fixtures import legacy_source

_SOURCES = (legacy_source(name="plan_source", max_visibility="public"),)

deployed_database = test_deployed_preflight_db.deployed_database


def _seed_plan_catalogue(owner_url):
    """Keep plan selectivity realistic with a bounded, trigger-maintained fixture."""
    # Mixed letter/digit fixture tokens preserve PostgreSQL lexical classification
    # and plan selectivity; they are data, not references to project tracking.
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO public.oral_history_datasets "
            "(source, uuid, title, description, access_level, visibility_tier, "
            "upstream_modified_at) "
            "SELECT 'plan_source', 'filler-' || n, 'Background interview ' || n, "
            "repeat('Archive contextual background material ', 8), 'public', "
            "CASE n % 3 WHEN 0 THEN 'public' WHEN 1 THEN 'registered' ELSE 'vetted' END, "
            "clock_timestamp() - n * INTERVAL '1 second' "
            "FROM generate_series(1, 5000) AS fixture(n)"
        )
        target = owner.execute(
            "INSERT INTO public.oral_history_datasets "
            "(source, uuid, title, description, access_level, visibility_tier, "
            "upstream_modified_at) VALUES "
            "('plan_source', 'visible', 'K2publicneedle', 'K2fullneedle', "
            "'restricted', 'vetted', clock_timestamp()) RETURNING id"
        ).fetchone()
        assert target is not None
        owner.execute(
            "INSERT INTO public.oral_history_datasets "
            "(source, uuid, title, description, access_level, visibility_tier) "
            "VALUES ('plan_source', 'hidden', 'K2publicneedle', 'K2fullneedle', "
            "'public', 'public')"
        )
        owner.execute(
            "INSERT INTO public.dataset_admin_state (source, uuid, hidden_at) "
            "VALUES ('plan_source', 'hidden', clock_timestamp())"
        )
        # Settle the bulk insert's GIN pending lists before measuring the plan.
        # ANALYZE alone does not perform this index maintenance; otherwise the
        # result depends on whether autovacuum ran between seeding and EXPLAIN.
        owner.commit()
        owner.autocommit = True
        owner.execute("VACUUM (ANALYZE) public.oral_history_datasets")
        for audience in ("public", "registered", "vetted"):
            owner.execute(f"VACUUM (ANALYZE) public.catalogue_search_{audience}")
            assert owner.execute(
                f"SELECT COUNT(*) FROM public.catalogue_search_{audience}"
            ).fetchone() == (5001,), "hidden records must be absent from physical search storage"
        owner.execute("ANALYZE public.dataset_admin_state")
        return target[0]


def _bitmap_index_names(node):
    """Read every branch of PostgreSQL's JSON plan without relying on node order."""
    if isinstance(node, dict):
        if node.get("Node Type") == "Bitmap Index Scan":
            yield node.get("Index Name")
        for value in node.values():
            yield from _bitmap_index_names(value)
    elif isinstance(node, list):
        for value in node:
            yield from _bitmap_index_names(value)


def _plan_values(node, name):
    """Inspect every executed branch, including both ordered page partitions."""
    if isinstance(node, dict):
        if name in node:
            yield node[name]
        for value in node.values():
            yield from _plan_values(value, name)
    elif isinstance(node, list):
        for value in node:
            yield from _plan_values(value, name)


def _assert_audience_search_plan(plan, audience, required_index):
    """User-controlled matching must never inspect another audience or raw index."""
    detail = json.dumps(plan, indent=2)
    assert set(_plan_values(plan, "Relation Name")) == {f"catalogue_search_{audience}"}, detail
    indexes = set(_plan_values(plan, "Index Name"))
    assert required_index in set(_bitmap_index_names(plan)), detail
    assert indexes and all(
        name.startswith(f"idx_catalogue_search_{audience}_")
        or name == f"catalogue_search_{audience}_pkey"
        for name in indexes
    ), detail
    assert not any(name.startswith("idx_search_") for name in indexes), detail


@pytest.fixture
def match_plan_probe(deployed_database):
    """Explain the real match function's generated SQL under its unchanged owner."""
    signature = "jsonb"
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        row = owner.execute(
            "SELECT pg_get_functiondef('public.catalogue_match_ids(jsonb)'::regprocedure)"
        ).fetchone()
        assert row is not None
        definition = row[0]
        old = "RETURN QUERY EXECUTE pg_catalog.format("
        assert definition.count(old) == 1
        definition = definition.replace(
            "FUNCTION public.catalogue_match_ids(", "FUNCTION public.catalogue_match_plan_probe(", 1
        ).replace("RETURNS SETOF integer", "RETURNS SETOF json", 1)
        definition = definition.replace(
            old,
            "RETURN QUERY EXECUTE "
            "'EXPLAIN (ANALYZE, BUFFERS, VERBOSE, SETTINGS, FORMAT JSON) ' || pg_catalog.format(",
            1,
        )
        owner.execute(definition)
        owner.execute(f"ALTER FUNCTION public.catalogue_match_plan_probe({signature}) VOLATILE")
        owner.execute(
            f"REVOKE ALL ON FUNCTION public.catalogue_match_plan_probe({signature}) FROM PUBLIC"
        )
        owner.execute(
            f"GRANT EXECUTE ON FUNCTION public.catalogue_match_plan_probe({signature}) "
            "TO oralhistarchiv_web"
        )
        assert owner.execute(
            "SELECT actual.proowner = probe.proowner, actual.prosecdef AND probe.prosecdef, "
            "actual.proconfig = probe.proconfig FROM pg_proc AS actual, pg_proc AS probe "
            "WHERE actual.oid = 'public.catalogue_match_ids(jsonb)'::regprocedure "
            "AND probe.oid = 'public.catalogue_match_plan_probe(jsonb)'::regprocedure"
        ).fetchone() == (True, True, True)
    try:
        yield
    finally:
        with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
            owner.execute(f"DROP FUNCTION public.catalogue_match_plan_probe({signature})")


@pytest.mark.usefixtures("match_plan_probe")
async def test_actual_web_exact_count_naturally_uses_gin(
    deployed_database, monkeypatch, tmp_path, bind_catalogue_policy
):
    """Exercise all audience plans on one seeded DB and one reusable web connection."""
    policy = bind_catalogue_policy(_SOURCES, database_url=deployed_database["oralhistarchiv"])
    target_id = _seed_plan_catalogue(deployed_database["oralhistarchiv"])
    cases = (
        ("public", "K2publicneedle", "idx_catalogue_search_public_vector"),
        ("registered", "K2publicneedle", "idx_catalogue_search_registered_vector"),
        ("vetted", "K2fullneedle", "idx_catalogue_search_vetted_vector"),
    )
    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_web"], min_size=1, max_size=1, open=False
    ) as pool:
        await pool.wait(timeout=5)
        for viewer, term, index_name in cases:
            try:
                await _assert_exact_count_plan_case(
                    pool, monkeypatch, tmp_path, policy, target_id, viewer, term, index_name
                )
            except Exception as exc:
                raise AssertionError(f"Exact-count plan failed for {viewer=}, {term=}") from exc


async def _assert_exact_count_plan_case(
    pool, monkeypatch, tmp_path, policy, target_id, viewer, term, index_name
):
    """Capture search SQL and verify count plans use the audience projection."""
    captured: list[tuple[str, Any, dict[str, str]]] = []

    class RecordingCursor:
        """Delegate cursor operations while recording SQL for plan assertions."""

        def __init__(self, cursor, search_context):
            """Store cursor, search_context on this test double."""
            self.cursor = cursor
            self.search_context = search_context

        def __getattr__(self, name):
            """Delegate missing attributes to the wrapped cursor."""
            return getattr(self.cursor, name)

        async def execute(self, query, params=None, **kwargs):
            """Forward SQL execution with this test's observation or injected failure."""
            statement = query if isinstance(query, str) else query.as_string(self.cursor.connection)
            copied_params = dict(params) if isinstance(params, Mapping) else params
            captured.append((statement, copied_params, dict(self.search_context)))
            if statement.startswith("SELECT COUNT(*) FROM"):
                # Retain the outer plan even when a bounded count fails before
                # the later ANALYZE probe can collect execution statistics.
                await self.cursor.execute("EXPLAIN (VERBOSE, FORMAT JSON) " + statement, params)
                planned = await self.cursor.fetchone()
                assert planned is not None
                (tmp_path / f"{index_name}-outer-before.json").write_text(
                    json.dumps(planned[0], indent=2), encoding="utf-8"
                )
            return await self.cursor.execute(query, params, **kwargs)

    @asynccontextmanager
    async def record_search_cursor(pool, viewer_tier, search_context, row_factory=dict_row):
        """Yield a real cursor wrapped to record executed SQL for plan assertions."""
        async with get_catalogue_search_cursor(
            pool, viewer_tier, search_context, row_factory=row_factory
        ) as cursor:
            yield RecordingCursor(cursor, search_context)

    monkeypatch.setattr(datasets, "get_catalogue_search_cursor", record_search_cursor)
    # Quoting explicitly selects the structured web-search mode. This plan
    # proof does not depend on an OR with the literal substring fallback.
    page = await datasets.search_catalogue_page(
        pool, viewer, search_text=f'"{term}"', configured_sources=_SOURCES
    )
    assert page.total_count is None
    assert [row.id for row in page.datasets] == [target_id]
    assert page.datasets[0].description == ("K2fullneedle" if viewer == "vetted" else None)
    assert len(captured) == 2
    assert captured[0][:2] == (
        "SELECT public.catalogue_guard_search_policy(%s)",
        (policy.fingerprint,),
    )
    assert "catalogue_page_ids" in captured[1][0]
    captured.clear()
    total = await datasets.count_search_datasets(
        pool,
        viewer,
        search_text=f'"{term}"',
        configured_sources=_SOURCES,
    )
    assert total == 1
    count_queries = [entry for entry in captured if "SELECT COUNT(*) FROM" in entry[0]]
    assert len(count_queries) == 1
    statement, parameters, search_context = count_queries[0]
    assert "catalogue_match_ids" in statement

    async with get_catalogue_search_cursor(
        pool, viewer, search_context, row_factory=tuple_row
    ) as cursor:
        await cursor.execute(
            "SELECT current_user, role.rolsuper, role.rolbypassrls, "
            "pg_catalog.pg_has_role(role.oid, relation.relowner, 'MEMBER'), "
            "pg_catalog.row_security_active(relation.oid), relation.relrowsecurity, "
            "current_setting('enable_seqscan'), current_setting('enable_bitmapscan') "
            "FROM pg_catalog.pg_roles AS role CROSS JOIN pg_catalog.pg_class AS relation "
            "WHERE role.rolname = current_user "
            "AND relation.oid = 'public.oral_history_datasets'::regclass"
        )
        assert await cursor.fetchone() == (
            "oralhistarchiv_web",
            False,
            False,
            False,
            True,
            True,
            "on",
            "on",
        )
        await cursor.execute(
            "SELECT index_relation.relname, access_method.amname "
            "FROM pg_catalog.pg_class AS index_relation "
            "JOIN pg_catalog.pg_am AS access_method "
            "ON access_method.oid = index_relation.relam "
            "WHERE index_relation.oid IN "
            "('public.idx_catalogue_search_public_vector'::regclass, "
            "'public.idx_catalogue_search_registered_vector'::regclass, "
            "'public.idx_catalogue_search_vetted_vector'::regclass) "
            "ORDER BY index_relation.relname"
        )
        assert await cursor.fetchall() == [
            ("idx_catalogue_search_public_vector", "gin"),
            ("idx_catalogue_search_registered_vector", "gin"),
            ("idx_catalogue_search_vetted_vector", "gin"),
        ]
        await cursor.execute(
            "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, SETTINGS, FORMAT JSON) " + statement,
            parameters,
        )
        explained = await cursor.fetchone()
        assert explained is not None
        outer_plan = explained[0]
        # The count consumes owner-returned IDs; the Function Scan hides
        # matching SQL. Explain that installed SQL separately under the
        # same owner, viewer and exact page_query captured from the service.
        await cursor.execute(
            "SELECT plan FROM public.catalogue_match_plan_probe(%s) AS probe(plan)",
            (parameters["page_query"],),
        )
        explained_match = await cursor.fetchone()
        assert explained_match is not None
        plan = explained_match[0]

    evidence = {
        "role": "oralhistarchiv_web",
        "viewer_tier": viewer,
        "seeded_rows": 5002,
        "sql": statement,
        "parameters": {
            key: value.obj if isinstance(value, Jsonb) else value
            for key, value in parameters.items()
        },
        "search_context": search_context,
        "plan": plan,
        "outer_plan": outer_plan,
    }
    (tmp_path / f"{index_name}.json").write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _assert_audience_search_plan(plan, viewer, index_name)
    assert not list(_plan_values(outer_plan, "Relation Name")), json.dumps(outer_plan, indent=2)
    assert list(_plan_values(outer_plan, "Function Name")) == ["catalogue_match_ids"], json.dumps(
        outer_plan, indent=2
    )
    assert not any(
        name.startswith("idx_search_") for name in _plan_values(outer_plan, "Index Name")
    )

    # The full-only term never becomes a public discovery match. The rare
    # public term above still discovered the same vetted row in redacted form.
    public_page = await datasets.search_catalogue_page(
        pool,
        "public",
        search_text='"K2fullneedle"',
        configured_sources=_SOURCES,
    )
    public_total = await datasets.count_search_datasets(
        pool,
        "public",
        search_text='"K2fullneedle"',
        configured_sources=_SOURCES,
    )
    assert public_page.datasets == []
    assert public_total == 0

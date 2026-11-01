"""The optional exact-count API has its own bounded, restoring SQL operation."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest
from psycopg import Error as DatabaseError
from psycopg.errors import ObjectNotInPrerequisiteState
from psycopg.rows import tuple_row

from app.services import SearchUnavailable, datasets
from tests.fixtures import make_async_cursor, make_mock_pool
from tests.source_fixtures import legacy_source

_SOURCES = (legacy_source(max_visibility="public"),)


@pytest.fixture
def count_scope(monkeypatch):
    """Install count-query scopes and return their cursor, pool, and exit observations."""
    state = SimpleNamespace(
        pool=make_mock_pool(),
        cursor=make_async_cursor(fetchone=[("750ms",), (7,)]),
        exit=None,
    )

    @asynccontextmanager
    async def scope(pool, _viewer_tier, *_context, **_kwargs):
        """Check the pool, yield the count cursor, and record commit or propagated rollback."""
        assert pool is state.pool
        try:
            yield state.cursor
        except BaseException:
            state.exit = "rollback"
            raise
        else:
            state.exit = "commit"

    state.plain = create_autospec(datasets.get_catalogue_cursor, side_effect=scope)
    state.search = create_autospec(datasets.get_catalogue_search_cursor, side_effect=scope)
    monkeypatch.setattr(datasets, "get_catalogue_cursor", state.plain)
    monkeypatch.setattr(datasets, "get_catalogue_search_cursor", state.search)
    return state


@pytest.mark.parametrize("timeout_ms", [0, -1, 30_001, True, False, None, "2000", 1.5])
async def test_count_refuses_invalid_timeout_before_acquiring_sql(count_scope, timeout_ms):
    """Check count refuses invalid timeout before acquiring SQL (ValueError)."""
    with pytest.raises(ValueError, match="Search count timeout"):
        await datasets.count_search_datasets(
            count_scope.pool,
            "public",
            configured_sources=_SOURCES,
            timeout_ms=timeout_ms,
        )
    count_scope.plain.assert_not_called()
    count_scope.search.assert_not_called()


@pytest.mark.parametrize("prior", ["0", "25ms", "750ms", "12s", "1min"])
async def test_success_restores_exact_prior_setting_and_defaults_to_2000ms(count_scope, prior):
    """Check success restores exact prior setting and defaults to 2000ms."""
    count_scope.cursor.fetchone.side_effect = [(prior,), (7,)]
    assert (
        await datasets.count_search_datasets(
            count_scope.pool, "public", configured_sources=_SOURCES
        )
        == 7
    )
    calls = count_scope.cursor.execute.call_args_list
    assert len(calls) == 5
    assert calls[0].args == (
        "SELECT public.catalogue_guard_search_policy(%s)",
        (datasets.build_catalogue_policy(_SOURCES).fingerprint,),
    )
    assert calls[1].args == ("SELECT current_setting('statement_timeout')",)
    assert calls[2].args[1] == (2000, 2000)
    # The server evaluates the shorter bound, including zero = unlimited.
    assert "LEAST" in calls[2].args[0]
    assert "interval '0'" in calls[2].args[0]
    assert calls[3].args[0].as_string() == (
        "SELECT COUNT(*) FROM public.catalogue_match_ids(%(page_query)s)"
    )
    context = calls[3].args[1]["page_query"].obj
    assert context["mode"] == "empty"
    assert context["fingerprint"] == calls[0].args[1][0]
    assert calls[4].args == ("SELECT set_config('statement_timeout', %s, true)", (prior,))
    assert count_scope.exit == "commit"
    count_scope.plain.assert_called_once_with(count_scope.pool, "public", row_factory=tuple_row)
    count_scope.search.assert_not_called()


async def test_nonempty_count_uses_current_search_policy_and_explicit_requested_budget(count_scope):
    """Check nonempty count uses current search policy and explicit requested budget."""
    assert (
        await datasets.count_search_datasets(
            count_scope.pool,
            "public",
            '"oral history"',
            keyword="interview",
            configured_sources=_SOURCES,
            timeout_ms=120,
        )
        == 7
    )
    count_scope.plain.assert_not_called()
    args, kwargs = count_scope.search.call_args
    assert args[:2] == (count_scope.pool, "public")
    assert args[2]["app.search_term"] == '"oral history"'
    assert kwargs == {"row_factory": tuple_row}
    calls = count_scope.cursor.execute.call_args_list
    assert calls[0].args == (
        "SELECT public.catalogue_guard_search_policy(%s)",
        (datasets.build_catalogue_policy(_SOURCES).fingerprint,),
    )
    assert calls[2].args[1] == (120, 120)
    context = calls[3].args[1]["page_query"].obj
    assert context["keyword"] == "interview"
    assert context["term"] == '"oral history"'
    assert context["fingerprint"] == calls[0].args[1][0]


async def test_database_error_propagates_through_transaction_rollback_without_restore_sql(
    count_scope,
):
    """Check database error propagates through transaction rollback without restore SQL."""
    failure = DatabaseError("synthetic count failure")

    async def execute(statement, _parameters=None):
        """Raise the configured failure only for the composed COUNT query."""
        if not isinstance(statement, str) and "COUNT(*)" in statement.as_string():
            raise failure

    count_scope.cursor.execute.side_effect = execute
    with pytest.raises(DatabaseError) as caught:
        await datasets.count_search_datasets(
            count_scope.pool, "public", configured_sources=_SOURCES
        )
    assert caught.value is failure
    assert count_scope.exit == "rollback"
    assert count_scope.cursor.execute.await_count == 4
    assert not any(
        call.args[0] == "SELECT set_config('statement_timeout', %s, true)"
        for call in count_scope.cursor.execute.call_args_list
    )


async def test_stale_policy_refuses_before_reading_timeout_or_counting(count_scope):
    """Check stale policy refuses before reading timeout or counting (SearchUnavailable)."""
    count_scope.cursor.execute.side_effect = ObjectNotInPrerequisiteState("stale policy")
    with pytest.raises(SearchUnavailable):
        await datasets.count_search_datasets(
            count_scope.pool, "public", configured_sources=_SOURCES
        )
    count_scope.cursor.execute.assert_awaited_once_with(
        "SELECT public.catalogue_guard_search_policy(%s)",
        (datasets.build_catalogue_policy(_SOURCES).fingerprint,),
    )
    count_scope.cursor.fetchone.assert_not_awaited()
    assert count_scope.exit == "rollback"


@pytest.mark.parametrize(
    ("rows", "message"),
    [([None], "timeout query returned no row"), ([("0",), None], "count query returned no row")],
)
async def test_missing_count_contract_rows_raise_and_roll_back(count_scope, rows, message):
    """Check missing count contract rows raise and roll back (RuntimeError)."""
    count_scope.cursor.fetchone.side_effect = rows
    with pytest.raises(RuntimeError, match=message):
        await datasets.count_search_datasets(
            count_scope.pool, "public", configured_sources=_SOURCES
        )
    assert count_scope.exit == "rollback"

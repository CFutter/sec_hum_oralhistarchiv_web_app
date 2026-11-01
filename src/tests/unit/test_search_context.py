"""Bound search scopes reject invalid inputs and delegate rollback to the transaction."""

import asyncio
from contextlib import asynccontextmanager
from types import MappingProxyType, SimpleNamespace
from unittest.mock import create_autospec, patch

import pytest
from psycopg.rows import tuple_row

from app.services import db
from tests.fixtures import make_async_cursor, make_mock_pool

SEARCH_KEYS = (
    "app.search_term",
    "app.search_pattern",
    "app.search_mode",
    "app.search_field_masks",
)
OUTER = {
    "app.search_term": "outer oral history",
    "app.search_pattern": "%outer oral history%",
    "app.search_mode": "auto",
    "app.search_field_masks": '{"title":"public"}',
}
INNER = {
    "app.search_term": "inner interview",
    "app.search_pattern": "%inner interview%",
    "app.search_mode": "literal",
    "app.search_field_masks": '{"description":"registered"}',
}


@pytest.fixture
def scope_seam(monkeypatch):
    """Observe the public catalogue seam without simulating PostgreSQL rollback."""
    state = SimpleNamespace(
        pool=make_mock_pool(), previous=[], scopes=[], cursors=[], events=[], fail_binding=None
    )

    @asynccontextmanager
    async def setting_cursor(*, row_factory):
        """Yield a new settings cursor and record scope entry, SQL, and exit."""
        assert row_factory is tuple_row
        index = len(state.scopes)
        scope = make_async_cursor(fetchone=state.previous.pop(0))
        state.scopes.append(scope)

        async def execute(query, params=None):
            """Record settings SQL and inject the configured set_config binding failure."""
            state.events.append(("sql", index, query, params))
            if state.fail_binding is not None and "set_config(" in query:
                raise state.fail_binding

        scope.execute.side_effect = execute
        state.events.append(("scope_enter", index))
        try:
            yield scope
        finally:
            state.events.append(("scope_exit", index))

    connection = SimpleNamespace(cursor=setting_cursor)

    @asynccontextmanager
    async def catalogue(pool, viewer_tier, row_factory):
        """Yield a new catalogue cursor and record commit or propagated rollback."""
        assert pool is state.pool
        index = len(state.cursors)
        cursor = make_async_cursor()
        cursor.connection = connection
        state.cursors.append(cursor)
        state.events.append(("catalogue_enter", index, viewer_tier, row_factory))
        try:
            yield cursor
        except BaseException as error:
            state.events.append(("rollback", index, type(error)))
            raise
        else:
            state.events.append(("commit", index))

    state.acquire = create_autospec(db.get_catalogue_cursor, side_effect=catalogue)
    monkeypatch.setattr(db, "get_catalogue_cursor", state.acquire)
    return state


@pytest.mark.parametrize("invalid", ("missing_key", "extra_key", "nontext_value"))
async def test_search_context_rejects_invalid_mapping_before_catalogue_acquisition(
    scope_seam, invalid
):
    """Check search context rejects invalid mapping before catalogue acquisition (ValueError)."""
    context = dict(OUTER)
    if invalid == "missing_key":
        context.pop("app.search_pattern")
    elif invalid == "extra_key":
        context["app.unreviewed_setting"] = "private"
    else:
        context["app.search_term"] = 123

    with pytest.raises(ValueError, match="Invalid catalogue search context"):
        async with db.get_catalogue_search_cursor(scope_seam.pool, "public", context):
            pytest.fail("Invalid search context reached the caller")
    scope_seam.acquire.assert_not_called()


async def test_search_context_rejects_unknown_mode_before_catalogue_acquisition(scope_seam):
    """Check search context rejects unknown mode before catalogue acquisition (ValueError)."""
    context = {**OUTER, "app.search_mode": "WEB"}
    with pytest.raises(ValueError, match="Invalid catalogue search mode"):
        async with db.get_catalogue_search_cursor(scope_seam.pool, "public", context):
            pytest.fail("An unknown search mode reached the caller")
    scope_seam.acquire.assert_not_called()


async def test_search_context_retains_viewer_validation_before_database_acquisition():
    """Check search context retains viewer validation before database acquisition (ValueError)."""
    with patch.object(db, "get_db_cursor", autospec=True) as acquire:
        with pytest.raises(ValueError, match="Unknown catalogue viewer tier"):
            async with db.get_catalogue_search_cursor(make_mock_pool(), "Public", OUTER):
                pytest.fail("An invalid viewer tier reached the caller")
        acquire.assert_not_called()


async def test_search_context_binds_query_values_and_preserves_requested_cursor(scope_seam):
    """Check search context binds query values and preserves requested cursor."""
    context = MappingProxyType(
        {
            "app.search_term": "interview'); SELECT pg_sleep(10); --",
            "app.search_pattern": "%\\_'untrusted%",
            "app.search_mode": "web",
            "app.search_field_masks": '{"title":"public"}',
        }
    )
    scope_seam.previous.append(("old term", "old pattern", "literal", "old masks"))
    async with db.get_catalogue_search_cursor(
        scope_seam.pool, "registered", context, row_factory=None
    ) as cursor:
        assert cursor is scope_seam.cursors[0]
    scope_seam.acquire.assert_called_once_with(scope_seam.pool, "registered", row_factory=None)
    calls = scope_seam.scopes[0].execute.await_args_list
    assert len(calls) == 3
    read_query, read_values = calls[0].args
    assert read_query.count("current_setting(") == 4
    assert read_query.count("%s") == 4
    assert read_values == SEARCH_KEYS
    set_query, set_values = calls[1].args
    assert set_query.count("set_config(") == 4
    assert set_query.count("%s") == 8
    assert all(value not in set_query for value in context.values())
    assert set_values == (
        "app.search_term",
        context["app.search_term"],
        "app.search_pattern",
        context["app.search_pattern"],
        "app.search_mode",
        "web",
        "app.search_field_masks",
        context["app.search_field_masks"],
    )
    assert calls[2].args == (
        set_query,
        (
            "app.search_term",
            "old term",
            "app.search_pattern",
            "old pattern",
            "app.search_mode",
            "literal",
            "app.search_field_masks",
            "old masks",
        ),
    )
    scope_seam.scopes[0].fetchone.assert_awaited_once()
    assert scope_seam.events[-1] == ("commit", 0)


async def test_successful_nested_search_scopes_restore_all_previous_values_in_order(scope_seam):
    """Check successful nested search scopes restore all previous values in order."""
    scope_seam.previous.extend([(None, "previous pattern", "web", None), tuple(OUTER.values())])
    async with db.get_catalogue_search_cursor(scope_seam.pool, "vetted", OUTER):
        scope_seam.events.append(("outer_body",))
        async with db.get_catalogue_search_cursor(scope_seam.pool, "public", INNER):
            scope_seam.events.append(("inner_body",))
        scope_seam.events.append(("outer_resumed",))
    writes = [
        event for event in scope_seam.events if event[0] == "sql" and "set_config(" in event[2]
    ]
    assert [event[1] for event in writes] == [0, 1, 1, 0]
    assert writes[2][3] == (
        "app.search_term",
        "outer oral history",
        "app.search_pattern",
        "%outer oral history%",
        "app.search_mode",
        "auto",
        "app.search_field_masks",
        '{"title":"public"}',
    )
    assert writes[3][3] == (
        "app.search_term",
        "",
        "app.search_pattern",
        "previous pattern",
        "app.search_mode",
        "web",
        "app.search_field_masks",
        "",
    )
    assert scope_seam.events.index(writes[2]) < scope_seam.events.index(("commit", 1))
    assert scope_seam.events.index(("commit", 1)) < scope_seam.events.index(("outer_resumed",))
    assert scope_seam.events.index(writes[3]) < scope_seam.events.index(("commit", 0))


@pytest.mark.parametrize("previous", (None, ("only", "three", "values")))
async def test_invalid_previous_search_row_refuses_before_binding_or_yield(scope_seam, previous):
    """Check invalid previous search row refuses before binding or yield (RuntimeError)."""
    scope_seam.previous.append(previous)
    with pytest.raises(RuntimeError, match="search settings query returned an invalid row"):
        async with db.get_catalogue_search_cursor(scope_seam.pool, "public", OUTER):
            pytest.fail("An invalid settings snapshot reached the caller")
    assert scope_seam.scopes[0].execute.await_count == 1
    assert scope_seam.events[-1] == ("rollback", 0, RuntimeError)


@pytest.mark.parametrize("error_type", (RuntimeError, asyncio.CancelledError))
async def test_search_body_failure_propagates_without_running_success_restoration(
    scope_seam, error_type
):
    """Check search body failure propagates without running success restoration (error_type)."""
    scope_seam.previous.append(tuple(OUTER.values()))
    error = error_type("caller abort")
    with pytest.raises(error_type) as raised:
        async with db.get_catalogue_search_cursor(scope_seam.pool, "public", INNER):
            raise error
    assert raised.value is error
    assert scope_seam.scopes[0].execute.await_count == 2
    assert scope_seam.events[-1] == ("rollback", 0, error_type)


async def test_failed_search_binding_never_yields_and_preserves_the_database_error(scope_seam):
    """Check failed search binding never yields and preserves the database error (RuntimeError)."""
    scope_seam.previous.append(tuple(OUTER.values()))
    error = RuntimeError("binding failed")
    scope_seam.fail_binding = error
    with pytest.raises(RuntimeError, match="binding failed") as raised:
        async with db.get_catalogue_search_cursor(scope_seam.pool, "public", INNER):
            pytest.fail("Failed binding reached the caller")
    assert raised.value is error
    assert scope_seam.scopes[0].execute.await_count == 2
    assert scope_seam.events[-1] == ("rollback", 0, RuntimeError)

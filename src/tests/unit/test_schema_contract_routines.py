"""Unit tests for the function/trigger half of the PostgreSQL schema contract
and the top-level validator that ties every contract check together.

`app.services.db_schema_contract` declares, per application table, the exact
non-internal triggers PostgreSQL must have, plus a small set of managed
functions shared across tables. `app.services.db_drift` converts live
`pg_proc`/`pg_trigger` catalog rows into the same dataclasses and compares
them for exact equality. This module also covers `validate_schema_against_db`,
the entry point that runs every per-table column/constraint/index/trigger
check plus the function check, and requires the four table-keyed contract
maps to agree on which tables exist. These tests exercise catalog-row
conversion and contract comparison without a database; PostgreSQL catalog
behavior itself is covered by the integration companion module.
"""

from contextlib import asynccontextmanager
from dataclasses import replace
from unittest.mock import call, create_autospec

import pytest
from psycopg import AsyncCursor
from psycopg.rows import tuple_row

from app.services import db_drift
from app.services.db_schema_contract import (
    ColumnSpec,
    ConstraintSpec,
    FunctionSpec,
    IndexKeySpec,
    IndexSpec,
    TriggerSpec,
)

_POOL = object()

_COLUMN = ColumnSpec(
    pg_type="integer",
    nullable=False,
    identity="a",
)
_COLUMN_CONTRACT = {"id": _COLUMN}

_PRIMARY_KEY = ConstraintSpec(
    kind="primary_key",
    columns=("id",),
)
_CONSTRAINT_CONTRACT = {"probe_pkey": _PRIMARY_KEY}

_INDEX_KEY = IndexKeySpec(
    definition="created_at",
    operator_class="timestamptz_ops",
)
_INDEX = IndexSpec(
    unique=False,
    method="btree",
    keys=(_INDEX_KEY,),
)
_INDEX_CONTRACT = {"probe_created_at_idx": _INDEX}

_FUNCTION = FunctionSpec(
    identity_arguments="",
    result="trigger",
    language="plpgsql",
    volatility="v",
    security_definer=False,
    strict=False,
    parallel="u",
    configuration=(),
    source="BEGIN\n    RETURN NEW;\nEND;",
)
_FUNCTION_CONTRACT = {"probe_trigger()": _FUNCTION}

_TRIGGER = TriggerSpec(
    enabled="O",
    internal=False,
    trigger_type=23,
    function_schema_is_application=True,
    function_name="probe_trigger",
    definition=(
        "CREATE TRIGGER probe_trigger BEFORE INSERT OR UPDATE "
        "ON public.probe FOR EACH ROW EXECUTE FUNCTION probe_trigger()"
    ),
)
_TRIGGER_CONTRACT = {"probe_trigger": _TRIGGER}


def _mock_get_function_specs(monkeypatch, return_value):
    """Autospec `_get_function_specs` and install a fixed result."""
    mock = create_autospec(db_drift._get_function_specs, spec_set=True)
    mock.return_value = return_value
    monkeypatch.setattr(db_drift, "_get_function_specs", mock)
    return mock


def _mock_get_table_trigger_specs(monkeypatch, return_value):
    """Autospec `_get_table_trigger_specs` and install a fixed result."""
    mock = create_autospec(db_drift._get_table_trigger_specs, spec_set=True)
    mock.return_value = return_value
    monkeypatch.setattr(db_drift, "_get_table_trigger_specs", mock)
    return mock


def _install_catalog_rows(monkeypatch, rows):
    """Replace get_db_cursor with a tuple-row cursor returning rows."""
    cursor = create_autospec(AsyncCursor, instance=True)
    cursor.fetchall.return_value = rows

    fake_get_db_cursor = create_autospec(db_drift.get_db_cursor, spec_set=True)

    @asynccontextmanager
    async def _cursor_context(pool, *, row_factory):
        assert pool is _POOL
        assert row_factory is tuple_row
        yield cursor

    fake_get_db_cursor.side_effect = _cursor_context
    monkeypatch.setattr(db_drift, "get_db_cursor", fake_get_db_cursor)
    return cursor


class TestFunctionCatalogConversion:
    """`_get_function_specs` converts `pg_proc` rows for managed functions."""

    async def test_function_catalog_row_is_converted_exactly(self, monkeypatch):
        row = (
            "probe_trigger",
            "",
            "trigger",
            "plpgsql",
            "v",
            False,
            False,
            "u",
            [],
            "BEGIN\n    RETURN NEW;\nEND;",
        )
        cursor = _install_catalog_rows(monkeypatch, [row])

        actual = await db_drift._get_function_specs(
            _POOL,
            {"probe_trigger"},
        )

        assert actual == _FUNCTION_CONTRACT
        query, params = cursor.execute.await_args.args
        assert "function_record.prosrc" in query
        assert "function_record.proconfig" in query
        assert "function_record.prokind = 'f'" in query
        assert params == (["probe_trigger"],)

    async def test_function_catalog_rejects_wrong_row_shape(self, monkeypatch):
        _install_catalog_rows(monkeypatch, [("too", "short")])

        with pytest.raises(RuntimeError, match="expected 10 values"):
            await db_drift._get_function_specs(
                _POOL,
                {"probe_trigger"},
            )

    @pytest.mark.parametrize(
        ("volatility", "parallel", "message"),
        [
            ("?", "u", "Unsupported volatility"),
            ("v", "?", "Unsupported parallel mode"),
        ],
        ids=["volatility", "parallel"],
    )
    async def test_function_catalog_rejects_unknown_mode_codes(
        self,
        monkeypatch,
        volatility,
        parallel,
        message,
    ):
        row = (
            "probe_trigger",
            "",
            "trigger",
            "plpgsql",
            volatility,
            False,
            False,
            parallel,
            [],
            "BEGIN RETURN NEW; END;",
        )
        _install_catalog_rows(monkeypatch, [row])

        with pytest.raises(RuntimeError, match=message):
            await db_drift._get_function_specs(
                _POOL,
                {"probe_trigger"},
            )

    async def test_function_catalog_returns_empty_without_managed_names(self, monkeypatch):
        get_cursor = create_autospec(db_drift.get_db_cursor, spec_set=True)
        monkeypatch.setattr(db_drift, "get_db_cursor", get_cursor)

        assert await db_drift._get_function_specs(_POOL, set()) == {}
        get_cursor.assert_not_called()


class TestFunctionContract:
    """`assert_function_contract` verifies exact managed-function shape."""

    async def test_function_check_accepts_exact_contract(self, monkeypatch):
        get_specs = _mock_get_function_specs(monkeypatch, dict(_FUNCTION_CONTRACT))

        await db_drift.assert_function_contract(
            _POOL,
            _FUNCTION_CONTRACT,
        )

        get_specs.assert_awaited_once_with(_POOL, {"probe_trigger"})

    async def test_function_check_rejects_invalid_contract_signature(self, monkeypatch):
        get_specs = _mock_get_function_specs(monkeypatch, None)

        with pytest.raises(RuntimeError, match="Invalid function-contract signature"):
            await db_drift.assert_function_contract(
                _POOL,
                {"probe_trigger": _FUNCTION},
            )

        get_specs.assert_not_called()

    async def test_function_check_rejects_missing_function(self, monkeypatch):
        _mock_get_function_specs(monkeypatch, {})

        with pytest.raises(RuntimeError, match=r"missing functions.*probe_trigger\(\)"):
            await db_drift.assert_function_contract(
                _POOL,
                _FUNCTION_CONTRACT,
            )

    async def test_function_check_rejects_unexpected_overload(self, monkeypatch):
        actual = {
            **_FUNCTION_CONTRACT,
            "probe_trigger(integer)": replace(
                _FUNCTION,
                identity_arguments="integer",
            ),
        }
        _mock_get_function_specs(monkeypatch, actual)

        with pytest.raises(
            RuntimeError,
            match=r"unexpected function overloads.*probe_trigger\(integer\)",
        ):
            await db_drift.assert_function_contract(
                _POOL,
                _FUNCTION_CONTRACT,
            )

    async def test_function_check_allows_explicit_transitional_overload(self, monkeypatch):
        actual = {
            **_FUNCTION_CONTRACT,
            "probe_trigger(integer)": replace(
                _FUNCTION,
                identity_arguments="integer",
            ),
        }
        _mock_get_function_specs(monkeypatch, actual)

        await db_drift.assert_function_contract(
            _POOL,
            _FUNCTION_CONTRACT,
            allowed_extra_functions={"probe_trigger(integer)"},
        )

    @pytest.mark.parametrize(
        "actual_function",
        [
            replace(_FUNCTION, identity_arguments="integer"),
            replace(_FUNCTION, result="integer"),
            replace(_FUNCTION, language="sql"),
            replace(_FUNCTION, volatility="s"),
            replace(_FUNCTION, security_definer=True),
            replace(_FUNCTION, strict=True),
            replace(_FUNCTION, parallel="s"),
            replace(_FUNCTION, configuration=("search_path=public",)),
            replace(_FUNCTION, source="BEGIN\n    RETURN NULL;\nEND;"),
        ],
        ids=[
            "identity-arguments",
            "result",
            "language",
            "volatility",
            "security-definer",
            "strict",
            "parallel",
            "configuration",
            "source",
        ],
    )
    async def test_function_check_rejects_structural_drift(
        self,
        monkeypatch,
        actual_function,
    ):
        _mock_get_function_specs(monkeypatch, {"probe_trigger()": actual_function})

        with pytest.raises(RuntimeError, match=r"function 'probe_trigger\(\)'"):
            await db_drift.assert_function_contract(
                _POOL,
                _FUNCTION_CONTRACT,
            )


class TestTriggerCatalogConversion:
    """`_get_table_trigger_specs` converts `pg_trigger` rows exactly."""

    async def test_trigger_catalog_row_is_converted_exactly(self, monkeypatch):
        row = (
            "probe_trigger",
            "O",
            False,
            23,
            True,
            "probe_trigger",
            _TRIGGER.definition,
        )
        cursor = _install_catalog_rows(monkeypatch, [row])

        actual = await db_drift._get_table_trigger_specs(
            _POOL,
            "probe",
        )

        assert actual == _TRIGGER_CONTRACT
        query, params = cursor.execute.await_args.args
        assert "NOT trigger_record.tgisinternal" in query
        assert "trigger_record.tgtype::integer" in query
        assert "pg_get_triggerdef" in query
        assert params == ("probe",)

    async def test_trigger_catalog_rejects_wrong_row_shape(self, monkeypatch):
        _install_catalog_rows(monkeypatch, [("too", "short")])

        with pytest.raises(RuntimeError, match="expected 7 values"):
            await db_drift._get_table_trigger_specs(
                _POOL,
                "probe",
            )

    async def test_trigger_catalog_rejects_unknown_enabled_mode(self, monkeypatch):
        row = (
            "probe_trigger",
            "?",
            False,
            23,
            True,
            "probe_trigger",
            _TRIGGER.definition,
        )
        _install_catalog_rows(monkeypatch, [row])

        with pytest.raises(RuntimeError, match="Unsupported enabled mode"):
            await db_drift._get_table_trigger_specs(
                _POOL,
                "probe",
            )


class TestTriggerContract:
    """`assert_table_trigger_contract` verifies exact non-internal trigger shape."""

    async def test_trigger_check_accepts_exact_contract(self, monkeypatch):
        get_specs = _mock_get_table_trigger_specs(monkeypatch, dict(_TRIGGER_CONTRACT))

        await db_drift.assert_table_trigger_contract(
            _POOL,
            "probe",
            _TRIGGER_CONTRACT,
        )

        get_specs.assert_awaited_once_with(_POOL, "probe")

    async def test_trigger_check_rejects_missing_trigger(self, monkeypatch):
        _mock_get_table_trigger_specs(monkeypatch, {})

        with pytest.raises(RuntimeError, match=r"missing triggers.*probe_trigger"):
            await db_drift.assert_table_trigger_contract(
                _POOL,
                "probe",
                _TRIGGER_CONTRACT,
            )

    async def test_trigger_check_rejects_unexpected_trigger(self, monkeypatch):
        actual = {
            **_TRIGGER_CONTRACT,
            "legacy_trigger": _TRIGGER,
        }
        _mock_get_table_trigger_specs(monkeypatch, actual)

        with pytest.raises(RuntimeError, match=r"unexpected triggers.*legacy_trigger"):
            await db_drift.assert_table_trigger_contract(
                _POOL,
                "probe",
                _TRIGGER_CONTRACT,
            )

    async def test_trigger_check_allows_explicit_transitional_trigger(self, monkeypatch):
        actual = {
            **_TRIGGER_CONTRACT,
            "legacy_trigger": _TRIGGER,
        }
        _mock_get_table_trigger_specs(monkeypatch, actual)

        await db_drift.assert_table_trigger_contract(
            _POOL,
            "probe",
            _TRIGGER_CONTRACT,
            allowed_extra_triggers={"legacy_trigger"},
        )

    @pytest.mark.parametrize(
        "actual_trigger",
        [
            replace(_TRIGGER, enabled="D"),
            replace(_TRIGGER, internal=True),
            replace(_TRIGGER, trigger_type=7),
            replace(_TRIGGER, function_schema_is_application=False),
            replace(_TRIGGER, function_name="other_trigger_function"),
            replace(_TRIGGER, definition="CREATE TRIGGER changed ..."),
        ],
        ids=[
            "enabled",
            "internal",
            "trigger-type",
            "function-schema",
            "function-name",
            "definition",
        ],
    )
    async def test_trigger_check_rejects_structural_drift(
        self,
        monkeypatch,
        actual_trigger,
    ):
        _mock_get_table_trigger_specs(monkeypatch, {"probe_trigger": actual_trigger})

        with pytest.raises(RuntimeError, match=r"trigger 'probe_trigger'"):
            await db_drift.assert_table_trigger_contract(
                _POOL,
                "probe",
                _TRIGGER_CONTRACT,
            )


class TestFullValidatorWiring:
    """`validate_schema_against_db` runs every per-table and function check."""

    async def test_validate_schema_runs_all_contract_checks(self, monkeypatch):
        column_contracts = {
            "probe": _COLUMN_CONTRACT,
            "probe_two": _COLUMN_CONTRACT,
        }
        constraint_contracts = {
            "probe": _CONSTRAINT_CONTRACT,
            "probe_two": _CONSTRAINT_CONTRACT,
        }
        index_contracts = {
            "probe": _INDEX_CONTRACT,
            "probe_two": _INDEX_CONTRACT,
        }
        trigger_contracts = {
            "probe": _TRIGGER_CONTRACT,
            "probe_two": {},
        }

        monkeypatch.setattr(
            db_drift,
            "TABLE_COLUMN_CONTRACTS",
            column_contracts,
        )
        monkeypatch.setattr(
            db_drift,
            "TABLE_CONSTRAINT_CONTRACTS",
            constraint_contracts,
        )
        monkeypatch.setattr(
            db_drift,
            "TABLE_INDEX_CONTRACTS",
            index_contracts,
        )
        monkeypatch.setattr(
            db_drift,
            "TRIGGER_CONTRACTS",
            trigger_contracts,
        )
        monkeypatch.setattr(
            db_drift,
            "FUNCTION_CONTRACTS",
            _FUNCTION_CONTRACT,
        )

        check_columns = create_autospec(
            db_drift.assert_table_column_contract,
        )
        check_constraints = create_autospec(
            db_drift.assert_table_constraint_contract,
        )
        check_indexes = create_autospec(
            db_drift.assert_table_index_contract,
        )
        check_triggers = create_autospec(
            db_drift.assert_table_trigger_contract,
        )
        check_functions = create_autospec(
            db_drift.assert_function_contract,
        )

        monkeypatch.setattr(
            db_drift,
            "assert_table_column_contract",
            check_columns,
        )
        monkeypatch.setattr(
            db_drift,
            "assert_table_constraint_contract",
            check_constraints,
        )
        monkeypatch.setattr(
            db_drift,
            "assert_table_index_contract",
            check_indexes,
        )
        monkeypatch.setattr(
            db_drift,
            "assert_table_trigger_contract",
            check_triggers,
        )
        monkeypatch.setattr(
            db_drift,
            "assert_function_contract",
            check_functions,
        )

        await db_drift.validate_schema_against_db(_POOL)

        expected_table_calls = [
            call(_POOL, "probe", _COLUMN_CONTRACT),
            call(_POOL, "probe_two", _COLUMN_CONTRACT),
        ]
        assert check_columns.await_args_list == expected_table_calls

        assert check_constraints.await_args_list == [
            call(_POOL, "probe", _CONSTRAINT_CONTRACT),
            call(_POOL, "probe_two", _CONSTRAINT_CONTRACT),
        ]
        assert check_indexes.await_args_list == [
            call(_POOL, "probe", _INDEX_CONTRACT),
            call(_POOL, "probe_two", _INDEX_CONTRACT),
        ]
        assert check_triggers.await_args_list == [
            call(_POOL, "probe", _TRIGGER_CONTRACT),
            call(_POOL, "probe_two", {}),
        ]
        check_functions.assert_awaited_once_with(
            _POOL,
            _FUNCTION_CONTRACT,
        )

    @pytest.mark.parametrize(
        "missing_map",
        ["columns", "constraints", "indexes", "triggers"],
    )
    async def test_validate_schema_rejects_mismatched_table_sets(
        self,
        monkeypatch,
        missing_map,
    ):
        column_contracts = {"probe": _COLUMN_CONTRACT}
        constraint_contracts = {"probe": _CONSTRAINT_CONTRACT}
        index_contracts = {"probe": _INDEX_CONTRACT}
        trigger_contracts = {"probe": _TRIGGER_CONTRACT}

        if missing_map == "columns":
            column_contracts = {}
        elif missing_map == "constraints":
            constraint_contracts = {}
        elif missing_map == "indexes":
            index_contracts = {}
        else:
            trigger_contracts = {}

        monkeypatch.setattr(
            db_drift,
            "TABLE_COLUMN_CONTRACTS",
            column_contracts,
        )
        monkeypatch.setattr(
            db_drift,
            "TABLE_CONSTRAINT_CONTRACTS",
            constraint_contracts,
        )
        monkeypatch.setattr(
            db_drift,
            "TABLE_INDEX_CONTRACTS",
            index_contracts,
        )
        monkeypatch.setattr(
            db_drift,
            "TRIGGER_CONTRACTS",
            trigger_contracts,
        )

        with pytest.raises(RuntimeError, match="table sets do not match"):
            await db_drift.validate_schema_against_db(_POOL)

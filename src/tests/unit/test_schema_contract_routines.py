"""Unit tests for the function/trigger half of the PostgreSQL schema contract and the top-level
validator that ties every contract check together.
"""

from contextlib import asynccontextmanager
from dataclasses import replace
from unittest.mock import call, create_autospec

import pytest
from psycopg import AsyncCursor
from psycopg.rows import tuple_row

from app.services import db_drift
from app.services.db_schema_contract import (
    FUNCTION_CONTRACTS,
    ColumnSpec,
    ConstraintSpec,
    FunctionSpec,
    IndexKeySpec,
    IndexSpec,
    PolicySpec,
    RowSecuritySpec,
    TriggerSpec,
    ViewSpec,
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
        """Yield the scripted cursor after checking the database boundary."""
        assert pool is _POOL
        assert row_factory is tuple_row
        yield cursor

    fake_get_db_cursor.side_effect = _cursor_context
    monkeypatch.setattr(db_drift, "get_db_cursor", fake_get_db_cursor)
    return cursor


class TestFunctionCatalogConversion:
    """`_get_function_specs` converts `pg_proc` rows for managed functions."""

    async def test_function_catalog_row_is_converted_exactly(self, monkeypatch):
        """Check function catalog row is converted exactly."""
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

    async def test_named_catalogue_arguments_match_the_declared_contract_key(self, monkeypatch):
        # PostgreSQL includes declared argument names in identity arguments.
        # A type-only mapping key would make startup reject the fresh schema.
        """Check named catalogue arguments match the declared contract key."""
        arguments = (
            "p_anchor integer, p_ceiling integer, p_backward boolean, "
            "p_limit integer, p_offset integer, p_query jsonb"
        )
        signature = f"catalogue_page_ids({arguments})"
        expected = FUNCTION_CONTRACTS[signature]
        row = (
            "catalogue_page_ids",
            arguments,
            "SETOF integer",
            "plpgsql",
            "s",
            True,
            False,
            "u",
            ["search_path=pg_catalog, public"],
            expected.source,
        )
        _install_catalog_rows(monkeypatch, [row])
        actual = await db_drift._get_function_specs(_POOL, {"catalogue_page_ids"})
        assert actual == {signature: expected}

    async def test_function_catalog_rejects_wrong_row_shape(self, monkeypatch):
        """Check function catalog rejects wrong row shape (RuntimeError)."""
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
        """Check function catalog rejects unknown mode codes (RuntimeError)."""
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
        """Check function catalog returns empty without managed names."""
        get_cursor = create_autospec(db_drift.get_db_cursor, spec_set=True)
        monkeypatch.setattr(db_drift, "get_db_cursor", get_cursor)

        assert await db_drift._get_function_specs(_POOL, set()) == {}
        get_cursor.assert_not_called()


class TestFunctionContract:
    """`assert_function_contract` verifies exact managed-function shape."""

    async def test_function_check_accepts_exact_contract(self, monkeypatch):
        """Check function check accepts exact contract."""
        get_specs = _mock_get_function_specs(monkeypatch, dict(_FUNCTION_CONTRACT))

        await db_drift.assert_function_contract(
            _POOL,
            _FUNCTION_CONTRACT,
        )

        get_specs.assert_awaited_once_with(_POOL, {"probe_trigger"})

    async def test_function_check_rejects_invalid_contract_signature(self, monkeypatch):
        """Check function check rejects invalid contract signature (RuntimeError)."""
        get_specs = _mock_get_function_specs(monkeypatch, None)

        with pytest.raises(RuntimeError, match="Invalid function-contract signature"):
            await db_drift.assert_function_contract(
                _POOL,
                {"probe_trigger": _FUNCTION},
            )

        get_specs.assert_not_called()

    async def test_function_check_rejects_missing_function(self, monkeypatch):
        """Check function check rejects missing function (RuntimeError)."""
        _mock_get_function_specs(monkeypatch, {})

        with pytest.raises(RuntimeError, match=r"missing functions.*probe_trigger\(\)"):
            await db_drift.assert_function_contract(
                _POOL,
                _FUNCTION_CONTRACT,
            )

    async def test_function_check_rejects_unexpected_overload(self, monkeypatch):
        """Check function check rejects unexpected overload (RuntimeError)."""
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
        """Check function check allows explicit transitional overload."""
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
        """Check function check rejects structural drift (RuntimeError)."""
        _mock_get_function_specs(monkeypatch, {"probe_trigger()": actual_function})

        with pytest.raises(RuntimeError, match=r"function 'probe_trigger\(\)'"):
            await db_drift.assert_function_contract(
                _POOL,
                _FUNCTION_CONTRACT,
            )


class TestTriggerCatalogConversion:
    """`_get_table_trigger_specs` converts `pg_trigger` rows exactly."""

    async def test_trigger_catalog_row_is_converted_exactly(self, monkeypatch):
        """Check trigger catalog row is converted exactly."""
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
        """Check trigger catalog rejects wrong row shape (RuntimeError)."""
        _install_catalog_rows(monkeypatch, [("too", "short")])

        with pytest.raises(RuntimeError, match="expected 7 values"):
            await db_drift._get_table_trigger_specs(
                _POOL,
                "probe",
            )

    async def test_trigger_catalog_rejects_unknown_enabled_mode(self, monkeypatch):
        """Check trigger catalog rejects unknown enabled mode (RuntimeError)."""
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
        """Check trigger check accepts exact contract."""
        get_specs = _mock_get_table_trigger_specs(monkeypatch, dict(_TRIGGER_CONTRACT))

        await db_drift.assert_table_trigger_contract(
            _POOL,
            "probe",
            _TRIGGER_CONTRACT,
        )

        get_specs.assert_awaited_once_with(_POOL, "probe")

    async def test_trigger_check_rejects_missing_trigger(self, monkeypatch):
        """Check trigger check rejects missing trigger (RuntimeError)."""
        _mock_get_table_trigger_specs(monkeypatch, {})

        with pytest.raises(RuntimeError, match=r"missing triggers.*probe_trigger"):
            await db_drift.assert_table_trigger_contract(
                _POOL,
                "probe",
                _TRIGGER_CONTRACT,
            )

    async def test_trigger_check_rejects_unexpected_trigger(self, monkeypatch):
        """Check trigger check rejects unexpected trigger (RuntimeError)."""
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
        """Check trigger check allows explicit transitional trigger."""
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
        """Check trigger check rejects structural drift (RuntimeError)."""
        _mock_get_table_trigger_specs(monkeypatch, {"probe_trigger": actual_trigger})

        with pytest.raises(RuntimeError, match=r"trigger 'probe_trigger'"):
            await db_drift.assert_table_trigger_contract(
                _POOL,
                "probe",
                _TRIGGER_CONTRACT,
            )


class TestFullValidatorWiring:
    """`validate_schema_against_db` runs every table, view and function check."""

    async def test_validate_schema_runs_all_contract_checks(self, monkeypatch):
        """Check validate schema runs all contract checks."""
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
        row_security_contracts = {
            "probe": RowSecuritySpec(enabled=True, forced=False),
            "probe_two": RowSecuritySpec(enabled=False, forced=False),
        }
        policy_contracts = {
            "probe": {
                "probe_read": PolicySpec(
                    command="r", permissive=True, roles=("PUBLIC",), using="true", with_check=None
                )
            },
            "probe_two": {},
        }
        view_contracts = {
            "probe_view": ViewSpec(
                columns=(("id", "integer"),),
                definition="SELECT id FROM public.probe;",
                options=("security_barrier=true", "security_invoker=false"),
            )
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
        monkeypatch.setattr(db_drift, "TABLE_ROW_SECURITY_CONTRACTS", row_security_contracts)
        monkeypatch.setattr(db_drift, "TABLE_POLICY_CONTRACTS", policy_contracts)
        monkeypatch.setattr(db_drift, "VIEW_CONTRACTS", view_contracts)

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
        check_row_security = create_autospec(db_drift.assert_table_row_security_contract)
        check_views = create_autospec(db_drift.assert_view_contract)

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
        monkeypatch.setattr(db_drift, "assert_table_row_security_contract", check_row_security)
        monkeypatch.setattr(db_drift, "assert_view_contract", check_views)

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
        assert check_row_security.await_args_list == [
            call(_POOL, name, row_security_contracts[name], policy_contracts[name])
            for name in ("probe", "probe_two")
        ]
        check_views.assert_awaited_once_with(_POOL, "probe_view", view_contracts["probe_view"])
        check_functions.assert_awaited_once_with(
            _POOL,
            _FUNCTION_CONTRACT,
        )

    @pytest.mark.parametrize(
        "missing_map",
        ["columns", "constraints", "indexes", "triggers", "row_security", "policies"],
    )
    async def test_validate_schema_rejects_mismatched_table_sets(
        self,
        monkeypatch,
        missing_map,
    ):
        """Check validate schema rejects mismatched table sets (RuntimeError)."""
        column_contracts = {"probe": _COLUMN_CONTRACT}
        constraint_contracts = {"probe": _CONSTRAINT_CONTRACT}
        index_contracts = {"probe": _INDEX_CONTRACT}
        trigger_contracts = {"probe": _TRIGGER_CONTRACT}
        row_security_contracts = {"probe": RowSecuritySpec(enabled=True, forced=False)}
        policy_contracts: dict[str, dict[str, PolicySpec]] = {"probe": {}}

        if missing_map == "columns":
            column_contracts = {}
        elif missing_map == "constraints":
            constraint_contracts = {}
        elif missing_map == "indexes":
            index_contracts = {}
        elif missing_map == "triggers":
            trigger_contracts = {}
        elif missing_map == "row_security":
            row_security_contracts = {}
        else:
            policy_contracts = {}

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
        monkeypatch.setattr(db_drift, "TABLE_ROW_SECURITY_CONTRACTS", row_security_contracts)
        monkeypatch.setattr(db_drift, "TABLE_POLICY_CONTRACTS", policy_contracts)

        with pytest.raises(RuntimeError, match="table sets do not match"):
            await db_drift.validate_schema_against_db(_POOL)

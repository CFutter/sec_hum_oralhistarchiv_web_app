"""Unit tests for the index half of the PostgreSQL schema contract.

`app.services.db_schema_contract` declares, per application table, the exact
application-managed indexes (method, keys, operator classes, ordering,
included columns, predicate, and catalog flags) PostgreSQL must have.
`app.services.db_drift` converts live `pg_index` catalog rows into the same
dataclasses, excludes indexes owned by a PRIMARY KEY/UNIQUE/exclusion
constraint (those are validated through `pg_constraint` instead), and
compares the remainder for exact equality. These tests exercise catalog-row
conversion and contract comparison without a database; PostgreSQL catalog
behavior itself is covered by the integration companion module.
"""

from contextlib import asynccontextmanager
from dataclasses import replace
from unittest.mock import create_autospec

import pytest
from psycopg import AsyncCursor
from psycopg.rows import tuple_row

from app.services import db_drift
from app.services.db_schema_contract import IndexKeySpec, IndexSpec

_POOL = object()

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


def _mock_get_table_index_specs(monkeypatch, return_value):
    """Autospec `_get_table_index_specs` and install a fixed result."""
    mock = create_autospec(db_drift._get_table_index_specs, spec_set=True)
    mock.return_value = return_value
    monkeypatch.setattr(db_drift, "_get_table_index_specs", mock)
    return mock


class TestIndexCatalogConversion:
    """`_index_spec_from_row` converts one `pg_index` row exactly."""

    def test_index_row_conversion_preserves_operator_class_and_ordering(self):
        row = (
            "ix_modified",
            False,
            "btree",
            ["upstream_modified_at", "id"],
            ["timestamptz_ops", "int4_ops"],
            [1, 3],
            [],
            None,
            True,
            True,
            True,
            False,
        )

        assert db_drift._index_spec_from_row(row) == IndexSpec(
            unique=False,
            method="btree",
            keys=(
                IndexKeySpec(
                    definition="upstream_modified_at",
                    operator_class="timestamptz_ops",
                    descending=True,
                    nulls_first=False,
                ),
                IndexKeySpec(
                    definition="id",
                    operator_class="int4_ops",
                    descending=True,
                    nulls_first=True,
                ),
            ),
        )

    def test_index_row_conversion_preserves_expression_predicate_and_flags(self):
        row = (
            "idx_users_email_lower",
            True,
            "btree",
            ["lower(email)"],
            ["text_ops"],
            [0],
            ["id"],
            "(is_active = true)",
            False,
            False,
            False,
            False,
        )

        assert db_drift._index_spec_from_row(row) == IndexSpec(
            unique=True,
            method="btree",
            keys=(
                IndexKeySpec(
                    definition="lower(email)",
                    operator_class="text_ops",
                ),
            ),
            include_columns=("id",),
            predicate="(is_active = true)",
            valid=False,
            ready=False,
            live=False,
        )

    def test_index_row_conversion_rejects_wrong_query_shape(self):
        with pytest.raises(RuntimeError, match="expected 12 values"):
            db_drift._index_spec_from_row(("too", "short"))

    def test_index_row_conversion_rejects_inconsistent_key_metadata(self):
        row = (
            "broken_idx",
            False,
            "btree",
            ["first", "second"],
            ["text_ops"],
            [0, 0],
            [],
            None,
            True,
            True,
            True,
            False,
        )

        with pytest.raises(RuntimeError, match="Inconsistent key metadata"):
            db_drift._index_spec_from_row(row)

    def test_index_row_conversion_rejects_unsupported_access_method(self):
        row = (
            "hash_idx",
            False,
            "hash",
            ["value"],
            ["text_ops"],
            [0],
            [],
            None,
            True,
            True,
            True,
            False,
        )

        with pytest.raises(RuntimeError, match="Unsupported access method 'hash'"):
            db_drift._index_spec_from_row(row)

    def test_index_row_conversion_rejects_unknown_option_bits(self):
        row = (
            "broken_idx",
            False,
            "btree",
            ["value"],
            ["text_ops"],
            [4],
            [],
            None,
            True,
            True,
            True,
            False,
        )

        with pytest.raises(RuntimeError, match="Unsupported key options"):
            db_drift._index_spec_from_row(row)


class TestIndexCatalogQuery:
    """`_get_table_index_specs` queries `pg_index` for application-managed indexes."""

    async def test_index_catalog_query_excludes_constraint_owned_indexes(
        self,
        monkeypatch,
    ):
        row = (
            "probe_created_at_idx",
            False,
            "btree",
            ["created_at"],
            ["timestamptz_ops"],
            [0],
            [],
            None,
            True,
            True,
            True,
            False,
        )
        cursor = create_autospec(AsyncCursor, instance=True)
        cursor.fetchall.return_value = [row]

        fake_get_db_cursor = create_autospec(db_drift.get_db_cursor, spec_set=True)

        @asynccontextmanager
        async def _cursor_context(pool, *, row_factory):
            assert pool is _POOL
            assert row_factory is tuple_row
            yield cursor

        fake_get_db_cursor.side_effect = _cursor_context
        monkeypatch.setattr(db_drift, "get_db_cursor", fake_get_db_cursor)

        actual = await db_drift._get_table_index_specs(_POOL, "probe")

        assert actual == _INDEX_CONTRACT
        cursor.execute.assert_awaited_once()
        query, params = cursor.execute.await_args.args
        assert "owner_constraint.oid IS NULL" in query
        assert "index_record.indclass" in query
        assert "index_record.indoption" in query
        assert "index_record.indisvalid" in query
        assert params == ("probe",)


class TestIndexContract:
    """`assert_table_index_contract` verifies exact index shape."""

    async def test_index_check_accepts_exact_contract(self, monkeypatch):
        get_specs = _mock_get_table_index_specs(monkeypatch, dict(_INDEX_CONTRACT))

        await db_drift.assert_table_index_contract(
            _POOL,
            "probe",
            _INDEX_CONTRACT,
        )

        get_specs.assert_awaited_once_with(_POOL, "probe")

    async def test_index_check_rejects_missing_index(self, monkeypatch):
        _mock_get_table_index_specs(monkeypatch, {})

        with pytest.raises(
            RuntimeError,
            match=r"missing indexes.*probe_created_at_idx",
        ):
            await db_drift.assert_table_index_contract(
                _POOL,
                "probe",
                _INDEX_CONTRACT,
            )

    async def test_index_check_rejects_unexpected_index(self, monkeypatch):
        actual = {
            **_INDEX_CONTRACT,
            "legacy_idx": _INDEX,
        }
        _mock_get_table_index_specs(monkeypatch, actual)

        with pytest.raises(RuntimeError, match=r"unexpected indexes.*legacy_idx"):
            await db_drift.assert_table_index_contract(
                _POOL,
                "probe",
                _INDEX_CONTRACT,
            )

    async def test_index_check_allows_explicit_transitional_index(self, monkeypatch):
        actual = {
            **_INDEX_CONTRACT,
            "legacy_idx": _INDEX,
        }
        _mock_get_table_index_specs(monkeypatch, actual)

        await db_drift.assert_table_index_contract(
            _POOL,
            "probe",
            _INDEX_CONTRACT,
            allowed_extra_indexes={"legacy_idx"},
        )

    @pytest.mark.parametrize(
        "actual_index",
        [
            replace(_INDEX, unique=True),
            replace(_INDEX, method="gin"),
            replace(
                _INDEX,
                keys=(replace(_INDEX_KEY, definition="updated_at"),),
            ),
            replace(
                _INDEX,
                keys=(replace(_INDEX_KEY, operator_class="timestamp_ops"),),
            ),
            replace(
                _INDEX,
                keys=(replace(_INDEX_KEY, descending=True),),
            ),
            replace(
                _INDEX,
                keys=(replace(_INDEX_KEY, nulls_first=True),),
            ),
            replace(_INDEX, include_columns=("user_id",)),
            replace(_INDEX, predicate="(status = 'pending'::text)"),
            replace(_INDEX, valid=False),
            replace(_INDEX, ready=False),
            replace(_INDEX, live=False),
        ],
        ids=[
            "unique",
            "method",
            "definition",
            "operator-class",
            "descending",
            "nulls-first",
            "included-columns",
            "predicate",
            "valid",
            "ready",
            "live",
        ],
    )
    async def test_index_check_rejects_structural_drift(
        self,
        monkeypatch,
        actual_index,
    ):
        _mock_get_table_index_specs(monkeypatch, {"probe_created_at_idx": actual_index})

        with pytest.raises(RuntimeError, match=r"index 'probe_created_at_idx'"):
            await db_drift.assert_table_index_contract(
                _POOL,
                "probe",
                _INDEX_CONTRACT,
            )

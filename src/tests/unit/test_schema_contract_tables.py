"""Unit tests for the table-shape half of the PostgreSQL schema contract."""

from dataclasses import replace
from unittest.mock import create_autospec

import pytest

from app.services import db_drift
from app.services.db_schema_contract import (
    FUNCTION_CONTRACTS,
    SYNC_STATUS_CONSTRAINT_CONTRACT,
    TABLE_COLUMN_CONTRACTS,
    TABLE_CONSTRAINT_CONTRACTS,
    TABLE_INDEX_CONTRACTS,
    TABLE_POLICY_CONTRACTS,
    TABLE_ROW_SECURITY_CONTRACTS,
    TRIGGER_CONTRACTS,
    VIEW_CONTRACTS,
    ColumnSpec,
    ConstraintSpec,
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


def _mock_get_table_column_specs(monkeypatch, return_value):
    """Autospec `_get_table_column_specs` and install a fixed result."""
    mock = create_autospec(db_drift._get_table_column_specs, spec_set=True)
    mock.return_value = return_value
    monkeypatch.setattr(db_drift, "_get_table_column_specs", mock)
    return mock


def _mock_get_table_constraint_specs(monkeypatch, return_value):
    """Autospec `_get_table_constraint_specs` and install a fixed result."""
    mock = create_autospec(db_drift._get_table_constraint_specs, spec_set=True)
    mock.return_value = return_value
    monkeypatch.setattr(db_drift, "_get_table_constraint_specs", mock)
    return mock


class TestContractTableCoverage:
    """All six table-keyed maps agree; views have their own explicit contract."""

    def test_contract_maps_cover_the_same_tables(self):
        """Check contract maps cover the same tables."""
        expected_tables = {
            "oral_history_datasets",
            "catalogue_search_policy",
            "catalogue_search_public",
            "catalogue_search_registered",
            "catalogue_search_vetted",
            "dataset_admin_state",
            "sync_status",
            "ingestion_failures",
            "ingestion_quarantine",
            "source_security_state",
            "source_binding_acknowledgements",
            "security_audit_events",
            "security_audit_receipts",
            "anonymous_mail_issuance",
            "users",
            "totp_recovery_codes",
            "admin_promotion_requests",
            "federation_policy_state",
            "email_outbox",
            "sessions",
            "pending_totp_rotations",
        }

        assert set(TABLE_COLUMN_CONTRACTS) == expected_tables
        assert set(TABLE_CONSTRAINT_CONTRACTS) == expected_tables
        assert set(TABLE_INDEX_CONTRACTS) == expected_tables
        assert set(TRIGGER_CONTRACTS) == expected_tables
        assert set(TABLE_ROW_SECURITY_CONTRACTS) == expected_tables
        assert set(TABLE_POLICY_CONTRACTS) == expected_tables
        assert set(VIEW_CONTRACTS) == {
            "catalogue_discovery",
            "catalogue_search_candidates",
            "dataset_admin_catalogue",
        }
        assert VIEW_CONTRACTS["catalogue_search_candidates"].columns == (("id", "integer"),)
        assert set(FUNCTION_CONTRACTS) == {
            "catalogue_preserve_source_security_state()",
            "catalogue_audit_restriction_state()",
            "update_search_text()",
            "catalogue_projection_write_lock()",
            "catalogue_refresh_search_record(p_id integer)",
            "catalogue_refresh_search_projection()",
            "catalogue_replace_search_policy(p_expected text, p_fingerprint text, p_masks jsonb)",
            "catalogue_initialize_search_policy(p_fingerprint text, p_masks jsonb)",
            "catalogue_guard_search_policy(p_fingerprint text)",
            "catalogue_search_relation(p_query jsonb)",
            "catalogue_match_ids(p_query jsonb)",
            "catalogue_search_candidates()",
            "catalogue_scan_ceiling()",
            "catalogue_page_ids(p_anchor integer, p_ceiling integer, p_backward boolean, "
            "p_limit integer, p_offset integer, p_query jsonb)",
        }
        assert VIEW_CONTRACTS["catalogue_discovery"].columns == (
            ("id", "integer"),
            ("uuid", "text"),
            ("title", "text"),
            ("access_level", "text"),
            ("version", "text"),
            ("source", "text"),
            ("visibility_tier", "text"),
        )
        columns = TABLE_COLUMN_CONTRACTS["oral_history_datasets"]
        assert columns["search_vector_public"] == ColumnSpec("tsvector", nullable=False)
        assert columns["search_vector_full"] == ColumnSpec("tsvector", nullable=False)
        indexes = TABLE_INDEX_CONTRACTS["oral_history_datasets"]
        assert set(indexes) == {
            "idx_datasets_source",
            "idx_search_text_public_trgm",
            "idx_search_text_full_trgm",
            "idx_search_vector_public",
            "idx_search_vector_full",
            "ix_datasets_upstream_modified_at",
            "ix_datasets_keywords_gin",
            "ix_datasets_languages_gin",
        }
        for name in ("public", "full"):
            vector_index = indexes[f"idx_search_vector_{name}"]
            assert vector_index.method == "gin"
            assert len(vector_index.keys) == 1
            assert vector_index.keys[0].definition == f"search_vector_{name}"
            assert vector_index.keys[0].operator_class == "tsvector_ops"


class TestColumnContract:
    """`assert_table_column_contract` verifies exact column shape."""

    async def test_column_check_accepts_exact_contract(self, monkeypatch):
        """Check column check accepts exact contract."""
        get_specs = _mock_get_table_column_specs(monkeypatch, dict(_COLUMN_CONTRACT))

        await db_drift.assert_table_column_contract(
            _POOL,
            "probe",
            _COLUMN_CONTRACT,
        )

        get_specs.assert_awaited_once_with(_POOL, "probe")

    async def test_column_check_rejects_missing_columns(self, monkeypatch):
        """Check column check rejects missing columns (RuntimeError)."""
        _mock_get_table_column_specs(monkeypatch, {})

        with pytest.raises(
            RuntimeError,
            match=r"Schema drift on 'probe'.*missing columns.*'id'",
        ):
            await db_drift.assert_table_column_contract(
                _POOL,
                "probe",
                _COLUMN_CONTRACT,
            )

    async def test_column_check_rejects_unexpected_columns(self, monkeypatch):
        """Check column check rejects unexpected columns (RuntimeError)."""
        actual = {
            **_COLUMN_CONTRACT,
            "legacy_value": ColumnSpec("text", nullable=True),
        }
        _mock_get_table_column_specs(monkeypatch, actual)

        with pytest.raises(
            RuntimeError,
            match=r"unexpected columns.*legacy_value",
        ):
            await db_drift.assert_table_column_contract(
                _POOL,
                "probe",
                _COLUMN_CONTRACT,
            )

    async def test_column_check_allows_explicit_transitional_column(self, monkeypatch):
        """Check column check allows explicit transitional column."""
        actual = {
            **_COLUMN_CONTRACT,
            "legacy_value": ColumnSpec("text", nullable=True),
        }
        _mock_get_table_column_specs(monkeypatch, actual)

        await db_drift.assert_table_column_contract(
            _POOL,
            "probe",
            _COLUMN_CONTRACT,
            allowed_extra_columns={"legacy_value"},
        )

    @pytest.mark.parametrize(
        "actual_column",
        [
            replace(_COLUMN, pg_type="bigint"),
            replace(_COLUMN, nullable=True),
            replace(_COLUMN, default="0"),
            replace(_COLUMN, identity=""),
        ],
        ids=["type", "nullability", "default", "identity"],
    )
    async def test_column_check_rejects_structural_drift(
        self,
        monkeypatch,
        actual_column,
    ):
        """Check column check rejects structural drift (RuntimeError)."""
        _mock_get_table_column_specs(monkeypatch, {"id": actual_column})

        with pytest.raises(RuntimeError, match=r"column 'id'"):
            await db_drift.assert_table_column_contract(
                _POOL,
                "probe",
                _COLUMN_CONTRACT,
            )


class TestConstraintCatalogConversion:
    """`_constraint_spec_from_row` converts one `pg_constraint` row exactly."""

    def test_constraint_row_conversion_preserves_primary_key_columns(self):
        """Check constraint row conversion preserves primary key columns."""
        row = (
            "probe_pkey",
            "p",
            ["id"],
            None,
            [],
            None,
            " ",
            " ",
            "PRIMARY KEY (id)",
            False,
            False,
            True,
            False,
        )

        assert db_drift._constraint_spec_from_row(row) == _PRIMARY_KEY

    def test_constraint_row_conversion_preserves_canonical_check_definition(self):
        """Check constraint row conversion preserves canonical check definition."""
        definition = "CHECK ((attempt_count >= 0))"
        row = (
            "attempt_count_check",
            "c",
            ["attempt_count"],
            None,
            [],
            None,
            " ",
            " ",
            definition,
            False,
            False,
            True,
            False,
        )

        assert db_drift._constraint_spec_from_row(row) == ConstraintSpec(
            kind="check",
            check_definition=definition,
        )

    def test_constraint_row_conversion_preserves_foreign_key_behavior(self):
        """Check constraint row conversion preserves foreign key behavior."""
        row = (
            "sessions_user_id_fkey",
            "f",
            ["user_id"],
            "users",
            ["id"],
            True,
            "a",
            "c",
            "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE",
            False,
            False,
            True,
            False,
        )

        assert db_drift._constraint_spec_from_row(row) == ConstraintSpec(
            kind="foreign_key",
            columns=("user_id",),
            referenced_table="users",
            referenced_columns=("id",),
            on_update="NO ACTION",
            on_delete="CASCADE",
            references_application_schema=True,
        )

    def test_constraint_row_conversion_rejects_wrong_query_shape(self):
        """Check constraint row conversion rejects wrong query shape (RuntimeError)."""
        with pytest.raises(RuntimeError, match="expected 13 values"):
            db_drift._constraint_spec_from_row(("too", "short"))

    def test_constraint_row_conversion_rejects_unknown_kind(self):
        """Check constraint row conversion rejects unknown kind (RuntimeError)."""
        row = (
            "probe_unknown",
            "x",
            [],
            None,
            [],
            None,
            " ",
            " ",
            "EXCLUDE USING gist (...) ",
            False,
            False,
            True,
            False,
        )

        with pytest.raises(RuntimeError, match="Unsupported PostgreSQL constraint type"):
            db_drift._constraint_spec_from_row(row)

    def test_constraint_row_conversion_rejects_unknown_foreign_key_action(self):
        """Check constraint row conversion rejects unknown foreign key action (RuntimeError)."""
        row = (
            "probe_fkey",
            "f",
            ["user_id"],
            "users",
            ["id"],
            True,
            "?",
            "c",
            "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE",
            False,
            False,
            True,
            False,
        )

        with pytest.raises(RuntimeError, match="Unsupported foreign-key action"):
            db_drift._constraint_spec_from_row(row)


class TestConstraintContract:
    """`assert_table_constraint_contract` verifies exact constraint shape."""

    async def test_constraint_check_accepts_exact_contract(self, monkeypatch):
        """Check constraint check accepts exact contract."""
        get_specs = _mock_get_table_constraint_specs(monkeypatch, dict(_CONSTRAINT_CONTRACT))

        await db_drift.assert_table_constraint_contract(
            _POOL,
            "probe",
            _CONSTRAINT_CONTRACT,
        )

        get_specs.assert_awaited_once_with(_POOL, "probe")

    async def test_constraint_check_rejects_missing_constraint(self, monkeypatch):
        """Check constraint check rejects missing constraint (RuntimeError)."""
        _mock_get_table_constraint_specs(monkeypatch, {})

        with pytest.raises(
            RuntimeError,
            match=r"missing constraints.*probe_pkey",
        ):
            await db_drift.assert_table_constraint_contract(
                _POOL,
                "probe",
                _CONSTRAINT_CONTRACT,
            )

    async def test_constraint_check_rejects_unexpected_constraint(self, monkeypatch):
        """Check constraint check rejects unexpected constraint (RuntimeError)."""
        actual = {
            **_CONSTRAINT_CONTRACT,
            "legacy_check": ConstraintSpec(
                kind="check",
                check_definition="CHECK (true)",
            ),
        }
        _mock_get_table_constraint_specs(monkeypatch, actual)

        with pytest.raises(RuntimeError, match=r"unexpected constraints.*legacy_check"):
            await db_drift.assert_table_constraint_contract(
                _POOL,
                "probe",
                _CONSTRAINT_CONTRACT,
            )

    async def test_constraint_check_allows_explicit_transitional_constraint(
        self,
        monkeypatch,
    ):
        """Check constraint check allows explicit transitional constraint."""
        actual = {
            **_CONSTRAINT_CONTRACT,
            "legacy_check": ConstraintSpec(
                kind="check",
                check_definition="CHECK (true)",
            ),
        }
        _mock_get_table_constraint_specs(monkeypatch, actual)

        await db_drift.assert_table_constraint_contract(
            _POOL,
            "probe",
            _CONSTRAINT_CONTRACT,
            allowed_extra_constraints={"legacy_check"},
        )

    @pytest.mark.parametrize(
        "actual_constraint",
        [
            replace(_PRIMARY_KEY, kind="unique"),
            replace(_PRIMARY_KEY, columns=("other_id",)),
            replace(_PRIMARY_KEY, deferrable=True),
            replace(_PRIMARY_KEY, initially_deferred=True),
            replace(_PRIMARY_KEY, validated=False),
        ],
        ids=["kind", "columns", "deferrable", "deferred", "validated"],
    )
    async def test_constraint_check_rejects_structural_drift(
        self,
        monkeypatch,
        actual_constraint,
    ):
        """Check constraint check rejects structural drift (RuntimeError)."""
        _mock_get_table_constraint_specs(monkeypatch, {"probe_pkey": actual_constraint})

        with pytest.raises(RuntimeError, match=r"constraint 'probe_pkey'"):
            await db_drift.assert_table_constraint_contract(
                _POOL,
                "probe",
                _CONSTRAINT_CONTRACT,
            )

    async def test_constraint_check_rejects_changed_check_definition(self, monkeypatch):
        """Check constraint check rejects changed check definition (RuntimeError)."""
        expected = {
            "state_check": ConstraintSpec(
                kind="check",
                check_definition="CHECK ((state = 'ready'::text))",
            )
        }
        actual = {
            "state_check": ConstraintSpec(
                kind="check",
                check_definition="CHECK ((state = ANY (ARRAY['ready'::text, 'bad'::text])))",
            )
        }
        _mock_get_table_constraint_specs(monkeypatch, actual)

        with pytest.raises(RuntimeError, match=r"constraint 'state_check'"):
            await db_drift.assert_table_constraint_contract(
                _POOL,
                "probe",
                expected,
            )

    @pytest.mark.parametrize("name", ["sessions_purpose_check", "sessions_flash_category_check"])
    async def test_constraint_check_accepts_dump_restore_casts(self, monkeypatch, name):
        """Check constraint check accepts dump restore casts."""
        expected = TABLE_CONSTRAINT_CONTRACTS["sessions"][name]
        restored = db_drift._canonical_check_constraint(expected)
        assert restored != expected
        assert "::text, (" in restored.check_definition
        _mock_get_table_constraint_specs(monkeypatch, {name: restored})
        await db_drift.assert_table_constraint_contract(_POOL, "sessions", {name: expected})

    @pytest.mark.parametrize(
        "before,after",
        [
            ("'full'", "'admin'"),
            ("'totp_setup'", "'full'"),
            ("purpose", "flash_category"),
            ("character varying", "character varying(2)"),
            ("::text", "::citext"),
        ],
    )
    async def test_dump_restore_normalization_preserves_real_drift(
        self, monkeypatch, before, after
    ):
        """Check dump restore normalization preserves real drift (RuntimeError)."""
        name = "sessions_purpose_check"
        expected = TABLE_CONSTRAINT_CONTRACTS["sessions"][name]
        restored = db_drift._canonical_check_constraint(expected)
        actual = replace(
            restored, check_definition=restored.check_definition.replace(before, after)
        )
        _mock_get_table_constraint_specs(monkeypatch, {name: actual})
        with pytest.raises(RuntimeError, match="Schema drift"):
            await db_drift.assert_table_constraint_contract(_POOL, "sessions", {name: expected})

    async def test_constraint_check_rejects_changed_foreign_key_action(self, monkeypatch):
        """Check constraint check rejects changed foreign key action (RuntimeError)."""
        expected_fk = ConstraintSpec(
            kind="foreign_key",
            columns=("user_id",),
            referenced_table="users",
            referenced_columns=("id",),
            on_update="NO ACTION",
            on_delete="CASCADE",
            references_application_schema=True,
        )
        actual_fk = replace(expected_fk, on_delete="NO ACTION")
        _mock_get_table_constraint_specs(monkeypatch, {"probe_fkey": actual_fk})

        with pytest.raises(RuntimeError, match=r"constraint 'probe_fkey'"):
            await db_drift.assert_table_constraint_contract(
                _POOL,
                "probe",
                {"probe_fkey": expected_fk},
            )


class TestSyncStatusProgressContractCoverage:
    """Cover sync status progress contract coverage."""

    def test_contract_bounds_incremental_progress_and_ties_it_to_a_staged_harvest(self):
        """Check contract bounds incremental progress and ties it to a staged harvest."""
        check_definitions = {
            spec.check_definition
            for spec in SYNC_STATUS_CONSTRAINT_CONTRACT.values()
            if spec.kind == "check" and spec.check_definition is not None
        }

        assert any(
            "incremental_position" in definition and ">= 0" in definition
            for definition in check_definitions
        ), "no declared check bounds incremental_position to nonnegative values"
        assert any(
            "incremental_affected" in definition and ">= 0" in definition
            for definition in check_definitions
        ), "no declared check bounds incremental_affected to nonnegative values"
        assert any(
            "incremental_started_at" in definition and "incremental_harvest" in definition
            for definition in check_definitions
        ), "no declared check ties incremental_started_at to a staged incremental_harvest"

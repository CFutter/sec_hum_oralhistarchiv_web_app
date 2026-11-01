"""Native search-schema drift controls restore every changed object before returning."""

import pytest
from psycopg import sql

from app.services.db_drift import validate_schema_against_db


@pytest.mark.parametrize("column", ["search_vector_public", "search_vector_full"])
@pytest.mark.parametrize("drift", ["renamed", "nullable"])
async def test_vector_column_name_and_nullability_drift_refuse_startup(
    db_pool, sync_conn, column, drift
):
    """Verify vector column name and nullability drift refuse startup."""
    await validate_schema_against_db(db_pool)
    if drift == "renamed":
        changed = f"stale_{column}"
        mutation = sql.SQL("ALTER TABLE oral_history_datasets RENAME COLUMN {} TO {}").format(
            sql.Identifier(column), sql.Identifier(changed)
        )
        restore = sql.SQL("ALTER TABLE oral_history_datasets RENAME COLUMN {} TO {}").format(
            sql.Identifier(changed), sql.Identifier(column)
        )
    else:
        mutation = sql.SQL(
            "ALTER TABLE oral_history_datasets ALTER COLUMN {} DROP NOT NULL"
        ).format(sql.Identifier(column))
        restore = sql.SQL("ALTER TABLE oral_history_datasets ALTER COLUMN {} SET NOT NULL").format(
            sql.Identifier(column)
        )
    sync_conn.execute(mutation)
    sync_conn.commit()
    try:
        with pytest.raises(
            RuntimeError, match=rf"Schema drift on 'oral_history_datasets'.*{column}"
        ):
            await validate_schema_against_db(db_pool)
    finally:
        sync_conn.execute(restore)
        sync_conn.commit()
    await validate_schema_against_db(db_pool)


@pytest.mark.parametrize("suffix", ["public", "full"])
@pytest.mark.parametrize("drift", ["missing", "wrong_vector"])
async def test_vector_gin_index_missing_or_wrong_key_refuses_startup(
    db_pool, sync_conn, suffix, drift
):
    """Verify vector gin index missing or wrong key refuses startup."""
    await validate_schema_against_db(db_pool)
    index = f"idx_search_vector_{suffix}"
    correct_column = f"search_vector_{suffix}"
    wrong_column = "search_vector_full" if suffix == "public" else "search_vector_public"
    drop = sql.SQL("DROP INDEX IF EXISTS {}").format(sql.Identifier(index))
    sync_conn.execute(drop)
    if drift == "wrong_vector":
        sync_conn.execute(
            sql.SQL("CREATE INDEX {} ON oral_history_datasets USING GIN ({})").format(
                sql.Identifier(index), sql.Identifier(wrong_column)
            )
        )
    sync_conn.commit()
    try:
        with pytest.raises(
            RuntimeError, match=rf"Schema drift on 'oral_history_datasets'.*{index}"
        ):
            await validate_schema_against_db(db_pool)
    finally:
        sync_conn.execute(drop)
        sync_conn.execute(
            sql.SQL("CREATE INDEX {} ON oral_history_datasets USING GIN ({})").format(
                sql.Identifier(index), sql.Identifier(correct_column)
            )
        )
        sync_conn.commit()
    await validate_schema_against_db(db_pool)


@pytest.mark.parametrize(
    "mutation,restore",
    [
        (
            "ALTER VIEW catalogue_search_candidates RENAME TO stale_search_candidates",
            "ALTER VIEW stale_search_candidates RENAME TO catalogue_search_candidates",
        ),
        (
            "ALTER VIEW catalogue_search_candidates RENAME COLUMN id TO unreviewed_identity",
            "ALTER VIEW catalogue_search_candidates RENAME COLUMN unreviewed_identity TO id",
        ),
        (
            "ALTER VIEW catalogue_search_candidates SET (security_barrier = false)",
            "ALTER VIEW catalogue_search_candidates SET (security_barrier = true)",
        ),
        (
            "ALTER VIEW catalogue_search_candidates SET (security_invoker = true)",
            "ALTER VIEW catalogue_search_candidates SET (security_invoker = false)",
        ),
    ],
    ids=["missing", "projection", "barrier", "invoker"],
)
async def test_search_candidate_view_contract_drift_refuses_startup(
    db_pool, sync_conn, mutation, restore
):
    """Verify search candidate view contract drift refuses startup."""
    await validate_schema_against_db(db_pool)
    sync_conn.execute(mutation)
    sync_conn.commit()
    try:
        with pytest.raises(
            RuntimeError,
            match=r"(?:Schema drift on view|Missing or malformed managed view).*catalogue_search_candidates",
        ):
            await validate_schema_against_db(db_pool)
    finally:
        sync_conn.execute(restore)
        sync_conn.commit()
    await validate_schema_against_db(db_pool)


async def test_trigger_vector_assignment_drift_restores_the_complete_current_function(
    db_pool, sync_conn
):
    """Verify trigger vector assignment drift restores the complete current function."""
    await validate_schema_against_db(db_pool)
    original = sync_conn.execute(
        "SELECT pg_get_functiondef('public.update_search_text()'::regprocedure)"
    ).fetchone()[0]
    anchor = "NEW.search_vector_public :="
    assert original.count(anchor) == 1
    changed = original.replace(anchor, "NEW.search_vector_full :=", 1)
    sync_conn.execute(changed)
    sync_conn.commit()
    try:
        with pytest.raises(
            RuntimeError, match=r"Schema drift in managed PostgreSQL functions.*update_search_text"
        ):
            await validate_schema_against_db(db_pool)
    finally:
        sync_conn.execute(original)
        sync_conn.commit()
    assert sync_conn.execute(
        "SELECT pg_get_functiondef('public.update_search_text()'::regprocedure)"
    ).fetchone() == (original,)
    await validate_schema_against_db(db_pool)

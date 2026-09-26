"""Shared fail-closed runtime validation for every application process."""

from alembic.config import Config
from alembic.script import ScriptDirectory
from psycopg.errors import UndefinedTable
from psycopg_pool import AsyncConnectionPool

from .paths import ALEMBIC_DIR, ALEMBIC_INI
from .services.access_tiers import assert_tier_rank_complete
from .services.database_privileges import (
    RuntimeProcess,
    validate_runtime_database_role,
)
from .services.datasets import (
    assert_redaction_total,
    validate_dataset_insert_schema,
    validate_dataset_schema,
)
from .services.db import get_db_cursor
from .services.db_drift import validate_schema_against_db
from .services.db_schema_contract import DATASET_COLUMN_CONTRACT, USER_COLUMN_CONTRACT
from .services.email_outbox import validate_email_outbox_contract
from .services.schema import (
    DATASET_INSERT_COLUMNS,
    DATASET_SELECT_COLUMNS,
    DATASET_TRIGGER_COLUMNS,
)
from .services.users import (
    USER_COLUMNS,
    USER_COMPUTED_SOURCE_COLUMNS,
    validate_user_schema,
)


def _alembic_config() -> Config:
    """Load the migration INI and set the resolved script directory."""
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_DIR))
    return config


async def validate_alembic_head(pool: AsyncConnectionPool) -> None:
    """Read alembic_version and require exactly the packaged head set.

    Raises RuntimeError for missing/empty/mismatched revisions; other DB/asset errors propagate.
    """

    expected_heads = set(ScriptDirectory.from_config(_alembic_config()).get_heads())

    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute("SELECT version_num FROM alembic_version")
            rows = await cur.fetchall()
    except UndefinedTable as exc:
        raise RuntimeError(
            "Database has no alembic_version table. Run `alembic upgrade head` first."
        ) from exc

    actual_heads = {row["version_num"] for row in rows}

    if not actual_heads:
        raise RuntimeError(
            "Database has an empty alembic_version table. Run `alembic upgrade head` first."
        )

    if actual_heads != expected_heads:
        raise RuntimeError(
            f"Schema is at {sorted(actual_heads)!r}, but code expects "
            f"{sorted(expected_heads)!r}. Run `alembic upgrade head` first."
        )


def validate_application_column_contracts() -> None:
    """Raise RuntimeError if dataset/user SQL column lists lack declared DB contracts."""
    dataset_columns = (
        set(DATASET_SELECT_COLUMNS) | set(DATASET_INSERT_COLUMNS) | set(DATASET_TRIGGER_COLUMNS)
    )
    user_columns = set(USER_COLUMNS) | set(USER_COMPUTED_SOURCE_COLUMNS)

    checks = (
        ("Dataset SQL", dataset_columns, DATASET_COLUMN_CONTRACT),
        ("User SQL", user_columns, USER_COLUMN_CONTRACT),
    )

    problems: list[str] = []
    for label, used_columns, contract in checks:
        if missing := used_columns - set(contract):
            problems.append(f"{label} columns lack DB contracts: {sorted(missing)}")

    if problems:
        raise RuntimeError("; ".join(problems))


async def validate_runtime_schema(
    pool: AsyncConnectionPool,
    *,
    process: RuntimeProcess,
) -> None:
    """Check model/SQL invariants, process role, Alembic heads and live schema using pool.

    Requires an open pool and process web or scheduler. Contract/database errors
    propagate; checks do not migrate or repair the database.
    """
    validate_dataset_schema()
    validate_dataset_insert_schema()
    validate_user_schema()
    validate_email_outbox_contract()
    assert_redaction_total()
    assert_tier_rank_complete()
    validate_application_column_contracts()

    await validate_runtime_database_role(pool, process)
    await validate_alembic_head(pool)
    await validate_schema_against_db(pool)

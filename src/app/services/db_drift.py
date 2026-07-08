"""Database drift detection.

Two helper functions that check for drift between the columns in the
database and the data model defined in the codebase. Raises RuntimeError
on drift detection.
"""

from psycopg_pool import AsyncConnectionPool
from psycopg.rows import tuple_row

from .db import get_db_cursor
from .schema import DATASET_INSERT_COLUMNS
from .users import USER_COLUMNS


async def assert_table_columns_match(
    pool: AsyncConnectionPool,
    table_name: str,
    expected_columns: set[str],
) -> None:
    """Verify the live table's columns are a superset of expected_columns.

    Raises RuntimeError on drift. Read-only; safe to run at startup.
    """
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute(
            """SELECT column_name
               FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = %s""",
            (table_name,),
        )
        actual = {row[0] for row in await cur.fetchall()}

    missing = expected_columns - actual
    if missing:
        raise RuntimeError(
            f"Schema drift on {table_name!r}: Python expects columns "
            f"absent from the database: {sorted(missing)}. "
            f"A migration is missing or out of order."
        )

async def validate_schema_against_db(pool: AsyncConnectionPool) -> None:
    """Validate the Python column lists against the live database.

    Checks that every column the code expects exists on oral_history_datasets,
    users, and sessions. The users and sessions checks include columns
    referenced only by raw SQL (auth/TOTP columns in authentication.py, totp.py,
    password_reset.py, email_change.py; the flash/purpose/expiry columns in
    sessions.py) — these are not in any ORM model and are the easiest to forget
    when a migration renames one. Raises RuntimeError on drift.
    """

    await assert_table_columns_match(pool, "sessions", {
    "id", "user_id", "purpose", "flash_message",
    "flash_category", "created_at", "expires_at", "ip_address",
    })

    await assert_table_columns_match(
        pool, "oral_history_datasets", set(DATASET_INSERT_COLUMNS)
    )
    user_columns = set(USER_COLUMNS) | {"password_hash", "totp_secret", "pending_totp_secret",
         "pending_totp_created_at", "pending_email", "pending_email_token_hash",
         "pending_email_created_at", "email_verification_token_hash",
         "email_verification_created_at", "password_reset_token_hash",
         "password_reset_created_at", "failed_login_count", "locked_until"}

    await assert_table_columns_match(pool, "users", user_columns)

"""DB-layer transaction semantics + re-auth verification (real PG).

Ported from the legacy suite's legitimate cases that the mocked tier cannot
prove: get_db_cursor's commit-on-success / rollback-on-exception behavior
(the sync loop's per-record isolation depends on it) and
verify_current_password (the email-change re-auth gate).
"""
import pytest

from app.services.authentication import verify_current_password
from app.services.db import get_db_cursor


async def test_cursor_commits_on_clean_exit(db_pool, sync_conn):
    """Writes inside get_db_cursor persist without an explicit commit — the
    per-record sync loop relies on each cursor block committing its record."""
    async with get_db_cursor(db_pool) as cur:
        await cur.execute(
            "INSERT INTO oral_history_datasets (uuid, title) VALUES (%s, %s)",
            ("oai:test:commit-check", "Committed"),
        )
    row = sync_conn.execute(
        "SELECT title FROM oral_history_datasets WHERE uuid = %s",
        ("oai:test:commit-check",),
    ).fetchone()
    assert row == ("Committed",)


async def test_cursor_rolls_back_on_exception(db_pool, sync_conn):
    """An exception inside the block must roll the write back — this is what
    makes a failed record in the sync loop leave no partial row behind."""
    with pytest.raises(RuntimeError):
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "INSERT INTO oral_history_datasets (uuid, title) VALUES (%s, %s)",
                ("oai:test:rollback-check", "Doomed"),
            )
            raise RuntimeError("boom")
    row = sync_conn.execute(
        "SELECT 1 FROM oral_history_datasets WHERE uuid = %s",
        ("oai:test:rollback-check",),
    ).fetchone()
    assert row is None


async def test_verify_current_password_matrix(db_pool, user_factory):
    """Re-auth path (email change): True only for a local user presenting
    their real password; False for wrong password, missing user, and
    Shibboleth accounts (no password_hash — IdP-authenticated)."""
    local = user_factory()
    shib = user_factory(auth_method="shibboleth")

    assert await verify_current_password(db_pool, local.id, local.password) is True
    assert await verify_current_password(db_pool, local.id, "wrong-password!") is False
    assert await verify_current_password(db_pool, 999_999, local.password) is False
    assert await verify_current_password(db_pool, shib.id, "anything-at-all") is False

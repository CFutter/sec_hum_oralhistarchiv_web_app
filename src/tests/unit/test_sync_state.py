"""Reject invalid state-provisioning identities before database access."""

from unittest.mock import create_autospec, patch

import pytest
from psycopg_pool import AsyncConnectionPool

from app.services.sync_state import ensure_source_status_rows


@pytest.mark.parametrize(
    ("source_names", "error"),
    [
        ([], ValueError),
        (["archive", "archive"], ValueError),
        (["bad-name"], ValueError),
        ("archive", TypeError),
        (["archive", 123], ValueError),
    ],
    ids=["empty", "duplicate", "noncanonical", "direct-string", "nonstring-name"],
)
async def test_invalid_source_names_are_rejected_before_database_access(
    source_names: object,
    error: type[Exception],
) -> None:
    """Check invalid source names are rejected before database access (error)."""
    pool = create_autospec(AsyncConnectionPool, instance=True)
    with (
        patch("app.services.sync_state.get_db_cursor", autospec=True) as get_cursor,
        pytest.raises(error),
    ):
        await ensure_source_status_rows(pool, source_names)  # type: ignore[arg-type]
    get_cursor.assert_not_called()
    pool.connection.assert_not_called()

"""Separate whole-run ingestion ownership from transactional catalogue writes."""

from typing import Any

from psycopg import AsyncCursor

# Keep the catalogue key stable: administrator actions and operator SQL use it.
CATALOGUE_WRITE_LOCK_KEY = 0x4F484153  # "OHAS"
INGESTION_RUN_LOCK_KEY = 0x4F484149  # "OHAI"; held through fetch, staging and replay.


async def acquire_catalogue_write_lock_cur(cur: AsyncCursor[Any]) -> None:
    """Hold the common catalogue lock until the caller's transaction ends.

    Call on the mutation transaction's cursor before policy, actor, session
    or administrator-state locks. Database timeout/cancellation propagates.
    Ingestion acquires this inside its separate session-level run lock, on
    that same connection. Administrator actions acquire only this lock.
    """
    await cur.execute("SELECT pg_advisory_xact_lock(%s)", (CATALOGUE_WRITE_LOCK_KEY,))

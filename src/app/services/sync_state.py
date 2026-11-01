"""Provision source-keyed ingestion state before scheduled work begins."""

from collections.abc import Sequence

from app.source_contract import SOURCE_NAME_BODY, SOURCE_NAME_PATTERN

from .db import Database, get_db_cursor


def _validated_source_name(value: object) -> str:
    """Return a canonical identity or reject it before database access."""
    if not isinstance(value, str) or SOURCE_NAME_PATTERN.fullmatch(value) is None:
        raise ValueError(f"Source names must match {SOURCE_NAME_BODY}")
    return value


def _validated_source_names(source_names: Sequence[str]) -> tuple[str, ...]:
    """Snapshot a nonempty, uniquely named source scope before resource access."""
    if isinstance(source_names, (str, bytes)):
        raise TypeError("Source names must be a nonempty sequence of identities")

    names = tuple(_validated_source_name(name) for name in source_names)
    if not names:
        raise ValueError("At least one source name is required")
    if len(set(names)) != len(names):
        raise ValueError("Source names must be unique")
    return names


async def ensure_source_status_rows(
    pool: Database,
    source_names: Sequence[str],
) -> None:
    """Insert missing source rows without changing existing durable state.

    Reject empty, duplicate or noncanonical identities before opening a
    transaction. A scalar source_names argument raises TypeError; empty, duplicate or
    invalid identities raise ValueError. Database errors propagate. An existing
    connection follows get_db_cursor's transaction/savepoint semantics.
    """
    names = _validated_source_names(source_names)

    async with get_db_cursor(pool) as cur:
        await cur.executemany(
            """
            INSERT INTO sync_status (source)
            VALUES (%s)
            ON CONFLICT (source) DO NOTHING
            """,
            [(name,) for name in names],
        )

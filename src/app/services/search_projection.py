"""Bind independently indexed search projections to reviewed catalogue policy."""

from typing import Any

from psycopg import AsyncCursor, InterfaceError, OperationalError
from psycopg.types.json import Jsonb

from .catalogue_policy import CataloguePolicy
from .db import Database, get_db_cursor
from .search_work import SearchUnavailable

_POLICY_DIGEST_LENGTH = 64


async def guard_catalogue_policy_cur(
    cursor: AsyncCursor[Any], policy: CataloguePolicy | str
) -> None:
    """Fence a serving transaction before reading or returning policy-dependent data.

    A shared transaction lock prevents a policy/record mutation between this
    check and subsequent reads. Busy maintenance, stale policy and database
    failure refuse safely without borrowing another connection or waiting.
    """
    fingerprint = policy.fingerprint if isinstance(policy, CataloguePolicy) else policy
    try:
        await cursor.execute("SELECT public.catalogue_guard_search_policy(%s)", (fingerprint,))
    except (InterfaceError, OperationalError):
        raise SearchUnavailable from None


async def synchronize_search_policy(pool: Database, policy: CataloguePolicy) -> None:
    """Initialize an unbound database or verify the already published policy.

    A different existing fingerprint is rejected. Ordinary worker startup must
    never roll back a newer configuration. Use the owner-only operator command
    with an expected prior fingerprint for deliberate policy replacement.
    """
    async with get_db_cursor(pool) as cursor:
        await cursor.execute(
            "SELECT public.catalogue_initialize_search_policy(%s, %s)",
            (
                policy.fingerprint,
                Jsonb({str(rank): dict(masks) for rank, masks in policy.page_masks.items()}),
            ),
        )


async def replace_search_policy(
    pool: Database, policy: CataloguePolicy, *, expected_fingerprint: str
) -> None:
    """Atomically replace a known policy binding using an operator database identity.

    Require a 64-character lowercase hexadecimal expected_fingerprint or raise
    ValueError; database errors, including a stale expected binding, propagate.
    """
    if len(expected_fingerprint) != _POLICY_DIGEST_LENGTH or any(
        value not in "0123456789abcdef" for value in expected_fingerprint
    ):
        raise ValueError("Expected policy fingerprint must be 64 lowercase hexadecimal characters")
    async with get_db_cursor(pool) as cursor:
        await cursor.execute(
            "SELECT public.catalogue_replace_search_policy(%s, %s, %s)",
            (
                expected_fingerprint,
                policy.fingerprint,
                Jsonb({str(rank): dict(masks) for rank, masks in policy.page_masks.items()}),
            ),
        )

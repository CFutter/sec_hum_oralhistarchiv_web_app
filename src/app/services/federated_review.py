"""Store advisory assertion observations separately from account authority.

Only the trusted federated finalizer records observations. Administrators see
this projection explicitly; ordinary User/session snapshots omit raw attributes.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from psycopg import AsyncCursor
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.federated_tier_rules import propose_federated_tier
from app.sources import AccessTier
from config import settings

from .db import get_db_cursor

__all__ = ["FederatedReview", "list_federated_reviews", "record_federated_review_cur"]


@dataclass(frozen=True, slots=True)
class FederatedReview:
    """Latest accepted assertion values and proposal for administrator review.

    A missing proposed_tier/rule means no rule matched, including malformed
    entitlement serialization. It is distinct from an explicit public proposal.
    Mismatch compares proposals with the reviewed approval baseline, so an
    intentionally different administrator choice does not create a mismatch.
    """

    revision: int
    issuer: str
    affiliation: str | None
    entitlement: str | None
    proposed_tier: AccessTier | None
    proposed_rule: dict[str, Any] | None
    mismatch: bool


async def record_federated_review_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    issuer: str,
    affiliation: str | None,
    entitlement: str | None,
) -> None:
    """Refresh review metadata for a locked, trusted federated identity.

    Call only after proxy, canonical-attribute, issuer, MFA and persisted-policy
    checks, in the identity upsert transaction. Revision changes only when the
    review values change. This does not modify profile, authority, approval,
    authentication revision or sessions, including pending/disabled accounts.
    """
    proposal = propose_federated_tier(
        settings.federated_tier_rules,
        issuer=issuer,
        affiliation=affiliation,
        entitlement=entitlement,
    )
    observation = Jsonb(
        {
            "issuer": issuer,
            "affiliation": affiliation,
            "entitlement": entitlement,
            "proposal": proposal.rule_snapshot if proposal is not None else None,
        }
    )
    await cur.execute(
        """UPDATE users
              SET federated_review = %(observation)s,
                  federated_review_revision = federated_review_revision + 1
            WHERE id = %(user_id)s
              AND auth_method = 'shibboleth'
              AND shibboleth_issuer = %(issuer)s
              AND federated_review IS DISTINCT FROM %(observation)s""",
        {"user_id": user_id, "issuer": issuer, "observation": observation},
    )


async def list_federated_reviews(
    pool: AsyncConnectionPool, *, user_ids: Sequence[int] | None = None
) -> dict[int, FederatedReview]:
    """Read observed federated review metadata for administrator-only rendering.

    Unobserved identities are absent. Approved rows predating observations have
    no comparison baseline until explicitly reviewed; they are not mismatches.
    An optional ID scope lets the admin page load only its current user page;
    an empty scope returns immediately. Values originate from bounded trusted
    principal attributes, not profile fallbacks, and must still be autoescaped
    when rendered.
    """
    if user_ids is not None and not user_ids:
        return {}
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT id, federated_review_revision, federated_review,
                      federated_approved_proposal IS NOT NULL
                      AND federated_approved_proposal IS DISTINCT FROM
                          jsonb_build_object('proposal', federated_review -> 'proposal')
                          AS mismatch
                 FROM users
                WHERE auth_method = 'shibboleth' AND federated_review IS NOT NULL
                  AND (%(user_ids)s::bigint[] IS NULL OR id = ANY(%(user_ids)s))""",
            {"user_ids": list(user_ids) if user_ids is not None else None},
        )
        rows = await cur.fetchall()
    reviews = {}
    for row in rows:
        observation = row["federated_review"]
        proposal = observation["proposal"]
        reviews[row["id"]] = FederatedReview(
            revision=row["federated_review_revision"],
            issuer=observation["issuer"],
            affiliation=observation["affiliation"],
            entitlement=observation["entitlement"],
            proposed_tier=proposal["tier"] if proposal is not None else None,
            proposed_rule=proposal,
            mismatch=row["mismatch"],
        )
    return reviews

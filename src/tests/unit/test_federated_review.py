"""Advisory observations stay distinct from profiles and authority snapshots."""

from unittest.mock import create_autospec, patch

import pytest

from app.federated_tier_rules import FederatedTierRule
from app.services import federated_review as review
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

ISSUER = "https://idp.example.org/idp/shibboleth"
SNAPSHOT = {"index": 1, "match": {"entitlement": "urn:example:research"}, "tier": "vetted"}


@pytest.mark.parametrize(
    ("entitlement", "expected"),
    [
        ("urn:example:research", SNAPSHOT),
        ("urn:example:unmatched", None),
        ("urn:example:research;", None),
    ],
)
async def test_observation_binds_configured_proposal_to_exact_latest_attributes(
    monkeypatch, entitlement, expected
):
    """Observation binds configured proposal to exact latest attributes."""
    monkeypatch.setattr(
        review.settings,
        "federated_tier_rules",
        (FederatedTierRule.model_validate({key: SNAPSHOT[key] for key in ("match", "tier")}),),
    )
    cur = make_async_cursor()

    await review.record_federated_review_cur(
        cur,
        user_id=42,
        issuer=ISSUER,
        affiliation="<b>Latest affiliation</b>",
        entitlement=entitlement,
    )

    params = cur.execute.await_args.args[1]
    assert params["user_id"] == 42
    assert params["issuer"] == ISSUER
    assert params["observation"].obj == {
        "issuer": ISSUER,
        "affiliation": "<b>Latest affiliation</b>",
        "entitlement": entitlement,
        "proposal": expected,
    }


async def test_observation_write_error_propagates_to_the_login_transaction(monkeypatch):
    """Observation write error propagates to the login transaction."""
    monkeypatch.setattr(review.settings, "federated_tier_rules", ())
    cur = make_async_cursor()
    cur.execute.side_effect = RuntimeError("observation write rejected")

    with pytest.raises(RuntimeError, match="observation write rejected"):
        await review.record_federated_review_cur(
            cur, user_id=42, issuer=ISSUER, affiliation=None, entitlement=None
        )


@pytest.mark.parametrize(
    ("proposal", "tier", "mismatch"),
    [
        (None, None, False),
        ({"index": 2, "match": {"issuer": ISSUER}, "tier": "public"}, "public", False),
        (SNAPSHOT, "vetted", True),
    ],
)
async def test_review_projection_preserves_no_proposal_and_explicit_public(
    proposal, tier, mismatch
):
    """Review projection preserves no proposal and explicit public."""
    cur = make_async_cursor(
        fetchall=[
            {
                "id": 42,
                "federated_review_revision": 8,
                "federated_review": {
                    "issuer": ISSUER,
                    "affiliation": None,
                    "entitlement": "<img src=x onerror=alert(1)>",
                    "proposal": proposal,
                },
                "mismatch": mismatch,
            }
        ]
    )
    with patch.object(review, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)):
        result = await review.list_federated_reviews(make_mock_pool())

    assert result == {
        42: review.FederatedReview(
            revision=8,
            issuer=ISSUER,
            affiliation=None,
            entitlement="<img src=x onerror=alert(1)>",
            proposed_tier=tier,
            proposed_rule=proposal,
            mismatch=mismatch,
        )
    }
    assert cur.execute.await_args.args[1] == {"user_ids": None}


async def test_review_query_scopes_raw_attributes_to_current_admin_page():
    """Review query scopes raw attributes to current admin page."""
    cur = make_async_cursor(fetchall=[])
    with patch.object(review, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)):
        result = await review.list_federated_reviews(make_mock_pool(), user_ids=(17, 42))

    assert result == {}
    assert "id = ANY(%(user_ids)s)" in cur.execute.await_args.args[0]
    assert cur.execute.await_args.args[1] == {"user_ids": [17, 42]}


async def test_empty_admin_page_does_not_acquire_or_read_any_raw_review():
    """Empty admin page does not acquire or read any raw review."""
    cursor_factory = create_autospec(review.get_db_cursor)
    with patch.object(review, "get_db_cursor", cursor_factory):
        assert await review.list_federated_reviews(make_mock_pool(), user_ids=[]) == {}

    cursor_factory.assert_not_called()

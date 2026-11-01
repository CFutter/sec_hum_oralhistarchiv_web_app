"""Trusted assertion proposals remain advisory across review and later logins."""

from dataclasses import replace

import psycopg
import pytest
from pydantic import SecretStr

from app.federated_tier_rules import FederatedTierRule
from app.services import federated_authentication as auth
from app.services import federated_session_policy, users
from app.services.federated_review import list_federated_reviews
from app.services.federated_session_policy import REQUIRED_SHIBBOLETH_AUTHN_CONTEXT
from app.services.sessions import get_session_user
from config import settings

ISSUER = "https://idp.test.example/idp/shibboleth"
SUBJECT = "urn:test:subject:advisory-review"
SECRET = "kPQ9mV2xL7sN4cB8fH1jD5gR0aY3eU6iO9wQ2tM7zX4vC8b"


def rule(tier, **match):
    """Validate a federated tier rule from its match fields and proposed tier."""
    return FederatedTierRule.model_validate({"match": match, "tier": tier})


def assertion(**overrides):
    """Build the test's federated principal with supplied identity overrides."""
    values = {
        "issuer": ISSUER,
        "subject_id": SUBJECT,
        "email": "review-person@example.org",
        "authn_context": REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
        "display_name": "First profile",
        "affiliation": "staff",
        "entitlement": "urn:member",
    }
    values.update(overrides)
    return auth.build_federated_principal(**values)


async def observe(pool, **overrides):
    """Perform the real upsert while capturing and re-raising database constraint errors."""
    return await auth.finalize_shibboleth_login(
        pool, principal=assertion(**overrides), ip_address="127.0.0.1"
    )


async def approve(pool, user_id, revision, actor, tier="vetted"):
    """Approve the test identity against its expected issuer, subject and review revision."""
    return await users.approve_federated_user(
        pool,
        user_id,
        expected_issuer=ISSUER,
        expected_subject_id=SUBJECT,
        expected_review_revision=revision,
        access_tier=tier,
        actor_id=actor.id,
        actor_session_id=actor.session_id,
    )


def authority(conn, user_id):
    """Read the authority fields used to compare federated approval state."""
    return conn.execute(
        """SELECT access_tier, is_active, is_admin, email_verified,
                  federated_status, federated_approved_at, federated_approved_by,
                  auth_revision, federated_approved_proposal
             FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()


@pytest.fixture(autouse=True)
async def trusted_federation(monkeypatch, clean_db, db_pool):
    """Install this test's trusted issuers and tier rules, then reconcile durable federation
    policy.
    """
    del clean_db
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER])
    monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET))
    monkeypatch.setattr(
        settings,
        "federated_tier_rules",
        (
            rule("registered", entitlement="urn:member"),
            rule("vetted", entitlement="urn:vetted"),
            rule("public", entitlement="urn:public"),
            rule("registered", entitlement="urn:another-member"),
        ),
    )
    await federated_session_policy.reconcile_federated_session_policy(db_pool)


async def test_first_assertion_persists_first_ordered_proposal_without_granting_authority(
    db_pool, sync_conn, monkeypatch
):
    """Verify first assertion persists first ordered proposal without granting authority."""
    first = rule("registered", affiliation="staff", entitlement={"prefix": "urn:"})
    monkeypatch.setattr(settings, "federated_tier_rules", (first, rule("vetted", issuer=ISSUER)))

    result = await observe(db_pool, entitlement="urn:member;urn:second")

    assert isinstance(result, auth.FederatedLoginFailure)
    assert result.reason == "inactive_account"
    assert result.user is not None
    assert result.user.access_tier == "public"
    assert result.user.is_active is False
    assert result.user.is_admin is False
    assert result.user.last_login is None
    review = (await list_federated_reviews(db_pool))[result.user.id]
    assert review.revision == 1
    assert review.issuer == ISSUER
    assert review.affiliation == "staff"
    assert review.entitlement == "urn:member;urn:second"
    assert review.proposed_tier == "registered"
    assert review.proposed_rule == {"index": 1, **first.model_dump()}
    assert review.mismatch is False
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone() == (0,)
    assert sync_conn.execute(
        "SELECT federated_approved_proposal FROM users WHERE id = %s", (result.user.id,)
    ).fetchone() == (None,)


async def test_pending_assertions_refresh_review_values_without_refreshing_profile(
    db_pool, sync_conn
):
    """Verify pending assertions refresh review values without refreshing profile."""
    pending = await observe(db_pool)
    changed = await observe(
        db_pool,
        email="later-address@example.org",
        display_name="Later profile",
        affiliation="later group",
        entitlement="urn:vetted",
    )

    assert pending.user is not None
    assert isinstance(changed, auth.FederatedLoginFailure)
    assert changed.user is not None
    assert changed.user.id == pending.user.id
    assert changed.user.email == "review-person@example.org"
    assert changed.user.display_name == "First profile"
    assert changed.user.affiliation == "staff"
    assert changed.user.access_tier == "public"
    review = (await list_federated_reviews(db_pool))[pending.user.id]
    assert review.revision == 2
    assert review.affiliation == "later group"
    assert review.entitlement == "urn:vetted"
    assert review.proposed_tier == "vetted"
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone() == (0,)


@pytest.mark.parametrize("chosen_tier", ["public", "registered", "vetted"])
async def test_manual_choice_is_independent_of_proposal_and_preserves_its_approval_baseline(
    db_pool, sync_conn, admin_actor, chosen_tier
):
    """Verify manual choice is independent of proposal and preserves its approval baseline."""
    pending = await observe(db_pool)
    assert pending.user is not None
    reviewed = (await list_federated_reviews(db_pool))[pending.user.id]

    approved = await approve(db_pool, pending.user.id, reviewed.revision, admin_actor, chosen_tier)

    assert approved.user.access_tier == chosen_tier
    assert approved.user.federated_approved_by == admin_actor.id
    assert approved.proposed_tier == "registered"
    assert approved.proposed_rule == reviewed.proposed_rule
    assert authority(sync_conn, pending.user.id)[-1] == {"proposal": reviewed.proposed_rule}
    assert (await list_federated_reviews(db_pool))[pending.user.id].mismatch is False
    before = authority(sync_conn, pending.user.id)
    logged_in = await observe(db_pool)
    assert isinstance(logged_in, auth.FederatedLoginSuccess)
    assert (await get_session_user(db_pool, logged_in.session_id)).user.access_tier == chosen_tier
    assert authority(sync_conn, pending.user.id) == before
    unchanged = (await list_federated_reviews(db_pool))[pending.user.id]
    assert unchanged.revision == reviewed.revision
    assert unchanged.mismatch is False


@pytest.mark.parametrize(
    ("before_entitlement", "after_entitlement", "after_tier"),
    [
        ("urn:member", "urn:vetted", "vetted"),
        ("urn:member", "urn:unknown", None),
        ("urn:unknown", "urn:member", "registered"),
        ("urn:unknown", "urn:public", "public"),
        ("urn:public", "urn:unknown", None),
        ("urn:member", "urn:another-member", "registered"),
    ],
    ids=[
        "higher-tier",
        "no-longer-matches",
        "new-match",
        "none-to-public",
        "public-to-none",
        "same-tier-new-rule",
    ],
)
async def test_changed_proposal_flags_mismatch_without_changing_authority_or_existing_session(
    db_pool, sync_conn, admin_actor, before_entitlement, after_entitlement, after_tier
):
    """Verify changed proposal flags mismatch without changing authority or existing session."""
    pending = await observe(db_pool, entitlement=before_entitlement)
    assert pending.user is not None
    await approve(db_pool, pending.user.id, 1, admin_actor, "vetted")
    first_login = await observe(db_pool, entitlement=before_entitlement)
    assert isinstance(first_login, auth.FederatedLoginSuccess)
    before = authority(sync_conn, pending.user.id)

    later_login = await observe(db_pool, entitlement=after_entitlement)

    assert isinstance(later_login, auth.FederatedLoginSuccess)
    review = (await list_federated_reviews(db_pool))[pending.user.id]
    assert review.revision == 2
    assert review.proposed_tier == after_tier
    assert review.mismatch is True
    assert authority(sync_conn, pending.user.id) == before
    assert (await get_session_user(db_pool, first_login.session_id)).user.id == pending.user.id
    assert (await get_session_user(db_pool, later_login.session_id)).user.access_tier == "vetted"


@pytest.mark.parametrize("changed_attribute", ["affiliation", "entitlement"])
async def test_changed_attributes_invalidate_review_even_when_the_proposal_is_identical(
    db_pool, sync_conn, admin_actor, monkeypatch, changed_attribute
):
    """Verify changed attributes invalidate review even when the proposal is identical."""
    monkeypatch.setattr(settings, "federated_tier_rules", (rule("registered", issuer=ISSUER),))
    pending = await observe(db_pool)
    assert pending.user is not None
    await observe(db_pool)
    original = (await list_federated_reviews(db_pool))[pending.user.id]
    assert original.revision == 1
    changed = {changed_attribute: "different accepted value"}
    await observe(db_pool, **changed)
    latest = (await list_federated_reviews(db_pool))[pending.user.id]
    assert latest.proposed_rule == original.proposed_rule
    assert latest.revision == 2
    before = authority(sync_conn, pending.user.id)

    with pytest.raises(users.AdminActionRejected, match="review changed"):
        await approve(db_pool, pending.user.id, original.revision, admin_actor)

    assert authority(sync_conn, pending.user.id) == before
    approved = await approve(db_pool, pending.user.id, latest.revision, admin_actor)
    assert approved.user.access_tier == "vetted"
    assert approved.proposed_tier == "registered"
    assert (await list_federated_reviews(db_pool))[pending.user.id].mismatch is False


async def test_unobserved_pending_row_cannot_be_approved(
    db_pool, user_factory, admin_actor, sync_conn
):
    """Verify unobserved pending row cannot be approved."""
    pending = user_factory(
        auth_method="shibboleth",
        shibboleth_issuer=ISSUER,
        shibboleth_subject_id=SUBJECT,
        federated_status="pending",
    )
    before = authority(sync_conn, pending.id)
    assert pending.id not in await list_federated_reviews(db_pool)

    with pytest.raises(users.AdminActionRejected, match="review changed"):
        await approve(db_pool, pending.id, 1, admin_actor)

    assert authority(sync_conn, pending.id) == before


@pytest.mark.parametrize("rejection", ["disabled", "issuer", "mfa", "noncanonical", "stale-policy"])
async def test_untrusted_or_stale_assertion_cannot_update_review(
    db_pool, sync_conn, monkeypatch, rejection
):
    """Verify untrusted or stale assertion cannot update review."""
    pending = await observe(db_pool)
    assert pending.user is not None
    original = (await list_federated_reviews(db_pool))[pending.user.id]
    before = authority(sync_conn, pending.user.id)
    candidate = assertion(affiliation="changed group", entitlement="urn:vetted")
    if rejection == "disabled":
        monkeypatch.setattr(settings, "shibboleth_enabled", False)
    elif rejection == "issuer":
        candidate = replace(candidate, issuer="https://untrusted.example.org/idp")
    elif rejection == "mfa":
        candidate = replace(candidate, authn_context="password")
    elif rejection == "noncanonical":
        candidate = replace(candidate, entitlement=" urn:vetted ")
    else:
        monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr("rotated" + SECRET))

    result = await auth.finalize_shibboleth_login(
        db_pool, principal=candidate, ip_address="127.0.0.1"
    )

    assert result == auth.FederatedLoginFailure("untrusted_assertion")
    assert (await list_federated_reviews(db_pool))[pending.user.id] == original
    assert authority(sync_conn, pending.user.id) == before
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone() == (0,)


async def test_email_collision_rolls_back_a_new_identity_and_all_review_metadata(
    db_pool, user_factory, sync_conn
):
    """Verify email collision rolls back a new identity and all review metadata."""
    local = user_factory(email="claimed@example.org")
    result = await observe(db_pool, email=local.email)
    assert result == auth.FederatedLoginFailure("account_conflict")
    assert await list_federated_reviews(db_pool) == {}
    assert sync_conn.execute(
        "SELECT count(*) FROM users WHERE auth_method = 'shibboleth'"
    ).fetchone() == (0,)


async def test_session_failure_rolls_back_changed_review_and_proposal_with_profile(
    db_pool, sync_conn, admin_actor, monkeypatch
):
    """Verify session failure rolls back changed review and proposal with profile."""
    pending = await observe(db_pool)
    assert pending.user is not None
    await approve(db_pool, pending.user.id, 1, admin_actor)
    original = (await list_federated_reviews(db_pool))[pending.user.id]
    before = authority(sync_conn, pending.user.id)
    real_create = auth.create_session_cur

    async def fail_after_insert(cur, **kwargs):
        """Perform the real insert, then trigger a PostgreSQL division error."""
        await real_create(cur, **kwargs)
        await cur.execute("SELECT 1 / 0")

    monkeypatch.setattr(auth, "create_session_cur", fail_after_insert)
    with pytest.raises(psycopg.errors.DivisionByZero):
        await observe(db_pool, entitlement="urn:vetted", display_name="Uncommitted profile")

    assert (await list_federated_reviews(db_pool))[pending.user.id] == original
    assert authority(sync_conn, pending.user.id) == before
    assert sync_conn.execute(
        "SELECT display_name FROM users WHERE id = %s", (pending.user.id,)
    ).fetchone() == ("First profile",)
    assert sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (pending.user.id,)
    ).fetchone() == (0,)


async def test_disabled_identity_refreshes_review_without_reactivation_or_profile_change(
    db_pool, sync_conn, admin_actor
):
    """Verify disabled identity refreshes review without reactivation or profile change."""
    pending = await observe(db_pool)
    assert pending.user is not None
    await approve(db_pool, pending.user.id, 1, admin_actor, "registered")
    await users.set_user_active(
        db_pool,
        pending.user.id,
        False,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )
    before = authority(sync_conn, pending.user.id)

    result = await observe(db_pool, entitlement="urn:vetted", display_name="Changed profile")

    assert isinstance(result, auth.FederatedLoginFailure)
    assert result.reason == "inactive_account"
    assert result.user is not None
    assert result.user.display_name == "First profile"
    assert authority(sync_conn, pending.user.id) == before
    latest = (await list_federated_reviews(db_pool))[pending.user.id]
    assert latest.proposed_tier == "vetted"
    assert latest.mismatch is True
    assert sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (pending.user.id,)
    ).fetchone() == (0,)


async def test_malformed_entitlement_is_observed_but_cannot_fall_through_to_a_rule(
    db_pool, monkeypatch
):
    """Verify malformed entitlement is observed but cannot fall through to a rule."""
    monkeypatch.setattr(settings, "federated_tier_rules", (rule("vetted", issuer=ISSUER),))
    pending = await observe(db_pool, entitlement="urn:member;;urn:other")
    assert pending.user is not None
    review = (await list_federated_reviews(db_pool))[pending.user.id]
    assert review.entitlement == "urn:member;;urn:other"
    assert review.proposed_tier is None
    assert review.proposed_rule is None


async def test_rule_config_changes_are_observed_on_next_assertion_and_reversion_clears_mismatch(
    db_pool, sync_conn, admin_actor, monkeypatch
):
    """Verify rule config changes are observed on next assertion and reversion clears mismatch."""
    pending = await observe(db_pool)
    assert pending.user is not None
    await approve(db_pool, pending.user.id, 1, admin_actor)
    logged_in = await observe(db_pool)
    assert isinstance(logged_in, auth.FederatedLoginSuccess)
    original_rules = settings.federated_tier_rules
    original = (await list_federated_reviews(db_pool))[pending.user.id]
    before = authority(sync_conn, pending.user.id)

    monkeypatch.setattr(settings, "federated_tier_rules", (rule("vetted", issuer=ISSUER),))
    assert await federated_session_policy.reconcile_federated_session_policy(db_pool) == 0
    assert (await list_federated_reviews(db_pool))[pending.user.id] == original
    assert (await get_session_user(db_pool, logged_in.session_id)).user.id == pending.user.id
    await observe(db_pool)
    changed = (await list_federated_reviews(db_pool))[pending.user.id]
    assert changed.revision == 2
    assert changed.proposed_tier == "vetted"
    assert changed.mismatch is True
    assert authority(sync_conn, pending.user.id) == before

    monkeypatch.setattr(settings, "federated_tier_rules", original_rules)
    await observe(db_pool)
    reverted = (await list_federated_reviews(db_pool))[pending.user.id]
    assert reverted.revision == 3
    assert reverted.proposed_rule == original.proposed_rule
    assert reverted.mismatch is False
    assert authority(sync_conn, pending.user.id) == before
    assert (await get_session_user(db_pool, logged_in.session_id)).user.id == pending.user.id


async def test_changed_attributes_with_the_same_approved_proposal_do_not_create_a_mismatch(
    db_pool, sync_conn, admin_actor, monkeypatch
):
    """Verify changed attributes with the same approved proposal do not create a mismatch."""
    monkeypatch.setattr(settings, "federated_tier_rules", (rule("registered", issuer=ISSUER),))
    pending = await observe(db_pool)
    assert pending.user is not None
    await approve(db_pool, pending.user.id, 1, admin_actor)
    original = (await list_federated_reviews(db_pool))[pending.user.id]
    before = authority(sync_conn, pending.user.id)

    result = await observe(db_pool, affiliation="new group", entitlement="urn:different")

    assert isinstance(result, auth.FederatedLoginSuccess)
    changed = (await list_federated_reviews(db_pool))[pending.user.id]
    assert changed.revision == 2
    assert changed.affiliation == "new group"
    assert changed.entitlement == "urn:different"
    assert changed.proposed_rule == original.proposed_rule
    assert changed.mismatch is False
    assert authority(sync_conn, pending.user.id) == before


async def test_existing_identity_email_collision_rolls_back_changed_review(
    db_pool, sync_conn, admin_actor, user_factory
):
    """Verify existing identity email collision rolls back changed review."""
    pending = await observe(db_pool)
    assert pending.user is not None
    await approve(db_pool, pending.user.id, 1, admin_actor)
    original = (await list_federated_reviews(db_pool))[pending.user.id]
    before = authority(sync_conn, pending.user.id)
    local = user_factory(email="later-conflict@example.org")

    result = await observe(db_pool, email=local.email, entitlement="urn:vetted")

    assert result == auth.FederatedLoginFailure("account_conflict")
    assert (await list_federated_reviews(db_pool))[pending.user.id] == original
    assert authority(sync_conn, pending.user.id) == before
    assert sync_conn.execute(
        "SELECT email FROM users WHERE id = %s", (pending.user.id,)
    ).fetchone() == ("review-person@example.org",)

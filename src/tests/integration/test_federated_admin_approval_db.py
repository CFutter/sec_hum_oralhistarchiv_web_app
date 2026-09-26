"""PostgreSQL contracts for explicit federated identity approval."""

from datetime import UTC, datetime

import psycopg
import pytest
from pydantic import SecretStr

from app.services import federated_session_policy, users

ISSUER = "https://idp.test.example/idp/shibboleth"
SUBJECT = "urn:test:subject:pending-review"
SECRET = "kPQ9mV2xL7sN4cB8fH1jD5gR0aY3eU6iO9wQ2tM7zX4vC8b"
ROTATED_SECRET = "vR4nM8qL1xC6kJ9hF2dS5aW0eT7yU3iP6oB9gH2mN5zX8cK1"


@pytest.fixture(autouse=True)
async def _enabled_trusted_federation(monkeypatch, clean_db, db_pool):
    del clean_db  # explicit ordering: reconcile only after the autouse truncate
    monkeypatch.setattr(users.settings, "shibboleth_enabled", True)
    monkeypatch.setattr(users.settings, "shibboleth_trusted_issuers", [ISSUER])
    monkeypatch.setattr(users.settings, "shibboleth_internal_secret", SecretStr(SECRET))
    await federated_session_policy.reconcile_federated_session_policy(db_pool)


async def test_pending_identity_approval_is_one_atomic_authority_transition(
    db_pool, user_factory, session_factory, admin_actor, sync_conn
):
    pending = user_factory(
        auth_method="shibboleth",
        is_active=False,
        federated_status="pending",
        shibboleth_issuer=ISSUER,
        shibboleth_subject_id=SUBJECT,
        access_tier="public",
    )
    session_factory(pending.id)
    before_revision = sync_conn.execute(
        "SELECT auth_revision FROM users WHERE id = %s", (pending.id,)
    ).fetchone()[0]

    approved = await users.approve_federated_user(
        db_pool,
        pending.id,
        expected_issuer=ISSUER,
        expected_subject_id=SUBJECT,
        access_tier="vetted",
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )

    assert approved.federated_status == "approved"
    assert approved.is_active is True
    assert approved.access_tier == "vetted"
    assert approved.is_admin is False
    assert approved.email_verified is False
    assert approved.federated_approved_at is not None
    assert approved.federated_approved_by == admin_actor.id
    row = sync_conn.execute(
        """SELECT federated_status, is_active, access_tier, is_admin,
                  email_verified, federated_approved_at, federated_approved_by
             FROM users WHERE id = %s""",
        (pending.id,),
    ).fetchone()
    assert row[:5] == ("approved", True, "vetted", False, False)
    assert row[5] is not None
    assert row[6] == admin_actor.id
    assert sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (pending.id,)
    ).fetchone() == (0,)
    assert sync_conn.execute(
        "SELECT auth_revision FROM users WHERE id = %s", (pending.id,)
    ).fetchone() == (before_revision + 1,)

    with pytest.raises(users.AdminActionRejected, match="no longer pending"):
        await users.approve_federated_user(
            db_pool,
            pending.id,
            expected_issuer=ISSUER,
            expected_subject_id=SUBJECT,
            access_tier="public",
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )
    assert sync_conn.execute(
        "SELECT access_tier, federated_approved_at, federated_approved_by FROM users WHERE id = %s",
        (pending.id,),
    ).fetchone() == ("vetted", row[5], admin_actor.id)


async def test_session_revocation_failure_rolls_back_the_entire_approval(
    db_pool,
    user_factory,
    session_factory,
    admin_actor,
    sync_conn,
    monkeypatch,
):
    """Approval, revision bump, and session deletion are one commit boundary."""
    pending = user_factory(
        auth_method="shibboleth",
        is_active=False,
        federated_status="pending",
        shibboleth_issuer=ISSUER,
        shibboleth_subject_id=f"{SUBJECT}:rollback",
        access_tier="public",
    )
    anomalous_session = session_factory(pending.id)
    before = sync_conn.execute(
        """SELECT federated_status, is_active, access_tier, is_admin,
                  email_verified, federated_approved_at, federated_approved_by,
                  auth_revision
             FROM users WHERE id = %s""",
        (pending.id,),
    ).fetchone()
    real_delete = users.delete_user_sessions_cur

    async def fail_after_delete(cur, user_id):
        await real_delete(cur, user_id)
        await cur.execute("SELECT 1 / 0")

    monkeypatch.setattr(users, "delete_user_sessions_cur", fail_after_delete)
    with pytest.raises(psycopg.errors.DivisionByZero):
        await users.approve_federated_user(
            db_pool,
            pending.id,
            expected_issuer=ISSUER,
            expected_subject_id=f"{SUBJECT}:rollback",
            access_tier="vetted",
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

    assert (
        sync_conn.execute(
            """SELECT federated_status, is_active, access_tier, is_admin,
                  email_verified, federated_approved_at, federated_approved_by,
                  auth_revision
             FROM users WHERE id = %s""",
            (pending.id,),
        ).fetchone()
        == before
    )
    assert sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE id = %s",
        (users.hash_session_id(anomalous_session),),
    ).fetchone() == (1,)

    # A transient failure must not strand the identity in a partially approved
    # state. Retrying through the real revoker performs the whole transition.
    monkeypatch.setattr(users, "delete_user_sessions_cur", real_delete)
    approved = await users.approve_federated_user(
        db_pool,
        pending.id,
        expected_issuer=ISSUER,
        expected_subject_id=f"{SUBJECT}:rollback",
        access_tier="vetted",
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )
    assert approved.federated_status == "approved"
    assert sync_conn.execute(
        "SELECT auth_revision FROM users WHERE id = %s",
        (pending.id,),
    ).fetchone() == (before[7] + 1,)
    assert sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s",
        (pending.id,),
    ).fetchone() == (0,)


async def test_stale_policy_cannot_approve_or_mutate_pending_identity(
    db_pool,
    user_factory,
    session_factory,
    admin_actor,
    sync_conn,
    monkeypatch,
):
    pending = user_factory(
        auth_method="shibboleth",
        is_active=False,
        federated_status="pending",
        shibboleth_issuer=ISSUER,
        shibboleth_subject_id=f"{SUBJECT}:stale-policy",
        access_tier="public",
    )
    session_factory(pending.id)
    before = sync_conn.execute(
        """SELECT federated_status, is_active, access_tier, auth_revision
             FROM users WHERE id = %s""",
        (pending.id,),
    ).fetchone()
    monkeypatch.setattr(
        users.settings,
        "shibboleth_internal_secret",
        SecretStr(ROTATED_SECRET),
    )

    with pytest.raises(users.AdminActionRejected, match="federation policy changed"):
        await users.approve_federated_user(
            db_pool,
            pending.id,
            expected_issuer=ISSUER,
            expected_subject_id=f"{SUBJECT}:stale-policy",
            access_tier="vetted",
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

    assert (
        sync_conn.execute(
            """SELECT federated_status, is_active, access_tier, auth_revision
             FROM users WHERE id = %s""",
            (pending.id,),
        ).fetchone()
        == before
    )
    assert sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (pending.id,)
    ).fetchone() == (1,)


@pytest.mark.parametrize(
    ("expected_issuer", "expected_subject"),
    [
        ("https://different-idp.example/idp/shibboleth", SUBJECT),
        (ISSUER, "urn:test:subject:different"),
    ],
)
async def test_stale_or_tampered_review_identity_cannot_approve(
    db_pool,
    user_factory,
    admin_actor,
    sync_conn,
    monkeypatch,
    expected_issuer,
    expected_subject,
):
    pending = user_factory(
        auth_method="shibboleth",
        is_active=False,
        federated_status="pending",
        shibboleth_issuer=ISSUER,
        shibboleth_subject_id=SUBJECT,
    )
    if expected_issuer != ISSUER:
        monkeypatch.setattr(
            users.settings,
            "shibboleth_trusted_issuers",
            [ISSUER, expected_issuer],
        )

    with pytest.raises(users.AdminActionRejected):
        await users.approve_federated_user(
            db_pool,
            pending.id,
            expected_issuer=expected_issuer,
            expected_subject_id=expected_subject,
            access_tier="registered",
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

    assert sync_conn.execute(
        """SELECT federated_status, is_active, access_tier,
                  federated_approved_at, federated_approved_by
             FROM users WHERE id = %s""",
        (pending.id,),
    ).fetchone() == ("pending", False, "public", None, None)


@pytest.mark.parametrize("status", ["pending", "legacy_quarantined"])
@pytest.mark.parametrize("operation", ["activate", "tier"])
async def test_generic_admin_mutations_cannot_bypass_federated_review(
    db_pool, user_factory, admin_actor, sync_conn, status, operation
):
    target = user_factory(
        auth_method="shibboleth",
        federated_status=status,
        shibboleth_issuer=ISSUER,
        shibboleth_subject_id=f"{SUBJECT}:{status}:{operation}",
    )

    common = {
        "actor_id": admin_actor.id,
        "actor_session_id": admin_actor.session_id,
    }
    with pytest.raises(users.AdminActionRejected, match="dedicated federated-review"):
        if operation == "activate":
            await users.set_user_active(db_pool, target.id, True, **common)
        else:
            await users.update_access_tier(db_pool, target.id, "vetted", **common)

    assert sync_conn.execute(
        "SELECT federated_status, is_active, access_tier, is_admin FROM users WHERE id = %s",
        (target.id,),
    ).fetchone() == (status, False, "public", False)


@pytest.mark.parametrize("status", ["pending", "legacy_quarantined"])
async def test_admin_grant_on_unreviewed_federated_identity_is_rejected_by_the_promotion_workflow(
    db_pool, user_factory, admin_actor, sync_conn, status
):
    """A direct administrator grant never exists: administrator access is
    offered and accepted through the promotion workflow, so the generic
    membership sink rejects it before federated review is even consulted, and
    the unreviewed identity stays exactly as it was."""
    target = user_factory(
        auth_method="shibboleth",
        federated_status=status,
        shibboleth_issuer=ISSUER,
        shibboleth_subject_id=f"{SUBJECT}:{status}:admin",
    )

    with pytest.raises(users.AdminActionRejected, match="promotion workflow"):
        await users.set_user_admin(
            db_pool,
            target.id,
            True,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

    assert sync_conn.execute(
        "SELECT federated_status, is_active, access_tier, is_admin FROM users WHERE id = %s",
        (target.id,),
    ).fetchone() == (status, False, "public", False)


async def test_approved_disable_and_reactivation_preserve_review_provenance(
    db_pool, user_factory, session_factory, admin_actor, sync_conn
):
    approved_at = datetime(2026, 2, 3, tzinfo=UTC)
    target = user_factory(
        auth_method="shibboleth",
        federated_status="approved",
        access_tier="registered",
        federated_approved_at=approved_at,
        federated_approved_by=admin_actor.id,
        shibboleth_issuer=ISSUER,
        shibboleth_subject_id=SUBJECT,
    )
    session_factory(target.id)

    disabled = await users.set_user_active(
        db_pool,
        target.id,
        False,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )
    assert disabled == users.SetActiveResult(True, False, False)
    assert sync_conn.execute(
        """SELECT federated_status, is_active, federated_approved_at,
                  federated_approved_by FROM users WHERE id = %s""",
        (target.id,),
    ).fetchone() == ("disabled", False, approved_at, admin_actor.id)
    assert sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (target.id,)
    ).fetchone() == (0,)

    reactivated = await users.set_user_active(
        db_pool,
        target.id,
        True,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )
    assert reactivated == users.SetActiveResult(False, True, False)
    assert sync_conn.execute(
        """SELECT federated_status, is_active, federated_approved_at,
                  federated_approved_by FROM users WHERE id = %s""",
        (target.id,),
    ).fetchone() == ("approved", True, approved_at, admin_actor.id)

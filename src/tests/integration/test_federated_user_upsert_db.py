"""Real-PostgreSQL tests for issuer-scoped Shibboleth provisioning.

The security identity is the exact ``(issuer, subject)`` pair. Email and
profile attributes are mutable claims and may never select or merge accounts.
New identities are deliberately quarantined pending administrator review:
public tier, inactive, and not locally email-verified.
"""

import pytest
from psycopg.errors import CheckViolation
from psycopg.rows import dict_row

from app.services.users import create_shibboleth_user

ISSUER_A = "https://idp-a.test.example/idp/shibboleth"
ISSUER_B = "https://idp-b.test.example/idp/shibboleth"


def _fetch_user_row(sync_conn, email_lower: str):
    """Fetch a raw users row by normalized email for security assertions."""
    with sync_conn.cursor(row_factory=dict_row) as cur:
        return cur.execute(
            """SELECT id, email, display_name, affiliation, country, auth_method,
                      access_tier, email_verified, is_active, is_admin,
                      last_login, password_hash, shibboleth_issuer,
                      shibboleth_subject_id, federated_status,
                      federated_approved_at, federated_approved_by
               FROM users WHERE LOWER(email) = %s""",
            (email_lower,),
        ).fetchone()


def _count_users(sync_conn) -> int:
    return sync_conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def _approve_federated_user(sync_conn, user_id: int) -> None:
    """Move a pending test identity into one coherent approved state."""
    sync_conn.execute(
        """UPDATE users
           SET federated_status = 'approved',
               is_active = true,
               federated_approved_at = clock_timestamp(),
               federated_approved_by = 9001
           WHERE id = %s""",
        (user_id,),
    )
    sync_conn.commit()


def _fetch_email_bound_state(sync_conn, user_id: int):
    """Return all user-row state invalidated when an asserted email changes."""
    with sync_conn.cursor(row_factory=dict_row) as cur:
        return cur.execute(
            """SELECT email, email_verified,
                      email_verification_token_hash,
                      email_verification_created_at,
                      pending_email,
                      pending_email_token_hash,
                      pending_email_created_at,
                      password_reset_token_hash,
                      password_reset_created_at
               FROM users
               WHERE id = %s""",
            (user_id,),
        ).fetchone()


def _seed_email_bound_state(sync_conn, user_id: int) -> None:
    """Seed credentials tied to the currently stored federated email."""
    sync_conn.execute(
        """UPDATE users
           SET email_verification_token_hash = 'verification-hash',
               email_verification_created_at = clock_timestamp(),
               pending_email = 'pending@example.org',
               pending_email_token_hash = 'pending-hash',
               pending_email_created_at = clock_timestamp(),
               password_reset_token_hash = 'reset-hash',
               password_reset_created_at = clock_timestamp()
           WHERE id = %s""",
        (user_id,),
    )
    sync_conn.commit()


async def _provision(db_pool, **overrides):
    values = {
        "issuer": ISSUER_A,
        "subject_id": "urn:sub:jane",
        "email": "jane@x.org",
        "display_name": "Jane",
    }
    values.update(overrides)
    return await create_shibboleth_user(db_pool, **values)


async def test_first_assertion_creates_only_a_pending_public_identity(db_pool, sync_conn):
    user = await _provision(
        db_pool,
        affiliation="UZH",
        country="CH",
    )

    assert user is not None
    assert user.email == "jane@x.org"
    assert user.display_name == "Jane"
    assert user.affiliation == "UZH"
    assert user.country == "CH"
    assert user.auth_method == "shibboleth"
    assert user.access_tier == "public"
    assert user.email_verified is False
    assert user.is_active is False
    assert user.last_login is None

    row = _fetch_user_row(sync_conn, "jane@x.org")
    assert row is not None
    assert row["shibboleth_issuer"] == ISSUER_A
    assert row["shibboleth_subject_id"] == "urn:sub:jane"
    assert row["auth_method"] == "shibboleth"
    assert row["access_tier"] == "public"
    assert row["email_verified"] is False
    assert row["is_active"] is False
    assert row["password_hash"] is None
    assert row["federated_status"] == "pending"
    assert row["federated_approved_at"] is None
    assert row["federated_approved_by"] is None


async def test_returning_identity_updates_profile_but_preserves_authorization(db_pool, sync_conn):
    first = await _provision(db_pool)
    assert first is not None

    sync_conn.execute(
        """UPDATE users
           SET access_tier = 'vetted', is_admin = true,
               is_active = true, email_verified = false,
               federated_status = 'approved',
               federated_approved_at = clock_timestamp(),
               federated_approved_by = 9001
           WHERE id = %s""",
        (first.id,),
    )
    sync_conn.commit()

    second = await _provision(
        db_pool,
        email="jane@new.org",
        display_name="Jane Doe",
        affiliation="New affiliation",
    )

    assert second is not None
    assert second.id == first.id
    assert second.email == "jane@new.org"
    assert second.display_name == "Jane Doe"
    assert second.affiliation == "New affiliation"
    assert second.access_tier == "vetted"
    assert second.is_admin is True
    assert second.is_active is True
    assert second.email_verified is False
    assert _count_users(sync_conn) == 1

    row = _fetch_user_row(sync_conn, "jane@new.org")
    assert row["shibboleth_issuer"] == ISSUER_A
    assert row["shibboleth_subject_id"] == "urn:sub:jane"


async def test_same_subject_from_different_issuers_is_a_different_identity(db_pool, sync_conn):
    first = await _provision(db_pool, email="a@example.org")
    second = await _provision(db_pool, issuer=ISSUER_B, email="b@example.org")

    assert first is not None
    assert second is not None
    assert second.id != first.id
    assert _count_users(sync_conn) == 2


async def test_same_issuer_and_subject_is_case_sensitive(db_pool, sync_conn):
    first = await _provision(db_pool, subject_id="Opaque-Subject", email="a@example.org")
    second = await _provision(db_pool, subject_id="opaque-subject", email="b@example.org")

    assert first is not None
    assert second is not None
    assert second.id != first.id
    assert _count_users(sync_conn) == 2


async def test_coalesce_keeps_profile_values_when_active_idp_omits_them(db_pool, sync_conn):
    first = await _provision(db_pool, affiliation="UZH", country="CH")
    assert first is not None
    _approve_federated_user(sync_conn, first.id)

    second = await _provision(
        db_pool,
        display_name=None,
        affiliation=None,
        country=None,
    )

    assert second is not None
    assert second.id == first.id
    assert second.display_name == "Jane"
    assert second.affiliation == "UZH"
    assert second.country == "CH"


async def test_mixed_case_email_is_normalized_on_insert_and_update(db_pool, sync_conn):
    first = await _provision(db_pool, email=" MiXed@Case.Org ")
    assert first is not None
    assert first.email == "mixed@case.org"
    _approve_federated_user(sync_conn, first.id)

    second = await _provision(db_pool, email="MIXED@CASE.ORG", display_name="Jane Doe")
    assert second is not None
    assert second.id == first.id
    assert second.email == "mixed@case.org"
    assert _count_users(sync_conn) == 1


async def test_same_normalized_email_preserves_email_bound_state(db_pool, sync_conn):
    first = await _provision(db_pool)
    assert first is not None
    _approve_federated_user(sync_conn, first.id)
    _seed_email_bound_state(sync_conn, first.id)
    before = _fetch_email_bound_state(sync_conn, first.id)

    returning = await _provision(
        db_pool,
        email=" JANE@X.ORG ",
        display_name="Updated profile",
    )

    assert returning is not None
    assert returning.id == first.id
    assert _fetch_email_bound_state(sync_conn, first.id) == before


async def test_changed_email_clears_every_old_email_credential(db_pool, sync_conn):
    first = await _provision(db_pool)
    assert first is not None
    _approve_federated_user(sync_conn, first.id)
    _seed_email_bound_state(sync_conn, first.id)

    returning = await _provision(db_pool, email="new-address@example.org")

    assert returning is not None
    assert returning.id == first.id
    assert _fetch_email_bound_state(sync_conn, first.id) == {
        "email": "new-address@example.org",
        "email_verified": False,
        "email_verification_token_hash": None,
        "email_verification_created_at": None,
        "pending_email": None,
        "pending_email_token_hash": None,
        "pending_email_created_at": None,
        "password_reset_token_hash": None,
        "password_reset_created_at": None,
    }


async def test_local_email_collision_returns_none_and_leaves_row_untouched(
    db_pool, sync_conn, user_factory
):
    user_factory(email="owned@uzh.ch")
    before = _fetch_user_row(sync_conn, "owned@uzh.ch")
    assert before is not None

    result = await _provision(
        db_pool,
        email="OWNED@uzh.ch",
        display_name="Attacker",
        affiliation="Untrusted",
    )

    assert result is None
    assert _fetch_user_row(sync_conn, "owned@uzh.ch") == before
    assert _count_users(sync_conn) == 1


async def test_recycled_federated_email_does_not_transfer_account(db_pool, sync_conn):
    original = await _provision(
        db_pool,
        subject_id="urn:sub:alice",
        email="shared@uzh.ch",
        display_name="Alice",
    )
    assert original is not None

    newcomer = await _provision(
        db_pool,
        subject_id="urn:sub:bob",
        email="shared@uzh.ch",
        display_name="Bob",
    )

    assert newcomer is None
    assert _count_users(sync_conn) == 1
    row = _fetch_user_row(sync_conn, "shared@uzh.ch")
    assert row["id"] == original.id
    assert row["display_name"] == "Alice"


def _grant_reviewed_authority(sync_conn, user_id: int) -> None:
    """Give an approved identity the standing an administrator granted it."""
    sync_conn.execute(
        "UPDATE users SET access_tier = 'vetted', is_admin = true WHERE id = %s",
        (user_id,),
    )
    sync_conn.commit()


def _session_owner_ids(sync_conn) -> list[int]:
    return [row[0] for row in sync_conn.execute("SELECT user_id FROM sessions ORDER BY id")]


async def test_an_email_one_subject_gave_up_never_carries_its_account_to_another(
    db_pool, sync_conn, session_factory
):
    """The reassignment case. One subject's asserted address changes, so the
    old address is free; a different subject then presents it. The newcomer
    must be provisioned as the stranger it is — its own quarantined row — and
    must inherit none of the first subject's tier, administrator standing, or
    live sessions.
    """
    original = await _provision(db_pool, subject_id="urn:sub:alice", email="shared@uzh.ch")
    assert original is not None
    _approve_federated_user(sync_conn, original.id)
    _grant_reviewed_authority(sync_conn, original.id)
    session_factory(original.id, purpose="full")

    moved = await _provision(db_pool, subject_id="urn:sub:alice", email="alice-elsewhere@uzh.ch")
    assert moved is not None
    assert moved.id == original.id, "an email change must not split the identity in two"

    newcomer = await _provision(db_pool, subject_id="urn:sub:bob", email="shared@uzh.ch")

    assert newcomer is not None
    assert newcomer.id != original.id
    assert newcomer.access_tier == "public"
    assert newcomer.is_active is False
    assert newcomer.is_admin is False
    assert newcomer.federated_status == "pending"

    retained = _fetch_user_row(sync_conn, "alice-elsewhere@uzh.ch")
    assert retained["id"] == original.id
    assert retained["access_tier"] == "vetted"
    assert retained["is_admin"] is True
    assert retained["shibboleth_subject_id"] == "urn:sub:alice"
    assert _session_owner_ids(sync_conn) == [original.id]


async def test_a_subject_cannot_take_over_another_row_by_asserting_its_email(
    db_pool, sync_conn, session_factory
):
    """The mirror case. The address a subject asserts is already held by a
    different subject, so the assertion must be refused outright rather than
    merging the two identities — and neither row may be touched on the way
    out.
    """
    incumbent = await _provision(db_pool, subject_id="urn:sub:bob", email="bob@uzh.ch")
    assert incumbent is not None
    _approve_federated_user(sync_conn, incumbent.id)
    _grant_reviewed_authority(sync_conn, incumbent.id)
    session_factory(incumbent.id, purpose="full")

    claimant = await _provision(db_pool, subject_id="urn:sub:alice", email="alice@uzh.ch")
    assert claimant is not None
    _approve_federated_user(sync_conn, claimant.id)

    incumbent_before = _fetch_user_row(sync_conn, "bob@uzh.ch")
    claimant_before = _fetch_user_row(sync_conn, "alice@uzh.ch")

    result = await _provision(db_pool, subject_id="urn:sub:alice", email="bob@uzh.ch")

    assert result is None
    assert _fetch_user_row(sync_conn, "bob@uzh.ch") == incumbent_before
    assert _fetch_user_row(sync_conn, "alice@uzh.ch") == claimant_before
    assert _count_users(sync_conn) == 2
    assert _session_owner_ids(sync_conn) == [incumbent.id]


async def test_cross_issuer_email_collision_does_not_transfer_account(db_pool, sync_conn):
    original = await _provision(db_pool, email="shared@uzh.ch")
    assert original is not None

    newcomer = await _provision(db_pool, issuer=ISSUER_B, email="shared@uzh.ch")

    assert newcomer is None
    assert _count_users(sync_conn) == 1
    row = _fetch_user_row(sync_conn, "shared@uzh.ch")
    assert row["id"] == original.id
    assert row["shibboleth_issuer"] == ISSUER_A


@pytest.mark.parametrize(
    ("issuer", "subject_id"),
    [
        ("", "urn:sub:jane"),
        ("   ", "urn:sub:jane"),
        (f" {ISSUER_A}", "urn:sub:jane"),
        (f"{ISSUER_A} ", "urn:sub:jane"),
        (f"{ISSUER_A},https://other.example/idp", "urn:sub:jane"),
        (ISSUER_A, ""),
        (ISSUER_A, "   "),
        (ISSUER_A, " urn:sub:jane"),
        (ISSUER_A, "urn:sub:jane "),
        (ISSUER_A, "urn:sub:jane,attacker-subject"),
    ],
)
async def test_blank_identity_component_is_refused_without_write(
    db_pool, sync_conn, issuer, subject_id
):
    assert await _provision(db_pool, issuer=issuer, subject_id=subject_id, email="x@uzh.ch") is None
    assert _count_users(sync_conn) == 0


def _insert_federated_row(
    sync_conn,
    *,
    issuer=ISSUER_A,
    subject_id="urn:sub:jane",
    status="pending",
    is_active=False,
    access_tier="public",
    is_admin=False,
    email_verified=False,
    approved_at=None,
    approved_by=None,
):
    return sync_conn.execute(
        """INSERT INTO users (
               email, auth_method, shibboleth_issuer, shibboleth_subject_id,
               federated_status, is_active, access_tier, is_admin,
               email_verified, federated_approved_at, federated_approved_by
           )
           VALUES (
               'identity-shape@example.org', 'shibboleth', %s, %s,
               %s, %s, %s, %s, %s, %s, %s
           )""",
        (
            issuer,
            subject_id,
            status,
            is_active,
            access_tier,
            is_admin,
            email_verified,
            approved_at,
            approved_by,
        ),
    )


@pytest.mark.parametrize(
    ("issuer", "subject_id"),
    [
        (None, "urn:sub:jane"),
        (ISSUER_A, None),
        ("", "urn:sub:jane"),
        (ISSUER_A, ""),
        (f" {ISSUER_A}", "urn:sub:jane"),
        (f"{ISSUER_A} ", "urn:sub:jane"),
        (ISSUER_A, " urn:sub:jane"),
        (ISSUER_A, "urn:sub:jane "),
    ],
)
def test_database_rejects_missing_blank_or_noncanonical_identity(sync_conn, issuer, subject_id):
    with pytest.raises(CheckViolation, match="users_federated_state_check"):
        _insert_federated_row(sync_conn, issuer=issuer, subject_id=subject_id)
    sync_conn.rollback()


@pytest.mark.parametrize(
    ("status", "is_active", "access_tier", "is_admin", "approved_at", "approved_by"),
    [
        ("pending", True, "public", False, None, None),
        ("pending", False, "registered", False, None, None),
        ("pending", False, "public", True, None, None),
        ("pending", False, "public", False, "2026-01-01T00:00:00Z", 7),
        ("approved", False, "registered", False, "2026-01-01T00:00:00Z", 7),
        ("approved", True, "registered", False, None, 7),
        ("approved", True, "registered", False, "2026-01-01T00:00:00Z", None),
        ("disabled", True, "registered", False, "2026-01-01T00:00:00Z", 7),
        ("disabled", False, "registered", False, None, None),
        ("legacy_quarantined", True, "public", False, None, None),
        ("legacy_quarantined", False, "vetted", False, None, None),
        ("legacy_quarantined", False, "public", True, None, None),
        ("unknown", False, "public", False, None, None),
        (None, False, "public", False, None, None),
    ],
)
def test_database_rejects_incoherent_federated_state(
    sync_conn,
    status,
    is_active,
    access_tier,
    is_admin,
    approved_at,
    approved_by,
):
    with pytest.raises(CheckViolation, match="users_federated_state_check"):
        _insert_federated_row(
            sync_conn,
            status=status,
            is_active=is_active,
            access_tier=access_tier,
            is_admin=is_admin,
            approved_at=approved_at,
            approved_by=approved_by,
        )
    sync_conn.rollback()


def test_database_rejects_verified_federated_identity(sync_conn):
    with pytest.raises(CheckViolation, match="users_federated_state_check"):
        _insert_federated_row(sync_conn, email_verified=True)
    sync_conn.rollback()


@pytest.mark.parametrize(
    ("status", "is_active", "access_tier", "is_admin", "approved_at", "approved_by"),
    [
        ("pending", False, "public", False, None, None),
        ("approved", True, "vetted", True, "2026-01-01T00:00:00Z", 7),
        ("disabled", False, "vetted", True, "2026-01-01T00:00:00Z", 7),
        ("legacy_quarantined", False, "public", False, None, None),
    ],
)
def test_database_accepts_each_coherent_federated_state(
    sync_conn,
    status,
    is_active,
    access_tier,
    is_admin,
    approved_at,
    approved_by,
):
    _insert_federated_row(
        sync_conn,
        status=status,
        is_active=is_active,
        access_tier=access_tier,
        is_admin=is_admin,
        approved_at=approved_at,
        approved_by=approved_by,
    )
    sync_conn.commit()
    assert _count_users(sync_conn) == 1


@pytest.mark.parametrize(
    ("issuer", "subject_id", "status", "approved_at", "approved_by"),
    [
        (ISSUER_A, None, None, None, None),
        (None, "urn:sub:jane", None, None, None),
        (None, None, "pending", None, None),
        (None, None, None, "2026-01-01T00:00:00Z", None),
        (None, None, None, None, 7),
    ],
)
def test_database_rejects_federation_state_on_local_account(
    sync_conn, issuer, subject_id, status, approved_at, approved_by
):
    with pytest.raises(CheckViolation, match="users_federated_state_check"):
        sync_conn.execute(
            """INSERT INTO users (
                   email, password_hash, auth_method,
                   shibboleth_issuer, shibboleth_subject_id,
                   federated_status, federated_approved_at, federated_approved_by
               )
               VALUES (
                   'local-shape@example.org', 'test-hash', 'local',
                   %s, %s, %s, %s, %s
               )""",
            (issuer, subject_id, status, approved_at, approved_by),
        )
    sync_conn.rollback()

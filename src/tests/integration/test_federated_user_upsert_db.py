"""Real-PostgreSQL tests for issuer-scoped Shibboleth provisioning."""

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
    """Count all stored user rows."""
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
    """Create a federated user with the supplied field overrides."""
    values = {
        "issuer": ISSUER_A,
        "subject_id": "urn:sub:jane",
        "email": "jane@x.org",
        "display_name": "Jane",
    }
    values.update(overrides)
    return await create_shibboleth_user(db_pool, **values)


async def test_first_assertion_creates_only_a_pending_public_identity(db_pool, sync_conn):
    """Verify first assertion creates only a pending public identity."""
    user = await _provision(
        db_pool,
        affiliation="Example University",
        country="CH",
    )

    assert user is not None
    assert user.email == "jane@x.org"
    assert user.display_name == "Jane"
    assert user.affiliation == "Example University"
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
    """Verify returning identity updates profile but preserves authorization."""
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
    """Verify same subject from different issuers is a different identity."""
    first = await _provision(db_pool, email="a@example.org")
    second = await _provision(db_pool, issuer=ISSUER_B, email="b@example.org")

    assert first is not None
    assert second is not None
    assert second.id != first.id
    assert _count_users(sync_conn) == 2


async def test_same_issuer_and_subject_is_case_sensitive(db_pool, sync_conn):
    """Verify same issuer and subject is case sensitive."""
    first = await _provision(db_pool, subject_id="Opaque-Subject", email="a@example.org")
    second = await _provision(db_pool, subject_id="opaque-subject", email="b@example.org")

    assert first is not None
    assert second is not None
    assert second.id != first.id
    assert _count_users(sync_conn) == 2


async def test_coalesce_keeps_profile_values_when_active_idp_omits_them(db_pool, sync_conn):
    """Verify coalesce keeps profile values when active idp omits them."""
    first = await _provision(db_pool, affiliation="Example University", country="CH")
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
    assert second.affiliation == "Example University"
    assert second.country == "CH"


async def test_mixed_case_email_is_normalized_on_insert_and_update(db_pool, sync_conn):
    """Verify mixed case email is normalized on insert and update."""
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
    """Verify same normalized email preserves email bound state."""
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
    """Verify changed email clears every old email credential."""
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
    """Verify local email collision returns none and leaves row untouched."""
    user_factory(email="owned@example.org")
    before = _fetch_user_row(sync_conn, "owned@example.org")
    assert before is not None

    result = await _provision(
        db_pool,
        email="OWNED@example.org",
        display_name="Attacker",
        affiliation="Untrusted",
    )

    assert result is None
    assert _fetch_user_row(sync_conn, "owned@example.org") == before
    assert _count_users(sync_conn) == 1


async def test_recycled_federated_email_does_not_transfer_account(db_pool, sync_conn):
    """Verify recycled federated email does not transfer account."""
    original = await _provision(
        db_pool,
        subject_id="urn:sub:alice",
        email="shared@example.org",
        display_name="Alice",
    )
    assert original is not None

    newcomer = await _provision(
        db_pool,
        subject_id="urn:sub:bob",
        email="shared@example.org",
        display_name="Bob",
    )

    assert newcomer is None
    assert _count_users(sync_conn) == 1
    row = _fetch_user_row(sync_conn, "shared@example.org")
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
    """Read session owner IDs in stored session order."""
    return [row[0] for row in sync_conn.execute("SELECT user_id FROM sessions ORDER BY id")]


async def test_an_email_one_subject_gave_up_never_carries_its_account_to_another(
    db_pool, sync_conn, session_factory
):
    """Verify an email one subject gave up never carries its account to another."""
    original = await _provision(db_pool, subject_id="urn:sub:alice", email="shared@example.org")
    assert original is not None
    _approve_federated_user(sync_conn, original.id)
    _grant_reviewed_authority(sync_conn, original.id)
    session_factory(original.id, purpose="full")

    moved = await _provision(
        db_pool, subject_id="urn:sub:alice", email="alice-elsewhere@example.org"
    )
    assert moved is not None
    assert moved.id == original.id, "an email change must not split the identity in two"

    newcomer = await _provision(db_pool, subject_id="urn:sub:bob", email="shared@example.org")

    assert newcomer is not None
    assert newcomer.id != original.id
    assert newcomer.access_tier == "public"
    assert newcomer.is_active is False
    assert newcomer.is_admin is False
    assert newcomer.federated_status == "pending"

    retained = _fetch_user_row(sync_conn, "alice-elsewhere@example.org")
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
    incumbent = await _provision(db_pool, subject_id="urn:sub:bob", email="bob@example.org")
    assert incumbent is not None
    _approve_federated_user(sync_conn, incumbent.id)
    _grant_reviewed_authority(sync_conn, incumbent.id)
    session_factory(incumbent.id, purpose="full")

    claimant = await _provision(db_pool, subject_id="urn:sub:alice", email="alice@example.org")
    assert claimant is not None
    _approve_federated_user(sync_conn, claimant.id)

    incumbent_before = _fetch_user_row(sync_conn, "bob@example.org")
    claimant_before = _fetch_user_row(sync_conn, "alice@example.org")

    result = await _provision(db_pool, subject_id="urn:sub:alice", email="bob@example.org")

    assert result is None
    assert _fetch_user_row(sync_conn, "bob@example.org") == incumbent_before
    assert _fetch_user_row(sync_conn, "alice@example.org") == claimant_before
    assert _count_users(sync_conn) == 2
    assert _session_owner_ids(sync_conn) == [incumbent.id]


async def test_cross_issuer_email_collision_does_not_transfer_account(db_pool, sync_conn):
    """Verify cross issuer email collision does not transfer account."""
    original = await _provision(db_pool, email="shared@example.org")
    assert original is not None

    newcomer = await _provision(db_pool, issuer=ISSUER_B, email="shared@example.org")

    assert newcomer is None
    assert _count_users(sync_conn) == 1
    row = _fetch_user_row(sync_conn, "shared@example.org")
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
    """Verify blank identity component is refused without write."""
    assert (
        await _provision(db_pool, issuer=issuer, subject_id=subject_id, email="x@example.org")
        is None
    )
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
    """Insert a federated identity with the supplied authority fields."""
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
    """Verify database rejects missing blank or noncanonical identity."""
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
        ("unsupported", False, "public", False, None, None),
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
    """Verify database rejects incoherent federated state."""
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
    """Verify database rejects verified federated identity."""
    with pytest.raises(CheckViolation, match="users_federated_state_check"):
        _insert_federated_row(sync_conn, email_verified=True)
    sync_conn.rollback()


@pytest.mark.parametrize(
    ("status", "is_active", "access_tier", "is_admin", "approved_at", "approved_by"),
    [
        ("pending", False, "public", False, None, None),
        ("approved", True, "vetted", True, "2026-01-01T00:00:00Z", 7),
        ("disabled", False, "vetted", True, "2026-01-01T00:00:00Z", 7),
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
    """Verify database accepts each coherent federated state."""
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
    """Verify database rejects federation state on local account."""
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

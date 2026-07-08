"""Integration tests for create_shibboleth_user (backlog §3.4).

The upsert uses `ON CONFLICT ((LOWER(email)))`, an EXPRESSION conflict
target that only binds against the real `idx_users_email_lower` unique
index at runtime — Postgres raises "no unique or exclusion constraint
matching the ON CONFLICT specification" if the expression and the index
ever drift. That binding cannot be proven with mocks, hence real PG here.

Covers: first-login auto-provision, returning-user update (same id,
refreshed last_login), the mixed-case IdP email pin, COALESCE keeping old
attributes on NULL, the local-account collision guard (SECURITY: never
merge a Shibboleth login into a local account, including case variants),
and email normalization on insert.
"""

from app.services.users import create_shibboleth_user


def _fetch_user_row(sync_conn, email_lower: str):
    """Fetch the raw users row (case-insensitively) for test-side asserts."""
    return sync_conn.execute(
        """SELECT id, email, display_name, affiliation, country, auth_method,
                  access_tier, email_verified, last_login, password_hash
           FROM users WHERE LOWER(email) = %s""",
        (email_lower,),
    ).fetchone()


def _count_users(sync_conn) -> int:
    return sync_conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


async def test_first_login_inserts_without_on_conflict_error(db_pool, sync_conn):
    """§3.4 binding proof: a brand-new email INSERTs cleanly — no
    'no unique or exclusion constraint matching the ON CONFLICT
    specification' error, proving `ON CONFLICT ((LOWER(email)))` binds to
    idx_users_email_lower. Row carries the Shibboleth provisioning
    defaults: auth_method shibboleth, tier registered, verified, last_login
    set, no password hash."""
    user = await create_shibboleth_user(
        db_pool, "jane@x.org", display_name="Jane", affiliation="UZH", country="CH"
    )

    assert user is not None
    assert user.email == "jane@x.org"
    assert user.display_name == "Jane"
    assert user.affiliation == "UZH"
    assert user.country == "CH"
    assert user.auth_method == "shibboleth"
    assert user.access_tier == "registered"
    assert user.email_verified is True
    assert user.last_login is not None

    row = _fetch_user_row(sync_conn, "jane@x.org")
    assert row is not None
    (_, email, display_name, affiliation, country, auth_method,
     access_tier, email_verified, last_login, password_hash) = row
    assert email == "jane@x.org"
    assert auth_method == "shibboleth"
    assert access_tier == "registered"
    assert email_verified is True
    assert last_login is not None
    assert password_hash is None


async def test_returning_user_updates_same_row(db_pool, sync_conn):
    """§3.4 returning-user path: a second login with the same email hits the
    DO UPDATE arm — same id (no duplicate row), display_name refreshed from
    the IdP, last_login moved forward (>= the first login's timestamp)."""
    first = await create_shibboleth_user(db_pool, "jane@x.org", display_name="Jane")
    assert first is not None

    second = await create_shibboleth_user(db_pool, "jane@x.org", display_name="Jane Doe")
    assert second is not None
    assert second.id == first.id
    assert second.display_name == "Jane Doe"
    assert second.last_login is not None
    assert first.last_login is not None
    assert second.last_login >= first.last_login

    assert _count_users(sync_conn) == 1


async def test_mixed_case_email_updates_existing_row(db_pool, sync_conn):
    """§3.4 sharp pin: the IdP starts sending 'Jane@X.org' for a user stored
    as 'jane@x.org'. The LOWER(email) conflict target must route this to the
    DO UPDATE arm — same id, still exactly one row, not an insert, not an
    error, not None (which would block the login)."""
    first = await create_shibboleth_user(db_pool, "jane@x.org", display_name="Jane")
    assert first is not None
    await create_shibboleth_user(db_pool, "jane@x.org", display_name="Jane Doe")

    third = await create_shibboleth_user(db_pool, "Jane@X.org", display_name="Jane D.")
    assert third is not None
    assert third.id == first.id
    assert third.display_name == "Jane D."

    assert _count_users(sync_conn) == 1
    row = _fetch_user_row(sync_conn, "jane@x.org")
    assert row[0] == first.id


async def test_coalesce_keeps_old_attributes_when_idp_sends_none(db_pool):
    """§3.4 COALESCE guard: a login where the IdP omits attributes
    (display_name/affiliation/country None) must NOT wipe the stored values —
    COALESCE(EXCLUDED.x, users.x) keeps the previous data."""
    first = await create_shibboleth_user(
        db_pool, "jane@x.org", display_name="Jane", affiliation="UZH", country="CH"
    )
    assert first is not None

    second = await create_shibboleth_user(
        db_pool, "jane@x.org", display_name=None, affiliation=None, country=None
    )
    assert second is not None
    assert second.id == first.id
    assert second.display_name == "Jane"
    assert second.affiliation == "UZH"
    assert second.country == "CH"


async def test_local_account_collision_returns_none_and_row_untouched(
    db_pool, sync_conn, user_factory
):
    """§3.4 SECURITY guard: when a LOCAL account owns the email, the
    `WHERE users.auth_method = 'shibboleth'` clause skips the update, so
    RETURNING is empty and the service returns None (caller must treat as
    login failure). The local row is left completely untouched — auth_method
    still 'local', password_hash intact, display_name unchanged."""
    user_factory(email="owned@uzh.ch")
    before = _fetch_user_row(sync_conn, "owned@uzh.ch")
    assert before is not None

    result = await create_shibboleth_user(
        db_pool, "owned@uzh.ch", display_name="Attacker", affiliation="Evil"
    )
    assert result is None

    after = _fetch_user_row(sync_conn, "owned@uzh.ch")
    assert after == before  # every column identical — no merge happened
    assert after[5] == "local"  # auth_method
    assert after[9] is not None  # password_hash intact
    assert _count_users(sync_conn) == 1


async def test_local_account_collision_case_variant_also_blocked(
    db_pool, sync_conn, user_factory
):
    """§3.4 SECURITY guard, case variant: 'OWNED@uzh.ch' against a local
    'owned@uzh.ch'. The LOWER() unique index catches the collision (so no
    second row is inserted) and the auth_method guard still refuses the
    update — result is None and exactly one (local) row remains."""
    user_factory(email="owned@uzh.ch")

    result = await create_shibboleth_user(db_pool, "OWNED@uzh.ch", display_name="Attacker")
    assert result is None

    assert _count_users(sync_conn) == 1
    row = _fetch_user_row(sync_conn, "owned@uzh.ch")
    assert row[5] == "local"
    assert row[9] is not None


async def test_email_normalized_on_insert(db_pool, sync_conn):
    """§3.4 normalization: the service strips and lowercases the IdP email
    before insert, so ' MiXed@Case.Org ' is stored as 'mixed@case.org'."""
    user = await create_shibboleth_user(db_pool, " MiXed@Case.Org ", display_name="Mixy")
    assert user is not None
    assert user.email == "mixed@case.org"

    row = sync_conn.execute(
        "SELECT email FROM users WHERE id = %s", (user.id,)
    ).fetchone()
    assert row[0] == "mixed@case.org"

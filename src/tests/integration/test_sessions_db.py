"""Integration tests for app.services.sessions against real PostgreSQL.

Covers TESTING_BACKLOG §2.11 (expired-session cleanup job — the
`await cur.rowcount` TypeError regression), the get_session_user JOIN
semantics (expiry + users.is_active gate), session purpose lifecycle,
the flash set/consume exactly-once contract, and §2.8 flash-through-
redirect end-to-end (real middleware consume-before-call_next ordering).
"""

import pyotp
import pytest

from app.services.crypto import encrypt_value
from app.services.sessions import (
    cleanup_expired_sessions,
    consume_flash,
    create_session,
    delete_user_sessions,
    get_session_user,
    set_flash,
    upgrade_session_purpose,
)
from tests.integration.conftest import DEFAULT_PASSWORD, do_login


# ---------------------------------------------------------------------------
# TEST-020 — the stored session id is SHA-256 of the cookie value, pinned
# INDEPENDENTLY of the app's own hasher
# ---------------------------------------------------------------------------

async def test_session_id_stored_as_sha256_never_raw(
    db_pool, user_factory, sync_conn
):
    """Every existing test built and queried session rows THROUGH
    _hash_session_id, so a downgrade to identity (or a weak/truncated digest)
    passed everything while the sessions table became a pile of directly
    usable login cookies. This recomputes the expected digest with hashlib
    directly — the same independent-pin pattern test_tokens.py uses for
    email-token hashes."""
    import hashlib

    u = user_factory()
    raw = await create_session(db_pool, u.id, "127.0.0.1", purpose="full")

    stored = sync_conn.execute("SELECT id FROM sessions").fetchone()[0]
    assert stored != raw, "session id stored RAW — cookie theft via DB read"
    assert stored == hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# §2.11 — cleanup_expired_sessions
# ---------------------------------------------------------------------------

async def test_cleanup_expired_sessions_deletes_only_expired_and_returns_count(
    db_pool, user_factory, session_factory, sync_conn
):
    """§2.11: cleanup returns the deleted count WITHOUT raising.

    Regression: `await cur.rowcount` (a property, not an awaitable) raised
    TypeError on every run of the hourly job — the call completing at all is
    the primary assertion. Expired rows must be gone, the live one intact.
    """
    user = user_factory()
    session_factory(user.id, expires_in_seconds=-10)
    session_factory(user.id, expires_in_seconds=-10)
    live_raw = session_factory(user.id, expires_in_seconds=3600)

    count = await cleanup_expired_sessions(db_pool)
    assert count == 2

    remaining = sync_conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
    assert remaining == 1
    # The surviving row is the live session — it still authenticates.
    lookup = await get_session_user(db_pool, live_raw)
    assert lookup.user is not None and lookup.user.id == user.id


async def test_cleanup_expired_sessions_second_run_returns_zero(
    db_pool, user_factory, session_factory
):
    """§2.11: a second run with nothing left to delete returns 0 (not an error)."""
    user = user_factory()
    session_factory(user.id, expires_in_seconds=-10)

    assert await cleanup_expired_sessions(db_pool) == 1
    assert await cleanup_expired_sessions(db_pool) == 0


# ---------------------------------------------------------------------------
# get_session_user — JOIN semantics
# ---------------------------------------------------------------------------

async def test_get_session_user_valid_session_returns_user_full_no_flash(
    db_pool, user_factory, session_factory
):
    """A valid 'full' session resolves to SessionLookup(user, 'full', False)
    with the correct user id — the happy-path contract the middleware unpacks."""
    user = user_factory()
    raw = session_factory(user.id, purpose="full")

    lookup = await get_session_user(db_pool, raw)
    assert lookup.user is not None
    assert lookup.user.id == user.id
    assert lookup.purpose == "full"
    assert lookup.flash_present is False


async def test_get_session_user_expired_session_is_invisible(
    db_pool, user_factory, session_factory
):
    """An expired session row must not authenticate: the SQL expiry gate
    (expires_at > CURRENT_TIMESTAMP) returns the all-falsy SessionLookup."""
    user = user_factory()
    raw = session_factory(user.id, expires_in_seconds=-10)

    assert await get_session_user(db_pool, raw) == (None, None, False)


async def test_get_session_user_deactivated_user_kills_session_at_lookup(
    db_pool, user_factory, session_factory, sync_conn
):
    """The JOIN's `u.is_active` gate: deactivating a user invalidates their
    live sessions at lookup time, even before any admin hard-revoke deletes
    the session rows."""
    user = user_factory()
    raw = session_factory(user.id)
    # Session works while active...
    assert (await get_session_user(db_pool, raw)).user is not None

    sync_conn.execute("UPDATE users SET is_active = false WHERE id = %s", (user.id,))
    sync_conn.commit()

    assert await get_session_user(db_pool, raw) == (None, None, False)


async def test_get_session_user_reports_pending_flash(
    db_pool, user_factory, session_factory
):
    """flash_present=True when the row carries a pending flash, so the
    middleware knows to run the consume query (§2.8 gating)."""
    user = user_factory()
    raw = session_factory(user.id, flash=("Hi", "info"))

    lookup = await get_session_user(db_pool, raw)
    assert lookup.user is not None
    assert lookup.flash_present is True


async def test_get_session_user_totp_setup_purpose_round_trips(
    db_pool, user_factory, session_factory
):
    """A 'totp_setup' session comes back with purpose='totp_setup' — the
    middleware's capability gate depends on this value surviving storage."""
    user = user_factory()
    raw = session_factory(user.id, purpose="totp_setup")

    lookup = await get_session_user(db_pool, raw)
    assert lookup.user is not None
    assert lookup.purpose == "totp_setup"


# ---------------------------------------------------------------------------
# upgrade_session_purpose
# ---------------------------------------------------------------------------

async def test_upgrade_session_purpose_totp_setup_to_full_persists(
    db_pool, user_factory, session_factory
):
    """Upgrading totp_setup → full persists: the subsequent lookup sees 'full'
    (the TOTP-enrollment completion path)."""
    user = user_factory()
    raw = session_factory(user.id, purpose="totp_setup")

    await upgrade_session_purpose(db_pool, raw, "full")

    lookup = await get_session_user(db_pool, raw)
    assert lookup.purpose == "full"


async def test_upgrade_session_purpose_unknown_session_raises(db_pool):
    """Unknown session id raises ValueError — the silent-no-op guard (a
    caller must not believe an upgrade succeeded when no row matched)."""
    with pytest.raises(ValueError, match="does not exist"):
        await upgrade_session_purpose(db_pool, "no-such-session-id", "full")


async def test_upgrade_session_purpose_invalid_purpose_raises(
    db_pool, user_factory, session_factory
):
    """An invalid purpose string is rejected with ValueError before any SQL —
    only 'full' and 'totp_setup' are legal capability levels."""
    user = user_factory()
    raw = session_factory(user.id, purpose="totp_setup")

    with pytest.raises(ValueError, match="Invalid session purpose"):
        await upgrade_session_purpose(db_pool, raw, "admin")

    # Purpose unchanged.
    assert (await get_session_user(db_pool, raw)).purpose == "totp_setup"


# ---------------------------------------------------------------------------
# set_flash / consume_flash — exactly-once contract
# ---------------------------------------------------------------------------

async def test_set_flash_overwrites_and_consume_is_exactly_once(
    db_pool, user_factory, session_factory
):
    """set_flash last-wins over a previous flash; consume_flash returns the
    (message, category) tuple exactly once, then None (the FOR UPDATE
    read-and-clear contract)."""
    user = user_factory()
    raw = session_factory(user.id)

    await set_flash(db_pool, raw, "First message", "info")
    await set_flash(db_pool, raw, "Second message", "error")

    assert await consume_flash(db_pool, raw) == ("Second message", "error")
    # Consumed: second read is empty, and flash_present is back to False.
    assert await consume_flash(db_pool, raw) is None
    assert (await get_session_user(db_pool, raw)).flash_present is False


async def test_set_flash_on_missing_session_raises(db_pool):
    """set_flash on a nonexistent session raises ValueError — flashes must
    not silently vanish when the target row is gone."""
    with pytest.raises(ValueError, match="does not exist"):
        await set_flash(db_pool, "no-such-session-id", "Hello", "info")


async def test_set_flash_invalid_category_raises(
    db_pool, user_factory, session_factory
):
    """A category outside success/error/info is rejected with ValueError
    (it drives the template's visual style and must stay a closed set)."""
    user = user_factory()
    raw = session_factory(user.id)

    with pytest.raises(ValueError, match="Invalid flash category"):
        await set_flash(db_pool, raw, "Hello", "warning")


async def test_consume_flash_returns_none_when_no_flash_pending(
    db_pool, user_factory, session_factory
):
    """consume_flash on a session with no pending flash returns None
    (the flash_message IS NOT NULL filter in the CTE)."""
    user = user_factory()
    raw = session_factory(user.id)

    assert await consume_flash(db_pool, raw) is None


# ---------------------------------------------------------------------------
# §2.8 — flash survives a redirect end-to-end, shown exactly once
# ---------------------------------------------------------------------------

def test_flash_survives_redirect_and_is_consumed_exactly_once(
    e2e_client, user_factory
):
    """§2.8: real set_flash → flash_present → middleware consumes BEFORE
    call_next → template renders. Change-display-name 303-redirects to
    /account; the first GET shows 'Display name updated.', the second GET
    does not (exactly-once consumption through the whole stack)."""
    secret = pyotp.random_base32()
    user = user_factory(totp_secret=encrypt_value(secret))

    resp = do_login(
        e2e_client, user.email, DEFAULT_PASSWORD, pyotp.TOTP(secret).now()
    )
    assert resp.status_code == 303

    # GET a page first so the CSRF cookie is rotated to the new session's
    # HMAC (the identifier changed at login).
    page = e2e_client.get("/account")
    assert page.status_code == 200
    csrf = e2e_client.cookies.get("csrf_token")

    post = e2e_client.post(
        "/account/change-name",
        data={"display_name": "New Name", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert post.status_code == 303
    assert post.headers["location"] == "/account"

    first = e2e_client.get("/account")
    assert first.status_code == 200
    assert "Display name updated." in first.text

    second = e2e_client.get("/account")
    assert second.status_code == 200
    assert "Display name updated." not in second.text


# ---------------------------------------------------------------------------
# delete_user_sessions
# ---------------------------------------------------------------------------

async def test_delete_user_sessions_only_removes_target_users_rows(
    db_pool, user_factory, session_factory
):
    """Force-logout-everywhere is scoped by user_id: both of the target's
    sessions die; another user's session survives."""
    target = user_factory()
    other = user_factory()
    t1 = session_factory(target.id)
    t2 = session_factory(target.id)
    o1 = session_factory(other.id)

    await delete_user_sessions(db_pool, target.id)

    assert await get_session_user(db_pool, t1) == (None, None, False)
    assert await get_session_user(db_pool, t2) == (None, None, False)
    surviving = await get_session_user(db_pool, o1)
    assert surviving.user is not None and surviving.user.id == other.id


# ---------------------------------------------------------------------------
# create_session
# ---------------------------------------------------------------------------

async def test_create_session_defaults_to_totp_setup_purpose(
    db_pool, user_factory
):
    """The fail-closed default: create_session without an explicit purpose
    yields a restricted 'totp_setup' session — callers must OPT IN to 'full'."""
    user = user_factory()

    raw = await create_session(db_pool, user.id, "127.0.0.1")

    lookup = await get_session_user(db_pool, raw)
    assert lookup.user is not None and lookup.user.id == user.id
    assert lookup.purpose == "totp_setup"


async def test_create_session_invalid_purpose_raises_before_insert(
    db_pool, user_factory, sync_conn
):
    """An invalid purpose raises ValueError before any INSERT — no session
    row may be created with an unknown capability level."""
    user = user_factory()

    with pytest.raises(ValueError, match="Invalid session purpose"):
        await create_session(db_pool, user.id, "127.0.0.1", purpose="superuser")

    count = sync_conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
    assert count == 0

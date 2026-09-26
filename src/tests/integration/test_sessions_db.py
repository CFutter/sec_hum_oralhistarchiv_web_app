"""Integration tests for app.services.sessions against real PostgreSQL.

Covers session id hashing independent of the app's own hasher, the
expired-session cleanup job, the get_session_user JOIN semantics (expiry +
users.is_active gate), session purpose lifecycle, the flash set/consume
exactly-once contract, and flash surviving a redirect end-to-end through the
real middleware (consume-before-call_next ordering).

Revocation cascades that also touch pending account capabilities (email
change, password reset, incident-response revoke-all) live in
test_session_revocation_db.py.
"""

import hashlib

import pyotp
import pytest

from app.services.crypto import encrypt_value
from app.services.session_revocation import delete_user_sessions
from app.services.sessions import (
    cleanup_expired_sessions,
    consume_flash,
    create_session,
    get_session_user,
    restore_flash_if_empty,
    set_flash,
)
from tests.integration.conftest import DEFAULT_PASSWORD, do_login


class TestSessionIdStorage:
    """The stored session id is SHA-256 of the cookie value, pinned
    independently of the app's own hasher."""

    async def test_session_id_stored_as_sha256_never_raw(self, db_pool, user_factory, sync_conn):
        """Every session row is built and queried THROUGH hash_session_id, so
        a downgrade to identity (or a weak/truncated digest) would pass
        everything while the sessions table became a pile of directly usable
        login cookies. This recomputes the expected digest with hashlib
        directly — the same independent-pin pattern test_tokens.py uses for
        email-token hashes."""
        u = user_factory()
        raw = await create_session(db_pool, u.id, "127.0.0.1", purpose="full")

        stored = sync_conn.execute("SELECT id FROM sessions").fetchone()[0]
        assert stored != raw, "session id stored RAW — cookie theft via DB read"
        assert stored == hashlib.sha256(raw.encode()).hexdigest()


class TestCleanupExpiredSessions:
    """cleanup_expired_sessions deletes only expired rows and reports the
    count without raising (cur.rowcount is a synchronous property, not an
    awaitable; the cleanup job must read it as such on every run)."""

    async def test_deletes_only_expired_and_returns_count(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
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

    async def test_second_run_with_nothing_left_returns_zero(
        self, db_pool, user_factory, session_factory
    ):
        user = user_factory()
        session_factory(user.id, expires_in_seconds=-10)

        assert await cleanup_expired_sessions(db_pool) == 1
        assert await cleanup_expired_sessions(db_pool) == 0


class TestGetSessionUserLookup:
    """get_session_user's JOIN semantics: expiry gate and users.is_active
    gate, plus the purpose and flash_present fields the middleware unpacks."""

    async def test_valid_session_returns_user_full_no_flash(
        self, db_pool, user_factory, session_factory
    ):
        """A valid 'full' session resolves to SessionLookup(user, 'full',
        False) with the correct user id — the happy-path contract the
        middleware unpacks."""
        user = user_factory()
        raw = session_factory(user.id, purpose="full")

        lookup = await get_session_user(db_pool, raw)
        assert lookup.user is not None
        assert lookup.user.id == user.id
        assert lookup.purpose == "full"
        assert lookup.flash_present is False

    async def test_expired_session_is_invisible(self, db_pool, user_factory, session_factory):
        """An expired session row must not authenticate: the SQL expiry gate
        (expires_at > CURRENT_TIMESTAMP) returns the all-falsy
        SessionLookup."""
        user = user_factory()
        raw = session_factory(user.id, expires_in_seconds=-10)

        assert await get_session_user(db_pool, raw) == (None, None, False)

    async def test_deactivated_user_kills_session_at_lookup(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        """The JOIN's `u.is_active` gate: deactivating a user invalidates
        their live sessions at lookup time, even before any admin
        hard-revoke deletes the session rows."""
        user = user_factory()
        raw = session_factory(user.id)
        # Session works while active...
        assert (await get_session_user(db_pool, raw)).user is not None

        sync_conn.execute("UPDATE users SET is_active = false WHERE id = %s", (user.id,))
        sync_conn.commit()

        assert await get_session_user(db_pool, raw) == (None, None, False)

    async def test_reports_pending_flash(self, db_pool, user_factory, session_factory):
        """flash_present=True when the row carries a pending flash, so the
        middleware knows to run the consume query."""
        user = user_factory()
        raw = session_factory(user.id, flash=("Hi", "info"))

        lookup = await get_session_user(db_pool, raw)
        assert lookup.user is not None
        assert lookup.flash_present is True

    async def test_totp_setup_purpose_round_trips(self, db_pool, user_factory, session_factory):
        """A 'totp_setup' session comes back with purpose='totp_setup' — the
        middleware's capability gate depends on this value surviving
        storage."""
        user = user_factory()
        raw = session_factory(user.id, purpose="totp_setup")

        lookup = await get_session_user(db_pool, raw)
        assert lookup.user is not None
        assert lookup.purpose == "totp_setup"


class TestFlashLifecycle:
    """set_flash / consume_flash / restore_flash_if_empty — the exactly-once
    read-and-clear contract, end to end through the real middleware."""

    async def test_set_flash_overwrites_and_consume_is_exactly_once(
        self, db_pool, user_factory, session_factory
    ):
        """set_flash last-wins over a previous flash; consume_flash returns
        the (message, category) tuple exactly once, then None (the FOR
        UPDATE read-and-clear contract)."""
        user = user_factory()
        raw = session_factory(user.id)

        await set_flash(db_pool, raw, "First message", "info")
        await set_flash(db_pool, raw, "Second message", "error")

        assert await consume_flash(db_pool, raw) == ("Second message", "error")
        # Consumed: second read is empty, and flash_present is back to False.
        assert await consume_flash(db_pool, raw) is None
        assert (await get_session_user(db_pool, raw)).flash_present is False

    async def test_set_flash_on_missing_session_raises(self, db_pool):
        """set_flash on a nonexistent session raises ValueError — flashes
        must not silently vanish when the target row is gone."""
        with pytest.raises(ValueError, match="does not exist"):
            await set_flash(db_pool, "no-such-session-id", "Hello", "info")

    async def test_set_flash_invalid_category_raises(self, db_pool, user_factory, session_factory):
        """A category outside success/error/info is rejected with
        ValueError (it drives the template's visual style and must stay a
        closed set)."""
        user = user_factory()
        raw = session_factory(user.id)

        with pytest.raises(ValueError, match="Invalid flash category"):
            await set_flash(db_pool, raw, "Hello", "warning")

    async def test_consume_flash_returns_none_when_no_flash_pending(
        self, db_pool, user_factory, session_factory
    ):
        """consume_flash on a session with no pending flash returns None
        (the flash_message IS NOT NULL filter in the CTE)."""
        user = user_factory()
        raw = session_factory(user.id)

        assert await consume_flash(db_pool, raw) is None

    async def test_restore_flash_if_empty_restores_consumed_message(
        self, db_pool, user_factory, session_factory
    ):
        user = user_factory()
        raw = session_factory(user.id, flash=("Saved earlier.", "success"))

        consumed = await consume_flash(db_pool, raw)
        assert consumed == ("Saved earlier.", "success")
        assert consumed is not None
        message, category = consumed

        assert await restore_flash_if_empty(db_pool, raw, message, category) is True
        assert await consume_flash(db_pool, raw) == consumed

    async def test_restore_flash_if_empty_preserves_newer_message(
        self, db_pool, user_factory, session_factory
    ):
        user = user_factory()
        raw = session_factory(user.id, flash=("Saved earlier.", "success"))

        consumed = await consume_flash(db_pool, raw)
        assert consumed == ("Saved earlier.", "success")
        assert consumed is not None
        message, category = consumed
        await set_flash(db_pool, raw, "New operation succeeded.", "info")

        assert await restore_flash_if_empty(db_pool, raw, message, category) is False
        assert await consume_flash(db_pool, raw) == ("New operation succeeded.", "info")

    async def test_restore_flash_if_empty_tolerates_deleted_session(self, db_pool):
        assert (
            await restore_flash_if_empty(
                db_pool,
                "no-such-session-id",
                "Saved earlier.",
                "success",
            )
            is False
        )

    def test_flash_survives_redirect_and_is_consumed_exactly_once(self, e2e_client, user_factory):
        """Real set_flash → flash_present → middleware consumes BEFORE
        call_next → template renders. Change-display-name 303-redirects to
        /account; the first GET shows 'Display name updated.', the second
        GET does not (exactly-once consumption through the whole stack)."""
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))

        resp = do_login(e2e_client, user.email, DEFAULT_PASSWORD, pyotp.TOTP(secret).now())
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


class TestDeleteUserSessions:
    """delete_user_sessions scopes force-logout-everywhere to one user."""

    async def test_only_removes_target_users_rows(self, db_pool, user_factory, session_factory):
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


class TestCreateSession:
    """create_session's purpose defaulting and validation."""

    async def test_defaults_to_totp_setup_purpose(self, db_pool, user_factory):
        """The fail-closed default: create_session without an explicit
        purpose yields a restricted 'totp_setup' session — callers must OPT
        IN to 'full'."""
        user = user_factory()

        raw = await create_session(db_pool, user.id, "127.0.0.1")

        lookup = await get_session_user(db_pool, raw)
        assert lookup.user is not None and lookup.user.id == user.id
        assert lookup.purpose == "totp_setup"

    async def test_invalid_purpose_raises_before_insert(self, db_pool, user_factory, sync_conn):
        """An invalid purpose raises ValueError before any INSERT — no
        session row may be created with an unknown capability level."""
        user = user_factory()

        with pytest.raises(ValueError, match="Invalid session purpose"):
            await create_session(db_pool, user.id, "127.0.0.1", purpose="superuser")

        count = sync_conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
        assert count == 0

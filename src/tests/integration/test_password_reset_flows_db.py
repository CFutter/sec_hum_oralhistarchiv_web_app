"""Password-reset integration tests — real PostgreSQL, real services, real routes.

Covers `app.services.password_reset`: session invalidation on reset, the
password-change rules (anti-reuse, strength policy), token validity (wrong
hash, expiry, single-use), the `/reset-password` and `/forgot-password`
routes, lockout clearing, and the actual emailed link driven end-to-end.

These guard the awaits that mypy cannot see are missing (`coroutine is
not None` / `if coroutine:` shapes) and that only a real database exercise
catches: an un-awaited coroutine is truthy even on a ZERO-row UPDATE, so
mocked cursors would happily "pass."
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec

import pytest
import time_machine
from lxml import html

from app.services import password_reset
from app.services.authentication import verify_password
from app.services.crypto import decrypt_outbox_body
from app.services.db import get_db_cursor
from app.services.password_reset import (
    generate_reset_token,
    store_reset_token_hash,
    update_password_with_token,
)
from app.services.sessions import get_session_user
from app.services.tokens import hash_token
from config import settings
from tests.integration.conftest import DEFAULT_PASSWORD, do_login

# Strong passwords used across tests. None contain the factory users'
# email local parts ("userN") or display-name parts ("test"/"user"),
# so validate_password_strength never trips on them incidentally.
NEW_PASSWORD = "Fresh-N3w-Passw0rd!"
THIRD_PASSWORD = "An0ther-G00d-Pw!x"


def _store_reset_hash_sync(sync_conn, user_id: int, token: str) -> None:
    """Sync-side equivalent of store_reset_token_hash for e2e setup."""
    sync_conn.execute(
        """UPDATE users
           SET password_reset_token_hash = %s,
               password_reset_created_at = CURRENT_TIMESTAMP
           WHERE id = %s""",
        (hash_token(token), user_id),
    )
    sync_conn.commit()


def _path_of(url: str) -> str:
    assert url.startswith(settings.public_base_url + "/"), (
        f"emailed URL {url!r} does not use settings.public_base_url — "
        "Host-header-derived links are poisonable"
    )
    return url[len(settings.public_base_url) :]


class TestPasswordResetSessionInvalidation:
    """A password reset must not leave a stolen session alive."""

    async def test_password_reset_invalidates_existing_sessions(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        """A stolen session must NOT survive a password reset.

        delete_user_sessions must be awaited inside update_password_with_token
        — an un-awaited call creates the coroutine, never runs it, and leaves
        the sessions silently alive."""
        u = user_factory()
        raw_session = session_factory(u.id)
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        await update_password_with_token(
            db_pool, u.id, hash_token(token), NEW_PASSWORD, expected_email=u.email
        )

        row = sync_conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (u.id,)
        ).fetchone()
        assert row[0] == 0

        lookup = await get_session_user(db_pool, raw_session)
        assert lookup == (None, None, False)


class TestPasswordResetPasswordRequirements:
    """`update_password_with_token` enforces the same password policy as
    registration, plus its own anti-reuse rule."""

    async def test_password_reset_with_different_password_succeeds(self, db_pool, user_factory):
        """Resetting to a DIFFERENT password succeeds; afterwards the new
        password verifies and the old one does not.

        `_is_same_as_current_password(...)` must be awaited in the check —
        an un-awaited coroutine is always truthy, so EVERY reset would be
        rejected with 'choose a different password'."""
        u = user_factory()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        await update_password_with_token(
            db_pool, u.id, hash_token(token), NEW_PASSWORD, expected_email=u.email
        )

        new_check = await verify_password(db_pool, u.email, NEW_PASSWORD)

        assert new_check.user is not None
        assert new_check.user.id == u.id
        assert new_check.password_ok is True

        old_check = await verify_password(db_pool, u.email, DEFAULT_PASSWORD)

        assert old_check.password_ok is False

    async def test_password_reset_same_password_is_rejected(self, db_pool, user_factory):
        """Resetting to the CURRENT password raises ValueError ('different
        password') — the anti-reuse check still fires when it should.

        display_name is overridden because the factory default 'Test User'
        makes DEFAULT_PASSWORD ('...-for-tests') trip the strength check's
        contains-name rule BEFORE the same-password check we want to reach."""
        u = user_factory(display_name="Alice Wonder")
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        with pytest.raises(ValueError, match="different password"):
            await update_password_with_token(
                db_pool, u.id, hash_token(token), DEFAULT_PASSWORD, expected_email=u.email
            )

    async def test_password_reset_rejects_weak_password(self, db_pool, user_factory):
        """Removing validate_password_strength from update_password_with_token
        would let anyone set 'a' as their password via recovery — a policy
        bypass on an auth-critical path. Positive control: a strong password
        succeeds through the exact same call."""
        u = user_factory(display_name="Alice Wonder")
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        with pytest.raises(ValueError, match="Password validation failed"):
            await update_password_with_token(
                db_pool, u.id, hash_token(token), "a", expected_email=u.email
            )

        # The failed attempt must not have consumed the token.
        await update_password_with_token(
            db_pool, u.id, hash_token(token), NEW_PASSWORD, expected_email=u.email
        )
        check = await verify_password(db_pool, u.email, NEW_PASSWORD)

        assert check.password_ok is True


class TestPasswordResetTokenValidity:
    """`update_password_with_token` rejects a hash that doesn't match, one
    that has expired, and reuse of an already-consumed token."""

    async def test_password_reset_wrong_token_hash_rejected(self, db_pool, user_factory):
        """A hash that doesn't match the stored one → zero-row UPDATE →
        ValueError (not a silent 'success')."""
        u = user_factory()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        with pytest.raises(ValueError, match="Invalid, expired, or already-used"):
            await update_password_with_token(
                db_pool,
                u.id,
                hash_token("not-the-real-token"),
                NEW_PASSWORD,
                expected_email=u.email,
            )

    async def test_password_reset_expired_token_rejected(self, db_pool, user_factory, sync_conn):
        """A token older than the 30-minute window fails the DB-level
        created_at check even with a matching hash."""
        u = user_factory()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        sync_conn.execute(
            """UPDATE users
               SET password_reset_created_at = CURRENT_TIMESTAMP - INTERVAL '31 minutes'
               WHERE id = %s""",
            (u.id,),
        )
        sync_conn.commit()

        with pytest.raises(ValueError, match="Invalid, expired, or already-used"):
            await update_password_with_token(
                db_pool, u.id, hash_token(token), NEW_PASSWORD, expected_email=u.email
            )

    async def test_password_reset_token_is_single_use(self, db_pool, user_factory):
        """A successful reset clears the stored hash, so reusing the same
        token (with yet another password) raises ValueError."""
        u = user_factory()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        await update_password_with_token(
            db_pool, u.id, hash_token(token), NEW_PASSWORD, expected_email=u.email
        )

        with pytest.raises(ValueError, match="Invalid, expired, or already-used"):
            await update_password_with_token(
                db_pool, u.id, hash_token(token), THIRD_PASSWORD, expected_email=u.email
            )

    @pytest.mark.parametrize(
        "state",
        ["consumed", "replaced", "expired", "inactive", "email_changed"],
        ids=[
            "consumed_token_is_rejected",
            "replaced_token_is_rejected",
            "expired_token_is_rejected",
            "inactive_account_is_rejected",
            "changed_email_is_rejected",
        ],
    )
    async def test_stale_reset_is_rejected_before_any_password_work(
        self, db_pool, sync_conn, user_factory, monkeypatch, state
    ):
        """A stale token predicate (already consumed, replaced by a newer
        hash, expired, an inactive account, or an email changed since
        issuance) must reject the reset BEFORE any Argon2 work runs — the
        final UPDATE ... WHERE predicate is the single source of truth, and
        it never spends CPU hashing a password it's about to discard."""
        u = user_factory()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(db_pool, u.id, hash_token(token), expected_email=u.email)
        updates = {
            "consumed": "password_reset_token_hash=NULL, password_reset_created_at=NULL",
            "replaced": "password_reset_token_hash=repeat('a',64)",
            "expired": "password_reset_created_at=clock_timestamp()-interval '2 days'",
            "inactive": "is_active=false",
            "email_changed": "email='changed@example.org'",
        }
        # Static test statements, no submitted values in SQL fragments.
        sync_conn.execute("UPDATE users SET " + updates[state] + " WHERE id=%s", (u.id,))
        sync_conn.commit()
        work = create_autospec(
            password_reset.run_password_work,
            side_effect=AssertionError("stale token must not invoke Argon2"),
        )
        monkeypatch.setattr(password_reset, "run_password_work", work)
        with pytest.raises(password_reset.InvalidResetToken):
            await update_password_with_token(
                db_pool,
                u.id,
                hash_token(token),
                "new-password-Strong-2356!",
                expected_email=u.email,
            )
        work.assert_not_awaited()

    async def test_reset_final_predicate_still_rejects_concurrent_token_replacement(
        self, db_pool, user_factory, monkeypatch
    ):
        """A concurrent reset that replaces the stored hash WHILE this
        request's password hash is being computed must still be caught: the
        UPDATE's WHERE predicate is re-evaluated against the CURRENT stored
        hash at commit time, not the hash this request read at the start."""
        u = user_factory()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(db_pool, u.id, hash_token(token), expected_email=u.email)
        real_work = password_reset.run_password_work
        once = False

        async def replace_during_hash(*args, **kwargs):
            nonlocal once
            if not once:
                once = True
                async with get_db_cursor(db_pool) as cur:
                    await cur.execute(
                        "UPDATE users SET password_reset_token_hash=repeat('a',64) WHERE id=%s",
                        (u.id,),
                    )
            return await real_work(*args, **kwargs)

        monkeypatch.setattr(
            password_reset,
            "run_password_work",
            create_autospec(real_work, side_effect=replace_during_hash),
        )
        with pytest.raises(password_reset.InvalidResetToken):
            await update_password_with_token(
                db_pool,
                u.id,
                hash_token(token),
                "New-password-Strong-987654!",
                expected_email=u.email,
            )


class TestPasswordResetFormRejection:
    """`POST /reset-password` re-renders the form as 422 — without consuming
    the token — for every input-validation failure, whatever the cause. The
    positive control for a valid submission is
    `TestPasswordResetEmailedLink.test_forgot_password_emailed_link_completes_a_real_reset`."""

    @pytest.mark.parametrize(
        ("password", "password_confirm", "expected_message"),
        [
            pytest.param(
                NEW_PASSWORD, THIRD_PASSWORD, "Passwords do not match", id="mismatched_confirmation"
            ),
            pytest.param("a", "a", "at least 12 characters", id="weak_password"),
        ],
    )
    def test_reset_password_route_rerenders_form_on_rejection(
        self, e2e_client, user_factory, sync_conn, password, password_confirm, expected_message
    ):
        u = user_factory()
        token = generate_reset_token(u.id, u.email)
        _store_reset_hash_sync(sync_conn, u.id, token)

        page = e2e_client.get(f"/reset-password/{token}")
        assert page.status_code == 200
        assert html.fromstring(page.text).xpath(
            './/form[@action="/reset-password" and @method="post"]'
        )
        assert f'<input type="hidden" name="token" value="{token}">' in page.text
        assert f'action="/reset-password/{token}"' not in page.text
        csrf = e2e_client.cookies.get("csrf_token")

        resp = e2e_client.post(
            "/reset-password",
            data={
                "token": token,
                "password": password,
                "password_confirm": password_confirm,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 422
        assert expected_message in resp.text
        assert html.fromstring(resp.text).xpath(
            './/form[@action="/reset-password" and @method="post"]'
        )
        assert f'<input type="hidden" name="token" value="{token}">' in resp.text
        assert f'action="/reset-password/{token}"' not in resp.text

        # Token not consumed and password unchanged: the stored hash survives.
        row = sync_conn.execute(
            "SELECT password_reset_token_hash FROM users WHERE id = %s", (u.id,)
        ).fetchone()
        assert row[0] == hash_token(token)

    def test_reset_password_route_accepts_a_valid_submission(
        self, e2e_client, user_factory, sync_conn
    ):
        """Positive control for the rejections above, in this same class: a
        matching, sufficiently strong password on the same route redirects
        to /login and consumes the token, instead of re-rendering the form."""
        u = user_factory()
        token = generate_reset_token(u.id, u.email)
        _store_reset_hash_sync(sync_conn, u.id, token)

        page = e2e_client.get(f"/reset-password/{token}")
        assert page.status_code == 200
        csrf = e2e_client.cookies.get("csrf_token")

        resp = e2e_client.post(
            "/reset-password",
            data={
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"
        row = sync_conn.execute(
            "SELECT password_reset_token_hash FROM users WHERE id = %s", (u.id,)
        ).fetchone()
        assert row[0] is None
        assert do_login(e2e_client, u.email, NEW_PASSWORD).status_code == 303


class TestForgotPasswordRequest:
    """`POST /forgot-password` is enumeration-neutral: eligible accounts get a
    stored token and a queued email, ineligible ones get neither."""

    def test_forgot_password_is_enumeration_neutral_and_stores_token(
        self,
        e2e_client,
        user_factory,
        sync_conn,
    ):
        """Known and unknown addresses receive byte-identical responses.

        A known eligible account gets a reset-token hash and one durable
        outbox message. An unknown address gets neither.
        """
        known = user_factory()
        unknown_email = "nobody@uzh.ch"

        e2e_client.get("/forgot-password")
        csrf = e2e_client.cookies.get("csrf_token")

        r_known = e2e_client.post(
            "/forgot-password",
            data={
                "email": known.email,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        r_unknown = e2e_client.post(
            "/forgot-password",
            data={
                "email": unknown_email,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

        assert r_known.status_code == r_unknown.status_code == 200
        assert r_known.text == r_unknown.text
        assert "password reset link shortly" in r_known.text

        token_row = sync_conn.execute(
            """
            SELECT password_reset_token_hash
            FROM users
            WHERE id = %s
            """,
            (known.id,),
        ).fetchone()

        assert token_row is not None
        assert token_row[0] is not None

        outbox_rows = sync_conn.execute(
            """
            SELECT
                user_id,
                recipient,
                status,
                attempt_count,
                body_ciphertext
            FROM email_outbox
            WHERE message_type = 'password_reset'
              AND recipient IN (%s, %s)
            ORDER BY id
            """,
            (
                known.email,
                unknown_email,
            ),
        ).fetchall()

        # Only the known account produces an outbox row.
        assert len(outbox_rows) == 1

        (
            user_id,
            recipient,
            status,
            attempt_count,
            body_ciphertext,
        ) = outbox_rows[0]

        assert user_id == known.id
        assert recipient == known.email
        assert status == "pending"
        assert attempt_count == 0
        assert body_ciphertext

    def test_forgot_password_issues_nothing_for_inactive_or_shibboleth(
        self,
        e2e_client,
        user_factory,
        sync_conn,
    ):
        """Inactive and federated accounts receive no reset capability.

        Both requests get the same neutral response, but neither a token hash
        nor a password-reset outbox message is created.
        """
        inactive = user_factory(is_active=False)
        shib = user_factory(auth_method="shibboleth")

        e2e_client.get("/forgot-password")
        csrf = e2e_client.cookies.get("csrf_token")

        responses = []
        for email in (inactive.email, shib.email):
            response = e2e_client.post(
                "/forgot-password",
                data={
                    "email": email,
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            responses.append(response)

            assert response.status_code == 200
            assert "password reset link shortly" in response.text

        assert responses[0].text == responses[1].text

        token_rows = sync_conn.execute(
            """
            SELECT id, password_reset_token_hash
            FROM users
            WHERE id IN (%s, %s)
            ORDER BY id
            """,
            (
                inactive.id,
                shib.id,
            ),
        ).fetchall()

        assert len(token_rows) == 2
        assert all(token_hash is None for _, token_hash in token_rows)

        outbox_rows = sync_conn.execute(
            """
            SELECT id
            FROM email_outbox
            WHERE message_type = 'password_reset'
              AND recipient IN (%s, %s)
            """,
            (
                inactive.email,
                shib.email,
            ),
        ).fetchall()

        assert outbox_rows == []


class TestPasswordResetClearsLockout:
    """Resetting a password also lifts a failed-login lockout."""

    async def test_password_reset_clears_lockout_state(self, db_pool, user_factory, sync_conn):
        """The lockout email promises 'resetting your password also unlocks
        the account'. Dropping failed_login_count=0 / locked_until=NULL from
        the reset UPDATE leaves the user with a working new password but a
        still-locked account — this pins both columns AND a subsequent
        login."""
        u = user_factory()
        sync_conn.execute(
            """UPDATE users
               SET failed_login_count = 7,
                   locked_until = CURRENT_TIMESTAMP + INTERVAL '15 minutes'
               WHERE id = %s""",
            (u.id,),
        )
        sync_conn.commit()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        await update_password_with_token(
            db_pool, u.id, hash_token(token), NEW_PASSWORD, expected_email=u.email
        )

        row = sync_conn.execute(
            "SELECT failed_login_count, locked_until FROM users WHERE id = %s",
            (u.id,),
        ).fetchone()
        assert row == (0, None)

        # The documented recovery path actually works: login succeeds, unlocked.
        check = await verify_password(db_pool, u.email, NEW_PASSWORD)

        assert check.user is not None
        assert check.user.id == u.id
        assert check.password_ok is True
        assert check.locked_until is None


class TestPasswordResetFormTokenGate:
    """`GET /reset-password/{token}` consults verify_reset_token_hash before
    rendering the form."""

    def test_reset_form_get_rejects_replaced_token_but_accepts_current(
        self, e2e_client, user_factory, sync_conn
    ):
        """After a NEWER token replaces the stored hash, the old link renders
        the 422 'invalid or expired' page — while the current link still
        renders the form (positive control; an inverted comparison would fail
        it)."""
        u = user_factory()
        # itsdangerous timestamps have 1s granularity — force distinct tokens
        # by minting them two seconds apart, then hold the clock there so the
        # later validation still sees both signatures as issued in the past.
        with time_machine.travel(datetime.now(UTC), tick=False) as traveler:
            token_a = generate_reset_token(u.id, u.email)
            _store_reset_hash_sync(sync_conn, u.id, token_a)
            traveler.shift(timedelta(seconds=2))
            token_b = generate_reset_token(u.id, u.email)
            assert token_b != token_a
            _store_reset_hash_sync(sync_conn, u.id, token_b)

            stale = e2e_client.get(f"/reset-password/{token_a}")
            assert stale.status_code == 422
            assert "invalid or has expired" in stale.text

            current = e2e_client.get(f"/reset-password/{token_b}")
        assert current.status_code == 200
        assert "Reset Password" in current.text
        assert html.fromstring(current.text).xpath(
            './/form[@action="/reset-password" and @method="post"]'
        )
        assert f'<input type="hidden" name="token" value="{token_b}">' in current.text
        assert f'action="/reset-password/{token_b}"' not in current.text

    def test_reset_form_get_rejects_token_after_account_email_changes(
        self,
        e2e_client,
        user_factory,
        sync_conn,
    ):
        """A reset token is bound to the email address it was issued to.

        Even when its hash remains stored and unexpired, changing the account
        email makes the old-address reset link invalid.
        """
        user = user_factory(email="old-address@uzh.ch")
        token = generate_reset_token(user.id, user.email)
        _store_reset_hash_sync(sync_conn, user.id, token)

        sync_conn.execute(
            """
            UPDATE users
            SET email = %s
            WHERE id = %s
            """,
            ("new-address@uzh.ch", user.id),
        )
        sync_conn.commit()

        response = e2e_client.get(f"/reset-password/{token}")

        assert response.status_code == 422
        assert "invalid or has expired" in response.text


class TestPasswordResetEmailedLink:
    """The actual emailed link — not a synthetically minted token — drives
    a password reset to completion."""

    @pytest.mark.usefixtures("sync_conn")
    def test_forgot_password_emailed_link_completes_a_real_reset(
        self,
        e2e_client,
        user_factory,
        sync_conn,
    ):
        """The reset URL from the real outbox message completes recovery.

        This covers request, durable queuing, token validation, password
        update, and subsequent login using the same generated token — the
        route-level positive control for `TestPasswordResetFormRejection`.
        """
        user = user_factory()

        e2e_client.get("/forgot-password")
        csrf = e2e_client.cookies.get("csrf_token")

        response = e2e_client.post(
            "/forgot-password",
            data={
                "email": user.email,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

        assert response.status_code == 200

        outbox_row = sync_conn.execute(
            """
            SELECT recipient, body_ciphertext
            FROM email_outbox
            WHERE user_id = %s
              AND message_type = 'password_reset'
            ORDER BY id DESC
            LIMIT 1
            """,
            (user.id,),
        ).fetchone()

        assert outbox_row is not None

        recipient, body_ciphertext = outbox_row
        assert recipient == user.email

        body = decrypt_outbox_body(body_ciphertext)
        assert body is not None

        reset_url = next(line.strip() for line in body.splitlines() if "/reset-password/" in line)
        path = _path_of(reset_url)

        assert path.startswith("/reset-password/")

        form = e2e_client.get(path)
        assert form.status_code == 200
        assert "Reset Password" in form.text
        token = path.removeprefix("/reset-password/")
        assert html.fromstring(form.text).xpath(
            './/form[@action="/reset-password" and @method="post"]'
        )
        assert f'<input type="hidden" name="token" value="{token}">' in form.text
        assert f'action="{path}"' not in form.text

        csrf = e2e_client.cookies.get("csrf_token")
        done = e2e_client.post(
            "/reset-password",
            data={
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

        assert done.status_code == 303
        assert done.headers["location"] == "/login"

        login = do_login(
            e2e_client,
            user.email,
            NEW_PASSWORD,
        )
        assert login.status_code == 303

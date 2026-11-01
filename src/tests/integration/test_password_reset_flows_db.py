"""Password-reset integration tests — real PostgreSQL, real services, real routes."""

import asyncio
import time
from unittest.mock import create_autospec
from urllib.parse import urlsplit

import pyotp
import pytest
from lxml import html

from app.services import password_reset
from app.services.authentication import verify_password
from app.services.crypto import decrypt_outbox_body
from app.services.db import get_db_cursor
from app.services.password_reset import (
    InvalidResetToken,
    InvalidResetTotp,
    generate_reset_token,
    store_reset_token_hash,
    update_password_with_token,
)
from app.services.sessions import get_session_user
from app.services.tokens import action_token_public_id, hash_token
from app.services.totp_crypto import encrypt_value
from config import settings
from tests.action_links import action_path, token_from_action_email
from tests.integration.conftest import DEFAULT_PASSWORD, do_login

# Strong passwords used across tests. None contain the factory users'
# email local parts ("userN") or display-name parts ("test"/"user"),
# so validate_password_strength never trips on them incidentally.
NEW_PASSWORD = "Fresh-N3w-Passw0rd!"
THIRD_PASSWORD = "An0ther-G00d-Pw!x"

_RESET_SECRET = "JBSWY3DPEHPK3PXP"


def _reset_code():
    """Generate the reset factor's current TOTP code."""
    return pyotp.TOTP(_RESET_SECRET).now()


def _login_code():
    # Reset consumed the current step; the adjacent next step is fresh.
    """Generate a code one TOTP step ahead of the current wall clock."""
    return pyotp.TOTP(_RESET_SECRET).at(time.time() + 30)


@pytest.fixture
def reset_user_factory(user_factory):
    """Return a user factory defaulting to the shared encrypted reset factor."""

    def make(**overrides):
        """Create a user defaulting to the shared encrypted reset factor."""
        overrides.setdefault("totp_secret", encrypt_value(_RESET_SECRET))
        return user_factory(**overrides)

    return make


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
    """Require an emailed URL under PUBLIC_BASE_URL and return its path."""
    assert url.startswith(settings.public_base_url + "/"), (
        f"emailed URL {url!r} does not use settings.public_base_url — "
        "Host-header-derived links are poisonable"
    )
    return urlsplit(url).path


def _assert_both_recovery_forms_have_the_checked_envelope(response, token, *, include_secret=False):
    """Both recovery choices use the same public locator and body-only security code."""
    document = html.fromstring(response.text)
    forms = document.xpath('//form[@action="/reset-password" or @action="/unlock-account"]')
    assert len(forms) == 2
    assert {form.get("action") for form in forms} == {"/reset-password", "/unlock-account"}
    token_fields = []
    for form in forms:
        assert form.get("method") == "post"
        assert form.xpath('./input[@name="public_id"]/@value') == [action_token_public_id(token)]
        fields = form.xpath('.//input[@name="token"]')
        assert len(fields) == 1
        field = fields[0]
        assert field.get("value") == (token if include_secret else "")
        assert field.get("type") == ("hidden" if include_secret else "text")
        assert "required" in field.attrib
        assert token not in form.get("action")
        token_fields.append(field)
    assert len({field.get("id") for field in token_fields}) == 2


class TestPasswordResetSessionInvalidation:
    """A password reset must not leave a stolen session alive."""

    async def test_password_reset_invalidates_existing_sessions(
        self, db_pool, reset_user_factory, session_factory, sync_conn
    ):
        """A stolen session must NOT survive a password reset.

        delete_user_sessions must be awaited inside update_password_with_token
        — an un-awaited call creates the coroutine, never runs it, and leaves
        the sessions silently alive."""
        u = reset_user_factory()
        raw_session = session_factory(u.id)
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        await update_password_with_token(
            db_pool, u.id, token, NEW_PASSWORD, expected_email=u.email, totp_code=_reset_code()
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

    async def test_password_reset_with_different_password_succeeds(
        self, db_pool, reset_user_factory
    ):
        """Verify password reset with different password succeeds."""
        u = reset_user_factory()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        await update_password_with_token(
            db_pool, u.id, token, NEW_PASSWORD, expected_email=u.email, totp_code=_reset_code()
        )

        new_check = await verify_password(db_pool, u.email, NEW_PASSWORD)

        assert new_check.user is not None
        assert new_check.user.id == u.id
        assert new_check.password_ok is True

        old_check = await verify_password(db_pool, u.email, DEFAULT_PASSWORD)

        assert old_check.password_ok is False

    async def test_password_reset_same_password_is_rejected(self, db_pool, reset_user_factory):
        """Verify password reset same password is rejected."""
        u = reset_user_factory(display_name="Alice Wonder")
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        with pytest.raises(ValueError, match="different password"):
            await update_password_with_token(
                db_pool,
                u.id,
                token,
                DEFAULT_PASSWORD,
                expected_email=u.email,
                totp_code=_reset_code(),
            )

    async def test_password_reset_rejects_weak_password(self, db_pool, reset_user_factory):
        """Removing validate_password_strength from update_password_with_token
        would let anyone set 'a' as their password via recovery — a policy
        bypass on an auth-critical path. Positive control: a strong password
        succeeds through the exact same call."""
        u = reset_user_factory(display_name="Alice Wonder")
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        with pytest.raises(ValueError, match="Password validation failed"):
            await update_password_with_token(
                db_pool, u.id, token, "a", expected_email=u.email, totp_code=_reset_code()
            )

        # The failed attempt must not have consumed the token.
        await update_password_with_token(
            db_pool, u.id, token, NEW_PASSWORD, expected_email=u.email, totp_code=_reset_code()
        )
        check = await verify_password(db_pool, u.email, NEW_PASSWORD)

        assert check.password_ok is True


class TestPasswordResetTokenValidity:
    """`update_password_with_token` rejects a hash that doesn't match, one
    that has expired, and reuse of an already-consumed token."""

    async def test_password_reset_wrong_token_hash_rejected(self, db_pool, reset_user_factory):
        """A hash that doesn't match the stored one → zero-row UPDATE →
        ValueError (not a silent 'success')."""
        u = reset_user_factory()
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
                generate_reset_token(u.id, u.email),
                NEW_PASSWORD,
                expected_email=u.email,
                totp_code=_reset_code(),
            )

    async def test_password_reset_expired_token_rejected(
        self, db_pool, reset_user_factory, sync_conn
    ):
        """A token older than the 30-minute window fails the DB-level
        created_at check even with a matching hash."""
        u = reset_user_factory()
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
                db_pool, u.id, token, NEW_PASSWORD, expected_email=u.email, totp_code=_reset_code()
            )

    async def test_password_reset_token_is_single_use(self, db_pool, reset_user_factory):
        """A successful reset clears the stored hash, so reusing the same
        token (with yet another password) raises ValueError."""
        u = reset_user_factory()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        await update_password_with_token(
            db_pool, u.id, token, NEW_PASSWORD, expected_email=u.email, totp_code=_reset_code()
        )

        with pytest.raises(ValueError, match="Invalid, expired, or already-used"):
            await update_password_with_token(
                db_pool,
                u.id,
                token,
                THIRD_PASSWORD,
                expected_email=u.email,
                totp_code=_reset_code(),
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
        self, db_pool, sync_conn, reset_user_factory, monkeypatch, state
    ):
        """Verify stale reset is rejected before any password work."""
        u = reset_user_factory()
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
                token,
                "new-password-Strong-2356!",
                expected_email=u.email,
                totp_code=_reset_code(),
            )
        work.assert_not_awaited()

    async def test_reset_final_predicate_still_rejects_concurrent_token_replacement(
        self, db_pool, reset_user_factory, monkeypatch
    ):
        """A concurrent reset that replaces the stored hash WHILE this
        request's password hash is being computed must still be caught: the
        UPDATE's WHERE predicate is re-evaluated against the CURRENT stored
        hash at commit time, not the hash this request read at the start."""
        u = reset_user_factory()
        token = generate_reset_token(u.id, u.email)
        await store_reset_token_hash(db_pool, u.id, hash_token(token), expected_email=u.email)
        real_work = password_reset.run_password_work
        once = False

        async def replace_during_hash(*args, **kwargs):
            """Replace the reset-token hash once before real password work."""
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
                token,
                "New-password-Strong-987654!",
                expected_email=u.email,
                totp_code=_reset_code(),
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
        self,
        e2e_client,
        reset_user_factory,
        sync_conn,
        password,
        password_confirm,
        expected_message,
    ):
        """Verify reset password route rerenders form on rejection."""
        u = reset_user_factory()
        token = generate_reset_token(u.id, u.email)
        _store_reset_hash_sync(sync_conn, u.id, token)

        page = e2e_client.get(action_path("/reset-password", token))
        assert page.status_code == 200
        assert html.fromstring(page.text).xpath(
            './/form[@action="/reset-password" and @method="post"]'
        )
        assert token not in page.text
        _assert_both_recovery_forms_have_the_checked_envelope(page, token)
        assert f'action="/reset-password/{token}"' not in page.text
        csrf = e2e_client.cookies.get("csrf_token")

        resp = e2e_client.post(
            "/reset-password",
            data={
                "token": token,
                "public_id": action_token_public_id(token),
                "password": password,
                "password_confirm": password_confirm,
                "totp_code": _reset_code(),
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 422
        assert expected_message in resp.text
        assert html.fromstring(resp.text).xpath(
            './/form[@action="/reset-password" and @method="post"]'
        )
        _assert_both_recovery_forms_have_the_checked_envelope(resp, token, include_secret=True)
        assert f'action="/reset-password/{token}"' not in resp.text

        # Token not consumed and password unchanged: the stored hash survives.
        row = sync_conn.execute(
            "SELECT password_reset_token_hash FROM users WHERE id = %s", (u.id,)
        ).fetchone()
        assert row[0] == hash_token(token)

    def test_reset_password_route_accepts_a_valid_submission(
        self, e2e_client, reset_user_factory, sync_conn
    ):
        """Positive control for the rejections above, in this same class: a
        matching, sufficiently strong password on the same route redirects
        to /login and consumes the token, instead of re-rendering the form."""
        u = reset_user_factory()
        token = generate_reset_token(u.id, u.email)
        _store_reset_hash_sync(sync_conn, u.id, token)

        page = e2e_client.get(action_path("/reset-password", token))
        assert page.status_code == 200
        csrf = e2e_client.cookies.get("csrf_token")

        resp = e2e_client.post(
            "/reset-password",
            data={
                "token": token,
                "public_id": action_token_public_id(token),
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "totp_code": _reset_code(),
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
        assert (
            do_login(e2e_client, u.email, NEW_PASSWORD, totp_code=_login_code()).status_code == 303
        )


class TestForgotPasswordRequest:
    """`POST /forgot-password` is enumeration-neutral: eligible accounts get a
    stored token and a queued email, ineligible ones get neither."""

    def test_forgot_password_is_enumeration_neutral_and_stores_token(
        self,
        e2e_client,
        reset_user_factory,
        sync_conn,
    ):
        """Known and unknown addresses receive byte-identical responses.

        A known eligible account gets a reset-token hash and one durable
        outbox message. An unknown address gets neither.
        """
        known = reset_user_factory()
        unknown_email = "nobody@example.org"

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
        assert "existing code stays valid" in r_known.text.lower()

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
        reset_user_factory,
        sync_conn,
    ):
        """Inactive and federated accounts receive no reset capability.

        Both requests get the same neutral response, but neither a token hash
        nor a password-reset outbox message is created.
        """
        inactive = reset_user_factory(is_active=False)
        shib = reset_user_factory(auth_method="shibboleth")

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
            assert "existing code stays valid" in response.text.lower()

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

    async def test_password_reset_clears_lockout_state(
        self, db_pool, reset_user_factory, sync_conn
    ):
        """Verify password reset clears lockout state."""
        u = reset_user_factory()
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
            db_pool, u.id, token, NEW_PASSWORD, expected_email=u.email, totp_code=_reset_code()
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
    """Public landing pages disclose no capability; the POST checks current state."""

    def test_reset_form_get_rejects_replaced_token_but_accepts_current(
        self, e2e_client, reset_user_factory, sync_conn
    ):
        """Both identifiers give generic forms, but only the current body proof works."""
        user = reset_user_factory()
        token_a = generate_reset_token(user.id, user.email)
        _store_reset_hash_sync(sync_conn, user.id, token_a)
        token_b = generate_reset_token(user.id, user.email)
        assert token_b != token_a
        _store_reset_hash_sync(sync_conn, user.id, token_b)
        for token in (token_a, token_b):
            page = e2e_client.get(action_path("/reset-password", token))
            assert page.status_code == 200
            assert token not in page.text and user.email not in page.text
            assert html.fromstring(page.text).xpath(
                './/form[@action="/reset-password" and @method="post"]'
            )
        rejected = e2e_client.post(
            "/reset-password",
            data={
                "public_id": action_token_public_id(token_a),
                "token": token_a,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "totp_code": _reset_code(),
                "csrf_token": e2e_client.cookies.get("csrf_token"),
            },
            follow_redirects=False,
        )
        assert rejected.status_code == 422
        assert sync_conn.execute(
            "SELECT password_reset_token_hash FROM users WHERE id=%s", (user.id,)
        ).fetchone() == (hash_token(token_b),)
        accepted = e2e_client.post(
            "/reset-password",
            data={
                "public_id": action_token_public_id(token_b),
                "token": token_b,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "totp_code": _reset_code(),
                "csrf_token": e2e_client.cookies.get("csrf_token"),
            },
            follow_redirects=False,
        )
        assert accepted.status_code == 303 and accepted.headers["location"] == "/login"
        assert sync_conn.execute(
            "SELECT password_reset_token_hash FROM users WHERE id=%s", (user.id,)
        ).fetchone() == (None,)

    def test_reset_form_get_rejects_token_after_account_email_changes(
        self, e2e_client, reset_user_factory, sync_conn
    ):
        """The public form stays generic; old-address proof cannot reset the account."""
        user = reset_user_factory(email="old-address@example.org")
        token = generate_reset_token(user.id, user.email)
        _store_reset_hash_sync(sync_conn, user.id, token)
        sync_conn.execute(
            "UPDATE users SET email=%s WHERE id=%s", ("new-address@example.org", user.id)
        )
        sync_conn.commit()
        page = e2e_client.get(action_path("/reset-password", token))
        assert page.status_code == 200
        assert token not in page.text and user.email not in page.text
        response = e2e_client.post(
            "/reset-password",
            data={
                "public_id": action_token_public_id(token),
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "totp_code": _reset_code(),
                "csrf_token": e2e_client.cookies.get("csrf_token"),
            },
            follow_redirects=False,
        )
        assert response.status_code == 422
        assert sync_conn.execute(
            "SELECT email, password_reset_token_hash FROM users WHERE id=%s", (user.id,)
        ).fetchone() == ("new-address@example.org", hash_token(token))


class TestPasswordResetEmailedLink:
    """The actual emailed link — not a synthetically minted token — drives
    a password reset to completion."""

    @pytest.mark.usefixtures("sync_conn")
    def test_forgot_password_emailed_link_completes_a_real_reset(
        self,
        e2e_client,
        reset_user_factory,
        sync_conn,
    ):
        """The reset URL from the real outbox message completes recovery.

        This covers request, durable queuing, token validation, password
        update, and subsequent login using the same generated token — the
        route-level positive control for `TestPasswordResetFormRejection`.
        """
        user = reset_user_factory()

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
        token = token_from_action_email(body, reset_url)
        assert html.fromstring(form.text).xpath(
            './/form[@action="/reset-password" and @method="post"]'
        )
        assert token not in form.text
        _assert_both_recovery_forms_have_the_checked_envelope(form, token)
        assert f'action="{path}"' not in form.text

        csrf = e2e_client.cookies.get("csrf_token")
        done = e2e_client.post(
            "/reset-password",
            data={
                "token": token,
                "public_id": action_token_public_id(token),
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "totp_code": _reset_code(),
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

        assert done.status_code == 303
        assert done.headers["location"] == "/login"

        login = do_login(e2e_client, user.email, NEW_PASSWORD, totp_code=_login_code())
        assert login.status_code == 303


class TestPasswordResetAuthenticatorProof:
    """Email proof alone cannot replace a password or replenish proof attempts."""

    @pytest.mark.parametrize("code", ["", "not-a-code", "\uff11\uff12\uff13\uff14\uff15\uff16"])
    async def test_invalid_code_preserves_password_token_and_authenticator(
        self, db_pool, reset_user_factory, sync_conn, code
    ):
        """Verify invalid code preserves password token and authenticator."""
        user = reset_user_factory()
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)
        original = sync_conn.execute(
            "SELECT password_hash, totp_secret, last_totp_step FROM users WHERE id=%s",
            (user.id,),
        ).fetchone()

        with pytest.raises(InvalidResetTotp):
            await update_password_with_token(
                db_pool, user.id, token, NEW_PASSWORD, expected_email=user.email, totp_code=code
            )

        assert (
            sync_conn.execute(
                "SELECT password_hash, totp_secret, last_totp_step FROM users WHERE id=%s",
                (user.id,),
            ).fetchone()
            == original
        )
        assert sync_conn.execute(
            "SELECT password_reset_token_hash, password_reset_attempt_count FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (hash_token(token), 1)

    async def test_replayed_code_is_rejected_without_consuming_reset(
        self, db_pool, reset_user_factory, sync_conn
    ):
        """Verify replayed code is rejected without consuming reset."""
        user = reset_user_factory()
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)
        code = _reset_code()
        async with get_db_cursor(db_pool) as cur:
            assert await password_reset.verify_and_consume_totp_cur(cur, user.id, code)

        with pytest.raises(InvalidResetTotp):
            await update_password_with_token(
                db_pool, user.id, token, NEW_PASSWORD, expected_email=user.email, totp_code=code
            )
        assert sync_conn.execute(
            "SELECT password_reset_token_hash FROM users WHERE id=%s", (user.id,)
        ).fetchone() == (hash_token(token),)

    async def test_replacement_tokens_do_not_replenish_account_budget(
        self, db_pool, reset_user_factory, sync_conn
    ):
        """Verify replacement tokens do not replenish account budget."""
        user = reset_user_factory()
        for _ in range(password_reset.RESET_TOTP_ATTEMPT_LIMIT):
            token = generate_reset_token(user.id, user.email)
            await store_reset_token_hash(
                db_pool, user.id, hash_token(token), expected_email=user.email
            )
            with pytest.raises(InvalidResetTotp):
                await update_password_with_token(
                    db_pool,
                    user.id,
                    token,
                    NEW_PASSWORD,
                    expected_email=user.email,
                    totp_code="malformed",
                )
        replacement = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(
            db_pool, user.id, hash_token(replacement), expected_email=user.email
        )
        with pytest.raises(InvalidResetToken):
            await update_password_with_token(
                db_pool,
                user.id,
                replacement,
                NEW_PASSWORD,
                expected_email=user.email,
                totp_code=_reset_code(),
            )
        assert sync_conn.execute(
            "SELECT password_reset_attempt_count, failed_login_count, locked_until "
            "FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (password_reset.RESET_TOTP_ATTEMPT_LIMIT, 0, None)

    async def test_expired_proof_window_starts_new_budget(
        self, db_pool, reset_user_factory, sync_conn
    ):
        """Verify expired proof window starts new budget."""
        user = reset_user_factory()
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)
        sync_conn.execute(
            "UPDATE users SET password_reset_attempt_count=5, "
            "password_reset_attempt_window_started_at=clock_timestamp()-INTERVAL '31 minutes' "
            "WHERE id=%s",
            (user.id,),
        )
        sync_conn.commit()
        await update_password_with_token(
            db_pool,
            user.id,
            token,
            NEW_PASSWORD,
            expected_email=user.email,
            totp_code=_reset_code(),
        )
        assert sync_conn.execute(
            "SELECT password_reset_attempt_count FROM users WHERE id=%s", (user.id,)
        ).fetchone() == (1,)

    @pytest.mark.parametrize("state", ["no_authenticator", "recovery_required"])
    async def test_missing_active_authenticator_requires_operator_recovery(
        self, db_pool, reset_user_factory, sync_conn, state
    ):
        """Verify missing active authenticator requires operator recovery."""
        overrides = (
            {"totp_secret": None}
            if state == "no_authenticator"
            else {"totp_secret": None, "totp_recovery_required": True}
        )
        user = reset_user_factory(**overrides)
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)
        with pytest.raises(InvalidResetToken):
            await update_password_with_token(
                db_pool,
                user.id,
                token,
                NEW_PASSWORD,
                expected_email=user.email,
                totp_code=_reset_code(),
            )
        assert sync_conn.execute(
            "SELECT password_reset_token_hash, password_reset_attempt_count FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (hash_token(token), 0)

    async def test_notice_queue_failure_rolls_back_password_and_totp_but_keeps_attempt(
        self, db_pool, reset_user_factory, sync_conn, monkeypatch
    ):
        """Verify notice queue failure rolls back password and TOTP but keeps attempt."""
        user = reset_user_factory()
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)
        original = sync_conn.execute(
            "SELECT password_hash, auth_revision FROM users WHERE id=%s", (user.id,)
        ).fetchone()
        monkeypatch.setattr(
            password_reset,
            "enqueue_outbound_email_cur",
            create_autospec(
                password_reset.enqueue_outbound_email_cur, side_effect=RuntimeError("queue")
            ),
        )
        with pytest.raises(RuntimeError, match="queue"):
            await update_password_with_token(
                db_pool,
                user.id,
                token,
                NEW_PASSWORD,
                expected_email=user.email,
                totp_code=_reset_code(),
            )
        assert (
            sync_conn.execute(
                "SELECT password_hash, auth_revision FROM users WHERE id=%s", (user.id,)
            ).fetchone()
            == original
        )
        assert sync_conn.execute(
            "SELECT last_totp_step, password_reset_token_hash, password_reset_attempt_count "
            "FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (None, hash_token(token), 1)

    async def test_success_preserves_authenticator_and_queues_change_notification(
        self, db_pool, reset_user_factory, sync_conn
    ):
        """Verify success preserves authenticator and queues change notification."""
        user = reset_user_factory()
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)
        original_secret = sync_conn.execute(
            "SELECT totp_secret FROM users WHERE id=%s", (user.id,)
        ).fetchone()[0]
        await update_password_with_token(
            db_pool,
            user.id,
            token,
            NEW_PASSWORD,
            expected_email=user.email,
            totp_code=_reset_code(),
        )
        row = sync_conn.execute(
            "SELECT totp_secret, last_totp_step, password_reset_attempt_count "
            "FROM users WHERE id=%s",
            (user.id,),
        ).fetchone()
        assert row[0] == original_secret and row[1] is not None and row[2] == 1
        notices = sync_conn.execute(
            "SELECT recipient, body_ciphertext FROM email_outbox "
            "WHERE user_id=%s AND message_type='password_changed_notice'",
            (user.id,),
        ).fetchall()
        assert len(notices) == 1 and notices[0][0] == user.email
        body = decrypt_outbox_body(notices[0][1])
        assert body and NEW_PASSWORD not in body and token not in body

    async def test_changed_revision_during_hashing_rejects_stale_proof(
        self, db_pool, reset_user_factory, sync_conn, monkeypatch
    ):
        """Verify changed revision during hashing rejects stale proof."""
        user = reset_user_factory()
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)
        real_work = password_reset.run_password_work

        async def change_revision(function, *args, **kwargs):
            """Increment the stored authentication revision before real password work."""
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    "UPDATE users SET auth_revision=auth_revision+1 WHERE id=%s", (user.id,)
                )
            return await real_work(function, *args, **kwargs)

        monkeypatch.setattr(
            password_reset,
            "run_password_work",
            create_autospec(real_work, side_effect=change_revision),
        )
        with pytest.raises(InvalidResetToken):
            await update_password_with_token(
                db_pool,
                user.id,
                token,
                NEW_PASSWORD,
                expected_email=user.email,
                totp_code=_reset_code(),
            )
        assert sync_conn.execute(
            "SELECT last_totp_step, password_reset_token_hash, password_reset_attempt_count "
            "FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (None, hash_token(token), 1)

    async def test_concurrent_completions_cannot_reuse_capability_or_totp(
        self, db_pool, reset_user_factory, sync_conn
    ):
        """Verify concurrent completions cannot reuse capability or TOTP."""
        user = reset_user_factory()
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)
        code = _reset_code()
        results = await asyncio.gather(
            *(
                update_password_with_token(
                    db_pool,
                    user.id,
                    token,
                    password,
                    expected_email=user.email,
                    totp_code=code,
                )
                for password in (NEW_PASSWORD, THIRD_PASSWORD)
            ),
            return_exceptions=True,
        )
        assert sum(result is None for result in results) == 1
        rejected = [result for result in results if isinstance(result, Exception)]
        assert len(rejected) == 1 and isinstance(rejected[0], InvalidResetToken)
        assert sync_conn.execute(
            "SELECT COUNT(*) FROM email_outbox WHERE user_id=%s "
            "AND message_type='password_changed_notice'",
            (user.id,),
        ).fetchone() == (1,)

    async def test_changed_profile_during_hashing_rechecks_password_policy(
        self, db_pool, reset_user_factory, sync_conn, monkeypatch
    ):
        """Verify changed profile during hashing rechecks password policy."""
        user = reset_user_factory()
        token = generate_reset_token(user.id, user.email)
        await store_reset_token_hash(db_pool, user.id, hash_token(token), expected_email=user.email)
        real_work = password_reset.run_password_work

        async def change_profile(function, *args, **kwargs):
            """Change the stored display name before performing real password work."""
            async with get_db_cursor(db_pool) as cur:
                await cur.execute("UPDATE users SET display_name='Fresh' WHERE id=%s", (user.id,))
            return await real_work(function, *args, **kwargs)

        monkeypatch.setattr(
            password_reset,
            "run_password_work",
            create_autospec(real_work, side_effect=change_profile),
        )
        with pytest.raises(ValueError, match="Password validation failed"):
            await update_password_with_token(
                db_pool,
                user.id,
                token,
                NEW_PASSWORD,
                expected_email=user.email,
                totp_code=_reset_code(),
            )
        assert sync_conn.execute(
            "SELECT last_totp_step, password_reset_token_hash, password_reset_attempt_count "
            "FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (None, hash_token(token), 1)

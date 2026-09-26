"""Email-verification integration tests — real PostgreSQL, real services, real routes.

Covers two-click email verification: single-use confirmation, expiry, and
binding to the recipient email and the currently-stored token hash, at both
the service layer (`app.services.email_verification`) and the
`/verify-email` routes, plus the actual emailed link driven end-to-end from
registration.

These guard the awaits that mypy cannot see are missing (`coroutine is
not None` shapes) and that only a real database exercise catches: an
un-awaited coroutine is truthy even on a ZERO-row UPDATE, so mocked cursors
would happily "pass."
"""

from datetime import UTC, datetime, timedelta

import time_machine

from app.services.crypto import decrypt_outbox_body
from app.services.email_verification import (
    confirm_email_verification,
    generate_verification_token,
    store_verification_token_hash,
)
from app.services.tokens import hash_token
from config import settings
from tests.fixtures import sign_session_id


def _email_verified(sync_conn, user_id: int) -> bool:
    row = sync_conn.execute("SELECT email_verified FROM users WHERE id = %s", (user_id,)).fetchone()
    return row[0]


def _store_verification_hash_sync(sync_conn, user_id: int, token: str) -> None:
    """Sync-side equivalent of store_verification_token_hash for e2e setup."""
    sync_conn.execute(
        """UPDATE users
           SET email_verification_token_hash = %s,
               email_verification_created_at = CURRENT_TIMESTAMP
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


class TestEmailVerificationConfirmation:
    """`confirm_email_verification` is single-use and bound to the token's
    age, the recipient email, and the currently-stored hash."""

    async def test_confirm_email_verification_is_single_use(self, db_pool, user_factory, sync_conn):
        """First confirm returns True and flips email_verified; the SAME
        token a second time returns False.

        `cur.fetchone()` must be awaited before the `is not None` test — the
        coroutine object itself is never None, so a zero-row UPDATE (token
        already consumed) would still report success.
        """
        u = user_factory(email_verified=False)
        token = generate_verification_token(u.id, u.email)
        await store_verification_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        first = await confirm_email_verification(db_pool, u.id, u.email, hash_token(token))
        assert first is True
        assert _email_verified(sync_conn, u.id) is True

        second = await confirm_email_verification(db_pool, u.id, u.email, hash_token(token))
        assert second is False

    async def test_confirm_email_verification_rejects_expired_token(
        self, db_pool, user_factory, sync_conn
    ):
        """A token whose created_at is older than 24h fails the DB-level
        expiry check (defense-in-depth beyond itsdangerous), returning
        False."""
        u = user_factory(email_verified=False)
        token = generate_verification_token(u.id, u.email)
        await store_verification_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        sync_conn.execute(
            """UPDATE users
               SET email_verification_created_at = CURRENT_TIMESTAMP - INTERVAL '25 hours'
               WHERE id = %s""",
            (u.id,),
        )
        sync_conn.commit()

        ok = await confirm_email_verification(db_pool, u.id, u.email, hash_token(token))
        assert ok is False
        assert _email_verified(sync_conn, u.id) is False

    async def test_confirm_email_verification_rejects_changed_email(
        self, db_pool, user_factory, sync_conn
    ):
        """A token is bound to the email it was issued for — if the user's
        current email no longer matches, the stale token must not verify."""
        u = user_factory(email_verified=False)
        token = generate_verification_token(u.id, u.email)
        await store_verification_token_hash(
            db_pool,
            u.id,
            hash_token(token),
            expected_email=u.email,
        )

        sync_conn.execute("UPDATE users SET email = %s WHERE id = %s", ("other@x.org", u.id))
        sync_conn.commit()

        ok = await confirm_email_verification(db_pool, u.id, u.email, hash_token(token))
        assert ok is False
        assert _email_verified(sync_conn, u.id) is False

    async def test_confirm_email_verification_rejects_replaced_token(
        self, db_pool, user_factory, sync_conn
    ):
        """Storing a newer token overwrites the previous hash, so the
        EARLIER link no longer verifies (one outstanding token per user)."""
        u = user_factory(email_verified=False)
        token_a = generate_verification_token(u.id, u.email)
        await store_verification_token_hash(
            db_pool,
            u.id,
            hash_token(token_a),
            expected_email=u.email,
        )

        with time_machine.travel(datetime.now(UTC) + timedelta(seconds=2)):
            token_b = generate_verification_token(u.id, u.email)
        assert token_b != token_a

        await store_verification_token_hash(
            db_pool,
            u.id,
            hash_token(token_b),
            expected_email=u.email,
        )

        ok = await confirm_email_verification(db_pool, u.id, u.email, hash_token(token_a))
        assert ok is False
        assert _email_verified(sync_conn, u.id) is False


class TestEmailVerificationRoute:
    """`POST /verify-email` and `GET /verify-email/{token}` end to end."""

    def test_verify_email_post_consumes_token_once(self, e2e_client, user_factory, sync_conn):
        """First POST /verify-email (deliberately WITHOUT CSRF — the signed
        single-use token IS the capability, per the route's security note)
        redirects 303 to /login; the SECOND POST with the same token renders
        the 200 'Already verified' page, NOT a second success redirect."""
        u = user_factory(email_verified=False)
        token = generate_verification_token(u.id, u.email)
        _store_verification_hash_sync(sync_conn, u.id, token)

        resp = e2e_client.post("/verify-email", data={"token": token}, follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"
        assert _email_verified(sync_conn, u.id) is True

        resp2 = e2e_client.post("/verify-email", data={"token": token}, follow_redirects=False)
        assert resp2.status_code == 200
        assert "Already verified" in resp2.text

    def test_verify_email_post_tampered_token_is_400(self, e2e_client, user_factory, sync_conn):
        """A token with a broken signature renders the 400 invalid-link error
        page and does not verify anyone."""
        u = user_factory(email_verified=False)
        token = generate_verification_token(u.id, u.email)
        _store_verification_hash_sync(sync_conn, u.id, token)

        resp = e2e_client.post(
            "/verify-email", data={"token": token + "tampered"}, follow_redirects=False
        )
        assert resp.status_code == 400
        assert "Invalid verification link" in resp.text
        assert _email_verified(sync_conn, u.id) is False

    def test_verify_email_with_active_session_redirects_to_setup_totp(
        self, e2e_client, user_factory, session_factory, sync_conn
    ):
        """Verifying while holding an active session for the SAME user gives
        a success flash and 303 to /setup-totp — not /login. Redirecting to
        /login here strands a new user mid-onboarding at the login page with
        no message.

        The session is planted directly (login blocks unverified users, but
        the session middleware resolves on is_active, not email_verified — a
        session can legitimately outlive the verified flag flipping during
        this request). The verify-email POST is CSRF-exempt (the token is the
        capability), so no CSRF cookie is needed for the planted session."""
        u = user_factory(email_verified=False)
        raw = session_factory(u.id, purpose="totp_setup")
        e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(raw))

        token = generate_verification_token(u.id, u.email)
        _store_verification_hash_sync(sync_conn, u.id, token)

        resp = e2e_client.post("/verify-email", data={"token": token}, follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup-totp"
        assert _email_verified(sync_conn, u.id) is True

        flash = sync_conn.execute(
            "SELECT flash_message FROM sessions WHERE user_id = %s", (u.id,)
        ).fetchone()
        assert flash is not None
        assert "set up two-factor" in flash[0].lower()

    def test_verify_email_replaced_hash_while_unverified_is_400(
        self, e2e_client, user_factory, sync_conn
    ):
        """A valid-SIGNATURE token whose stored hash was replaced (a newer
        link issued) while the user is STILL unverified must render the 400
        'no longer valid' page — the distinct arm from the already-verified
        200 case."""
        u = user_factory(email_verified=False)
        token_a = generate_verification_token(u.id, u.email)
        _store_verification_hash_sync(sync_conn, u.id, token_a)
        # Replace the stored hash with a different token's, user still unverified.
        with time_machine.travel(datetime.now(UTC) + timedelta(seconds=2)):
            token_b = generate_verification_token(u.id, u.email)
        assert token_b != token_a
        _store_verification_hash_sync(sync_conn, u.id, token_b)

        resp = e2e_client.post("/verify-email", data={"token": token_a}, follow_redirects=False)
        assert resp.status_code == 400
        assert "no longer valid" in resp.text
        assert _email_verified(sync_conn, u.id) is False

    def test_verify_email_get_does_not_consume_token(self, e2e_client, user_factory, sync_conn):
        """GET /verify-email/{token} is side-effect-free (prefetcher guard) —
        two GETs must not burn the token, so the POST still succeeds."""
        u = user_factory(email_verified=False)
        token = generate_verification_token(u.id, u.email)
        _store_verification_hash_sync(sync_conn, u.id, token)

        for _ in range(2):
            resp = e2e_client.get(f"/verify-email/{token}")
            assert resp.status_code == 200
        assert _email_verified(sync_conn, u.id) is False

        resp = e2e_client.post("/verify-email", data={"token": token}, follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"
        assert _email_verified(sync_conn, u.id) is True


class TestEmailVerificationEmailedLink:
    """The actual emailed link — not a synthetically minted token — verifies
    a freshly registered account end to end."""

    def test_register_flow_emailed_link_verifies_account(
        self,
        e2e_client,
        sync_conn,
    ):
        """Registration queues a working verification link.

        The token extracted from the encrypted outbox message matches the
        hash stored on the user, and submitting that token verifies the
        account. Hostile privilege-related form fields remain ignored.
        """
        PENDING_PAGE_MARKER = "Check your email"  # send_verification.html success branch
        email = "newcomer@uzh.ch"

        e2e_client.get("/register")
        csrf = e2e_client.cookies.get("csrf_token")

        response = e2e_client.post(
            "/register",
            data={
                "email": email,
                "display_name": "New Comer",
                "affiliation": "UZH",
                "country": "CH",
                "password": "Str0ng-Horse-Battery!9",
                "password_confirm": "Str0ng-Horse-Battery!9",
                "csrf_token": csrf,
                # Hostile mass-assignment extras must be ignored.
                "is_admin": "true",
                "access_tier": "vetted",
                "email_verified": "true",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        assert PENDING_PAGE_MARKER in response.text

        row = sync_conn.execute(
            """
            SELECT
                users.email_verification_token_hash,
                users.is_admin,
                users.access_tier,
                users.email_verified,
                email_outbox.recipient,
                email_outbox.body_ciphertext,
                email_outbox.status,
                email_outbox.attempt_count
            FROM users
            JOIN email_outbox
              ON email_outbox.user_id = users.id
             AND email_outbox.message_type = 'email_verification'
            WHERE users.email = %s
            ORDER BY email_outbox.id DESC
            LIMIT 1
            """,
            (email,),
        ).fetchone()

        assert row is not None

        (
            stored_hash,
            is_admin,
            access_tier,
            email_verified,
            recipient,
            body_ciphertext,
            outbox_status,
            attempt_count,
        ) = row

        assert recipient == email
        assert outbox_status == "pending"
        assert attempt_count == 0

        body = decrypt_outbox_body(body_ciphertext)
        assert body is not None

        verification_url = next(
            line.strip() for line in body.splitlines() if "/verify-email/" in line
        )
        path = _path_of(verification_url)

        assert path.startswith("/verify-email/")

        token = path.removeprefix("/verify-email/")
        assert token
        assert stored_hash == hash_token(token)

        # Hostile privilege-related form fields were ignored.
        assert is_admin is False
        assert access_tier == "public"
        assert email_verified is False

        confirm = e2e_client.post(
            "/verify-email",
            data={"token": token},
            follow_redirects=False,
        )

        assert confirm.status_code == 303
        assert confirm.headers["location"] == "/login"

        verified = sync_conn.execute(
            """
            SELECT
                email_verified,
                email_verification_token_hash
            FROM users
            WHERE email = %s
            """,
            (email,),
        ).fetchone()

        assert verified is not None
        assert verified[0] is True
        assert verified[1] is None

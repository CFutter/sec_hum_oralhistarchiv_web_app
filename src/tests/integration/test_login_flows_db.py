"""Login-route and admin-seeding integration tests — real PostgreSQL, real routes.

Covers the two normalization/fallback branches on the credential lookup in
`login_submit` (`app/routes/login.py`), the bootstrap contract of
`app.services.seed_admin.seed_admin_user` on a database with no administrator
yet, and that a mutation flash stored in the session survives a redirect
chain driven by an authenticated admin session.
"""

from unittest.mock import patch

import pytest

from app.services.seed_admin import seed_admin_user
from tests.integration.conftest import DEFAULT_PASSWORD, do_login, login_admin

# 16 chars, no "admin" substring, so it clears the email-local-part check.
SEED_PASSWORD = "Xk9!mQ2#vL8@pZw4"


class TestLoginEmailNormalization:
    """`login_submit` normalizes the typed email before the DB lookup, and
    falls back to the raw value (matching nothing) when normalization fails."""

    def test_login_with_nfd_unicode_variant_normalizes_to_stored_account(
        self, e2e_client, user_factory
    ):
        """The account's STORED email is the NFC-composed form; the user
        instead TYPES an NFD-decomposed form (same glyphs, different case)
        that a bare `LOWER()` comparison would not match. Login only succeeds
        because login_submit (login.py:105-107) runs the typed value through
        normalize_email() BEFORE calling verify_password, and
        normalize_email's email_validator backend composes to NFC + lowercases
        (email_utils.py:14-16) — producing exactly the stored string.
        verify_password's own SQL lookup is only a case-fold,
        `WHERE LOWER(email) = LOWER(%s)` (authentication.py:70), which does
        NOT perform Unicode composition, so this fails without the
        Python-side normalize_email() step.
        """
        # ä = LATIN SMALL LETTER A WITH DIAERESIS, precomposed (NFC). This
        # is the form email_validator's `.normalized` output uses, and so the
        # form the stored row is created with below. Written as an explicit
        # escape (not a literal glyph in the source) so an editor/encoding
        # round-trip can't silently re-normalize the two variants together.
        stored_email = "user@kässel.example"
        # 'a' (U+0061) + ̈ COMBINING DIAERESIS, decomposed (NFD) — the
        # exact same rendered glyphs as ä above, plus mixed case on top
        # (a real OS input method can easily produce either form for the
        # "same" typed text).
        typed_email = "USER@kässel.EXAMPLE"

        # Positive control: confirm these two strings are NOT related by
        # a bare case-fold alone.
        assert typed_email.lower() != stored_email, (
            "typed/stored forms must differ after simple .lower() — otherwise "
            "this pins nothing beyond the pre-existing SQL LOWER() match"
        )

        user_factory(email=stored_email)

        resp = do_login(e2e_client, typed_email, DEFAULT_PASSWORD)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup-totp"

    def test_login_with_syntactically_invalid_email_falls_back_to_generic_401(
        self, e2e_client, user_factory
    ):
        """When normalize_email() returns None for a syntactically invalid
        address, login_submit falls back to the RAW typed value for the SQL
        lookup (login.py:105-107: `lookup_email = normalized if normalized is
        not None else email`), which naturally matches no user. The route
        must still render the SAME generic 401 copy used for a real account's
        wrong password (login.py:121 and :152 share the literal string) — the
        enumeration defense holds even down this fallback branch, so an
        attacker cannot distinguish "malformed address" from "wrong password
        on a real account" by response content.
        """
        u = user_factory()
        generic_401 = "Invalid email, password, or authentication code."

        invalid_resp = do_login(e2e_client, "not-an-email-at-all", DEFAULT_PASSWORD)
        wrong_password_resp = do_login(e2e_client, u.email, "definitely-wrong-password")

        assert invalid_resp.status_code == 401
        assert wrong_password_resp.status_code == 401
        # Same error copy on both paths (positive control: the shared literal
        # actually appears, not just "some 401").
        assert generic_401 in invalid_resp.text
        assert generic_401 in wrong_password_resp.text


class TestSeedAdminBootstrap:
    """`seed_admin_user` creates exactly one administrator on a database with
    none, is idempotent, and refuses unsafe or policy-violating seeds."""

    async def test_seed_admin_creates_admin_on_empty_db_and_is_idempotent(self, db_pool, sync_conn):
        """On an EMPTY users table the seed CREATES the admin (the buggy
        un-awaited fetchone made `if existing:` truthy on a fresh DB, so a new
        deployment failed to boot). Running it AGAIN skips silently — still
        exactly one admin, no raise."""
        await seed_admin_user(db_pool, "admin@uzh.ch", SEED_PASSWORD)

        row = sync_conn.execute(
            """SELECT is_admin, email_verified, access_tier, auth_method
               FROM users WHERE email = %s""",
            ("admin@uzh.ch",),
        ).fetchone()
        assert row is not None
        assert row == (True, True, "public", "local")

        # Second run: idempotent skip, no error, no duplicate admin.
        await seed_admin_user(db_pool, "admin@uzh.ch", SEED_PASSWORD)
        count = sync_conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = true").fetchone()
        assert count[0] == 1

    async def test_seed_admin_refuses_to_promote_existing_user(self, db_pool, user_factory):
        """If a NON-admin user already owns the seed email (and no admin
        exists), seeding raises RuntimeError instead of silently elevating."""
        user_factory(email="admin@uzh.ch")

        with pytest.raises(RuntimeError, match="refusing to promote"):
            await seed_admin_user(db_pool, "admin@uzh.ch", SEED_PASSWORD)

    async def test_seed_admin_rejects_short_password(self, db_pool, sync_conn):
        """A password under 12 characters is refused with RuntimeError and no
        user is created."""
        with pytest.raises(RuntimeError, match="at least 12 characters"):
            await seed_admin_user(db_pool, "admin@uzh.ch", "Sh0rt!pw")

        count = sync_conn.execute("SELECT COUNT(*) FROM users").fetchone()
        assert count[0] == 0

    async def test_seed_admin_rejects_password_containing_email_local_part(
        self, db_pool, sync_conn
    ):
        """The strength check runs with the seed email — a long password that
        contains the email local part ('admin') is refused."""
        with pytest.raises(RuntimeError, match="ADMIN_SEED_PASSWORD rejected"):
            await seed_admin_user(db_pool, "admin@uzh.ch", "admin-Xk9!mQ2#vL")

        count = sync_conn.execute("SELECT COUNT(*) FROM users").fetchone()
        assert count[0] == 0

    async def test_seed_admin_is_inert_when_an_admin_already_exists(self, db_pool, user_factory):
        """When an administrator already exists, seed_admin_user returns
        before validating or hashing the seed password at all — an
        operator's leftover/obsolete ADMIN_SEED_PASSWORD environment value
        must never be checked against policy or hashed on every boot."""
        user_factory(is_admin=True)
        with (
            patch(
                "app.services.seed_admin.validate_password_strength",
                autospec=True,
                side_effect=AssertionError("must be inert"),
            ),
            patch(
                "app.services.seed_admin.run_password_work",
                autospec=True,
                side_effect=AssertionError("must not hash"),
            ),
        ):
            await seed_admin_user(db_pool, "admin@uzh.ch", "obsolete")


class TestSessionFlashAcrossRedirects:
    """A flash message stashed on the session survives a redirect chain and
    is consumed exactly once."""

    def test_admin_flash_survives_out_of_range_page_redirect(self, e2e_client, user_factory):
        """The mutation flash survives the dashboard's page-correction
        redirect, then is consumed permanently on the render that shows it."""
        _, csrf = login_admin(e2e_client, user_factory)
        target = user_factory()

        mutation = e2e_client.post(
            f"/admin/users/{target.id}/set-tier",
            data={
                "access_tier": "vetted",
                "page": "999",
                "page_size": "20",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert mutation.status_code == 303

        correction = e2e_client.get(
            mutation.headers["location"],
            follow_redirects=False,
        )
        assert correction.status_code == 303

        rendered = e2e_client.get(
            correction.headers["location"],
            follow_redirects=False,
        )
        assert rendered.status_code == 200
        assert "Tier changed: public → vetted." in rendered.text

        # Exactly once: the rendered response consumed it permanently.
        again = e2e_client.get(
            correction.headers["location"],
            follow_redirects=False,
        )
        assert again.status_code == 200
        assert "Tier changed: public → vetted." not in again.text

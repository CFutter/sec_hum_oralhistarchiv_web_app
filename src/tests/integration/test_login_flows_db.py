"""Login-route and admin-seeding integration tests — real PostgreSQL, real routes."""

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
        """Verify login with NFD unicode variant normalizes to stored account."""
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
        """Verify login with syntactically invalid email falls back to generic 401."""
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
        await seed_admin_user(db_pool, "admin@example.org", SEED_PASSWORD)

        row = sync_conn.execute(
            """SELECT is_admin, email_verified, access_tier, auth_method
               FROM users WHERE email = %s""",
            ("admin@example.org",),
        ).fetchone()
        assert row is not None
        assert row == (True, True, "public", "local")

        # Second run: idempotent skip, no error, no duplicate admin.
        await seed_admin_user(db_pool, "admin@example.org", SEED_PASSWORD)
        count = sync_conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = true").fetchone()
        assert count[0] == 1

    async def test_seed_admin_refuses_to_promote_existing_user(self, db_pool, user_factory):
        """If a NON-admin user already owns the seed email (and no admin
        exists), seeding raises RuntimeError instead of silently elevating."""
        user_factory(email="admin@example.org")

        with pytest.raises(RuntimeError, match="refusing to promote"):
            await seed_admin_user(db_pool, "admin@example.org", SEED_PASSWORD)

    async def test_seed_admin_rejects_short_password(self, db_pool, sync_conn):
        """A password under 12 characters is refused with RuntimeError and no
        user is created."""
        with pytest.raises(RuntimeError, match="at least 12 characters"):
            await seed_admin_user(db_pool, "admin@example.org", "Sh0rt!pw")

        count = sync_conn.execute("SELECT COUNT(*) FROM users").fetchone()
        assert count[0] == 0

    @pytest.mark.parametrize(
        "password",
        [
            "change-me-immediately-use-a-strong-password",
            "GENERATE_STRONG_INITIAL_ADMIN_PASSWORD",
            "REPLACE_WITH_STRONG_ADMIN_PASSWORD",
            "REPLACE_WITH_INITIAL_ADMIN_PASSWORD",
        ],
    )
    async def test_documented_placeholders_cannot_create_an_administrator(
        self, db_pool, sync_conn, password
    ):
        """Verify documented placeholders cannot create an administrator."""
        with pytest.raises(RuntimeError, match="published example"):
            await seed_admin_user(db_pool, "operator@example.org", password)
        assert sync_conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0

    async def test_seed_admin_rejects_password_containing_email_local_part(
        self, db_pool, sync_conn
    ):
        """The strength check runs with the seed email — a long password that
        contains the email local part ('admin') is refused."""
        with pytest.raises(RuntimeError, match="ADMIN_SEED_PASSWORD rejected"):
            await seed_admin_user(db_pool, "admin@example.org", "admin-Xk9!mQ2#vL")

        count = sync_conn.execute("SELECT COUNT(*) FROM users").fetchone()
        assert count[0] == 0

    async def test_seed_admin_is_inert_when_an_admin_already_exists(self, db_pool, user_factory):
        """When an administrator already exists, seed_admin_user returns
        before password-policy work. Repeating the operator-only command
        against an initialized database must not alter the existing account
        or waste credential work."""
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
            await seed_admin_user(db_pool, "admin@example.org", "obsolete")


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

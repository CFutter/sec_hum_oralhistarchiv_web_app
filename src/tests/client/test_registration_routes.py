"""Registration, rename and resend-verification routes (client tier).

Pins, at the route level (real app + middleware, mocked pool):

- A display name with a control character gets a friendly 422 render of
  register.html, never a 500. Two invariants: `_register_error` must not
  re-validate the preserved input (the error renderer itself would crash),
  and the route must catch the plain `ValueError` around
  `register_local_user`. The route validates up front, before any DB/Argon2 work.
- Enumeration guard on /register: duplicate and successful registrations have
  the same client-visible status, rendered body, and lack of Set-Cookie.
  Their intended database/outbox work and destination-side emails differ, so
  these tests do not claim equal complete-request latency or identical
  external side effects.
- Except-ordering: `UserAlreadyExistsError` is a `ValueError` subclass; the
  specific handler must stay ordered before `except ValueError` AND the
  generic handler must still catch plain ValueErrors. Both misorderings are
  distinguishable and tested.
- /account/change-name rejects the exact same input through the same
  `normalize_display_name` gate, surfacing the message as an 'error' flash
  instead of a 422 page.
- Enumeration guard on /send_verification: unknown, already-verified,
  non-local, and eligible unverified-local addresses all return the same
  status and rendered page. Only the eligible account receives a replacement
  token and email; these tests therefore do not claim equal request latency
  or identical email side effects.

Rate-limit budgets: POST /register is 3/minute and POST /send_verification is
3/hour in the test environment; no test here issues more POSTs than that
budget allows (the limiter resets between tests).
"""

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import patch, sentinel

import pytest
from psycopg_pool import PoolTimeout, TooManyRequests

from app.services import UserAlreadyExistsError
from app.services.password_validation import MIN_PASSWORD_LENGTH
from app.services.tokens import ActionEmailMetadata
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user

# Stable markers for which template actually rendered.
REGISTER_PAGE_MARKER = "Create Account"  # register.html <h1>
PENDING_PAGE_MARKER = "Check your email"  # send_verification.html success branch
LENGTH_MSG = f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
GENERIC_SUCCESS = "If this address belongs to an unverified account,"

VALID_FORM = {
    "email": "alice.new@example.com",
    "display_name": "Alice Example",
    "affiliation": "University of Zurich",
    "country": "Switzerland",
    "password": "correct-horse-battery-staple-9",
    "password_confirm": "correct-horse-battery-staple-9",
}


def _post_register(client, **overrides):
    data = {**VALID_FORM, "csrf_token": client.csrf_token, **overrides}
    return client.post("/register", data=data)


def _post_send_verification(client, email):
    return client.post(
        "/send_verification",
        data={"email": email, "csrf_token": client.csrf_token},
    )


class TestRegisterFailsClosedBeforePool:
    """Input rejected before any DB/Argon2 work gets a friendly 422 render."""

    @pytest.mark.parametrize(
        ("overrides", "expected_message"),
        [
            pytest.param(
                {"display_name": "Alice\x07"},
                "Display name cannot contain control characters.",
                id="control_character_display_name",
            ),
            pytest.param(
                {"email": "not-an-email"},
                "Please enter a valid email address.",
                id="syntactically_invalid_email",
            ),
            pytest.param(
                {"password_confirm": "different-horse-battery-staple-9"},
                "Passwords do not match.",
                id="password_confirmation_mismatch",
            ),
            pytest.param(
                {"password": "Ab1!Ab1!Ab1", "password_confirm": "Ab1!Ab1!Ab1"},
                LENGTH_MSG,
                id="password_below_minimum_length",
            ),
        ],
    )
    def test_invalid_submission_renders_friendly_422_without_touching_pool(
        self, guest_client, overrides, expected_message
    ):
        """Every fail-fast validation error renders register.html at 422
        with its specific message, decided entirely before the pool is used."""
        response = _post_register(guest_client, **overrides)

        assert response.status_code == 422
        assert REGISTER_PAGE_MARKER in response.text
        assert expected_message in response.text
        guest_client.mock_pool.connection.assert_not_called()

    def test_control_character_display_name_preserves_submitted_email(self, guest_client):
        """The re-rendered form echoes the submitted email back to the user.

        Two invariants: `_register_error` must not re-validate the preserved
        input (the error renderer itself would crash), and the route must
        catch `normalize_display_name`'s `ValueError`.
        """
        response = _post_register(guest_client, display_name="Alice\x07")

        assert response.status_code == 422
        assert "alice.new@example.com" in response.text


class TestRegisterPageAccess:
    """GET /register is the entry point to local registration for guests."""

    def test_guest_sees_the_registration_form(self, guest_client):
        response = guest_client.get("/register")
        assert response.status_code == 200
        assert REGISTER_PAGE_MARKER in response.text

    def test_authenticated_full_session_is_redirected_home(self, authenticated_client):
        response = authenticated_client.get("/register", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/"


class TestRegisterEnumerationGuard:
    """Duplicate and new registrations are indistinguishable to the client."""

    def test_duplicate_registration_indistinguishable_from_success(self, guest_client):
        """Duplicate and new registrations return the same HTTP representation.

        The duplicate path queues an account-existence notice to the submitted
        address; the new path delegates to the verification-token/outbox helper.
        The assertion is deliberately limited to response status, body, and
        session-cookie behavior, not server timing or recipient-side mail.
        """

        @asynccontextmanager
        async def fake_get_db_cursor(_pool):
            yield sentinel.cursor

        with (
            patch(
                "app.routes.auth.register.get_db_cursor",
                autospec=True,
                side_effect=fake_get_db_cursor,
            ) as get_cursor,
            patch(
                "app.routes.auth.register.build_duplicate_registration_notice",
                autospec=True,
                return_value=sentinel.duplicate_notice,
            ) as build_notice,
            patch(
                "app.routes.auth.register.enqueue_outbound_email_cur",
                autospec=True,
                action=None,
            ) as enqueue,
            patch(
                "app.routes.auth.register._queue_verification_email",
                autospec=True,
            ) as queue_verification,
        ):
            with patch(
                "app.routes.auth.register.register_local_user",
                autospec=True,
                side_effect=UserAlreadyExistsError("a@b.com"),
            ):
                duplicate = _post_register(guest_client)

            assert duplicate.status_code == 200
            assert PENDING_PAGE_MARKER in duplicate.text
            assert "already exists" not in duplicate.text
            assert "set-cookie" not in duplicate.headers

            build_notice.assert_called_once_with(
                "alice.new@example.com",
            )
            get_cursor.assert_called_once_with(
                guest_client.mock_pool,
            )
            enqueue.assert_awaited_once_with(
                sentinel.cursor,
                user_id=None,
                email=sentinel.duplicate_notice,
                action=None,
            )
            queue_verification.assert_not_awaited()

            user = make_sample_user(
                email="alice.new@example.com",
            )
            with patch(
                "app.routes.auth.register.register_local_user",
                autospec=True,
                return_value=user,
            ):
                success = _post_register(guest_client)

            assert success.status_code == 200
            assert PENDING_PAGE_MARKER in success.text
            assert "already exists" not in success.text
            assert "set-cookie" not in success.headers

            # The registration service has already committed its own queued mail.
            queue_verification.assert_not_awaited()

            build_notice.assert_called_once()
            get_cursor.assert_called_once()
            enqueue.assert_awaited_once()

        assert duplicate.text == success.text

    def test_plain_valueerror_from_create_user_renders_message_not_neutral_page(self, guest_client):
        """A plain ValueError from register_local_user must render register.html
        (422) WITH the error message, not the neutral pending page.

        Because `UserAlreadyExistsError` subclasses `ValueError`, both
        misorderings of the route's except clauses are detectable here: if
        `except ValueError` came first, duplicates would leak the 'already
        exists' message; if `except UserAlreadyExistsError` swallowed all
        ValueErrors, this test would see the neutral pending page instead.
        """
        with patch(
            "app.routes.auth.register.register_local_user",
            autospec=True,
            side_effect=ValueError("Display name cannot be empty."),
        ):
            response = _post_register(guest_client)

        assert response.status_code == 422
        assert REGISTER_PAGE_MARKER in response.text
        assert "Display name cannot be empty." in response.text
        assert PENDING_PAGE_MARKER not in response.text  # not the neutral page


class TestChangeDisplayNameValidation:
    """/account/change-name rejects and accepts through the same gate."""

    def test_change_name_rejects_control_char_with_error_flash(self, authenticated_client):
        """A control character is rejected by the same normalize_display_name
        gate as registration — 303 back to /account with the validator's
        message flashed as 'error'. The ValueError fires before
        update_display_name touches the DB (pool untouched apart from the
        patched set_flash_if_exists).
        """
        with patch("app.routes.auth.account.set_flash_if_exists", autospec=True) as flash:
            response = authenticated_client.post(
                "/account/change-name",
                data={
                    "display_name": "Alice\x07",
                    "csrf_token": authenticated_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        flash.assert_awaited_once()
        args = flash.await_args.args
        assert args[1] == RAW_SESSION_ID  # flash bound to the caller's session
        assert args[2] == "Display name cannot contain control characters."
        assert args[3] == "error"
        # normalize_display_name raised before the UPDATE ran.
        authenticated_client.mock_pool.connection.assert_not_called()

    def test_change_name_happy_path_updates_and_flashes_success(self, authenticated_client):
        """Happy rename: update_display_name is awaited with the submitted
        name and the user is redirected to /account with a 'success' flash."""
        with (
            patch("app.routes.auth.account.update_display_name", autospec=True) as update,
            patch("app.routes.auth.account.set_flash_if_exists", autospec=True) as flash,
        ):
            response = authenticated_client.post(
                "/account/change-name",
                data={
                    "display_name": "Alice Renamed",
                    "csrf_token": authenticated_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        update.assert_awaited_once()
        assert update.await_args.args[1] == 1  # authenticated user's id
        assert update.await_args.args[2] == "Alice Renamed"
        flash.assert_awaited_once()
        assert flash.await_args.args[2] == "Display name updated."
        assert flash.await_args.args[3] == "success"


class TestRegistrationDisabled:
    """Both verbs bounce to /login while local registration is switched off."""

    def test_register_disabled_get_and_post_redirect_to_login(self, guest_client, monkeypatch):
        """With settings.local_registration_enabled=False, GET /register 303s
        to /login and a fully valid POST 303s too, without ever attempting
        user creation. (The enabled case is exercised by every other test in
        this module, which all register against a guest client with the
        default, enabled setting.)
        """
        monkeypatch.setattr(settings, "local_registration_enabled", False)

        get_response = guest_client.get("/register", follow_redirects=False)
        assert get_response.status_code == 303
        assert get_response.headers["location"] == "/login"

        with patch("app.routes.auth.register.register_local_user", autospec=True) as create:
            post_response = guest_client.post(
                "/register",
                data={**VALID_FORM, "csrf_token": guest_client.csrf_token},
                follow_redirects=False,
            )
        assert post_response.status_code == 303
        assert post_response.headers["location"] == "/login"
        create.assert_not_awaited()


class TestSendVerificationPage:
    """GET /send_verification renders the request form."""

    def test_get_page_prefills_email(self, guest_client):
        response = guest_client.get("/send_verification?email=alice%40uzh.ch")
        assert response.status_code == 200
        assert "alice@uzh.ch" in response.text


class TestSendVerificationEnumerationGuard:
    """Every account state returns the same page; only eligible ones resend."""

    def test_unverified_local_user_gets_resend(self, guest_client):
        """An unverified local account gets a new token and outbox message.

        The token hash and email are written through the same database cursor,
        ensuring they participate in one transaction.
        """
        user = make_sample_user(email_verified=False)
        action = ActionEmailMetadata(
            "fresh-token-hash",
            datetime(2030, 1, 1, tzinfo=UTC),
        )

        @asynccontextmanager
        async def fake_get_db_cursor(_pool):
            yield sentinel.cursor

        with (
            patch(
                "app.routes.auth.register.get_user_by_email",
                autospec=True,
                return_value=user,
            ),
            patch(
                "app.services.registration.generate_verification_token",
                autospec=True,
                return_value="fresh-token",
            ) as generate,
            patch(
                "app.services.registration.build_verification_email",
                autospec=True,
                return_value=sentinel.verification_email,
            ) as build_email,
            patch(
                "app.routes.auth.register.get_db_cursor",
                autospec=True,
                side_effect=fake_get_db_cursor,
            ) as get_cursor,
            patch(
                "app.services.registration.store_verification_token_hash_cur",
                autospec=True,
            ) as store,
            patch(
                "app.services.registration.enqueue_outbound_email_cur",
                autospec=True,
            ) as enqueue,
            patch(
                "app.services.registration.verification_token_email_metadata",
                autospec=True,
                return_value=action,
            ) as metadata,
        ):
            response = _post_send_verification(guest_client, user.email)

        assert response.status_code == 200
        assert GENERIC_SUCCESS in response.text
        assert "We&#39;ve sent a verification link" not in response.text
        assert "We've sent a verification link" not in response.text

        generate.assert_called_once_with(
            user.id,
            user.email,
        )
        metadata.assert_called_once_with("fresh-token")

        build_email.assert_called_once_with(
            user.email,
            f"{settings.public_base_url}/verify-email/fresh-token",
            expires_at=action.expires_at,
        )

        enqueue.assert_awaited_once_with(
            sentinel.cursor,
            user_id=user.id,
            email=sentinel.verification_email,
            action=action,
        )
        get_cursor.assert_called_once_with(
            guest_client.mock_pool,
        )
        store.assert_awaited_once_with(
            sentinel.cursor,
            user.id,
            "fresh-token-hash",
            expected_email=user.email,
        )

    def test_verified_and_unknown_emails_are_indistinguishable(self, guest_client):
        """Already-verified and unknown addresses produce the same HTTP
        representation."""
        verified_user = make_sample_user(
            email="probe@uzh.ch",
            email_verified=True,
        )

        with (
            patch(
                "app.routes.auth.register.get_user_by_email",
                autospec=True,
                side_effect=[verified_user, None],
            ),
            patch(
                "app.routes.auth.register._queue_verification_email",
                autospec=True,
            ) as queue_verification,
        ):
            exists = _post_send_verification(guest_client, "probe@uzh.ch")
            unknown = _post_send_verification(guest_client, "probe@uzh.ch")

        assert exists.status_code == unknown.status_code == 200
        assert exists.text == unknown.text
        assert GENERIC_SUCCESS in exists.text
        queue_verification.assert_not_awaited()

    def test_invalid_email_gets_same_generic_page(self, guest_client):
        """A syntactically invalid address short-circuits before any lookup
        but still renders the same success page — validation errors must not
        become an enumeration side channel either."""
        with patch("app.routes.auth.register.get_user_by_email", autospec=True) as lookup:
            response = _post_send_verification(guest_client, "not-an-email")
        assert response.status_code == 200
        assert GENERIC_SUCCESS in response.text
        assert "We&#39;ve sent a verification link" not in response.text
        assert "We've sent a verification link" not in response.text
        lookup.assert_not_awaited()

    def test_shibboleth_account_never_resent(self, guest_client):
        """Federated accounts never receive local verification messages."""
        shib = make_sample_user(
            auth_method="shibboleth",
            email_verified=False,
        )

        with (
            patch(
                "app.routes.auth.register.get_user_by_email",
                autospec=True,
                return_value=shib,
            ),
            patch(
                "app.routes.auth.register._queue_verification_email",
                autospec=True,
            ) as queue_verification,
        ):
            response = _post_send_verification(guest_client, shib.email)

        assert response.status_code == 200
        assert GENERIC_SUCCESS in response.text
        assert "We&#39;ve sent a verification link" not in response.text
        assert "We've sent a verification link" not in response.text
        queue_verification.assert_not_awaited()


class TestSendVerificationCapacityFailureIsEnumerationNeutral:
    """A pool-capacity failure at the initial lookup must produce the same
    generic page for any address and never reach the queueing helper."""

    @pytest.mark.parametrize(
        "exception",
        [PoolTimeout("pool exhausted"), TooManyRequests("queue full")],
        ids=["pool_timeout", "too_many_requests"],
    )
    def test_lookup_failure_never_queues_and_hides_which_address_failed(
        self, guest_client, exception
    ):
        with (
            patch(
                "app.routes.auth.register.get_user_by_email",
                autospec=True,
                side_effect=exception,
            ) as lookup,
            patch(
                "app.routes.auth.register._queue_verification_email", autospec=True
            ) as queue_verification,
        ):
            first = _post_send_verification(guest_client, "alice@uzh.ch")
            second = _post_send_verification(guest_client, "alice@uzh.ch")

        for response in (first, second):
            assert response.status_code == 200
            assert GENERIC_SUCCESS in response.text
        assert lookup.await_count == 2
        queue_verification.assert_not_awaited()

    def test_healthy_lookup_still_queues_for_a_known_unverified_address(self, guest_client):
        """Positive control: absent the injected failure, an eligible
        address does reach the queueing helper (the full transaction is
        proven separately by
        TestSendVerificationEnumerationGuard.test_unverified_local_user_gets_resend;
        this pins only that the failure-path assertion above is non-vacuous)."""
        user = make_sample_user(email_verified=False)
        with (
            patch(
                "app.routes.auth.register.get_user_by_email",
                autospec=True,
                return_value=user,
            ),
            patch(
                "app.routes.auth.register._queue_verification_email", autospec=True
            ) as queue_verification,
        ):
            response = _post_send_verification(guest_client, user.email)

        assert response.status_code == 200
        queue_verification.assert_awaited_once()


class TestVerifyEmailCapabilityRoute:
    """POST /verify-email is the CSRF-exempt capability route: the signed,
    single-use token is the capability, not a session-bound CSRF pair."""

    def test_post_without_csrf_pair_still_reaches_the_service(self, guest_client):
        with (
            patch(
                "app.routes.auth.verify_email.validate_verification_token",
                autospec=True,
                return_value={"user_id": 7, "email": "alice@uzh.ch"},
            ) as validate,
            patch(
                "app.routes.auth.verify_email.confirm_email_verification",
                autospec=True,
                return_value=True,
            ) as confirm,
        ):
            response = guest_client.post(
                "/verify-email",
                data={"token": "a-live-verification-token"},  # no csrf_token field
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        validate.assert_called_once_with("a-live-verification-token")
        confirm.assert_awaited_once()

    def test_post_with_json_body_is_still_415(self, guest_client):
        """Content-Type validation is not part of CSRF and stays automatic
        even on the CSRF-exempt capability route."""
        with patch(
            "app.routes.auth.verify_email.confirm_email_verification", autospec=True
        ) as confirm:
            response = guest_client.post(
                "/verify-email",
                content='{"token": "a-live-verification-token"}',
                headers={"Content-Type": "application/json"},
                follow_redirects=False,
            )

        assert response.status_code == 415
        confirm.assert_not_awaited()

    def test_get_page_does_not_consume_the_token(self, guest_client):
        """The preceding GET is SAFE — it never touches confirm_email_verification."""
        with (
            patch(
                "app.routes.auth.verify_email.validate_verification_token",
                autospec=True,
                return_value={"user_id": 7, "email": "alice@uzh.ch"},
            ),
            patch(
                "app.routes.auth.verify_email.confirm_email_verification", autospec=True
            ) as confirm,
        ):
            response = guest_client.get("/verify-email/a-live-verification-token")

        assert response.status_code == 200
        assert "alice@uzh.ch" in response.text
        confirm.assert_not_awaited()

"""Email-only requests and mailbox-bound credential setup through real guards."""

import json
import logging
from unittest.mock import create_autospec, patch

import pytest
from psycopg import Error as DatabaseError
from psycopg_pool import PoolTimeout

from app.credentials import LOCAL_PASSWORD_MAX_CHARS
from app.middleware.csrf import CSRF_COOKIE_NAME
from app.routes.auth import account, register, verify_email
from app.service_errors import UserInputRejected, UserStateChanged
from app.services import registration_setup
from app.services.audit import audit_user_event as _REAL_AUDIT
from app.services.sessions import set_flash_if_exists as _REAL_FLASH
from app.services.tokens import action_token_public_id
from app.services.users import update_display_name as _REAL_RENAME
from config import settings
from config.logging import JSONFormatter, RedactingFormatter
from tests.fixtures import RAW_SESSION_ID, make_sample_user

_EMAIL = "owner@example.org"
_TOKEN = "mailbox-capability-private-canary"
_PASSWORD = "Mailbox-Owner-Chose-739!Quartz"
_SETUP = registration_setup.RegistrationSetup(7, _EMAIL)
_PROFILE = {
    "display_name": "Mailbox Owner",
    "affiliation": "University",
    "country": "Switzerland",
    "password": _PASSWORD,
    "password_confirm": _PASSWORD,
}


def _service(module, name, **kwargs):
    # Capture the defining collaborator before replacing its route-local alias.
    """Patch a registration service with a strict signature-checked mock."""
    real = getattr(registration_setup, name)
    return patch.object(module, name, create_autospec(real, spec_set=True, **kwargs))


def _post_register(client, **fields):
    """Submit the valid CSRF-protected form without following redirects."""
    return client.post(
        "/register",
        data={"email": _EMAIL, "csrf_token": client.csrf_token, **fields},
        follow_redirects=False,
    )


def _post_complete(client, **fields):
    """Submit the valid CSRF-protected form without following redirects."""
    return client.post(
        "/verify-email",
        data={
            "token": _TOKEN,
            "public_id": action_token_public_id(_TOKEN),
            **_PROFILE,
            "csrf_token": client.csrf_token,
            **fields,
        },
        follow_redirects=False,
    )


def _post_resend(client, email=_EMAIL):
    """Submit a CSRF-protected verification resend for the selected email."""
    return client.post("/send_verification", data={"email": email, "csrf_token": client.csrf_token})


def _assert_sensitive_headers(response):
    """Require uncached responses with the strict-origin referrer policy."""
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "strict-origin"


class TestRegisterPageAccess:
    """Cover register page access."""

    def test_guest_sees_the_registration_form(self, guest_client):
        """Check guest sees the registration form (HTTP 200)."""
        response = guest_client.get("/register")
        assert response.status_code == 200 and 'name="email"' in response.text
        for field in ("password", "password_confirm", "display_name", "affiliation", "country"):
            assert f'name="{field}"' not in response.text

    def test_authenticated_full_session_is_redirected_home(self, authenticated_client):
        """Check authenticated full session is redirected home (HTTP 303)."""
        response = authenticated_client.get("/register", follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == "/"


class TestRegisterEnumerationGuard:
    """Cover register enumeration guard."""

    def test_duplicate_registration_indistinguishable_from_success(self, guest_client):
        """A void service result cannot disclose new/duplicate state; no timing claim."""
        with _service(register, "begin_local_registration", return_value=None) as begin:
            first = _post_register(guest_client)
            second = _post_register(guest_client)
        assert first.status_code == second.status_code == 200
        assert first.text == second.text and "Check your email" in first.text
        assert "set-cookie" not in first.headers and "set-cookie" not in second.headers
        assert begin.await_count == 2
        begin.assert_awaited_with(guest_client.mock_pool, email=_EMAIL)

    def test_hostile_extra_fields_cannot_supply_credentials_or_privilege(self, guest_client):
        """Check hostile extra fields cannot supply credentials or privilege (HTTP 200)."""
        with _service(register, "begin_local_registration", return_value=None) as begin:
            response = _post_register(
                guest_client,
                email=" OWNER@EXAMPLE.ORG ",
                password="attacker-password",
                password_confirm="attacker-password",
                display_name="Attacker",
                affiliation="Attacker Org",
                country="Elsewhere",
                is_admin="true",
                access_tier="vetted",
                email_verified="true",
                is_active="true",
            )
        assert response.status_code == 200
        begin.assert_awaited_once_with(guest_client.mock_pool, email=_EMAIL)
        assert "attacker-password" not in response.text and "Attacker Org" not in response.text

    @pytest.mark.parametrize("email", ["not-an-email", "owner@example.org\nInjected"])
    def test_invalid_email_never_reaches_service(self, guest_client, email):
        """Check invalid email never reaches service (HTTP 422)."""
        with _service(register, "begin_local_registration") as begin:
            response = _post_register(guest_client, email=email)
        assert response.status_code == 422 and "valid email address" in response.text
        begin.assert_not_awaited()
        guest_client.mock_pool.connection.assert_not_called()

    @pytest.mark.parametrize(
        ("error", "status"),
        [
            (UserInputRejected("Please enter a valid email address."), 422),
            (DatabaseError("database unavailable"), 500),
            (PoolTimeout("capacity"), 500),
        ],
        ids=["validation", "database", "capacity"],
    )
    def test_service_failures_share_the_same_route_boundary(self, guest_client, error, status):
        """Check service failures share the same route boundary."""
        with _service(register, "begin_local_registration", side_effect=error):
            response = _post_register(guest_client)
        assert response.status_code == status and "Check your email" not in response.text


class TestRegistrationDisabled:
    """Cover registration disabled."""

    def test_register_disabled_get_and_post_redirect_to_login(self, guest_client, monkeypatch):
        """Check register disabled GET and POST redirect to login (HTTP 303)."""
        monkeypatch.setattr(settings, "local_registration_enabled", False)
        with _service(register, "begin_local_registration") as begin:
            responses = [
                guest_client.get("/register", follow_redirects=False),
                _post_register(guest_client),
            ]
        for response in responses:
            assert response.status_code == 303 and response.headers["location"] == "/login"
        begin.assert_not_awaited()

    def test_existing_mailbox_proof_and_resend_remain_usable(self, guest_client, monkeypatch):
        """Check existing mailbox proof and resend remain usable."""
        monkeypatch.setattr(settings, "local_registration_enabled", False)
        with (
            _service(verify_email, "inspect_local_registration", return_value=_SETUP),
            _service(
                verify_email,
                "complete_local_registration",
                return_value=make_sample_user(id=7, email=_EMAIL),
            ),
            _service(register, "resend_local_registration", return_value=None) as resend,
            patch.object(verify_email, "audit_user_event", create_autospec(_REAL_AUDIT)),
        ):
            assert (
                guest_client.get(f"/verify-email/{action_token_public_id(_TOKEN)}").status_code
                == 200
            )
            response = _post_complete(guest_client)
            assert _post_resend(guest_client).status_code == 200
        assert response.status_code == 303
        assert response.headers["location"] == "/login?notice=registration_complete"
        resend.assert_awaited_once()


class TestSendVerificationPage:
    """Cover send verification page."""

    def test_get_page_prefills_email(self, guest_client):
        """Check GET page prefills email (HTTP 200)."""
        response = guest_client.get("/send_verification?email=owner%40example.org")
        assert response.status_code == 200 and _EMAIL in response.text


class TestSendVerificationEnumerationGuard:
    """Cover send verification enumeration guard."""

    def test_unverified_local_user_gets_resend(self, guest_client):
        """Check unverified local user gets resend (HTTP 200)."""
        with _service(register, "resend_local_registration", return_value=None) as resend:
            response = _post_resend(guest_client, " OWNER@EXAMPLE.ORG ")
        assert response.status_code == 200
        assert "If this address belongs to an unverified account," in response.text
        resend.assert_awaited_once_with(guest_client.mock_pool, email=" OWNER@EXAMPLE.ORG ")

    @pytest.mark.parametrize(
        "error",
        [
            None,
            UserStateChanged("ineligible"),
            DatabaseError("unavailable"),
            PoolTimeout("capacity"),
        ],
        ids=["void", "ineligible", "database", "capacity"],
    )
    def test_eligibility_and_storage_outcomes_are_neutral(self, guest_client, error):
        """Check eligibility and storage outcomes are neutral (HTTP 200)."""
        with _service(register, "resend_local_registration", return_value=None) as resend:
            baseline = _post_resend(guest_client)
            resend.side_effect = error
            response = _post_resend(guest_client)
        assert baseline.status_code == response.status_code == 200
        assert baseline.text == response.text
        assert "If this address belongs to an unverified account," in response.text
        assert "set-cookie" not in response.headers

    def test_invalid_email_has_the_same_generic_page_without_database(self, guest_client):
        """Check invalid email has the same generic page without database (HTTP 200)."""
        with _service(
            register,
            "resend_local_registration",
            side_effect=registration_setup.resend_local_registration,
        ) as resend:
            response = _post_resend(guest_client, "not-an-email")
        assert response.status_code == 200
        assert "If this address belongs to an unverified account," in response.text
        resend.assert_awaited_once_with(guest_client.mock_pool, email="not-an-email")
        guest_client.mock_pool.connection.assert_not_called()


class TestVerifyEmailCapabilityRoute:
    """Cover verify email capability route."""

    def test_get_page_does_not_consume_the_token(self, guest_client):
        """Check GET page does not consume the token (HTTP 200)."""
        with (
            _service(verify_email, "inspect_local_registration", return_value=_SETUP) as inspect,
            _service(verify_email, "complete_local_registration") as complete,
        ):
            response = guest_client.get(f"/verify-email/{action_token_public_id(_TOKEN)}")
        assert response.status_code == 200 and _EMAIL not in response.text
        assert _TOKEN not in response.text
        for field in (
            "public_id",
            "token",
            "display_name",
            "affiliation",
            "country",
            "password",
            "password_confirm",
            "csrf_token",
        ):
            assert f'name="{field}"' in response.text
        inspect.assert_not_awaited()
        complete.assert_not_awaited()
        guest_client.mock_pool.connection.assert_not_called()
        _assert_sensitive_headers(response)

    def test_get_rejects_stale_live_state(self, guest_client):
        """Only POST can check state: identifier-only GET reveals no capability status."""
        with _service(verify_email, "inspect_local_registration", return_value=None) as inspect:
            response = _post_complete(guest_client)
        assert response.status_code == 400 and 'name="password"' not in response.text
        inspect.assert_awaited_once_with(guest_client.mock_pool, _TOKEN)
        _assert_sensitive_headers(response)

    @pytest.mark.parametrize("fixture", ["guest_client", "totp_setup_client"])
    def test_completion_uses_mailbox_identity_and_does_not_log_in(self, request, fixture):
        """Check completion uses mailbox identity and does not log in (HTTP 303)."""
        client = request.getfixturevalue(fixture)
        with (
            _service(verify_email, "inspect_local_registration", return_value=_SETUP) as inspect,
            _service(
                verify_email,
                "complete_local_registration",
                return_value=make_sample_user(id=7, email=_EMAIL),
            ) as complete,
            patch.object(verify_email, "audit_user_event", create_autospec(_REAL_AUDIT)) as audit,
        ):
            response = _post_complete(
                client,
                email="attacker@example.org",
                user_id="999",
                is_admin="true",
                access_tier="vetted",
            )
        assert response.status_code == 303
        assert response.headers["location"] == "/login?notice=registration_complete"
        inspect.assert_awaited_once_with(client.mock_pool, _TOKEN)
        complete.assert_awaited_once_with(
            client.mock_pool,
            token=_TOKEN,
            display_name="Mailbox Owner",
            password=_PASSWORD,
            affiliation="University",
            country="Switzerland",
        )
        audit.assert_called_once()
        assert audit.call_args.kwargs["event_type"] == "email_verified"
        assert audit.call_args.kwargs["user_id"] == 7
        assert "set-cookie" not in response.headers
        _assert_sensitive_headers(response)

    @pytest.mark.parametrize("fixture", ["guest_client", "totp_setup_client"])
    @pytest.mark.parametrize(
        "failure", ["missing_form", "wrong_form", "missing_cookie", "forged_pair"]
    )
    def test_completion_requires_the_current_first_party_csrf_pair(self, request, fixture, failure):
        """Check completion requires the current first party CSRF pair (HTTP 403)."""
        client = request.getfixturevalue(fixture)
        fields = {
            "token": _TOKEN,
            "public_id": action_token_public_id(_TOKEN),
            **_PROFILE,
            "csrf_token": client.csrf_token,
        }
        if failure == "missing_form":
            fields.pop("csrf_token")
        elif failure == "wrong_form":
            fields["csrf_token"] = "wrong"
        elif failure == "missing_cookie":
            client.cookies.delete(CSRF_COOKIE_NAME)
        else:
            fields["csrf_token"] = "a" * 64
            client.cookies.set(CSRF_COOKIE_NAME, fields["csrf_token"])
        with (
            _service(verify_email, "inspect_local_registration") as inspect,
            _service(verify_email, "complete_local_registration") as complete,
        ):
            response = client.post("/verify-email", data=fields, follow_redirects=False)
        assert response.status_code == 403
        inspect.assert_not_awaited()
        complete.assert_not_awaited()
        _assert_sensitive_headers(response)

    @pytest.mark.parametrize("content_type", ["application/json", "text/plain"])
    def test_post_with_unsupported_body_is_415(self, guest_client, content_type):
        """Check POST with unsupported body is 415."""
        with _service(verify_email, "complete_local_registration") as complete:
            response = guest_client.post(
                "/verify-email",
                content='{"token":"private"}',
                headers={"content-type": content_type},
            )
        assert response.status_code == 415
        complete.assert_not_awaited()
        _assert_sensitive_headers(response)

    def test_token_only_post_cannot_activate_an_account(self, guest_client):
        """Check token only POST cannot activate an account (HTTP 422)."""
        with _service(verify_email, "complete_local_registration") as complete:
            response = guest_client.post(
                "/verify-email",
                data={
                    "token": _TOKEN,
                    "public_id": action_token_public_id(_TOKEN),
                    "csrf_token": guest_client.csrf_token,
                },
            )
        assert response.status_code == 422
        complete.assert_not_awaited()
        _assert_sensitive_headers(response)

    @pytest.mark.parametrize("live", [False, True], ids=["stale", "live"])
    def test_capability_is_checked_before_password_confirmation(self, guest_client, live):
        """Check capability is checked before password confirmation."""
        with (
            _service(
                verify_email, "inspect_local_registration", return_value=_SETUP if live else None
            ),
            _service(verify_email, "complete_local_registration") as complete,
        ):
            response = _post_complete(guest_client, password_confirm="mismatch")
        assert response.status_code == (422 if live else 400)
        complete.assert_not_awaited()
        assert _PASSWORD not in response.text and "mismatch" not in response.text
        if live:
            assert "Passwords do not match." in response.text
            assert "Mailbox Owner" in response.text and "University" in response.text
        _assert_sensitive_headers(response)

    @pytest.mark.parametrize(
        "result",
        [None, UserInputRejected("Display name cannot contain control characters.")],
        ids=["changed_capability", "invalid_profile"],
    )
    def test_completion_rejection_never_audits_success(self, guest_client, result):
        """Check completion rejection never audits success."""
        with (
            _service(verify_email, "inspect_local_registration", return_value=_SETUP),
            _service(
                verify_email,
                "complete_local_registration",
                side_effect=result if isinstance(result, Exception) else None,
                return_value=None,
            ),
            patch.object(verify_email, "audit_user_event", create_autospec(_REAL_AUDIT)) as audit,
        ):
            response = _post_complete(guest_client, display_name="Bad\x01Name")
        assert response.status_code == (422 if isinstance(result, Exception) else 400)
        assert _PASSWORD not in response.text
        assert all(call.kwargs["event_type"] != "email_verified" for call in audit.call_args_list)
        _assert_sensitive_headers(response)

    @pytest.mark.parametrize("stage", ["inspect", "complete"])
    @pytest.mark.parametrize("error_type", [DatabaseError, PoolTimeout])
    def test_storage_errors_are_generic_and_do_not_disclose_credentials(
        self, guest_client, caplog, stage, error_type
    ):
        """Check storage errors are generic and do not disclose credentials (HTTP 500)."""
        caplog.set_level(logging.WARNING, logger=verify_email.__name__)
        with (
            _service(
                verify_email,
                "inspect_local_registration",
                return_value=_SETUP,
                side_effect=error_type(f"{_TOKEN} {_PASSWORD}") if stage == "inspect" else None,
            ),
            _service(
                verify_email,
                "complete_local_registration",
                side_effect=error_type(f"{_TOKEN} {_PASSWORD}"),
            ),
            patch.object(verify_email, "audit_user_event", create_autospec(_REAL_AUDIT)) as audit,
        ):
            response = _post_complete(guest_client)
        assert response.status_code == 500
        assert _TOKEN not in response.text and _PASSWORD not in response.text
        records = [record for record in caplog.records if record.name == verify_email.__name__]
        assert len(records) == 1
        record = records[0]
        assert record.exc_info is not None
        for formatter in (JSONFormatter(), RedactingFormatter()):
            rendered = formatter.format(record)
            assert _TOKEN not in rendered and _PASSWORD not in rendered
            assert response.headers["x-request-id"] in rendered
        entry = json.loads(JSONFormatter().format(record))
        assert entry["phase"] == stage
        assert entry["exception"]["type"] == (f"{error_type.__module__}.{error_type.__qualname__}")
        assert all(call.kwargs["event_type"] != "email_verified" for call in audit.call_args_list)
        _assert_sensitive_headers(response)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("token", "t" * 2001),
            ("display_name", "n" * 201),
            ("affiliation", "a" * 201),
            ("country", "c" * 101),
            ("password", "p" * (LOCAL_PASSWORD_MAX_CHARS + 1)),
        ],
        ids=["token", "display_name", "affiliation", "country", "password"],
    )
    def test_oversized_fields_never_reach_the_service(self, guest_client, field, value):
        """Check oversized fields never reach the service (HTTP 422)."""
        with _service(verify_email, "complete_local_registration") as complete:
            response = _post_complete(guest_client, **{field: value})
        assert response.status_code == 422
        complete.assert_not_awaited()
        assert _PASSWORD not in response.text
        _assert_sensitive_headers(response)


class TestChangeDisplayNameValidation:
    """Cover change display name validation."""

    def test_change_name_rejects_control_char_with_error_flash(self, authenticated_client):
        """Check change name rejects control char with error flash (HTTP 303)."""
        with patch.object(account, "set_flash_if_exists", create_autospec(_REAL_FLASH)) as flash:
            response = authenticated_client.post(
                "/account/change-name",
                data={"display_name": "Alice\x07", "csrf_token": authenticated_client.csrf_token},
                follow_redirects=False,
            )
        assert response.status_code == 303 and response.headers["location"] == "/account"
        assert flash.await_args.args[1:] == (
            RAW_SESSION_ID,
            "Display name cannot contain control characters.",
            "error",
        )
        authenticated_client.mock_pool.connection.assert_not_called()

    def test_change_name_happy_path_updates_and_flashes_success(self, authenticated_client):
        """Check change name happy path updates and flashes success (HTTP 303)."""
        with (
            patch.object(account, "update_display_name", create_autospec(_REAL_RENAME)) as update,
            patch.object(account, "set_flash_if_exists", create_autospec(_REAL_FLASH)) as flash,
        ):
            response = authenticated_client.post(
                "/account/change-name",
                data={
                    "display_name": "Alice Renamed",
                    "csrf_token": authenticated_client.csrf_token,
                },
                follow_redirects=False,
            )
        assert response.status_code == 303 and response.headers["location"] == "/account"
        update.assert_awaited_once_with(authenticated_client.mock_pool, 1, "Alice Renamed")
        assert flash.await_args.args[2:] == ("Display name updated.", "success")

"""TOTP enrollment routes (`GET`/`POST /setup-totp`) — the MFA-critical surface."""

import re
from unittest.mock import patch

import pytest

from app.middleware import CSRF_COOKIE_NAME
from app.services.totp import (
    PendingTotpOutcome,
    PendingTotpPurpose,
    PendingTotpResult,
    TotpEnrollmentOutcome,
)
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user

SECRET = "JBSWY3DPEHPK3PXP"
RECOVERY_CODE = "AAAAA-BBBBB-CCCCC-DDDDD"


def _patch(name, **kw):
    """Patch the route collaborator with its real signature."""
    return patch(f"app.routes.auth.totp.{name}", autospec=True, **kw)


def _pending_ready(secret=SECRET):
    """Build a ready pending-secret result from the supplied seed."""
    return PendingTotpResult(PendingTotpOutcome.READY, secret)


_NEW_SECRET_RE = re.compile(r'class="totp-key">([A-Z2-7]+)<')


def _extract_new_secret(text: str) -> str:
    """Pull the once-disclosed secret out of setup_totp.html's markup — the
    same pattern the integration tier's `_extract_new_secret` reads."""
    match = _NEW_SECRET_RE.search(text)
    assert match, "no secret disclosed on the enrollment page"
    return match.group(1)


def _assert_auth_cookies_cleared(response):
    """Require deletion headers for the authentication cookies."""
    set_cookie_headers = response.headers.get_list("set-cookie")
    for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
        assert any(
            header.startswith(f"{cookie_name}=") and "Max-Age=0" in header
            for header in set_cookie_headers
        )


def _deleted_cookie_headers(response, name: str) -> list[str]:
    """Select deletion headers for the named cookie."""
    return [
        header
        for header in response.headers.get_list("set-cookie")
        if header.startswith(f"{name}=") and "max-age=0" in header.lower()
    ]


def _post_setup(client, totp_code="123456", recovery_code_confirmation=RECOVERY_CODE, **extra):
    """Submit the valid CSRF-protected form without following redirects."""
    data = {
        "totp_code": totp_code,
        "recovery_code_confirmation": recovery_code_confirmation,
        "csrf_token": client.csrf_token,
        **extra,
    }
    return client.post("/setup-totp", data=data, follow_redirects=False)


class TestSetupTotpPage:
    """GET /setup-totp mints or reuses a pending secret unless a gate fires
    first (already configured, ineligible, unverified email)."""

    def test_setup_totp_page_requests_atomic_pending_secret(self, totp_setup_client):
        """The exact TOTP-enrolment policy admits a setup-purpose session."""
        with _patch(
            "get_or_create_pending_totp_secret",
            return_value=_pending_ready(),
        ) as pending:
            resp = totp_setup_client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 200
        assert _extract_new_secret(resp.text) == SECRET
        pending.assert_awaited_once_with(
            totp_setup_client.mock_pool,
            1,
            purpose=PendingTotpPurpose.ENROLLMENT,
            session_id=RAW_SESSION_ID,
        )

    def test_setup_totp_page_handles_already_configured_race(self, totp_setup_client):
        """If enrollment completes after middleware builds its user snapshot,
        the restricted session is invalidated instead of entering a redirect loop."""
        with (
            _patch(
                "get_or_create_pending_totp_secret",
                return_value=PendingTotpResult(PendingTotpOutcome.ALREADY_CONFIGURED),
            ) as pending,
            _patch("delete_session") as delete,
        ):
            resp = totp_setup_client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?notice=totp_setup_completed"
        pending.assert_awaited_once_with(
            totp_setup_client.mock_pool,
            1,
            purpose=PendingTotpPurpose.ENROLLMENT,
            session_id=RAW_SESSION_ID,
        )
        delete.assert_awaited_once_with(totp_setup_client.mock_pool, RAW_SESSION_ID)
        _assert_auth_cookies_cleared(resp)

    def test_setup_totp_page_redirects_when_already_configured(self, authenticated_client):
        """A user with TOTP already configured is bounced to /account before any
        pending-secret work — re-enrollment is only via /account/reset-totp."""
        with (
            _patch("get_or_create_pending_totp_secret") as pending,
            _patch("delete_session") as delete,
        ):
            resp = authenticated_client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/account"
        pending.assert_not_awaited()
        delete.assert_not_awaited()

    def test_setup_totp_page_blocks_unverified_email(self, client_builder):
        """The email_verified gate: an unverified user gets the
        verify-email-pending page, and NO pending secret is minted — enrollment
        cannot begin before the address is proven."""
        user = make_sample_user(totp_configured=False, email_verified=False)
        client = client_builder(session_user=user, session_purpose="totp_setup")
        with _patch("get_or_create_pending_totp_secret") as pending:
            resp = client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 200
        assert user.email in resp.text
        pending.assert_not_awaited()


class TestCompletedSetupSessionEscapesLoop:
    """Cover completed setup session escapes loop."""

    def test_setup_totp_page_invalidates_completed_restricted_session(self, client_builder):
        """A configured user left in a ``totp_setup`` session is sent to a
        fresh login instead of bouncing between /account and /setup-totp."""
        user = make_sample_user(totp_configured=True)
        client = client_builder(session_user=user, session_purpose="totp_setup")

        with (
            _patch("get_or_create_pending_totp_secret") as pending,
            _patch("delete_session") as delete,
        ):
            resp = client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?notice=totp_setup_completed"
        pending.assert_not_awaited()
        delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)
        _assert_auth_cookies_cleared(resp)

    def test_stale_totp_setup_session_escapes_loop_even_if_revocation_fails(self, client_builder):
        """Completed setup must terminate the gate loop and reach public login
        even when the best-effort session revocation itself raises."""
        client = client_builder(
            session_user=make_sample_user(totp_configured=True),
            session_purpose="totp_setup",
        )

        first = client.get("/account", follow_redirects=False)
        assert first.status_code == 303
        assert first.headers["location"] == "/setup-totp"

        with patch(
            "app.routes.auth.totp.delete_session",
            autospec=True,
            side_effect=RuntimeError("db unavailable"),
        ) as delete:
            second = client.get(first.headers["location"], follow_redirects=False)

        assert second.status_code == 303
        assert second.headers["location"] == "/login?notice=totp_setup_completed"
        delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)

        for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
            assert len(_deleted_cookie_headers(second, cookie_name)) == 1

        # The harness seeds a hostless cookie, whereas the response deletion is
        # scoped to localhost. Apply the browser-side deletion explicitly before
        # following the public destination.
        client.cookies.delete(settings.session_cookie_name)
        final = client.get(second.headers["location"], follow_redirects=False)

        assert final.status_code == 200
        assert (
            "Authenticator setup is complete. Wait for a fresh code, then sign in again."
            in final.text
        )


class TestSetupTotpSubmit:
    """POST /setup-totp verifies the code and a displayed recovery code in one
    atomic call; a fully verified pair requires a fresh login."""

    def test_setup_totp_success_clears_the_old_cookie_and_requires_fresh_login(
        self, totp_setup_client
    ):
        """Successful atomic enrollment signs out the setup session."""
        with _patch(
            "verify_and_enroll_totp",
            return_value=TotpEnrollmentOutcome.ENROLLED,
        ) as enroll:
            resp = _post_setup(totp_setup_client, secret="EVILATTACKERSECRET")

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?notice=totp_setup_completed"
        assert any("Max-Age=0" in value for value in resp.headers.get_list("set-cookie"))

        enroll.assert_awaited_once_with(
            totp_setup_client.mock_pool,
            1,
            "123456",
            RECOVERY_CODE,
            session_id=RAW_SESSION_ID,
        )
        assert "EVILATTACKERSECRET" not in str(enroll.await_args)

    @pytest.mark.parametrize(
        "totp_code, recovery_code_confirmation, outcome, expected_message, absent_message",
        [
            (
                "000000",
                RECOVERY_CODE,
                TotpEnrollmentOutcome.INVALID_CODE,
                "Invalid authenticator code. Scan the current QR code and try again.",
                None,
            ),
            (
                "123456",
                "stale-code",
                TotpEnrollmentOutcome.INVALID_RECOVERY_CODE,
                "That recovery code is not in the current displayed set. Try again.",
                "Invalid authenticator code",
            ),
        ],
        ids=["wrong_totp_code", "wrong_recovery_code"],
    )
    def test_setup_totp_rejected_code_never_persists_or_upgrades(
        self,
        totp_setup_client,
        totp_code,
        recovery_code_confirmation,
        outcome,
        expected_message,
        absent_message,
    ):
        """An invalid code, or a recovery code outside the currently displayed
        set, re-renders enrollment with its own error and never upgrades the
        session."""
        with (
            _patch("verify_and_enroll_totp", return_value=outcome) as enroll,
            _patch(
                "get_or_create_pending_totp_secret",
                return_value=_pending_ready(),
            ) as pending,
        ):
            resp = _post_setup(
                totp_setup_client,
                totp_code=totp_code,
                recovery_code_confirmation=recovery_code_confirmation,
            )

        assert resp.status_code == 422
        assert expected_message in resp.text
        if absent_message is not None:
            assert absent_message not in resp.text

        enroll.assert_awaited_once_with(
            totp_setup_client.mock_pool,
            1,
            totp_code,
            recovery_code_confirmation,
            session_id=RAW_SESSION_ID,
        )
        pending.assert_awaited_once_with(
            totp_setup_client.mock_pool,
            1,
            purpose=PendingTotpPurpose.ENROLLMENT,
            session_id=RAW_SESSION_ID,
        )

    def test_setup_totp_missing_pending_secret_restarts_enrollment(self, totp_setup_client):
        """A missing or expired pending secret restarts enrollment."""
        with _patch(
            "verify_and_enroll_totp",
            return_value=TotpEnrollmentOutcome.PENDING_SECRET_MISSING,
        ) as enroll:
            resp = _post_setup(totp_setup_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup-totp"

        enroll.assert_awaited_once_with(
            totp_setup_client.mock_pool,
            1,
            "123456",
            RECOVERY_CODE,
            session_id=RAW_SESSION_ID,
        )

    @pytest.mark.parametrize(
        "outcome",
        [TotpEnrollmentOutcome.SESSION_EXPIRED, TotpEnrollmentOutcome.ALREADY_CONFIGURED],
        ids=["session_expired_after_commit", "already_configured_after_commit"],
    )
    def test_setup_totp_post_commit_race_invalidates_restricted_session(
        self, totp_setup_client, outcome
    ):
        """A committed enrollment discovered to be expired or already
        configured cannot leave a password-only session trapped in the
        completed setup flow."""
        with (
            _patch("verify_and_enroll_totp", return_value=outcome) as enroll,
            _patch("delete_session") as delete,
        ):
            resp = _post_setup(totp_setup_client)

        assert resp.status_code == 303
        expected_location = (
            "/login?error=session_expired"
            if outcome is TotpEnrollmentOutcome.SESSION_EXPIRED
            else "/login?notice=totp_setup_completed"
        )
        assert resp.headers["location"] == expected_location

        enroll.assert_awaited_once_with(
            totp_setup_client.mock_pool,
            1,
            "123456",
            RECOVERY_CODE,
            session_id=RAW_SESSION_ID,
        )
        delete.assert_awaited_once_with(totp_setup_client.mock_pool, RAW_SESSION_ID)
        _assert_auth_cookies_cleared(resp)


class TestTotpSetupSessionFullSessionGuard:
    """A ``totp_setup`` session (minted from password alone) must not be able to reach any full-session
    route, GET or POST.
    """

    def test_totp_setup_session_cannot_execute_state_changing_post(self, totp_setup_client):
        """A totp_setup session that POSTs a full-session mutation is 303'd to
        /setup-totp and the handler never runs."""
        with patch("app.routes.auth.account.update_display_name", autospec=True) as update:
            resp = totp_setup_client.post(
                "/account/change-name",
                data={
                    "display_name": "Mallory",
                    "csrf_token": totp_setup_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup-totp"
        update.assert_not_awaited()

    def test_totp_setup_session_cannot_reach_account_page(self, totp_setup_client):
        """Check TOTP setup session cannot reach account page (HTTP 303)."""
        resp = totp_setup_client.get("/account", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup-totp"


def _recovery_client(client_builder, **user_overrides):
    """A `totp_recovery`-purpose session: the only shape that satisfies
    require_totp_enrollment_session's recovery branch (recovery required,
    not yet configured)."""
    user = make_sample_user(totp_configured=False, totp_recovery_required=True, **user_overrides)
    return client_builder(session_user=user, session_purpose="totp_recovery")


class TestSetupTotpRecoveryPurposeGet:
    """Cover setup TOTP recovery purpose GET."""

    def test_recovery_purpose_session_renders_the_same_enrollment_page(self, client_builder):
        """Check recovery purpose session renders the same enrollment page (HTTP 200)."""
        client = _recovery_client(client_builder)
        with _patch("get_or_create_pending_totp_secret", return_value=_pending_ready()) as pending:
            resp = client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 200
        assert _extract_new_secret(resp.text) == SECRET
        pending.assert_awaited_once_with(
            client.mock_pool,
            1,
            purpose=PendingTotpPurpose.RECOVERY,
            session_id=RAW_SESSION_ID,
        )

    def test_expired_recovery_session_is_sent_back_to_the_recovery_entry_point(
        self, client_builder
    ):
        """Check expired recovery session is sent back to the recovery entry point (HTTP 303)."""
        client = _recovery_client(client_builder)
        with (
            _patch(
                "get_or_create_pending_totp_secret",
                return_value=PendingTotpResult(PendingTotpOutcome.SESSION_EXPIRED),
            ) as pending,
            _patch("delete_session") as delete,
        ):
            resp = client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/recover-totp?error=session_expired"
        pending.assert_awaited_once_with(
            client.mock_pool,
            1,
            purpose=PendingTotpPurpose.RECOVERY,
            session_id=RAW_SESSION_ID,
        )
        delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)
        _assert_auth_cookies_cleared(resp)


class TestSetupTotpPendingOutcomeVariants:
    """Two typed pending-secret outcomes besides SESSION_EXPIRED and READY,
    each with its own destination."""

    def test_already_configured_outside_a_totp_setup_session_returns_to_account(
        self, client_builder
    ):
        """Check already configured outside a TOTP setup session returns to account (HTTP 303)."""
        user = make_sample_user(totp_configured=False)
        client = client_builder(session_user=user, session_purpose="full")
        with _patch(
            "get_or_create_pending_totp_secret",
            return_value=PendingTotpResult(PendingTotpOutcome.ALREADY_CONFIGURED),
        ) as pending:
            resp = client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/account"
        pending.assert_awaited_once()

    def test_ineligible_pending_outcome_renders_branded_403(self, client_builder):
        """Check ineligible pending outcome renders branded 403."""
        user = make_sample_user(totp_configured=False)
        client = client_builder(session_user=user, session_purpose="full")
        with _patch(
            "get_or_create_pending_totp_secret",
            return_value=PendingTotpResult(PendingTotpOutcome.INELIGIBLE),
        ) as pending:
            resp = client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 403
        assert "Authenticator setup unavailable" in resp.text
        pending.assert_awaited_once()


class TestSetupTotpPendingContractViolation:
    """get_or_create_pending_totp_secret's own contract requires a secret
    whenever it reports READY; a violation fails loudly instead of rendering
    a QR code for `None`."""

    def test_ready_outcome_without_a_secret_fails_closed(self, client_builder):
        """Check ready outcome without a secret fails closed (HTTP 500)."""
        user = make_sample_user(totp_configured=False)
        client = client_builder(session_user=user, session_purpose="full")
        with _patch(
            "get_or_create_pending_totp_secret",
            return_value=PendingTotpResult(PendingTotpOutcome.READY, None),
        ):
            resp = client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 500


class TestSetupTotpBestEffortRevocation:
    """Cover setup TOTP best effort revocation."""

    def test_skips_revocation_when_no_session_id_was_resolved(self, totp_setup_client):
        """Check skips revocation when no session ID was resolved (HTTP 303)."""
        with (
            _patch(
                "get_or_create_pending_totp_secret",
                return_value=PendingTotpResult(PendingTotpOutcome.ALREADY_CONFIGURED),
            ),
            _patch("delete_session") as delete,
            patch(
                "app.routes.auth.totp.get_resolved_session_id",
                autospec=True,
                return_value=None,
            ),
        ):
            resp = totp_setup_client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?notice=totp_setup_completed"
        delete.assert_not_awaited()
        _assert_auth_cookies_cleared(resp)

    def test_positive_control_revokes_the_session_when_the_cookie_is_present(
        self, totp_setup_client
    ):
        """Check positive control revokes the session when the cookie is present (HTTP 303)."""
        with (
            _patch(
                "get_or_create_pending_totp_secret",
                return_value=PendingTotpResult(PendingTotpOutcome.ALREADY_CONFIGURED),
            ),
            _patch("delete_session") as delete,
        ):
            resp = totp_setup_client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 303
        delete.assert_awaited_once_with(totp_setup_client.mock_pool, RAW_SESSION_ID)


class TestSetupTotpSubmitRecoveryPurpose:
    """Cover setup TOTP submit recovery purpose."""

    def test_recovered_outcome_redirects_to_login_and_clears_cookies(self, client_builder):
        """Check recovered outcome redirects to login and clears cookies (HTTP 303)."""
        client = _recovery_client(client_builder)
        with _patch(
            "verify_and_enroll_totp", return_value=TotpEnrollmentOutcome.RECOVERED
        ) as enroll:
            resp = _post_setup(client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?notice=totp_recovery_completed"
        _assert_auth_cookies_cleared(resp)
        enroll.assert_awaited_once_with(
            client.mock_pool, 1, "123456", RECOVERY_CODE, session_id=RAW_SESSION_ID
        )

    def test_session_expired_returns_to_the_recovery_entry_point(self, client_builder):
        """Check session expired returns to the recovery entry point (HTTP 303)."""
        client = _recovery_client(client_builder)
        with (
            _patch(
                "verify_and_enroll_totp",
                return_value=TotpEnrollmentOutcome.SESSION_EXPIRED,
            ),
            _patch("delete_session") as delete,
        ):
            resp = _post_setup(client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/recover-totp?error=session_expired"
        delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)

    def test_already_configured_race_redirects_to_a_fresh_login(self, client_builder):
        """Check already configured race redirects to a fresh login (HTTP 303)."""
        client = _recovery_client(client_builder)
        with (
            _patch(
                "verify_and_enroll_totp",
                return_value=TotpEnrollmentOutcome.ALREADY_CONFIGURED,
            ),
            _patch("delete_session") as delete,
        ):
            resp = _post_setup(client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?notice=totp_recovery_completed"
        delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)

    def test_ineligible_account_returns_to_the_recovery_entry_point(self, client_builder):
        """Check ineligible account returns to the recovery entry point (HTTP 303)."""
        client = _recovery_client(client_builder)
        with (
            _patch(
                "verify_and_enroll_totp",
                return_value=TotpEnrollmentOutcome.INELIGIBLE,
            ),
            _patch("delete_session") as delete,
        ):
            resp = _post_setup(client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/recover-totp?error=session_expired"
        delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)


class TestSetupTotpSubmitAlreadyConfiguredFullSession:
    """Cover setup TOTP submit already configured full session."""

    def test_full_session_already_configured_renders_a_conflict_page(self, authenticated_client):
        """authenticated_client's default user already has TOTP configured
        and holds a `full` session, matching the real shape that could
        resubmit here."""
        with _patch(
            "verify_and_enroll_totp",
            return_value=TotpEnrollmentOutcome.ALREADY_CONFIGURED,
        ) as enroll:
            resp = _post_setup(authenticated_client)

        assert resp.status_code == 409
        assert "Authenticator already configured" in resp.text
        enroll.assert_awaited_once()


class TestSetupTotpSubmitInvalidCodeStaleSecondPending:
    """Cover setup TOTP submit invalid code stale second pending."""

    def test_invalid_code_with_a_since_expired_pending_secret_restarts_enrollment(
        self, totp_setup_client
    ):
        """Check invalid code with a since expired pending secret restarts enrollment (HTTP 303)."""
        with (
            _patch(
                "verify_and_enroll_totp",
                return_value=TotpEnrollmentOutcome.INVALID_CODE,
            ),
            _patch(
                "get_or_create_pending_totp_secret",
                return_value=PendingTotpResult(PendingTotpOutcome.SESSION_EXPIRED),
            ) as pending,
        ):
            resp = _post_setup(totp_setup_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup-totp"
        pending.assert_awaited_once()


class TestSetupTotpSubmitContractViolation:
    """Cover setup TOTP submit contract violation."""

    def test_unrecognised_outcome_fails_closed(self, totp_setup_client):
        """Check unrecognised outcome fails closed (HTTP 500)."""
        with _patch(
            "verify_and_enroll_totp",
            return_value=object(),
        ):
            resp = _post_setup(totp_setup_client)

        assert resp.status_code == 500

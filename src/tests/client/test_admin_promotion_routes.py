"""Target-side administrator invitation routes (`app.routes.auth.admin_promotion`)."""

from datetime import UTC, datetime
from unittest.mock import patch

from app.services.admin_promotion import (
    AcceptedAdminPromotion,
    AdminPromotion,
    AdminPromotionRejected,
    PreparedAdminPromotion,
)
from app.services.totp import TotpDecryptionError
from tests.fixtures import RAW_SESSION_ID, make_sample_user

PROMOTION = AdminPromotion(
    user_id=1,
    requested_by=99,
    requested_at=datetime(2026, 1, 1, tzinfo=UTC),
    expires_at=datetime(2026, 1, 2, tzinfo=UTC),
    expired=False,
    prepared_for_current_session=False,
)


def _patch(name, **kw):
    """Patch the route collaborator with its real signature."""
    return patch(f"app.routes.auth.admin_promotion.{name}", autospec=True, **kw)


class TestAdminPromotionPageAccess:
    """Cover admin promotion page access."""

    def test_guest_is_redirected_to_login(self, guest_client):
        """Check guest is redirected to login (HTTP 303)."""
        response = guest_client.get("/account/admin-promotion", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")

    def test_federated_full_session_is_refused(self, client_builder):
        """Check federated full session is refused (HTTP 403)."""
        federated = make_sample_user(auth_method="shibboleth", federated_status="approved")
        client = client_builder(session_user=federated)
        response = client.get("/account/admin-promotion", follow_redirects=False)
        assert response.status_code == 403

    def test_local_full_session_with_a_pending_invitation_sees_it(self, authenticated_client):
        """Check local full session with a pending invitation sees it (HTTP 200)."""
        with _patch("get_admin_promotion", return_value=PROMOTION) as lookup:
            response = authenticated_client.get("/account/admin-promotion")

        assert response.status_code == 200
        assert "administrator" in response.text.lower()
        lookup.assert_awaited_once()

    def test_local_full_session_without_a_pending_invitation_is_sent_to_account(
        self, authenticated_client
    ):
        """Check local full session without a pending invitation is sent to account (HTTP 303)."""
        with (
            _patch("get_admin_promotion", return_value=None),
            _patch("set_flash_if_exists") as flash,
        ):
            response = authenticated_client.get("/account/admin-promotion", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        flash.assert_awaited_once()
        assert flash.await_args.args[3] == "info"


class TestAdminPromotionPrepare:
    """Cover admin promotion prepare."""

    def _post(self, client, **extra):
        """Submit the valid CSRF-protected form without following redirects."""
        data = {
            "current_password": "correct horse",
            "totp_code": "111111",
            "csrf_token": client.csrf_token,
            **extra,
        }
        return client.post("/account/admin-promotion/prepare", data=data, follow_redirects=False)

    def test_missing_csrf_pair_is_refused_before_any_service_call(self, authenticated_client):
        """Check missing CSRF pair is refused before any service call (HTTP 403)."""
        with _patch("prepare_admin_promotion") as prepare:
            response = authenticated_client.post(
                "/account/admin-promotion/prepare",
                data={"current_password": "correct horse", "totp_code": "111111"},
                follow_redirects=False,
            )
        assert response.status_code == 403
        prepare.assert_not_awaited()

    def test_json_body_is_415_before_any_service_call(self, authenticated_client):
        """Check JSON body is 415 before any service call."""
        with _patch("prepare_admin_promotion") as prepare:
            response = authenticated_client.post(
                "/account/admin-promotion/prepare",
                content='{"current_password": "x", "totp_code": "111111"}',
                headers={"Content-Type": "application/json"},
                follow_redirects=False,
            )
        assert response.status_code == 415
        prepare.assert_not_awaited()

    def test_valid_pair_calls_the_service_exactly_once_and_shows_the_codes(
        self, authenticated_client
    ):
        """Check valid pair calls the service exactly once and shows the codes (HTTP 200)."""
        prepared = PreparedAdminPromotion(
            user_id=1,
            invitation_expires_at=datetime(2026, 1, 2, tzinfo=UTC),
            preparation_expires_at=datetime(2026, 1, 1, 0, 10, tzinfo=UTC),
            recovery_codes=("AAAAA-BBBBB-CCCCC-DDDDD",),
        )
        with _patch("prepare_admin_promotion", return_value=prepared) as prepare:
            response = self._post(authenticated_client)

        assert response.status_code == 200
        assert "AAAAA-BBBBB-CCCCC-DDDDD" in response.text
        prepare.assert_awaited_once()

    def test_unreadable_authenticator_returns_actionable_uncached_503(
        self, authenticated_client, caplog
    ):
        """Check unreadable authenticator returns actionable uncached 503."""
        with (
            _patch("prepare_admin_promotion", side_effect=TotpDecryptionError(1)) as prepare,
            _patch("get_admin_promotion") as reload,
        ):
            response = self._post(authenticated_client)
        assert response.status_code == 503
        assert "Please contact support." in response.text
        assert "Try again" not in response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        assert response.headers["referrer-policy"] == "strict-origin"
        prepare.assert_awaited_once_with(
            authenticated_client.mock_pool,
            user_id=1,
            session_id=RAW_SESSION_ID,
            password="correct horse",
            totp_code="111111",
        )
        reload.assert_not_awaited()
        events = [record for record in caplog.records if record.name == "audit"]
        assert any(
            getattr(record, "event_type", None) == "totp_secret_undecryptable"
            and record.user_id == 1
            and record.operation == "admin_promotion_prepare"
            for record in events
        )
        assert not any(
            getattr(record, "event_type", None) == "admin_promotion_codes_prepared"
            for record in events
        )

    def test_rejected_preparation_renders_the_invitation_with_its_error(self, authenticated_client):
        """Check rejected preparation renders the invitation with its error (HTTP 422)."""
        with (
            _patch(
                "prepare_admin_promotion", side_effect=AdminPromotionRejected("invalid_credentials")
            ),
            _patch("get_admin_promotion", return_value=PROMOTION),
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 422
        assert "incorrect" in response.text.lower()


class TestAdminPromotionAccept:
    """Cover admin promotion accept."""

    def _post(self, client, **extra):
        """Submit the valid CSRF-protected form without following redirects."""
        data = {
            "recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD",
            "csrf_token": client.csrf_token,
            **extra,
        }
        return client.post("/account/admin-promotion/accept", data=data, follow_redirects=False)

    def test_missing_csrf_pair_is_refused_before_any_service_call(self, authenticated_client):
        """Check missing CSRF pair is refused before any service call (HTTP 403)."""
        with _patch("accept_admin_promotion") as accept:
            response = authenticated_client.post(
                "/account/admin-promotion/accept",
                data={"recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD"},
                follow_redirects=False,
            )
        assert response.status_code == 403
        accept.assert_not_awaited()

    def test_json_body_is_415_before_any_service_call(self, authenticated_client):
        """Check JSON body is 415 before any service call."""
        with _patch("accept_admin_promotion") as accept:
            response = authenticated_client.post(
                "/account/admin-promotion/accept",
                content='{"recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD"}',
                headers={"Content-Type": "application/json"},
                follow_redirects=False,
            )
        assert response.status_code == 415
        accept.assert_not_awaited()

    def test_valid_pair_calls_the_service_exactly_once_and_redirects_to_login(
        self, authenticated_client
    ):
        """Check valid pair calls the service exactly once and redirects to login (HTTP 303)."""
        accepted = AcceptedAdminPromotion(user_id=1, requested_by=99)
        with _patch("accept_admin_promotion", return_value=accepted) as accept:
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/login?notice=admin_promotion_completed"
        accept.assert_awaited_once()

    def test_rejected_acceptance_renders_the_invitation_with_its_error(self, authenticated_client):
        """Check rejected acceptance renders the invitation with its error (HTTP 422)."""
        with (
            _patch(
                "accept_admin_promotion",
                side_effect=AdminPromotionRejected("invalid_recovery_code"),
            ),
            _patch("get_admin_promotion", return_value=PROMOTION),
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 422
        assert "not in the current displayed" in response.text


class TestAdminPromotionDecline:
    """Cover admin promotion decline."""

    def test_missing_csrf_pair_is_refused_before_any_service_call(self, authenticated_client):
        """Check missing CSRF pair is refused before any service call (HTTP 403)."""
        with _patch("decline_admin_promotion") as decline:
            response = authenticated_client.post(
                "/account/admin-promotion/decline",
                data={"unused": "1"},  # form-encoded body, deliberately no csrf_token
                follow_redirects=False,
            )
        assert response.status_code == 403
        decline.assert_not_awaited()

    def test_json_body_is_415_before_any_service_call(self, authenticated_client):
        """Check JSON body is 415 before any service call."""
        with _patch("decline_admin_promotion") as decline:
            response = authenticated_client.post(
                "/account/admin-promotion/decline",
                content="{}",
                headers={"Content-Type": "application/json"},
                follow_redirects=False,
            )
        assert response.status_code == 415
        decline.assert_not_awaited()

    def test_valid_pair_calls_the_service_exactly_once_and_redirects_to_account(
        self, authenticated_client
    ):
        """Check valid pair calls the service exactly once and redirects to account (HTTP 303)."""
        with (
            _patch("decline_admin_promotion", return_value=99) as decline,
            _patch("set_flash_if_exists") as flash,
        ):
            response = authenticated_client.post(
                "/account/admin-promotion/decline",
                data={"csrf_token": authenticated_client.csrf_token},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        decline.assert_awaited_once()
        flash.assert_awaited_once()
        assert flash.await_args.args[3] == "success"

"""Target-side administrator invitation routes (`app.routes.auth.admin_promotion`).

`GET /account/admin-promotion` shows a pending invitation without mutating
it; `POST .../prepare` reauthenticates and stages a one-time code set;
`POST .../accept` confirms a staged code and activates administrator
authority; `POST .../decline` withdraws the invitation without changing the
target's authority. All four routes require a LOCAL full session (federated
accounts have no invitation flow — their attributes come from the IdP and
carry no local password/authenticator to re-prove), and every mutating POST
carries the ordinary content-type + CSRF guards of a `local_full_session`
mutation route.
"""

from datetime import UTC, datetime
from unittest.mock import patch

from app.services.admin_promotion import (
    AcceptedAdminPromotion,
    AdminPromotion,
    AdminPromotionRejected,
    PreparedAdminPromotion,
)
from tests.fixtures import make_sample_user

PROMOTION = AdminPromotion(
    user_id=1,
    requested_by=99,
    requested_at=datetime(2026, 1, 1, tzinfo=UTC),
    expires_at=datetime(2026, 1, 2, tzinfo=UTC),
    expired=False,
    prepared_for_current_session=False,
)


def _patch(name, **kw):
    return patch(f"app.routes.auth.admin_promotion.{name}", autospec=True, **kw)


# ---------------------------------------------------------------------------
# GET /account/admin-promotion
# ---------------------------------------------------------------------------


class TestAdminPromotionPageAccess:
    def test_guest_is_redirected_to_login(self, guest_client):
        response = guest_client.get("/account/admin-promotion", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")

    def test_federated_full_session_is_refused(self, client_builder):
        federated = make_sample_user(auth_method="shibboleth", federated_status="approved")
        client = client_builder(session_user=federated)
        response = client.get("/account/admin-promotion", follow_redirects=False)
        assert response.status_code == 403

    def test_local_full_session_with_a_pending_invitation_sees_it(self, authenticated_client):
        with _patch("get_admin_promotion", return_value=PROMOTION) as lookup:
            response = authenticated_client.get("/account/admin-promotion")

        assert response.status_code == 200
        assert "administrator" in response.text.lower()
        lookup.assert_awaited_once()

    def test_local_full_session_without_a_pending_invitation_is_sent_to_account(
        self, authenticated_client
    ):
        with (
            _patch("get_admin_promotion", return_value=None),
            _patch("set_flash_if_exists") as flash,
        ):
            response = authenticated_client.get("/account/admin-promotion", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        flash.assert_awaited_once()
        assert flash.await_args.args[3] == "info"


# ---------------------------------------------------------------------------
# POST /account/admin-promotion/prepare
# ---------------------------------------------------------------------------


class TestAdminPromotionPrepare:
    def _post(self, client, **extra):
        data = {
            "current_password": "correct horse",
            "totp_code": "111111",
            "csrf_token": client.csrf_token,
            **extra,
        }
        return client.post("/account/admin-promotion/prepare", data=data, follow_redirects=False)

    def test_missing_csrf_pair_is_refused_before_any_service_call(self, authenticated_client):
        with _patch("prepare_admin_promotion") as prepare:
            response = authenticated_client.post(
                "/account/admin-promotion/prepare",
                data={"current_password": "correct horse", "totp_code": "111111"},
                follow_redirects=False,
            )
        assert response.status_code == 403
        prepare.assert_not_awaited()

    def test_json_body_is_415_before_any_service_call(self, authenticated_client):
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

    def test_rejected_preparation_renders_the_invitation_with_its_error(self, authenticated_client):
        with (
            _patch(
                "prepare_admin_promotion", side_effect=AdminPromotionRejected("invalid_credentials")
            ),
            _patch("get_admin_promotion", return_value=PROMOTION),
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 422
        assert "incorrect" in response.text.lower()


# ---------------------------------------------------------------------------
# POST /account/admin-promotion/accept
# ---------------------------------------------------------------------------


class TestAdminPromotionAccept:
    def _post(self, client, **extra):
        data = {
            "recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD",
            "csrf_token": client.csrf_token,
            **extra,
        }
        return client.post("/account/admin-promotion/accept", data=data, follow_redirects=False)

    def test_missing_csrf_pair_is_refused_before_any_service_call(self, authenticated_client):
        with _patch("accept_admin_promotion") as accept:
            response = authenticated_client.post(
                "/account/admin-promotion/accept",
                data={"recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD"},
                follow_redirects=False,
            )
        assert response.status_code == 403
        accept.assert_not_awaited()

    def test_json_body_is_415_before_any_service_call(self, authenticated_client):
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
        accepted = AcceptedAdminPromotion(user_id=1, requested_by=99)
        with _patch("accept_admin_promotion", return_value=accepted) as accept:
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/login?error=admin_promotion_completed"
        accept.assert_awaited_once()

    def test_rejected_acceptance_renders_the_invitation_with_its_error(self, authenticated_client):
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


# ---------------------------------------------------------------------------
# POST /account/admin-promotion/decline
# ---------------------------------------------------------------------------


class TestAdminPromotionDecline:
    def test_missing_csrf_pair_is_refused_before_any_service_call(self, authenticated_client):
        with _patch("decline_admin_promotion") as decline:
            response = authenticated_client.post(
                "/account/admin-promotion/decline",
                data={"unused": "1"},  # form-encoded body, deliberately no csrf_token
                follow_redirects=False,
            )
        assert response.status_code == 403
        decline.assert_not_awaited()

    def test_json_body_is_415_before_any_service_call(self, authenticated_client):
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

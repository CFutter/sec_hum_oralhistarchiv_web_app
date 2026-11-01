"""Administrator-invitation rejection redirects, stale-state handling, and cookie cleanup."""

from datetime import UTC, datetime
from unittest.mock import patch

from app.services.admin_promotion import AdminPromotion, AdminPromotionRejected
from config import settings

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


def _assert_session_cookie_cleared(response) -> None:
    """Require deletion headers for the authentication cookies."""
    set_cookie_headers = response.headers.get_list("set-cookie")
    assert any(
        header.startswith(f"{settings.session_cookie_name}=") and "Max-Age=0" in header
        for header in set_cookie_headers
    )


class TestAdminPromotionPrepareAccountLockedRedirectsAwayFromTheForm:
    """An account-locked rejection hides the (now unusable) invitation form behind a redirect; every other rejection still shows it."""

    def _post(self, client):
        """Submit the valid CSRF-protected form without following redirects."""
        return client.post(
            "/account/admin-promotion/prepare",
            data={
                "current_password": "correct horse",
                "totp_code": "111111",
                "csrf_token": client.csrf_token,
            },
            follow_redirects=False,
        )

    def test_locked_account_redirects_to_account_instead_of_rendering_the_form(
        self, authenticated_client
    ):
        """Check locked account redirects to account instead of rendering the form (HTTP 303)."""
        with (
            _patch(
                "prepare_admin_promotion", side_effect=AdminPromotionRejected("account_locked")
            ) as prepare,
            _patch("set_flash_if_exists") as flash,
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        prepare.assert_awaited_once()
        flash.assert_awaited_once()
        assert (
            flash.await_args.args[2] == "This account is temporarily unavailable. Try again later."
        )

    def test_non_locked_rejection_still_renders_the_form(self, authenticated_client):
        """Check non locked rejection still renders the form (HTTP 422)."""
        with (
            _patch("prepare_admin_promotion", side_effect=AdminPromotionRejected("invalid_totp")),
            _patch("get_admin_promotion", return_value=PROMOTION),
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 422
        assert "authenticator code" in response.text.lower()


class TestAdminPromotionPrepareReloadsOrRedirectsWhenTheInvitationIsGone:
    """When the invitation has disappeared by the time of the reload, prepare redirects instead of rendering a form for nothing."""

    def _post(self, client):
        """Submit the valid CSRF-protected form without following redirects."""
        return client.post(
            "/account/admin-promotion/prepare",
            data={
                "current_password": "correct horse",
                "totp_code": "111111",
                "csrf_token": client.csrf_token,
            },
            follow_redirects=False,
        )

    def test_invitation_gone_by_reload_redirects_to_account(self, authenticated_client):
        """Check invitation gone by reload redirects to account (HTTP 303)."""
        with (
            _patch(
                "prepare_admin_promotion", side_effect=AdminPromotionRejected("codes_not_prepared")
            ),
            _patch("get_admin_promotion", return_value=None),
            _patch("set_flash_if_exists") as flash,
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        assert (
            flash.await_args.args[2]
            == "Generate a fresh recovery-code set before accepting the invitation."
        )

    def test_invitation_still_present_renders_the_form_with_its_error(self, authenticated_client):
        """Check invitation still present renders the form with its error (HTTP 422)."""
        with (
            _patch(
                "prepare_admin_promotion", side_effect=AdminPromotionRejected("codes_not_prepared")
            ),
            _patch("get_admin_promotion", return_value=PROMOTION),
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 422
        assert "fresh recovery-code set" in response.text


class TestAdminPromotionAcceptAccountLockedRedirectsAwayFromTheForm:
    """An account-locked rejection hides the (now unusable) invitation form behind a redirect; every other rejection still shows it."""

    def _post(self, client):
        """Submit the valid CSRF-protected form without following redirects."""
        return client.post(
            "/account/admin-promotion/accept",
            data={"recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD", "csrf_token": client.csrf_token},
            follow_redirects=False,
        )

    def test_locked_account_redirects_to_account_instead_of_rendering_the_form(
        self, authenticated_client
    ):
        """Check locked account redirects to account instead of rendering the form (HTTP 303)."""
        with (
            _patch(
                "accept_admin_promotion", side_effect=AdminPromotionRejected("account_locked")
            ) as accept,
            _patch("set_flash_if_exists") as flash,
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        accept.assert_awaited_once()
        assert (
            flash.await_args.args[2] == "This account is temporarily unavailable. Try again later."
        )

    def test_non_locked_rejection_still_renders_the_form(self, authenticated_client):
        """Check non locked rejection still renders the form (HTTP 422)."""
        with (
            _patch(
                "accept_admin_promotion",
                side_effect=AdminPromotionRejected("invalid_recovery_code"),
            ),
            _patch("get_admin_promotion", return_value=PROMOTION),
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 422


class TestAdminPromotionAcceptReloadsOrRedirectsWhenTheInvitationIsGone:
    """When the invitation has disappeared by the time of the reload, accept redirects instead of rendering a form for nothing."""

    def _post(self, client):
        """Submit the valid CSRF-protected form without following redirects."""
        return client.post(
            "/account/admin-promotion/accept",
            data={"recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD", "csrf_token": client.csrf_token},
            follow_redirects=False,
        )

    def test_invitation_gone_by_reload_redirects_to_account(self, authenticated_client):
        """Check invitation gone by reload redirects to account (HTTP 303)."""
        with (
            _patch(
                "accept_admin_promotion",
                side_effect=AdminPromotionRejected("invalid_recovery_code"),
            ),
            _patch("get_admin_promotion", return_value=None),
            _patch("set_flash_if_exists") as flash,
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        assert (
            flash.await_args.args[2]
            == "That code is not in the current displayed recovery-code set."
        )

    def test_invitation_still_present_renders_the_form_with_its_error(self, authenticated_client):
        """Check invitation still present renders the form with its error (HTTP 422)."""
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


class TestAdminPromotionDeclineRejectionOutcomes:
    """Require decline rejections to clear expired sessions or show mapped account-page feedback."""

    def _post(self, client):
        """Submit the valid CSRF-protected form without following redirects."""
        return client.post(
            "/account/admin-promotion/decline",
            data={"csrf_token": client.csrf_token},
            follow_redirects=False,
        )

    def test_expired_session_redirects_to_login_and_clears_the_session_cookie(
        self, authenticated_client
    ):
        """Check expired session redirects to login and clears the session cookie (HTTP 303)."""
        with _patch(
            "decline_admin_promotion", side_effect=AdminPromotionRejected("invalid_session")
        ) as decline:
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/login?error=session_expired"
        decline.assert_awaited_once()
        _assert_session_cookie_cleared(response)

    def test_ineligible_target_redirects_to_account_with_its_mapped_error(
        self, authenticated_client
    ):
        """Check ineligible target redirects to account with its mapped error (HTTP 303)."""
        with (
            _patch(
                "decline_admin_promotion", side_effect=AdminPromotionRejected("ineligible_account")
            ) as decline,
            _patch("set_flash_if_exists") as flash,
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        decline.assert_awaited_once()
        assert flash.await_args.args[2] == "This account is not eligible to accept the invitation."

    def test_eligible_target_with_a_live_invitation_still_declines_normally(
        self, authenticated_client
    ):
        """Check eligible target with a live invitation still declines normally (HTTP 303)."""
        with (
            _patch("decline_admin_promotion", return_value=99) as decline,
            _patch("set_flash_if_exists") as flash,
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        decline.assert_awaited_once()
        assert flash.await_args.args[2] == "Administrator invitation declined."

"""Rejection-branch outcomes of app.routes.auth.admin_promotion not already
proven by test_admin_promotion_routes.py.

That module proves the ordinary success and re-render paths. This module
proves the remaining triage a rejected `prepare`/`accept`/`decline` performs:
an account-locked rejection always redirects to `/account` instead of
re-rendering the (now unusable) form; a rejection whose invitation has since
disappeared redirects instead of rendering a form for state that no longer
exists; and `decline`'s own exception handling — untested elsewhere — clears
the session on an expired-session rejection and otherwise redirects to
`/account` with the mapped error.
"""

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
    return patch(f"app.routes.auth.admin_promotion.{name}", autospec=True, **kw)


def _assert_session_cookie_cleared(response) -> None:
    set_cookie_headers = response.headers.get_list("set-cookie")
    assert any(
        header.startswith(f"{settings.session_cookie_name}=") and "Max-Age=0" in header
        for header in set_cookie_headers
    )


# ---------------------------------------------------------------------------
# POST /account/admin-promotion/prepare
# ---------------------------------------------------------------------------


class TestAdminPromotionPrepareAccountLockedRedirectsAwayFromTheForm:
    """An account-locked rejection hides the (now unusable) invitation form behind a redirect; every other rejection still shows it."""

    def _post(self, client):
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
        """Positive control: a rejection other than account_locked still re-renders the invitation form."""
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
        """Positive control: when the invitation still exists, the rejection re-renders the form instead of redirecting away."""
        with (
            _patch(
                "prepare_admin_promotion", side_effect=AdminPromotionRejected("codes_not_prepared")
            ),
            _patch("get_admin_promotion", return_value=PROMOTION),
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 422
        assert "fresh recovery-code set" in response.text


# ---------------------------------------------------------------------------
# POST /account/admin-promotion/accept
# ---------------------------------------------------------------------------


class TestAdminPromotionAcceptAccountLockedRedirectsAwayFromTheForm:
    """An account-locked rejection hides the (now unusable) invitation form behind a redirect; every other rejection still shows it."""

    def _post(self, client):
        return client.post(
            "/account/admin-promotion/accept",
            data={"recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD", "csrf_token": client.csrf_token},
            follow_redirects=False,
        )

    def test_locked_account_redirects_to_account_instead_of_rendering_the_form(
        self, authenticated_client
    ):
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
        """Positive control: a rejection other than account_locked still re-renders the invitation form."""
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
        return client.post(
            "/account/admin-promotion/accept",
            data={"recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD", "csrf_token": client.csrf_token},
            follow_redirects=False,
        )

    def test_invitation_gone_by_reload_redirects_to_account(self, authenticated_client):
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
        """Positive control: when the invitation still exists, the rejection re-renders the form instead of redirecting away."""
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


class TestAdminPromotionDeclineRejectionOutcomes:
    """decline's own exception handling: an expired-session rejection clears the session, every other rejection redirects to /account with the mapped error, and an eligible target still declines normally."""

    def _post(self, client):
        return client.post(
            "/account/admin-promotion/decline",
            data={"csrf_token": client.csrf_token},
            follow_redirects=False,
        )

    def test_expired_session_redirects_to_login_and_clears_the_session_cookie(
        self, authenticated_client
    ):
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
        """Positive control: an eligible target with a live invitation still declines it and redirects to /account."""
        with (
            _patch("decline_admin_promotion", return_value=99) as decline,
            _patch("set_flash_if_exists") as flash,
        ):
            response = self._post(authenticated_client)

        assert response.status_code == 303
        assert response.headers["location"] == "/account"
        decline.assert_awaited_once()
        assert flash.await_args.args[2] == "Administrator invitation declined."

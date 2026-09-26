"""Administrator TOTP-recovery decision outcomes and the demotion fault path.

`_totp_recovery_target_error` (admin.py) is the single eligibility gate shared
by the recovery confirmation page (GET) and its authorization POST: every
reason it can return is pinned here, once, against both call sites, rather
than duplicated per route. `POST /admin/users/{id}/totp-recovery` then maps
every typed outcome of `authorize_totp_recovery` to its response — including
the two invariant guards (`RuntimeError`) that fire only if the target lookup
and its own eligibility helper disagree with each other, which happens only
under an injected contract violation, never in real traffic.

This is the sibling scenario class to test_admin_recovery_routes.py (page
rendering and access-cloak) and test_admin_membership_routes.py (the other
mutation routes' shared not-found/rejection contract); named for the decision
outcomes it proves rather than the route file, since both routes below share
one eligibility helper.
"""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from app.middleware import CSRF_COOKIE_NAME
from app.services.admin_promotion import AdminPromotionRejected
from app.services.totp import TotpDecryptionError
from app.services.totp_recover import (
    TotpRecoveryAuthorization,
    TotpRecoveryRejected,
    TotpRecoveryTarget,
)
from app.services.users import AdminActionRejected
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user

ELIGIBLE_TARGET = TotpRecoveryTarget(
    user_id=7,
    email="target@uzh.ch",
    display_name="Target User",
    auth_method="local",
    is_active=True,
    email_verified=True,
    totp_configured=True,
    recovery_required=False,
    recovery_codes_available=True,
    recovery_authorization_active=False,
    recovery_expires_at=None,
)


def _patch(name, **kw):
    return patch(f"app.routes.auth.admin.{name}", autospec=True, **kw)


def _target(**overrides):
    fields = {
        "user_id": 7,
        "email": "target@uzh.ch",
        "display_name": "Target User",
        "auth_method": "local",
        "is_active": True,
        "email_verified": True,
        "totp_configured": True,
        "recovery_required": False,
        "recovery_codes_available": True,
        "recovery_authorization_active": False,
        "recovery_expires_at": None,
    }
    fields.update(overrides)
    return TotpRecoveryTarget(**fields)


def _post_authorize(client, *, user_id=7, confirm_reset=True, **extra):
    data = {
        "admin_totp_code": "654321",
        "page": "1",
        "page_size": "20",
        "csrf_token": client.csrf_token,
        **extra,
    }
    if confirm_reset:
        data["confirm_reset"] = "true"
    return client.post(
        f"/admin/users/{user_id}/totp-recovery",
        data=data,
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# _totp_recovery_target_error — the eligibility gate shared by GET and POST
# ---------------------------------------------------------------------------


class TestTotpRecoveryTargetEligibility:
    """Every reason the shared eligibility helper can report, proven through
    the GET confirmation page; POST reuses the identical helper (see
    TestAdminAuthorizeTotpRecoveryOutcomes for its own outcome mapping)."""

    def test_missing_target_user_is_reported_as_not_found(self, admin_client):
        with (
            _patch("get_totp_recovery_target", return_value=None) as lookup,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = admin_client.get("/admin/users/999999/totp-recovery", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        lookup.assert_awaited_once_with(admin_client.mock_pool, 999999)
        assert flash.await_args.args[2] == "User not found."

    def test_recovery_target_matching_the_acting_admin_is_refused_as_self_recovery(
        self, admin_client
    ):
        """An administrator cannot authorize recovery for their own account —
        a second administrator is required."""
        with (
            _patch("get_totp_recovery_target", return_value=_target(user_id=99)),
            _patch("set_flash_if_exists") as flash,
        ):
            resp = admin_client.get("/admin/users/99/totp-recovery", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert "different administrator" in flash.await_args.args[2]

    def test_target_with_no_saved_recovery_code_is_refused_regardless_of_other_state(
        self, admin_client
    ):
        with (
            _patch(
                "get_totp_recovery_target",
                return_value=_target(recovery_codes_available=False, totp_configured=False),
            ),
            _patch("set_flash_if_exists") as flash,
        ):
            resp = admin_client.get("/admin/users/7/totp-recovery", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert "no unused saved recovery code" in flash.await_args.args[2]

    def test_active_verified_local_target_with_no_authenticator_yet_is_refused_to_normal_setup(
        self, admin_client
    ):
        """A target that has never enrolled (nothing to recover, and not
        already flagged for recovery) is refused with a distinct message from
        the generic ineligible-account case."""
        with (
            _patch(
                "get_totp_recovery_target",
                return_value=_target(totp_configured=False, recovery_required=False),
            ),
            _patch("set_flash_if_exists") as flash,
        ):
            resp = admin_client.get("/admin/users/7/totp-recovery", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert "no authenticator to recover" in flash.await_args.args[2]

    def test_inactive_target_falls_back_to_the_generic_ineligible_account_reason(
        self, admin_client
    ):
        """A target that is otherwise disqualified (here: deactivated) but
        does not match the no-authenticator-yet shape gets the generic
        ineligible-account message instead."""
        with (
            _patch("get_totp_recovery_target", return_value=_target(is_active=False)),
            _patch("set_flash_if_exists") as flash,
        ):
            resp = admin_client.get("/admin/users/7/totp-recovery", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert "available only for active, verified local accounts" in flash.await_args.args[2]

    def test_eligible_target_renders_the_confirmation_form(self, admin_client):
        """Positive control for every refusal above: an eligible target
        reaches the destructive-confirmation page instead of being bounced."""
        with _patch("get_totp_recovery_target", return_value=ELIGIBLE_TARGET) as lookup:
            resp = admin_client.get("/admin/users/7/totp-recovery", follow_redirects=False)

        assert resp.status_code == 200
        assert ELIGIBLE_TARGET.email in resp.text
        lookup.assert_awaited_once_with(admin_client.mock_pool, 7)


class TestAdminTotpRecoveryActorEligibility:
    """The acting administrator must themselves be a local account with a
    configured authenticator before they can authorize anyone else's
    recovery. (Only the auth-method half of this OR condition is reachable
    through a real request: require_full_session already redirects a local
    admin without TOTP configured to /setup-totp before this handler runs, so
    the totp_configured half of the check is a defensive-only remainder — see
    the coverage report for admin.py:234-235.)"""

    def test_shibboleth_admin_cannot_authorize_recovery(self, client_builder):
        shib_admin = make_sample_user(
            id=99, is_admin=True, auth_method="shibboleth", access_tier="vetted"
        )
        client = client_builder(session_user=shib_admin)
        with (
            _patch("get_totp_recovery_target") as lookup,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = client.get("/admin/users/7/totp-recovery", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        lookup.assert_not_awaited()
        assert "local administrator with an authenticator" in flash.await_args.args[2]

    def test_local_admin_with_totp_configured_can_reach_the_confirmation_page(self, admin_client):
        """Positive control: the default admin_client (local, TOTP configured)
        is exactly the eligible actor shape."""
        with _patch("get_totp_recovery_target", return_value=ELIGIBLE_TARGET) as lookup:
            resp = admin_client.get("/admin/users/7/totp-recovery", follow_redirects=False)

        assert resp.status_code == 200
        lookup.assert_awaited_once()


# ---------------------------------------------------------------------------
# POST /admin/users/{user_id}/totp-recovery — authorization outcomes
# ---------------------------------------------------------------------------


class TestAdminAuthorizeTotpRecoveryOutcomes:
    """Every typed outcome of authorize_totp_recovery, plus the confirmation
    checkbox gate the form enforces before the service is ever awaited."""

    def test_unchecked_confirmation_box_is_refused_before_any_service_call(self, admin_client):
        with (
            _patch("get_totp_recovery_target", return_value=ELIGIBLE_TARGET),
            _patch("authorize_totp_recovery") as authorize,
        ):
            resp = _post_authorize(admin_client, confirm_reset=False)

        assert resp.status_code == 422
        assert "Confirm that you understand" in resp.text
        authorize.assert_not_awaited()

    def test_ineligible_target_is_refused_before_any_service_call(self, admin_client):
        """The POST route rechecks the same eligibility gate as the GET page
        before ever awaiting the authorization service — a stale confirmation
        page submitted after the target became ineligible cannot authorize
        recovery."""
        with (
            _patch("get_totp_recovery_target", return_value=_target(user_id=99)),
            _patch("authorize_totp_recovery") as authorize,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = _post_authorize(admin_client, user_id=99)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert "different administrator" in flash.await_args.args[2]
        authorize.assert_not_awaited()

    def test_confirmed_reset_reaches_the_authorization_service(self, admin_client):
        """Positive control for the checkbox gate above."""
        authorization = TotpRecoveryAuthorization(
            target_user_id=7,
            email="target@uzh.ch",
            display_name="Target User",
            expires_at=datetime(2026, 1, 1, tzinfo=UTC),
            reissued=False,
        )
        with (
            _patch("get_totp_recovery_target", return_value=ELIGIBLE_TARGET),
            _patch("authorize_totp_recovery", return_value=authorization) as authorize,
            _patch("audit_admin_action") as audit,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = _post_authorize(admin_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        authorize.assert_awaited_once_with(
            admin_client.mock_pool,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
            target_user_id=7,
            admin_totp_code="654321",
        )
        assert flash.await_args.args[3] == "success"
        audit.assert_called_once()
        assert audit.call_args.kwargs["reissued"] is False

    def test_authority_changed_mid_request_sends_the_admin_to_a_fresh_login(self, admin_client):
        with (
            _patch("get_totp_recovery_target", return_value=ELIGIBLE_TARGET),
            _patch("authorize_totp_recovery", side_effect=AdminActionRejected("stale authority")),
            _patch("audit_admin_action") as audit,
        ):
            resp = _post_authorize(admin_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?error=session_expired"
        set_cookie_headers = resp.headers.get_list("set-cookie")
        for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
            assert any(
                header.startswith(f"{cookie_name}=") and "Max-Age=0" in header
                for header in set_cookie_headers
            )
        audit.assert_called_once()

    @pytest.mark.parametrize(
        "reason",
        ["actor_session_invalid", "actor_step_up_exhausted"],
        ids=["actor_session_invalid", "actor_step_up_exhausted"],
    )
    def test_actor_step_up_failure_sends_the_admin_to_a_fresh_login(self, admin_client, reason):
        with (
            _patch("get_totp_recovery_target", return_value=ELIGIBLE_TARGET),
            _patch("authorize_totp_recovery", side_effect=TotpRecoveryRejected(reason)),
            _patch("audit_admin_action") as audit,
        ):
            resp = _post_authorize(admin_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?error=session_expired"
        audit.assert_called_once()

    def test_actor_account_locked_flashes_without_reloading_the_target(self, admin_client):
        with (
            _patch("get_totp_recovery_target", return_value=ELIGIBLE_TARGET) as lookup,
            _patch(
                "authorize_totp_recovery", side_effect=TotpRecoveryRejected("actor_account_locked")
            ),
            _patch("audit_admin_action") as audit,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = _post_authorize(admin_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert "temporarily unavailable" in flash.await_args.args[2]
        assert flash.await_args.args[3] == "error"
        lookup.assert_awaited_once()  # only the initial pre-check read, no reload
        audit.assert_called_once()

    def test_invalid_admin_totp_reloads_the_target_and_re_renders_the_form(self, admin_client):
        """A rejection whose reason is neither a step-up nor a lockout reloads
        the current target state and re-renders the confirmation form with
        its own error, rather than bouncing to the dashboard."""
        with (
            _patch("get_totp_recovery_target", return_value=ELIGIBLE_TARGET) as lookup,
            _patch(
                "authorize_totp_recovery",
                side_effect=TotpRecoveryRejected("invalid_admin_totp"),
            ),
            _patch("audit_admin_action") as audit,
        ):
            resp = _post_authorize(admin_client)

        assert resp.status_code == 422
        assert "already used" in resp.text
        assert lookup.await_count == 2  # the pre-check read, then the reload
        audit.assert_called_once()

    def test_target_deleted_between_precheck_and_rejection_flashes_not_found(self, admin_client):
        """The reload after a non-lockout rejection can itself discover the
        target is gone (deleted mid-request); that is reported exactly like
        any other not-found mutation, not a 500."""
        with (
            _patch(
                "get_totp_recovery_target",
                side_effect=[ELIGIBLE_TARGET, None],
            ) as lookup,
            _patch(
                "authorize_totp_recovery",
                side_effect=TotpRecoveryRejected("invalid_admin_totp"),
            ),
            _patch("audit_admin_action") as audit,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = _post_authorize(admin_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert flash.await_args.args[2] == "User not found."
        assert lookup.await_count == 2
        audit.assert_called_once()

    def test_undecryptable_administrator_secret_fails_closed_without_resetting_the_target(
        self, admin_client
    ):
        with (
            _patch("get_totp_recovery_target", return_value=ELIGIBLE_TARGET),
            _patch("authorize_totp_recovery", side_effect=TotpDecryptionError(99)),
        ):
            resp = _post_authorize(admin_client)

        assert resp.status_code == 503
        assert "cannot be verified right now" in resp.text


class TestAdminTotpRecoveryTargetInvariantGuards:
    """Both routes trust `_totp_recovery_target_error` to report every reason
    a `None` or ineligible target is unusable; if the eligibility helper and
    the target lookup ever disagreed (an injected contract violation — this
    cannot happen with the real helper, whose first check is `target is
    None`), the route fails loudly instead of dereferencing a `None`
    target."""

    def test_get_page_raises_if_the_eligibility_helper_and_lookup_disagree_on_a_missing_target(
        self, admin_client
    ):
        with (
            _patch("get_totp_recovery_target", return_value=None),
            patch(
                "app.routes.auth.admin._totp_recovery_target_error",
                autospec=True,
                return_value=None,
            ),
        ):
            resp = admin_client.get("/admin/users/7/totp-recovery", follow_redirects=False)

        assert resp.status_code == 500

    def test_post_route_raises_if_the_eligibility_helper_and_lookup_disagree_on_a_missing_target(
        self, admin_client
    ):
        with (
            _patch("get_totp_recovery_target", return_value=None),
            patch(
                "app.routes.auth.admin._totp_recovery_target_error",
                autospec=True,
                return_value=None,
            ),
        ):
            resp = _post_authorize(admin_client)

        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# POST /admin/users/{user_id}/set-admin — demotion's not-found fault path
# ---------------------------------------------------------------------------


class TestAdminSetAdminDemotionContract:
    """The membership route's stale-form contract, pinned for the demotion
    branch specifically (the invitation branch is covered in
    test_admin_membership_routes.py's shared mutation-contract parametrize)."""

    def test_demoting_a_deleted_user_flashes_not_found(self, admin_client):
        with (
            _patch("set_user_admin", side_effect=ValueError("User 999999 not found")) as write,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = admin_client.post(
                "/admin/users/999999/set-admin",
                data={"is_admin": "false", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert flash.await_args.args[2] == "User not found."
        assert flash.await_args.args[3] == "error"
        write.assert_awaited_once()

    def test_demoting_an_existing_administrator_succeeds(self, admin_client):
        """Positive control: an existing target demotes cleanly and audits
        the transition."""
        with (
            _patch("set_user_admin", return_value=(True, False)) as write,
            _patch("audit_admin_action") as audit,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = admin_client.post(
                "/admin/users/7/set-admin",
                data={"is_admin": "false", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )

        assert resp.status_code == 303
        write.assert_awaited_once_with(
            admin_client.mock_pool,
            7,
            False,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
        )
        assert flash.await_args.args[2] == "Administrator access revoked."
        assert flash.await_args.args[3] == "success"
        audit.assert_called_once()


# ---------------------------------------------------------------------------
# POST /admin/users/{user_id}/cancel-admin-promotion — typed rejections
# ---------------------------------------------------------------------------


class TestAdminCancelPromotionRejections:
    """test_admin_recovery_routes.py pins this route's success shape (an
    invitation cancelled, and the no-op "nothing pending" case); this class
    pins the two typed rejections that never reach a success flash."""

    def _post(self, client, **extra):
        data = {"page": "1", "page_size": "25", "csrf_token": client.csrf_token, **extra}
        return client.post(
            "/admin/users/7/cancel-admin-promotion", data=data, follow_redirects=False
        )

    def test_authority_changed_mid_request_flashes_the_rejection_without_a_success_audit(
        self, admin_client
    ):
        with (
            _patch(
                "cancel_admin_promotion",
                side_effect=AdminActionRejected("Your administrator access changed."),
            ) as cancel,
            _patch("audit_admin_action") as audit,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = self._post(admin_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert flash.await_args.args[2] == "Your administrator access changed."
        assert flash.await_args.args[3] == "error"
        cancel.assert_awaited_once()
        audit.assert_not_called()

    def test_cancelling_for_a_deleted_user_flashes_not_found(self, admin_client):
        with (
            _patch(
                "cancel_admin_promotion",
                side_effect=AdminPromotionRejected("user_not_found"),
            ) as cancel,
            _patch("audit_admin_action") as audit,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = self._post(admin_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        assert flash.await_args.args[2] == "User not found."
        assert flash.await_args.args[3] == "error"
        cancel.assert_awaited_once()
        audit.assert_not_called()

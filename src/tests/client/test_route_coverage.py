"""Every live HTTP route has a registered client-tier witness and pinned guards.

The registry below is the single place that says, per (method, path) of the
running application, which client-tier test exercises the route through the
real middleware stack and which guards the route must carry: its access
policy, whether mutation bodies must be form-encoded, whether the CSRF pair
is verified, and the rate limits registered on the endpoint. The tests read
the live route table from the application object, so a route that is added
without a registry row, a row whose guards drift from the wired dependencies,
or a witness that no longer collects each fails here.
"""

import importlib
import re
from dataclasses import dataclass

import pytest
from fastapi.routing import APIRoute
from starlette.routing import Mount

from app.main import app
from app.middleware.rate_limiting import limiter
from app.route_security import _dependency_calls


@dataclass(frozen=True)
class RouteCoverage:
    """What one route must carry, and the client-tier node that proves it."""

    access: str
    form_body: bool
    csrf: bool
    limits: tuple[str, ...]
    witness: str


_DEFAULT: tuple[str, ...] = ()
_PUBLIC_POST_LIMITS = ("3 per 1 minute", "10 per 1 hour")
_STEP_UP_LIMITS = ("5 per 1 minute", "20 per 1 hour")
_READ_LIMITS = ("10 per 1 minute", "30 per 1 hour")

ROUTE_COVERAGE: dict[tuple[str, str], RouteCoverage] = {
    ("GET", "/"): RouteCoverage(
        "public",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_error_handling.py::test_guest_dynamic_page_is_no_stored",
    ),
    ("GET", "/search"): RouteCoverage(
        "public",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_page_routes.py::TestSearchPageBounds::test_last_search_page_discloses_window_and_has_no_unservable_next",
    ),
    ("GET", "/dataset/{dataset_id}"): RouteCoverage(
        "public",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_page_routes.py::TestDatasetKeywordLinks::test_generated_long_keyword_link_round_trips_through_router",
    ),
    ("GET", "/about"): RouteCoverage(
        "public",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_csrf.py::test_first_get_mints_pre_session_and_hmac_bound_csrf_cookie",
    ),
    ("GET", "/health"): RouteCoverage(
        "public",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_health_routes.py::TestLivenessProbe::test_alive_response_never_touches_the_database",
    ),
    ("GET", "/health/detail"): RouteCoverage(
        "capability",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_health_routes.py::TestHealthDetailAuthorization::test_missing_authorization_header_is_rejected_as_not_found",
    ),
    ("GET", "/login"): RouteCoverage(
        "public",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_auth_routes.py::TestLoginErrorReporting::test_known_login_error_is_visible",
    ),
    ("POST", "/login"): RouteCoverage(
        "public",
        True,
        True,
        _STEP_UP_LIMITS,
        "src/tests/client/test_credential_budget_route_outcomes.py::test_account_locked_response_is_bounded_and_does_not_reflect_credentials",
    ),
    ("GET", "/auth/shibboleth/callback"): RouteCoverage(
        "capability",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_auth_routes.py::TestShibbolethCallbackAccess::test_enabled_federation_with_the_trusted_internal_header_reaches_the_finalizer",
    ),
    ("POST", "/logout"): RouteCoverage(
        "open_during_enrollment",
        True,
        True,
        _DEFAULT,
        "src/tests/client/test_auth_routes.py::TestLogoutCookies::test_logout_deletes_session_and_csrf_cookies_exactly_once",
    ),
    ("GET", "/recover-totp"): RouteCoverage(
        "public",
        False,
        False,
        _READ_LIMITS,
        "src/tests/client/test_credential_budget_route_outcomes.py::test_public_recovery_page_renders_without_touching_any_service",
    ),
    ("POST", "/recover-totp"): RouteCoverage(
        "public",
        True,
        True,
        _PUBLIC_POST_LIMITS,
        "src/tests/client/test_credential_budget_route_outcomes.py::test_public_recovery_rejection_reasons_have_identical_generic_response",
    ),
    ("GET", "/register"): RouteCoverage(
        "public",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_registration_routes.py::TestRegisterPageAccess::test_guest_sees_the_registration_form",
    ),
    ("POST", "/register"): RouteCoverage(
        "public",
        True,
        True,
        _PUBLIC_POST_LIMITS,
        "src/tests/client/test_registration_routes.py::TestRegisterEnumerationGuard::test_duplicate_registration_indistinguishable_from_success",
    ),
    ("GET", "/send_verification"): RouteCoverage(
        "open_during_enrollment",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_registration_routes.py::TestSendVerificationPage::test_get_page_prefills_email",
    ),
    ("POST", "/send_verification"): RouteCoverage(
        "open_during_enrollment",
        True,
        True,
        ("3 per 1 hour", "10 per 1 day"),
        "src/tests/client/test_registration_routes.py::TestSendVerificationEnumerationGuard::test_unverified_local_user_gets_resend",
    ),
    ("GET", "/setup-totp"): RouteCoverage(
        "totp_enrollment",
        False,
        False,
        _READ_LIMITS,
        "src/tests/client/test_totp_enrollment_routes.py::TestSetupTotpPage::test_setup_totp_page_requests_atomic_pending_secret",
    ),
    ("POST", "/setup-totp"): RouteCoverage(
        "totp_enrollment",
        True,
        True,
        _STEP_UP_LIMITS,
        "src/tests/client/test_totp_enrollment_routes.py::TestSetupTotpSubmit::test_setup_totp_valid_code_persists_db_secret_and_upgrades_purpose",
    ),
    ("GET", "/account/reset-totp"): RouteCoverage(
        "full_session",
        False,
        False,
        _READ_LIMITS,
        "src/tests/client/test_totp_rotation_routes.py::TestResetTotpPage::test_reset_totp_page_renders_fresh_auth_form_without_calling_any_service",
    ),
    ("POST", "/account/reset-totp"): RouteCoverage(
        "full_session",
        True,
        True,
        _STEP_UP_LIMITS,
        "src/tests/client/test_totp_rotation_routes.py::TestResetTotpStart::test_reset_totp_start_ready_returns_confirm_page_with_new_seed",
    ),
    ("POST", "/account/reset-totp/confirm"): RouteCoverage(
        "full_session",
        True,
        True,
        _STEP_UP_LIMITS,
        "src/tests/client/test_totp_rotation_routes.py::TestResetTotpConfirm::test_reset_totp_confirm_rotated_redirects_to_login",
    ),
    ("GET", "/forgot-password"): RouteCoverage(
        "public",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_auth_routes.py::TestForgotPasswordRoute::test_guest_sees_the_request_form",
    ),
    ("POST", "/forgot-password"): RouteCoverage(
        "public",
        True,
        True,
        _PUBLIC_POST_LIMITS,
        "src/tests/client/test_auth_routes.py::TestForgotPasswordRoute::test_valid_pair_reaches_the_lookup_service_and_renders_the_neutral_page",
    ),
    ("GET", "/reset-password/{token}"): RouteCoverage(
        "capability",
        False,
        False,
        _READ_LIMITS,
        "src/tests/client/test_auth_routes.py::TestResetPasswordRoute::test_valid_token_renders_the_new_password_form",
    ),
    ("POST", "/reset-password"): RouteCoverage(
        "capability",
        True,
        True,
        _STEP_UP_LIMITS,
        "src/tests/client/test_auth_routes.py::TestResetPasswordRoute::test_valid_submission_redirects_and_commits_exactly_once",
    ),
    ("GET", "/account"): RouteCoverage(
        "full_session",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_error_handling.py::test_authenticated_page_gets_no_store",
    ),
    ("POST", "/account/change-name"): RouteCoverage(
        "local_full_session",
        True,
        True,
        _DEFAULT,
        "src/tests/client/test_registration_routes.py::TestChangeDisplayNameValidation::test_change_name_happy_path_updates_and_flashes_success",
    ),
    ("GET", "/account/admin-promotion"): RouteCoverage(
        "local_full_session",
        False,
        False,
        _READ_LIMITS,
        "src/tests/client/test_admin_promotion_routes.py::TestAdminPromotionPageAccess::test_local_full_session_with_a_pending_invitation_sees_it",
    ),
    ("POST", "/account/admin-promotion/prepare"): RouteCoverage(
        "local_full_session",
        True,
        True,
        _PUBLIC_POST_LIMITS,
        "src/tests/client/test_admin_promotion_routes.py::TestAdminPromotionPrepare::test_valid_pair_calls_the_service_exactly_once_and_shows_the_codes",
    ),
    ("POST", "/account/admin-promotion/accept"): RouteCoverage(
        "local_full_session",
        True,
        True,
        ("5 per 1 minute", "15 per 1 hour"),
        "src/tests/client/test_admin_promotion_routes.py::TestAdminPromotionAccept::test_valid_pair_calls_the_service_exactly_once_and_redirects_to_login",
    ),
    ("POST", "/account/admin-promotion/decline"): RouteCoverage(
        "local_full_session",
        True,
        True,
        ("5 per 1 minute", "15 per 1 hour"),
        "src/tests/client/test_admin_promotion_routes.py::TestAdminPromotionDecline::test_valid_pair_calls_the_service_exactly_once_and_redirects_to_account",
    ),
    ("GET", "/admin"): RouteCoverage(
        "admin",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_admin_membership_routes.py::TestAdminDashboardAccess::test_admin_dashboard_renders_for_admin",
    ),
    ("GET", "/admin/users/{user_id}/totp-recovery"): RouteCoverage(
        "admin",
        False,
        False,
        _READ_LIMITS,
        "src/tests/client/test_admin_recovery_routes.py::TestAdminTotpRecoveryPageAccess::test_admin_sees_the_confirmation_form_without_changing_any_state",
    ),
    ("POST", "/admin/users/{user_id}/totp-recovery"): RouteCoverage(
        "admin",
        True,
        True,
        _PUBLIC_POST_LIMITS,
        "src/tests/client/test_credential_budget_route_outcomes.py::test_admin_recovery_session_rejection_does_not_reload_target",
    ),
    ("POST", "/admin/users/{user_id}/approve-federated"): RouteCoverage(
        "admin",
        True,
        True,
        _STEP_UP_LIMITS,
        "src/tests/client/test_admin_membership_routes.py::TestApproveFederatedMutation::test_approve_federated_delegates_exact_identity_and_audits_without_subject",
    ),
    ("POST", "/admin/users/{user_id}/set-active"): RouteCoverage(
        "admin",
        True,
        True,
        _DEFAULT,
        "src/tests/client/test_admin_membership_routes.py::TestSetActiveMutation::test_deactivation_revokes_sessions_and_audits_lock_cleared",
    ),
    ("POST", "/admin/users/{user_id}/set-tier"): RouteCoverage(
        "admin",
        True,
        True,
        _DEFAULT,
        "src/tests/client/test_admin_membership_routes.py::TestSetTierMutation::test_no_op_tier_change_flashes_info_and_skips_audit",
    ),
    ("POST", "/admin/users/{user_id}/set-admin"): RouteCoverage(
        "admin",
        True,
        True,
        _DEFAULT,
        "src/tests/client/test_admin_membership_routes.py::TestSetAdminMutation::test_admin_change_audits_old_and_new_from_service_return",
    ),
    ("POST", "/admin/users/{user_id}/cancel-admin-promotion"): RouteCoverage(
        "admin",
        True,
        True,
        _DEFAULT,
        "src/tests/client/test_admin_recovery_routes.py::TestAdminCancelPromotionAccess::test_admin_cancellation_calls_the_service_exactly_once_and_redirects",
    ),
    ("POST", "/admin/users/{user_id}/change-email"): RouteCoverage(
        "admin",
        True,
        True,
        _DEFAULT,
        "src/tests/client/test_admin_email_change_routes.py::TestAdminChangeEmail::test_admin_email_change_delegates_resolved_authority",
    ),
    ("GET", "/verify-email/{token}"): RouteCoverage(
        "capability",
        False,
        False,
        _READ_LIMITS,
        "src/tests/client/test_session_middleware.py::TestSessionPurposeRouteAccess::test_verify_email_capability_is_reachable_during_totp_setup",
    ),
    ("POST", "/verify-email"): RouteCoverage(
        "capability",
        True,
        False,
        _READ_LIMITS,
        "src/tests/client/test_registration_routes.py::TestVerifyEmailCapabilityRoute::test_post_without_csrf_pair_still_reaches_the_service",
    ),
    ("GET", "/account/change-email"): RouteCoverage(
        "local_full_session",
        False,
        False,
        _DEFAULT,
        "src/tests/client/test_email_change_routes.py::test_local_full_session_sees_the_change_email_form",
    ),
    ("POST", "/account/change-email"): RouteCoverage(
        "local_full_session",
        True,
        True,
        _STEP_UP_LIMITS,
        "src/tests/client/test_credential_budget_route_outcomes.py::test_email_change_session_rejection_clears_session_before_follow_up",
    ),
    ("GET", "/account/confirm-email/{token}"): RouteCoverage(
        "capability",
        False,
        False,
        _READ_LIMITS,
        "src/tests/client/test_email_change_routes.py::test_valid_confirmation_token_renders_the_form_without_consuming_it",
    ),
    ("POST", "/account/confirm-email"): RouteCoverage(
        "capability",
        True,
        False,
        _READ_LIMITS,
        "src/tests/client/test_email_change_routes.py::test_self_service_confirm_redirects_and_clears_session_cookie",
    ),
}


@dataclass(frozen=True)
class LiveRoute:
    """The guards the running application actually wires on one route."""

    access: str
    form_body: bool
    csrf: bool
    limits: tuple[str, ...]


def live_routes() -> dict[tuple[str, str], LiveRoute]:
    """Walk the application object: one entry per (method, path) of every API route."""
    table: dict[tuple[str, str], LiveRoute] = {}
    for route in app.routes:
        if isinstance(route, Mount) or not isinstance(route, APIRoute):
            continue
        calls = {call.__name__ for call in _dependency_calls(route)}
        endpoint_key = f"{route.endpoint.__module__}.{route.endpoint.__name__}"
        limits = tuple(str(item.limit) for item in limiter._route_limits.get(endpoint_key, []))
        access = (route.openapi_extra or {})["x-oralhistarchiv-access"]
        for method in route.methods:
            table[(method, route.path)] = LiveRoute(
                access=access,
                form_body="validate_form_content_type" in calls,
                csrf="verify_csrf" in calls,
                limits=limits,
            )
    return table


def routes_without_coverage(
    live: dict[tuple[str, str], LiveRoute], registry: dict[tuple[str, str], RouteCoverage]
) -> set[tuple[str, str]]:
    return {key for key in live if key not in registry or not registry[key].witness}


def resolve_node(node_id: str) -> object:
    """Import the module and walk to the test object a node id names."""
    path, _, rest = node_id.partition("::")
    module_name = re.sub(r"\.py$", "", path.removeprefix("src/")).replace("/", ".")
    target = importlib.import_module(module_name)
    for part in rest.split("::"):
        target = getattr(target, re.sub(r"\[.*\]$", "", part))
    return target


def _route_id(key: tuple[str, str]) -> str:
    return f"{key[0]} {key[1]}"


class TestEveryRouteIsCovered:
    """The registry and the live route table describe the same set of routes."""

    def test_every_live_route_has_a_registered_witness(self):
        missing = routes_without_coverage(live_routes(), ROUTE_COVERAGE)
        assert missing == set(), (
            f"routes without a client-tier witness: {sorted(missing)}; add a RouteCoverage row"
        )

    def test_every_registry_row_names_a_live_route(self):
        stale = set(ROUTE_COVERAGE) - set(live_routes())
        assert stale == set(), f"registry rows for routes that no longer exist: {sorted(stale)}"

    def test_a_route_missing_from_the_registry_is_reported(self):
        """Positive control for the coverage check: drop one row and it is named."""
        live = live_routes()
        key = ("GET", "/about")
        assert key in live
        assert key not in routes_without_coverage(live, ROUTE_COVERAGE)
        registry = {k: v for k, v in ROUTE_COVERAGE.items() if k != key}
        assert key in routes_without_coverage(live, registry)

    def test_a_row_without_a_witness_is_reported(self):
        live = live_routes()
        key = ("GET", "/about")
        registry = dict(ROUTE_COVERAGE)
        row = registry[key]
        registry[key] = RouteCoverage(row.access, row.form_body, row.csrf, row.limits, "")
        assert key not in routes_without_coverage(live, ROUTE_COVERAGE)
        assert key in routes_without_coverage(live, registry)


class TestRegisteredGuardsMatchTheLiveRoute:
    """A guard the registry promises is a guard the application wires, and vice versa."""

    @pytest.mark.parametrize("key", sorted(ROUTE_COVERAGE), ids=_route_id)
    def test_registered_guards_match_the_wired_dependencies(self, key):
        expected = ROUTE_COVERAGE[key]
        actual = live_routes()[key]
        assert (actual.access, actual.form_body, actual.csrf, actual.limits) == (
            expected.access,
            expected.form_body,
            expected.csrf,
            expected.limits,
        )

    def test_a_dropped_guard_is_detected(self):
        """Positive control: a registry row promising CSRF on a CSRF-exempt route mismatches."""
        actual = live_routes()[("POST", "/verify-email")]
        assert actual.csrf is False
        promised = RouteCoverage("capability", True, True, _READ_LIMITS, "x")
        assert (actual.access, actual.form_body, actual.csrf) != (
            promised.access,
            promised.form_body,
            promised.csrf,
        )


class TestEveryWitnessCollects:
    """A witness is a node id that resolves to a test function in the client tier."""

    @pytest.mark.parametrize("key", sorted(ROUTE_COVERAGE), ids=_route_id)
    def test_witness_resolves_to_a_client_tier_test(self, key):
        witness = ROUTE_COVERAGE[key].witness
        assert witness.startswith("src/tests/client/"), witness
        target = resolve_node(witness)
        assert callable(target)
        assert target.__name__.startswith("test_")

    def test_an_unknown_witness_is_rejected(self):
        with pytest.raises(AttributeError):
            resolve_node(
                "src/tests/client/test_route_coverage.py::TestEveryWitnessCollects::test_does_not_exist"
            )

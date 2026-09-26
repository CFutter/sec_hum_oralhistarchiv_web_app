"""Admin membership routes at the client tier — the DB-less tier's admin coverage.

Before this file the unit/client tier had ZERO admin coverage, so a developer running
`pytest -m "not integration"` stayed green after regressing require_admin —
the only admin authz tests lived in the integration tier, which can be
skipped. These tests pin the 404 cloak, the admin-unlock UI contract,
the CSRF rejection on the highest-privilege mutation, the framework-level
422 for a garbage tier value, and the not-found/rejection flash contract that
every mutation route on this router shares — none of which need a database.
"""

from contextlib import ExitStack
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from lxml import html
from psycopg.errors import DivisionByZero

from app.services.admin_promotion import AdminPromotionRejected, AdminPromotionRequestResult
from app.services.email_change import AdminEmailChangeRejected
from app.services.users import AdminActionRejected, SetActiveResult
from tests.fixtures import RAW_SESSION_ID, make_sample_user


def _patch(name, **kw):
    return patch(f"app.routes.auth.admin.{name}", autospec=True, **kw)


@pytest.fixture(autouse=True)
def _no_pending_admin_promotions():
    """admin_dashboard (admin.py) awaits list_admin_promotion_states for the
    rendered page's user ids on every GET /admin. Default to 'nothing
    pending' so every dashboard test in this module stays focused on what it
    actually asserts; a test exercising invitation display overrides this
    patch itself."""
    with _patch("list_admin_promotion_states", return_value={}):
        yield


def _set_active_actions(response, user_id):
    """Return {button label: submitted is_active value} for one user row."""
    document = html.fromstring(response.text)
    forms = document.xpath(f'//form[@action="/admin/users/{user_id}/set-active"]')
    actions = {}
    for form in forms:
        assert form.get("method") == "post"
        fields = {
            field.get("name"): field.get("value", "")
            for field in form.xpath('.//input[@type="hidden"]')
        }
        assert {"csrf_token", "page", "page_size", "is_active"} <= fields.keys()
        label = form.xpath("string(.//button)").strip()
        assert label not in actions
        actions[label] = fields["is_active"]
    return actions


class TestAdminDashboardAccess:
    """require_admin — the 404 cloak holds both directions, in both methods."""

    def test_admin_dashboard_404_for_guest_and_non_admin(self, guest_client, authenticated_client):
        """Both a guest and an ordinary authenticated user get a 404 (NEVER a
        403 — the cloak must not confirm the endpoint exists)."""
        for client in (guest_client, authenticated_client):
            resp = client.get("/admin", follow_redirects=False)
            assert resp.status_code == 404
            assert "Page not found" in resp.text

    def test_admin_dashboard_renders_for_admin(self, admin_client):
        """Positive control (and the admin_client fixture's first consumer): an
        is_admin session gets the real dashboard, with the user list fetched."""
        with _patch("list_users", return_value=([], 0)) as users:
            resp = admin_client.get("/admin")
        assert resp.status_code == 200
        users.assert_awaited_once()

    def test_admin_dashboard_rejects_a_setup_purpose_admin(self, client_builder):
        """An admin flag cannot turn a password-only session into admin access."""
        user = make_sample_user(is_admin=True, totp_configured=False)
        client = client_builder(session_user=user, session_purpose="totp_setup")

        with _patch("list_users") as users:
            response = client.get("/admin", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/setup-totp"
        users.assert_not_awaited()

    def test_admin_mutation_404_for_non_admin_post(self, authenticated_client):
        """The cloak holds on POST too: a non-admin with a VALID CSRF pair gets
        404 from set-admin and the service is never reached."""
        with _patch("set_user_admin") as set_admin:
            resp = authenticated_client.post(
                "/admin/users/7/set-admin",
                data={"is_admin": "true", "csrf_token": authenticated_client.csrf_token},
                follow_redirects=False,
            )
        assert resp.status_code == 404
        set_admin.assert_not_awaited()


class TestFederatedIdentityDisplay:
    """The dashboard shows only the identity/action state each federated
    account status permits, so a stale login page can't confirm the tier."""

    def test_admin_dashboard_exposes_issuer_scoped_identity_for_review(self, admin_client):
        """A federation account awaiting review shows both immutable identity components.

        Email and display name are mutable claims, so an administrator must see
        the issuer/subject binding before activating the account or raising tier.
        """
        target = make_sample_user(
            id=7,
            auth_method="shibboleth",
            is_active=False,
            shibboleth_issuer="https://idp.example.org/idp/shibboleth",
            shibboleth_subject_id="stable-subject-7",
        )
        with _patch("list_users", return_value=([target], 1)):
            response = admin_client.get("/admin")

        assert response.status_code == 200
        document = html.fromstring(response.text)
        identity = document.xpath("//td[contains(@class, 'federated-identity')]")[0]
        assert identity.xpath("string(.)").split() == [
            "Issuer",
            "https://idp.example.org/idp/shibboleth",
            "Subject",
            "stable-subject-7",
            "Status",
            "pending",
        ]

    def test_pending_federated_identity_has_only_exact_approval_action(self, admin_client):
        target = make_sample_user(
            id=7,
            auth_method="shibboleth",
            is_active=False,
            shibboleth_issuer="https://idp.example.org/idp/shibboleth",
            shibboleth_subject_id="stable-subject-7",
            federated_status="pending",
        )
        with _patch("list_users", return_value=([target], 1)):
            response = admin_client.get("/admin")

        document = html.fromstring(response.text)
        approval = document.xpath('//form[@action="/admin/users/7/approve-federated"]')
        assert len(approval) == 1
        fields = {
            field.get("name"): field.get("value", "")
            for field in approval[0].xpath('.//input[@type="hidden"]')
        }
        assert fields["expected_issuer"] == target.shibboleth_issuer
        assert fields["expected_subject_id"] == target.shibboleth_subject_id
        assert fields["csrf_token"]
        assert document.xpath('//form[@action="/admin/users/7/set-active"]') == []
        assert document.xpath('//form[@action="/admin/users/7/set-tier"]') == []
        assert document.xpath('//form[@action="/admin/users/7/set-admin"]') == []

    def test_legacy_federated_identity_has_no_generic_membership_action(self, admin_client):
        target = make_sample_user(
            id=7,
            auth_method="shibboleth",
            federated_status="legacy_quarantined",
        )
        with _patch("list_users", return_value=([target], 1)):
            response = admin_client.get("/admin")

        document = html.fromstring(response.text)
        assert "Manual identity reconciliation required." in response.text
        assert document.xpath('//form[starts-with(@action, "/admin/users/7/")]') == []

    def test_disabled_approved_federated_identity_has_reactivation_state_action(self, admin_client):
        target = make_sample_user(
            id=7,
            auth_method="shibboleth",
            federated_status="disabled",
        )
        with _patch("list_users", return_value=([target], 1)):
            response = admin_client.get("/admin")

        assert _set_active_actions(response, target.id) == {"Reactivate": "true"}
        document = html.fromstring(response.text)
        assert document.xpath('//form[@action="/admin/users/7/approve-federated"]') == []


class TestAccountStateActions:
    """Every account state exposes exactly the mutation buttons it permits."""

    @pytest.mark.parametrize(
        ("target", "expected_actions"),
        [
            (
                make_sample_user(id=7, auth_method="local", is_active=True),
                {"Unlock": "true", "Deactivate": "false"},
            ),
            (
                make_sample_user(id=7, auth_method="local", is_active=False),
                {"Reactivate": "true"},
            ),
            (
                make_sample_user(id=7, auth_method="shibboleth", is_active=True),
                {"Deactivate": "false"},
            ),
            (
                make_sample_user(id=99, auth_method="local", is_active=True),
                {},
            ),
        ],
        ids=("active-local", "inactive-local", "active-shibboleth", "current-admin"),
    )
    def test_admin_dashboard_exposes_only_valid_account_state_actions(
        self, admin_client, target, expected_actions
    ):
        """Unlock is available only for another active local account."""
        with _patch("list_users", return_value=([target], 1)):
            response = admin_client.get("/admin")

        assert response.status_code == 200
        assert _set_active_actions(response, target.id) == expected_actions


class TestSetAdminCsrfProtection:
    """CSRF on the highest-privilege mutation (behavioural companion to the
    structural canary in unit/test_route_guards.py)."""

    def test_set_admin_without_csrf_token_is_403_and_writes_nothing(self, admin_client):
        """POST /admin/users/{id}/set-admin with NO csrf_token → 403 before the
        handler runs: no privilege write."""
        with _patch("set_user_admin") as write:
            resp = admin_client.post(
                "/admin/users/7/set-admin",
                data={"is_admin": "true"},
                follow_redirects=False,
            )
        assert resp.status_code == 403
        write.assert_not_awaited()

    def test_set_admin_with_forged_csrf_token_is_403(self, admin_client):
        """A well-formed but non-HMAC-matching token fails the recompute → 403,
        no write."""
        with _patch("set_user_admin") as write:
            resp = admin_client.post(
                "/admin/users/7/set-admin",
                data={"is_admin": "true", "csrf_token": "deadbeef" * 8},
                follow_redirects=False,
            )
        assert resp.status_code == 403
        write.assert_not_awaited()


class TestApproveFederatedMutation:
    def test_approve_federated_without_csrf_is_403_and_writes_nothing(self, admin_client):
        with _patch("approve_federated_user") as approve:
            response = admin_client.post(
                "/admin/users/7/approve-federated",
                data={
                    "expected_issuer": "https://idp.example.org/idp/shibboleth",
                    "expected_subject_id": "stable-subject-7",
                    "access_tier": "registered",
                },
                follow_redirects=False,
            )

        assert response.status_code == 403
        approve.assert_not_awaited()

    def test_approve_federated_delegates_exact_identity_and_audits_without_subject(
        self, admin_client
    ):
        approved = make_sample_user(
            id=7,
            auth_method="shibboleth",
            access_tier="vetted",
            federated_status="approved",
        )
        issuer = "https://idp.example.org/idp/shibboleth"
        subject = "stable-subject-7"
        with (
            _patch("approve_federated_user", return_value=approved) as approve,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            response = admin_client.post(
                "/admin/users/7/approve-federated",
                data={
                    "expected_issuer": issuer,
                    "expected_subject_id": subject,
                    "access_tier": "vetted",
                    "csrf_token": admin_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        approve.assert_awaited_once_with(
            admin_client.mock_pool,
            7,
            expected_issuer=issuer,
            expected_subject_id=subject,
            access_tier="vetted",
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
        )
        audit.assert_called_once()
        audit_fields = audit.call_args.kwargs
        assert audit_fields["event_type"] == "admin_federated_user_approved"
        assert audit_fields["target_user_id"] == 7
        assert audit_fields["old_value"] == "pending"
        assert audit_fields["new_value"] == "approved"
        assert audit_fields["access_tier"] == "vetted"
        assert "subject" not in " ".join(audit_fields)
        assert issuer not in repr(audit.call_args)
        assert subject not in repr(audit.call_args)
        assert flash.await_args.args[2:] == (
            "Federated identity approved at tier 'vetted'.",
            "success",
        )

    def test_approve_federated_rejects_unknown_tier_before_service(self, admin_client):
        with _patch("approve_federated_user") as approve:
            response = admin_client.post(
                "/admin/users/7/approve-federated",
                data={
                    "expected_issuer": "https://idp.example.org/idp/shibboleth",
                    "expected_subject_id": "stable-subject-7",
                    "access_tier": "root",
                    "csrf_token": admin_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert response.status_code == 422
        approve.assert_not_awaited()


class TestSetTierMutation:
    def test_set_tier_with_unknown_tier_value_is_422_before_any_db_work(self, admin_client):
        """access_tier is typed as the AccessTier Literal, so 'root' must die in
        framework validation (422 branded page) before any UPDATE runs.
        Loosening the annotation to str would turn this into an uncaught CHECK-
        constraint 500 on every mistyped submission."""
        with _patch("update_access_tier") as write:
            resp = admin_client.post(
                "/admin/users/7/set-tier",
                data={"access_tier": "root", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )
        assert resp.status_code == 422
        assert "Invalid request" in resp.text  # branded 422, not JSON
        write.assert_not_awaited()

    def test_no_op_tier_change_flashes_info_and_skips_audit(self, admin_client):
        """A no-op write (old == new from the locked-CTE return) must flash the
        info copy and emit NO audit event — an unchanged row is not an admin
        action worth an audit line (admin.py admin_set_tier no-op arm)."""
        with (
            _patch("update_access_tier", return_value=("registered", "registered")) as write,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            resp = admin_client.post(
                "/admin/users/7/set-tier",
                data={"access_tier": "registered", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )
        assert resp.status_code == 303
        write.assert_awaited_once_with(
            admin_client.mock_pool,
            7,
            "registered",
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
        )
        audit.assert_not_called()
        assert flash.await_args.args[2] == "User already has tier 'registered'."
        assert flash.await_args.args[3] == "info"


class TestSetAdminMutation:
    def test_admin_change_audits_old_and_new_from_service_return(self, admin_client):
        """Granting admin access is a two-person control: POST is-admin=true
        creates an acceptance invitation (request_admin_promotion) rather than
        writing is_admin directly (admin.py admin_set_admin, docstring "Invite a
        non-admin to accept authority"; set_user_admin itself now rejects
        is_admin=True). The audit payload must be the invitation the service
        returned atomically — not a value recomputed by the route."""
        expires_at = datetime(2026, 4, 1, tzinfo=UTC)
        invitation = AdminPromotionRequestResult(user_id=7, expires_at=expires_at, reissued=False)
        with (
            _patch("request_admin_promotion", return_value=invitation) as write,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            resp = admin_client.post(
                "/admin/users/7/set-admin",
                data={"is_admin": "true", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )
        assert resp.status_code == 303
        write.assert_awaited_once_with(
            admin_client.mock_pool,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
            target_user_id=7,
        )
        audit.assert_called_once()
        assert audit.call_args.kwargs["event_type"] == "admin_promotion_requested"
        assert audit.call_args.kwargs["target_user_id"] == 7
        assert audit.call_args.kwargs["reissued"] is False
        assert audit.call_args.kwargs["expires_at"] == expires_at.isoformat()
        assert flash.await_args.args[2] == "Administrator invitation created."
        assert flash.await_args.args[3] == "success"


class TestSetActiveMutation:
    def test_set_active_no_op_with_lock_cleared_is_the_unlock_path(self, admin_client):
        """SetActiveResult(True, True, lock_cleared=True) — activating an
        already-active user whose row held lockout state — is the documented
        admin-unlock path: recovery success flash + a dedicated
        admin_user_unlocked audit event. The database tests check that unlock
        preserves existing sessions."""
        with (
            _patch(
                "set_user_active",
                return_value=SetActiveResult(old_value=True, new_value=True, lock_cleared=True),
            ) as write,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            resp = admin_client.post(
                "/admin/users/7/set-active",
                data={"is_active": "true", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )
        assert resp.status_code == 303
        write.assert_awaited_once_with(
            admin_client.mock_pool,
            7,
            True,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
        )
        audit.assert_called_once()
        assert audit.call_args.kwargs["event_type"] == "admin_user_unlocked"
        assert "Pending email changes must be requested again" in flash.await_args.args[2]
        assert flash.await_args.args[3] == "success"

    def test_set_active_without_lock_reports_authentication_invalidation(self, admin_client):
        """Recovery changes auth_revision even when no lockout needed clearing."""
        with (
            _patch(
                "set_user_active",
                return_value=SetActiveResult(old_value=True, new_value=True, lock_cleared=False),
            ),
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            resp = admin_client.post(
                "/admin/users/7/set-active",
                data={"is_active": "true", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )
        assert resp.status_code == 303
        assert audit.call_args.kwargs["authentication_state_invalidated"] is True
        assert "Pending email changes must be requested again" in flash.await_args.args[2]
        assert flash.await_args.args[3] == "success"

    def test_deactivation_revokes_sessions_and_audits_lock_cleared(self, admin_client):
        """The route delegates deactivation once and audits its returned state.

        Session deletion is now owned by set_user_active(), and is verified in
        test_account_deactivation_db.py. An extra route-level database operation
        is rejected by the client fixture's database guard.
        """
        with (
            _patch(
                "set_user_active",
                return_value=SetActiveResult(old_value=True, new_value=False, lock_cleared=False),
            ) as write,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            resp = admin_client.post(
                "/admin/users/7/set-active",
                data={"is_active": "false", "csrf_token": admin_client.csrf_token},
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
        audit.assert_called_once()
        assert audit.call_args.kwargs["event_type"] == "admin_user_active_changed"
        assert audit.call_args.kwargs["old_value"] is True
        assert audit.call_args.kwargs["new_value"] is False
        assert audit.call_args.kwargs["lock_cleared"] is False
        assert flash.await_args.args[2] == "User deactivated."
        assert flash.await_args.args[3] == "success"

    def test_repeated_deactivation_audits_revocation_and_preserves_pagination(self, admin_client):
        """An already-inactive account still triggers the service and a revocation audit."""
        with (
            _patch(
                "set_user_active",
                return_value=SetActiveResult(False, False, False),
            ) as write,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            resp = admin_client.post(
                "/admin/users/7/set-active",
                data={
                    "is_active": "false",
                    "csrf_token": admin_client.csrf_token,
                    "page": "2",
                    "page_size": "10",
                },
                follow_redirects=False,
            )

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin?page=2&page_size=10"
        write.assert_awaited_once_with(
            admin_client.mock_pool,
            7,
            False,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
        )
        audit.assert_called_once()
        assert audit.call_args.kwargs["event_type"] == "admin_user_sessions_revoked"
        assert audit.call_args.kwargs["target_user_id"] == 7
        assert audit.call_args.kwargs["reason"] == "already_inactive"
        assert flash.await_args.args[2:] == (
            "User remains inactive. All sessions revoked.",
            "success",
        )

    def test_reactivation_audits_state_change_and_unlock_result(self, admin_client):
        """False->True is a state-change audit, even when lockout state was also cleared."""
        with (
            _patch("set_user_active", return_value=SetActiveResult(False, True, True)) as write,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            resp = admin_client.post(
                "/admin/users/7/set-active",
                data={"is_active": "true", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )

        assert resp.status_code == 303
        write.assert_awaited_once_with(
            admin_client.mock_pool,
            7,
            True,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
        )
        audit.assert_called_once()
        assert audit.call_args.kwargs["event_type"] == "admin_user_active_changed"
        assert audit.call_args.kwargs["old_value"] is False
        assert audit.call_args.kwargs["new_value"] is True
        assert audit.call_args.kwargs["lock_cleared"] is True
        assert flash.await_args.args[2:] == ("User activated.", "success")

    def test_deactivation_database_failure_has_no_success_flash_or_audit(self, admin_client):
        """A failed service transaction must not be reported as completed or as missing user."""
        with (
            _patch("set_user_active", side_effect=DivisionByZero("injected SQL failure")) as write,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            resp = admin_client.post(
                "/admin/users/7/set-active",
                data={"is_active": "false", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )

        assert resp.status_code == 500
        write.assert_awaited_once_with(
            admin_client.mock_pool,
            7,
            False,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
        )
        flash.assert_not_awaited()
        audit.assert_not_called()


class TestSelfProtectionGuards:
    """Self-protection guards — pure ID comparisons, client-tier coverage."""

    def test_admin_cannot_deactivate_own_account(self, admin_client):
        """The self-deactivation guard fires before any service call (admin.py
        compares path id to request.state.user.id — admin_client is id 99)."""
        with _patch("set_user_active") as write, _patch("set_flash_if_exists") as flash:
            resp = admin_client.post(
                "/admin/users/99/set-active",
                data={"is_active": "false", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )
        assert resp.status_code == 303
        write.assert_not_awaited()
        assert flash.await_args.args[2] == "You cannot deactivate your own account."
        assert flash.await_args.args[3] == "error"

    def test_admin_cannot_remove_own_admin_status(self, admin_client):
        """Self-demotion guard: same ID-comparison mechanism, set-admin route."""
        with _patch("set_user_admin") as write, _patch("set_flash_if_exists") as flash:
            resp = admin_client.post(
                "/admin/users/99/set-admin",
                data={"is_admin": "false", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )
        assert resp.status_code == 303
        write.assert_not_awaited()
        assert flash.await_args.args[2] == "You cannot remove your own admin status."
        assert flash.await_args.args[3] == "error"


class TestMutationRouteContracts:
    """Contracts every /admin/users/{id}/<mutation> route shares, including
    the email-change route: a stale form for a deleted user always flashes
    'User not found.' instead of a 500, and a mid-request authority or
    session change always flashes the rejection message without a success
    audit. Grouped here (rather than split by production surface) because the
    invariant, not the destination service, is what each case proves."""

    @pytest.mark.parametrize(
        ("path", "form", "service"),
        [
            (
                "/admin/users/999999/approve-federated",
                {
                    "expected_issuer": "https://idp.example.org/idp/shibboleth",
                    "expected_subject_id": "stable-subject-999999",
                    "access_tier": "public",
                },
                "approve_federated_user",
            ),
            ("/admin/users/999999/set-active", {"is_active": "false"}, "set_user_active"),
            (
                "/admin/users/999999/set-tier",
                {"access_tier": "vetted"},
                "update_access_tier",
            ),
            ("/admin/users/999999/set-admin", {"is_admin": "true"}, "request_admin_promotion"),
            (
                "/admin/users/999999/change-email",
                {"new_email": "x@uzh.ch"},
                "stage_admin_email_change",
            ),
        ],
        ids=(
            "approve_federated",
            "set_active",
            "set_tier",
            "set_admin",
            "change_email",
        ),
    )
    def test_mutation_on_nonexistent_user_flashes_not_found(
        self, admin_client, path, form, service
    ):
        """A stale admin form (user deleted between page load and submit) must
        land back on /admin with the 'User not found.' flash — never a 500.

        The locked-CTE write service itself raises ValueError for a
        missing user and admin.py catches it. Email staging uses its typed
        policy rejection so an internal ValueError is not mistaken for a stale
        form.
        """
        with ExitStack() as stack:
            flash = stack.enter_context(_patch("set_flash_if_exists"))
            if service == "stage_admin_email_change":
                writer = stack.enter_context(
                    _patch(service, side_effect=AdminEmailChangeRejected("user_not_found"))
                )
            elif service == "request_admin_promotion":
                writer = stack.enter_context(
                    _patch(service, side_effect=AdminPromotionRejected("user_not_found"))
                )
            else:
                writer = stack.enter_context(
                    _patch(service, side_effect=ValueError("User 999999 not found"))
                )

            resp = admin_client.post(
                path,
                data={**form, "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )

        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin"
        flash.assert_awaited_once()
        assert flash.await_args.args[2] == "User not found."
        assert flash.await_args.args[3] == "error"
        writer.assert_awaited_once()  # the write was attempted and failed cleanly

    @pytest.mark.parametrize(
        ("path", "form", "service"),
        [
            (
                "approve-federated",
                {
                    "expected_issuer": "https://idp.example.org/idp/shibboleth",
                    "expected_subject_id": "stable-subject-7",
                    "access_tier": "registered",
                },
                "approve_federated_user",
            ),
            ("set-active", {"is_active": "false"}, "set_user_active"),
            ("set-tier", {"access_tier": "vetted"}, "update_access_tier"),
            ("set-admin", {"is_admin": "false"}, "set_user_admin"),
            ("change-email", {"new_email": "new@uzh.ch"}, "stage_admin_email_change"),
        ],
        ids=(
            "approve_federated",
            "set_active",
            "set_tier",
            "set_admin",
            "change_email",
        ),
    )
    def test_membership_rejection_is_error_flash_without_success_audit(
        self, admin_client, path, form, service
    ):
        message = "Your administrator access changed. Please log in again."
        with (
            _patch(service, side_effect=AdminActionRejected(message)) as write,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            response = admin_client.post(
                f"/admin/users/7/{path}",
                data={**form, "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )
        assert response.status_code == 303
        write.assert_awaited_once()
        assert flash.await_args.args[2:] == (message, "error")
        audit.assert_not_called()

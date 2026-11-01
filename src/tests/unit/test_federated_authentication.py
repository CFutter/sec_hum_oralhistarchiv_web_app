"""Federated principal/login validation and administrator approval boundaries."""

from dataclasses import replace
from unittest.mock import create_autospec, patch

import pytest

from app.federation_contract import ENTITLEMENT_MAX_LENGTH
from app.services import federated_authentication as auth
from app.services import users
from app.services.federated_session_policy import REQUIRED_SHIBBOLETH_AUTHN_CONTEXT
from config import settings
from tests.fixtures import (
    FakeCursorCtx,
    make_async_cursor,
    make_mock_pool,
    make_sample_user,
    make_sample_user_row,
)

ISSUER = "https://idp.example.org/idp/shibboleth"
SUBJECT = "stable-subject-7"


def principal(**overrides) -> auth.FederatedPrincipal:
    """Return a trusted synthetic principal with explicit attribute overrides."""
    values = {
        "issuer": ISSUER,
        "subject_id": "stable-subject-1",
        "email": "person@example.org",
        "authn_context": REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
        "display_name": "Person",
    }
    values.update(overrides)
    return auth.FederatedPrincipal(**values)


def _healthy_actor_row() -> dict[str, object]:
    """The row `guard_current_admin_session_cur` reads for the acting administrator.

    A local admin with an active, unused recovery-code generation passes the
    recovery-configuration guard (users.py, ``guard_current_admin_session_cur``).
    """
    return {
        "is_active": True,
        "is_admin": True,
        "auth_method": "local",
        "totp_secret": "encrypted-secret",
        "totp_recovery_code_generation": 1,
        "recovery_codes_available": True,
    }


class TestFederatedPrincipalBuilder:
    """build_federated_principal validates raw headers and normalizes profile fields."""

    def test_builder_preserves_security_values_and_normalizes_profile(self):
        """Builder preserves security values and normalizes profile."""
        result = auth.build_federated_principal(
            issuer=ISSUER,
            subject_id="Opaque-Subject",
            email=" Person@Example.ORG ",
            authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
            display_name=" Person Name ",
            affiliation=" Research Group ",
            country=" CH ",
            entitlement=r" urn:example:researcher;urn:example:escaped\;value ",
        )

        assert result == auth.FederatedPrincipal(
            issuer=ISSUER,
            subject_id="Opaque-Subject",
            email="person@example.org",
            authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
            display_name="Person Name",
            affiliation="Research Group",
            country="CH",
            entitlement=r"urn:example:researcher;urn:example:escaped\;value",
        )

    @pytest.mark.parametrize(
        "profile",
        [
            "\nPerson\n",
            "Person\u202ewith-bidi-control",
            "x" * 201,
        ],
        ids=["embedded_newlines", "bidi_control_character", "over_length"],
    )
    def test_builder_rejects_unsafe_raw_profile_values(self, profile):
        """Builder rejects unsafe raw profile values."""
        with pytest.raises(auth.InvalidFederatedPrincipal):
            auth.build_federated_principal(
                issuer=ISSUER,
                subject_id="Opaque-Subject",
                email="person@example.org",
                authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
                display_name=profile,
            )


class TestFinalizeShibbolethLoginSink:
    """finalize_shibboleth_login re-enforces issuer/MFA policy at the write sink."""

    @pytest.fixture(autouse=True)
    def trusted_issuer(self, monkeypatch):
        """Enable federation and trust the synthetic issuer for the test."""
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER])

    @pytest.fixture(autouse=True)
    def current_federation_policy(self):
        """Opt into the already-reconciled startup invariant by default."""
        with (
            patch.object(
                auth,
                "federation_policy_is_current_cur",
                autospec=True,
                return_value=True,
            ) as current,
            patch.object(auth, "record_federated_review_cur", autospec=True),
        ):
            yield current

    async def test_disabled_flag_is_rejected_without_database(self, monkeypatch):
        """Disabled flag is rejected without database."""
        monkeypatch.setattr(settings, "shibboleth_enabled", False)
        with patch.object(auth, "get_db_cursor", autospec=True) as acquire:
            result = await auth.finalize_shibboleth_login(
                make_mock_pool(), principal=principal(), ip_address="127.0.0.1"
            )

        assert result == auth.FederatedLoginFailure("untrusted_assertion")
        acquire.assert_not_called()

    async def test_nonprincipal_object_is_rejected_without_database(self):
        """Nonprincipal object is rejected without database."""
        with patch.object(auth, "get_db_cursor", autospec=True) as acquire:
            result = await auth.finalize_shibboleth_login(
                make_mock_pool(),
                principal=object(),
                ip_address="127.0.0.1",
            )

        assert result == auth.FederatedLoginFailure("untrusted_assertion")
        acquire.assert_not_called()

    async def test_stale_policy_aborts_before_provisioning_or_session_write(
        self, current_federation_policy
    ):
        """Stale policy aborts before provisioning or session write."""
        cur = make_async_cursor()
        current_federation_policy.return_value = False
        with (
            patch.object(auth, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            patch.object(auth, "create_shibboleth_user_cur", autospec=True) as provision,
            patch.object(auth, "create_session_cur", autospec=True) as issue,
        ):
            result = await auth.finalize_shibboleth_login(
                make_mock_pool(),
                principal=principal(),
                ip_address="127.0.0.1",
            )

        assert result == auth.FederatedLoginFailure("untrusted_assertion")
        current_federation_policy.assert_awaited_once_with(cur)
        provision.assert_not_awaited()
        issue.assert_not_awaited()
        cur.execute.assert_not_awaited()

    async def test_inactive_profile_never_reaches_login_writes(self):
        """Inactive profile never reaches login writes."""
        user = make_sample_user(
            auth_method="shibboleth",
            is_active=False,
            federated_status="pending",
        )
        cur = make_async_cursor()
        with (
            patch.object(auth, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            patch.object(auth, "create_shibboleth_user_cur", autospec=True, return_value=user),
            patch.object(auth, "create_session_cur", autospec=True) as issue,
        ):
            result = await auth.finalize_shibboleth_login(
                make_mock_pool(), principal=principal(email=user.email), ip_address="127.0.0.1"
            )
        assert result == auth.FederatedLoginFailure("inactive_account", user)
        issue.assert_not_awaited()
        cur.execute.assert_not_awaited()

    async def test_success_uses_shared_cursor_and_authoritative_row(self):
        """Success uses shared cursor and authoritative row."""
        user = make_sample_user(auth_method="shibboleth", federated_status="approved")
        row = make_sample_user_row(
            auth_method="shibboleth",
            display_name="Fresh name",
            federated_status="approved",
        )
        cur = make_async_cursor(fetchone=row)
        with (
            patch.object(
                auth, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)
            ) as acquire,
            patch.object(
                auth, "create_shibboleth_user_cur", autospec=True, return_value=user
            ) as provision,
            patch.object(
                auth, "create_session_cur", autospec=True, return_value="raw-token"
            ) as issue,
        ):
            result = await auth.finalize_shibboleth_login(
                make_mock_pool(), principal=principal(email=user.email), ip_address="127.0.0.1"
            )
        acquire.assert_called_once()
        assert provision.await_args.args == (cur,)
        assert provision.await_args.kwargs["issuer"] == ISSUER
        assert provision.await_args.kwargs["subject_id"] == "stable-subject-1"
        assert issue.await_args.args == (cur,)
        assert issue.await_args.kwargs["purpose"] == "full"
        assert result.user.display_name == "Fresh name"
        assert result.session_id == "raw-token"
        assert "raw-token" not in repr(result)

    async def test_session_failure_propagates_out_of_transaction(self):
        """Session failure propagates out of transaction."""
        user = make_sample_user(auth_method="shibboleth", federated_status="approved")
        cur = make_async_cursor(
            fetchone=make_sample_user_row(
                auth_method="shibboleth",
                federated_status="approved",
            )
        )
        with (
            patch.object(auth, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            patch.object(auth, "create_shibboleth_user_cur", autospec=True, return_value=user),
            patch.object(
                auth, "create_session_cur", autospec=True, side_effect=RuntimeError("insert failed")
            ),
            pytest.raises(RuntimeError, match="insert failed"),
        ):
            await auth.finalize_shibboleth_login(
                make_mock_pool(), principal=principal(email=user.email), ip_address="127.0.0.1"
            )

    @pytest.mark.parametrize("status", [None, "pending", "disabled", "unsupported"])
    async def test_only_approved_federated_status_can_reach_session_issue(self, status):
        # Deliberately model a corrupt/inconsistent read. The shared factory
        # keeps normal rows schema-coherent and would otherwise force these
        # states inactive, letting the is_active guard mask a missing status
        # check.
        """Only approved federated status can reach session issue."""
        user = replace(
            make_sample_user(auth_method="shibboleth", federated_status="approved"),
            is_active=True,
            federated_status=status,
        )
        cur = make_async_cursor()
        with (
            patch.object(auth, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            patch.object(auth, "create_shibboleth_user_cur", autospec=True, return_value=user),
            patch.object(auth, "create_session_cur", autospec=True) as issue,
        ):
            result = await auth.finalize_shibboleth_login(
                make_mock_pool(), principal=principal(email=user.email), ip_address="127.0.0.1"
            )

        assert result == auth.FederatedLoginFailure("inactive_account", user)
        issue.assert_not_awaited()
        cur.execute.assert_not_awaited()

    @pytest.mark.parametrize(
        "untrusted",
        [
            principal(issuer="https://other.example.org/idp"),
            principal(issuer=f"{ISSUER}/child"),
            principal(issuer=ISSUER.upper()),
            principal(
                authn_context=("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
            ),
            principal(authn_context=f"{REQUIRED_SHIBBOLETH_AUTHN_CONTEXT},password"),
            principal(authn_context=f"{REQUIRED_SHIBBOLETH_AUTHN_CONTEXT} "),
        ],
        ids=[
            "different_issuer",
            "issuer_with_path_suffix",
            "issuer_case_mismatch",
            "authn_context_below_required_assurance",
            "authn_context_with_trailing_value",
            "authn_context_trailing_whitespace",
        ],
    )
    async def test_untrusted_principal_is_rejected_before_database_access(self, untrusted):
        """Untrusted principal is rejected before database access."""
        with patch.object(auth, "get_db_cursor", autospec=True) as acquire:
            result = await auth.finalize_shibboleth_login(
                make_mock_pool(), principal=untrusted, ip_address="127.0.0.1"
            )
        assert result == auth.FederatedLoginFailure("untrusted_assertion")
        acquire.assert_not_called()

    @pytest.mark.parametrize(
        "invalid",
        [
            principal(issuer=f" {ISSUER}"),
            principal(issuer=f"{ISSUER} "),
            principal(subject_id=" stable-subject-1"),
            principal(subject_id="stable-subject-1 "),
            principal(subject_id="stable-subject-1,attacker-subject"),
            principal(authn_context=f" {REQUIRED_SHIBBOLETH_AUTHN_CONTEXT}"),
            principal(authn_context=f"{REQUIRED_SHIBBOLETH_AUTHN_CONTEXT},password"),
            principal(email="not-an-email"),
            principal(email=" Person@Example.org "),
            principal(email="Person@Example.org"),
            principal(display_name=" Person "),
            principal(entitlement=" urn:example:member "),
            principal(entitlement="x" * (ENTITLEMENT_MAX_LENGTH + 1)),
            principal(entitlement="urn:example:\u202emember"),
        ],
        ids=[
            "issuer_leading_whitespace",
            "issuer_trailing_whitespace",
            "subject_leading_whitespace",
            "subject_trailing_whitespace",
            "subject_comma_ambiguous",
            "authn_context_leading_whitespace",
            "authn_context_comma_ambiguous",
            "email_not_an_email",
            "email_needs_normalization",
            "email_needs_lowercasing",
            "display_name_needs_normalization",
            "entitlement_needs_normalization",
            "entitlement_oversized",
            "entitlement_nonprintable",
        ],
    )
    async def test_noncanonical_or_invalid_principal_is_rejected_before_database(self, invalid):
        """Noncanonical or invalid principal is rejected before database."""
        with patch.object(auth, "get_db_cursor", autospec=True) as acquire:
            result = await auth.finalize_shibboleth_login(
                make_mock_pool(), principal=invalid, ip_address="127.0.0.1"
            )

        assert result == auth.FederatedLoginFailure("untrusted_assertion")
        acquire.assert_not_called()


class TestUserProvisioningIdentityExactness:
    """create_shibboleth_user_cur revalidates the opaque identity at the write boundary."""

    @pytest.mark.parametrize(
        ("issuer", "subject_id"),
        [
            (f" {ISSUER}", "stable-subject-1"),
            (f"{ISSUER} ", "stable-subject-1"),
            (ISSUER, " stable-subject-1"),
            (ISSUER, "stable-subject-1 "),
            (f"{ISSUER},https://other.example/idp", "stable-subject-1"),
            (ISSUER, "stable-subject-1,attacker-subject"),
        ],
        ids=[
            "issuer_leading_whitespace",
            "issuer_trailing_whitespace",
            "subject_leading_whitespace",
            "subject_trailing_whitespace",
            "issuer_comma_ambiguous",
            "subject_comma_ambiguous",
        ],
    )
    async def test_provisioning_rejects_nonexact_identity_without_query(self, issuer, subject_id):
        """Provisioning rejects nonexact identity without query."""
        cur = make_async_cursor()

        result = await users.create_shibboleth_user_cur(
            cur,
            issuer=issuer,
            subject_id=subject_id,
            email="person@example.org",
        )

        assert result is None
        cur.execute.assert_not_awaited()

    async def test_provisioning_queries_for_exact_identity(self):
        """Provisioning queries for exact identity."""
        cur = make_async_cursor(
            fetchone=make_sample_user_row(auth_method="shibboleth", federated_status="pending")
        )

        result = await users.create_shibboleth_user_cur(
            cur,
            issuer=ISSUER,
            subject_id="stable-subject-1",
            email="person@example.org",
        )

        cur.execute.assert_awaited_once()
        assert result is not None


class TestFederatedAdminApproval:
    """approve_federated_user activates one exact pending identity atomically."""

    @pytest.fixture(autouse=True)
    def enabled_trusted_federation(self, monkeypatch):
        """Enable trusted federation and return the signature-checked current-policy double."""
        monkeypatch.setattr(users.settings, "shibboleth_enabled", True)
        monkeypatch.setattr(users.settings, "shibboleth_trusted_issuers", [ISSUER])
        current_policy = create_autospec(users.federation_policy_is_current_cur, return_value=True)
        monkeypatch.setattr(
            users,
            "federation_policy_is_current_cur",
            current_policy,
        )
        return current_policy

    async def test_atomically_binds_pending_identity_tier_and_actor(self):
        """Atomically binds pending identity tier and actor."""
        approved_row = make_sample_user_row(
            id=7,
            auth_method="shibboleth",
            access_tier="vetted",
            federated_status="approved",
            reviewed_proposal=None,
        )
        cur = make_async_cursor(
            fetchone=[
                _healthy_actor_row(),
                {"exists": 1},
                approved_row,
            ]
        )

        with patch.object(users, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)):
            approved = await users.approve_federated_user(
                make_mock_pool(),
                7,
                expected_issuer=ISSUER,
                expected_subject_id=SUBJECT,
                expected_review_revision=1,
                access_tier="vetted",
                actor_id=99,
                actor_session_id="resolved-admin-session",
            )

        assert approved.user.id == 7
        assert approved.user.federated_status == "approved"
        assert approved.user.is_active is True
        assert approved.user.access_tier == "vetted"
        assert approved.user.is_admin is False
        assert approved.user.email_verified is False

        update = cur.execute.await_args_list[3]
        statement = str(update.args[0])
        assert "federated_status = 'pending'" in statement
        assert "shibboleth_issuer = %(expected_issuer)s" in statement
        assert "shibboleth_subject_id = %(expected_subject_id)s" in statement
        assert "federated_status = 'approved'" in statement
        assert "federated_approved_at = clock_timestamp()" in statement
        assert "federated_approved_by = %(actor_id)s" in statement
        assert "is_admin = false" in statement
        assert "email_verified = false" in statement
        assert "auth_revision = auth_revision + 1" in statement
        assert update.args[1] == {
            "user_id": 7,
            "expected_issuer": ISSUER,
            "expected_subject_id": SUBJECT,
            "expected_review_revision": 1,
            "access_tier": "vetted",
            "actor_id": 99,
        }
        revoke = cur.execute.await_args_list[4]
        assert "DELETE FROM sessions WHERE user_id = %s" in str(revoke.args[0])
        assert revoke.args[1] == (7,)

    @pytest.mark.parametrize(
        ("enabled", "trusted_issuers"),
        [
            (False, [ISSUER]),
            (True, []),
            (True, ["https://different-idp.example.org/idp/shibboleth"]),
        ],
        ids=["federation_disabled", "no_trusted_issuers", "issuer_not_trusted"],
    )
    async def test_refuses_disabled_or_untrusted_federation_before_db(
        self, monkeypatch, enabled, trusted_issuers
    ):
        """Refuses disabled or untrusted federation before database."""
        monkeypatch.setattr(users.settings, "shibboleth_enabled", enabled)
        monkeypatch.setattr(users.settings, "shibboleth_trusted_issuers", trusted_issuers)

        with (
            patch.object(users, "get_db_cursor", autospec=True) as db,
            pytest.raises(users.AdminActionRejected, match="approval request is invalid"),
        ):
            await users.approve_federated_user(
                make_mock_pool(),
                7,
                expected_issuer=ISSUER,
                expected_subject_id=SUBJECT,
                expected_review_revision=1,
                access_tier="registered",
                actor_id=99,
                actor_session_id="resolved-admin-session",
            )

        db.assert_not_called()

    async def test_refuses_stale_persisted_policy_before_admin_or_user_write(
        self, enabled_trusted_federation
    ):
        """Refuses stale persisted policy before admin or user write."""
        enabled_trusted_federation.return_value = False
        cur = make_async_cursor()

        with (
            patch.object(users, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            pytest.raises(users.AdminActionRejected, match="federation policy changed"),
        ):
            await users.approve_federated_user(
                make_mock_pool(),
                7,
                expected_issuer=ISSUER,
                expected_subject_id=SUBJECT,
                expected_review_revision=1,
                access_tier="registered",
                actor_id=99,
                actor_session_id="resolved-admin-session",
            )

        enabled_trusted_federation.assert_awaited_once_with(cur)
        cur.execute.assert_not_awaited()

    @pytest.mark.parametrize(
        ("issuer", "subject"),
        [
            (f" {ISSUER}", SUBJECT),
            (ISSUER, f"{SUBJECT} "),
            (f"{ISSUER},https://other.example/idp", SUBJECT),
        ],
        ids=["issuer_leading_whitespace", "subject_trailing_whitespace", "issuer_comma_ambiguous"],
    )
    async def test_never_normalizes_or_accepts_ambiguous_identity(self, issuer, subject):
        """Never normalizes or accepts ambiguous identity."""
        with (
            patch.object(users, "get_db_cursor", autospec=True) as db,
            pytest.raises(users.AdminActionRejected, match="approval request is invalid"),
        ):
            await users.approve_federated_user(
                make_mock_pool(),
                7,
                expected_issuer=issuer,
                expected_subject_id=subject,
                expected_review_revision=1,
                access_tier="public",
                actor_id=99,
                actor_session_id="resolved-admin-session",
            )

        db.assert_not_called()

    async def test_stale_or_mismatched_identity_cannot_be_approved(self):
        """Stale or mismatched identity cannot be approved."""
        cur = make_async_cursor(
            fetchone=[
                _healthy_actor_row(),
                {"exists": 1},
                None,
                {"exists": 1},
            ]
        )
        with (
            patch.object(users, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            pytest.raises(users.AdminActionRejected, match="no longer pending"),
        ):
            await users.approve_federated_user(
                make_mock_pool(),
                7,
                expected_issuer=ISSUER,
                expected_subject_id=SUBJECT,
                expected_review_revision=1,
                access_tier="registered",
                actor_id=99,
                actor_session_id="resolved-admin-session",
            )


class TestNonApprovalPathsCannotBypassFederatedReview:
    """Generic membership and promotion paths never substitute for federated review."""

    @pytest.fixture(autouse=True)
    def enabled_trusted_federation(self, monkeypatch):
        """Enable trusted federation and return the signature-checked current-policy double."""
        monkeypatch.setattr(users.settings, "shibboleth_enabled", True)
        monkeypatch.setattr(users.settings, "shibboleth_trusted_issuers", [ISSUER])
        current_policy = create_autospec(users.federation_policy_is_current_cur, return_value=True)
        monkeypatch.setattr(
            users,
            "federation_policy_is_current_cur",
            current_policy,
        )
        return current_policy

    @pytest.mark.parametrize("status", ["pending", "unsupported", None])
    @pytest.mark.parametrize("operation", ["activate", "tier"])
    async def test_generic_membership_paths_reject_unapproved_federated_state(
        self, status, operation
    ):
        """Activation and access-tier changes cannot bypass federated review."""
        cur = make_async_cursor(
            fetchone=[
                _healthy_actor_row(),
                {"exists": 1},
                {
                    "is_active": False,
                    "is_admin": False,
                    "auth_method": "shibboleth",
                    "federated_status": status,
                    "access_tier": "public",
                },
            ]
        )

        async def invoke():
            """Activate or raise the test account tier using the fixed administrator session."""
            common = {
                "actor_id": 99,
                "actor_session_id": "resolved-admin-session",
            }
            if operation == "activate":
                return await users.set_user_active(make_mock_pool(), 7, True, **common)
            return await users.update_access_tier(make_mock_pool(), 7, "registered", **common)

        with (
            patch.object(users, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            pytest.raises(users.AdminActionRejected, match="dedicated federated-review"),
        ):
            await invoke()

        assert len(cur.execute.await_args_list) == 4

    @pytest.mark.parametrize("operation", ["activate", "tier"])
    async def test_generic_membership_paths_permit_an_approved_federated_state(self, operation):
        """Generic membership paths permit an approved federated state."""
        target_row = {
            "is_active": False,
            "is_admin": False,
            "auth_method": "shibboleth",
            "federated_status": "approved",
            "access_tier": "public",
        }
        final_row = (
            {"old_value": False, "new_value": True, "lock_cleared": False}
            if operation == "activate"
            else {"new_value": "registered"}
        )
        cur = make_async_cursor(
            fetchone=[_healthy_actor_row(), {"exists": 1}, target_row, final_row]
        )

        async def invoke():
            """Activate or raise the test account tier using the fixed administrator session."""
            common = {
                "actor_id": 99,
                "actor_session_id": "resolved-admin-session",
            }
            if operation == "activate":
                return await users.set_user_active(make_mock_pool(), 7, True, **common)
            return await users.update_access_tier(make_mock_pool(), 7, "registered", **common)

        with patch.object(users, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)):
            result = await invoke()

        executed_sql = [str(call.args[0]) for call in cur.execute.await_args_list]
        if operation == "activate":
            assert result == users.SetActiveResult(False, True, False)
            assert any("SET is_active = true" in sql for sql in executed_sql)
        else:
            assert result == ("public", "registered")
            assert any("SET access_tier" in sql for sql in executed_sql)

    async def test_admin_grant_is_rejected_by_the_promotion_workflow_before_any_federation_check(
        self,
    ):
        """Admin grant is rejected by the promotion workflow before any federation check."""
        with (
            patch.object(users, "get_db_cursor", autospec=True) as db,
            pytest.raises(
                users.AdminActionRejected,
                match="offered and accepted through the promotion workflow",
            ),
        ):
            await users.set_user_admin(
                make_mock_pool(),
                7,
                True,
                actor_id=99,
                actor_session_id="resolved-admin-session",
            )

        db.assert_not_called()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        ("urn:example:member", "urn:example:member"),
        ("x" * ENTITLEMENT_MAX_LENGTH, "x" * ENTITLEMENT_MAX_LENGTH),
    ],
    ids=["absent", "empty", "blank", "opaque-value", "maximum-length"],
)
def test_builder_preserves_bounded_optional_entitlement(raw, expected):
    """Builder preserves bounded optional entitlement."""
    result = auth.build_federated_principal(
        issuer=ISSUER,
        subject_id="Opaque-Subject",
        email="person@example.org",
        authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
        entitlement=raw,
    )

    assert result.entitlement == expected


@pytest.mark.parametrize(
    "raw",
    [
        1,
        True,
        [],
        "urn:example:member\n",
        "urn:example:\u202emember",
        "x" * (ENTITLEMENT_MAX_LENGTH + 1),
        " " + "x" * ENTITLEMENT_MAX_LENGTH,
    ],
    ids=["integer", "boolean", "list", "newline", "bidi", "oversized", "raw-bound"],
)
def test_builder_rejects_unsafe_entitlement_before_normalization(raw):
    """Builder rejects unsafe entitlement before normalization."""
    with pytest.raises(auth.InvalidFederatedPrincipal, match="entitlement:"):
        auth.build_federated_principal(
            issuer=ISSUER,
            subject_id="Opaque-Subject",
            email="person@example.org",
            authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
            entitlement=raw,
        )


@pytest.mark.parametrize(
    "review_revision", [None, True, False, "1", 0, -1, 9_223_372_036_854_775_808]
)
async def test_invalid_review_revision_cannot_reach_the_database(monkeypatch, review_revision):
    """Invalid review revision cannot reach the database."""
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER])
    with (
        patch.object(users, "get_db_cursor", autospec=True) as acquire,
        pytest.raises(users.AdminActionRejected, match="approval request is invalid"),
    ):
        await users.approve_federated_user(
            make_mock_pool(),
            7,
            expected_issuer=ISSUER,
            expected_subject_id=SUBJECT,
            expected_review_revision=review_revision,
            access_tier="vetted",
            actor_id=99,
            actor_session_id="resolved-admin-session",
        )
    acquire.assert_not_called()

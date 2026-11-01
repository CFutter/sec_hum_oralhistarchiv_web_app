"""Federation policy fingerprints, startup revocation and live session eligibility."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from app.services import federated_session_policy as policy
from app.services import sessions
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_sample_user_row

ISSUER_A = "https://idp-a.example.org/idp/shibboleth"
ISSUER_B = "https://idp-b.example.org/idp/shibboleth"
SECRET_A = "Xpsp9j2Hn8DwvzBEPi9ivWneKjPxbGuQxoWYgRrNj_QTgX_gz9wJL65s82RJJJwz"
SECRET_B = "Bvn3v2uTyRLeUmRGXuGTt4IbjaAwhivCcwpDBKlqiuLbWrMqPP2AzUQs6wtawK3C"

TRUSTED_ISSUER = "https://idp.example.org/idp/shibboleth"
OTHER_ISSUER = "https://other-idp.example.org/idp/shibboleth"


class TestPolicyFingerprint:
    """Fingerprint session-authorizing settings independently of ordering without exposing secrets."""

    def test_fingerprint_is_order_independent_but_covers_callback_secret(self, monkeypatch):
        """Fingerprint is order independent but covers callback secret."""
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER_B, ISSUER_A])
        monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET_A))

        first = policy.federated_session_policy_fingerprint()
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER_A, ISSUER_B])
        reordered = policy.federated_session_policy_fingerprint()
        monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET_B))
        rotated = policy.federated_session_policy_fingerprint()

        assert reordered == first
        assert rotated != first
        assert len(first) == 64
        assert SECRET_A not in first

    def test_flag_and_trusted_issuer_changes_change_fingerprint(self, monkeypatch):
        """Flag and trusted issuer changes change fingerprint."""
        monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET_A))
        monkeypatch.setattr(settings, "shibboleth_enabled", False)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER_A])
        disabled = policy.federated_session_policy_fingerprint()

        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        enabled = policy.federated_session_policy_fingerprint()
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER_B])
        issuer_changed = policy.federated_session_policy_fingerprint()

        assert len({disabled, enabled, issuer_changed}) == 3

    def test_code_policy_version_and_mfa_context_change_fingerprint(self, monkeypatch):
        """Code policy version and mfa context change fingerprint."""
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER_A])
        monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET_A))
        baseline = policy.federated_session_policy_fingerprint()

        monkeypatch.setattr(
            policy,
            "REQUIRED_SHIBBOLETH_AUTHN_CONTEXT",
            "https://example.invalid/reviewed-replacement-mfa",
        )
        changed_context = policy.federated_session_policy_fingerprint()
        monkeypatch.setattr(policy, "FEDERATED_SESSION_POLICY_VERSION", 2)
        changed_version = policy.federated_session_policy_fingerprint()

        assert baseline != changed_context
        assert changed_context != changed_version


class TestSessionIssuePolicyCheck:
    """``federation_policy_is_current_cur`` gates new federated session
    issuance: only an exact ASCII digest match is current, everything else
    fails closed.
    """

    @pytest.mark.parametrize(
        ("persisted_row", "expected"),
        [
            ({"fingerprint": "expected-digest"}, True),
            (None, False),
            ({"fingerprint": "stale-digest"}, False),
            ({"fingerprint": 123}, False),
            ({"fingerprint": "malformed-é"}, False),
        ],
        ids=["exact", "missing", "mismatch", "malformed", "non-ascii"],
    )
    async def test_session_issue_policy_check_is_exact_and_fail_closed(
        self,
        monkeypatch,
        persisted_row,
        expected,
    ):
        """Session issue policy check is exact and fail closed."""
        cur = make_async_cursor(fetchone=persisted_row)
        monkeypatch.setattr(
            policy,
            "federated_session_policy_fingerprint",
            lambda: "expected-digest",
        )

        result = await policy.federation_policy_is_current_cur(cur)

        assert result is expected
        cur.execute.assert_awaited_once_with(
            "SELECT fingerprint FROM federation_policy_state WHERE id = 1 FOR SHARE"
        )


def _policy_cursor(*, stored: str | None, delete_count: int = 0, update_count: int = 1):
    """Return a fake policy cursor with configurable fingerprint and mutation counts."""
    cur = MagicMock(name="policy_cursor")
    cur.fetchone = AsyncMock(return_value=None if stored is None else {"fingerprint": stored})
    cur.rowcount = 0

    async def execute(query, _params=None):
        """Set rowcount for session deletion or policy-fingerprint updates."""
        query_text = str(query)
        if "DELETE FROM sessions" in query_text:
            cur.rowcount = delete_count
        elif "UPDATE federation_policy_state" in query_text:
            cur.rowcount = update_count

    cur.execute = AsyncMock(side_effect=execute)
    return cur


class TestPolicyReconciliationAtStartup:
    """Revoke Shibboleth sessions on policy change and fail startup on inconsistent policy state."""

    async def test_changed_or_first_start_policy_revokes_before_recording_fingerprint(
        self,
        monkeypatch,
    ):
        """Changed or first start policy revokes before recording fingerprint."""
        cur = _policy_cursor(stored="", delete_count=3)
        monkeypatch.setattr(policy, "federated_session_policy_fingerprint", lambda: "new-digest")

        with patch.object(policy, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)):
            revoked = await policy.reconcile_federated_session_policy(object())

        assert revoked == 3
        sql_calls = [str(item.args[0]) for item in cur.execute.await_args_list]
        assert "INSERT INTO federation_policy_state" in sql_calls[0]
        assert "FOR UPDATE" in sql_calls[1]
        assert "DELETE FROM sessions" in sql_calls[2]
        assert "users.auth_method = 'shibboleth'" in sql_calls[2]
        assert "UPDATE federation_policy_state" in sql_calls[3]
        assert cur.execute.await_args_list[3].args[1] == ("new-digest",)

    async def test_callback_secret_rotation_drives_session_revocation(self, monkeypatch):
        """Callback secret rotation drives session revocation."""
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER_A])
        monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET_A))
        before_rotation = policy.federated_session_policy_fingerprint()
        monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET_B))
        after_rotation = policy.federated_session_policy_fingerprint()
        cur = _policy_cursor(stored=before_rotation, delete_count=4)

        with patch.object(policy, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)):
            revoked = await policy.reconcile_federated_session_policy(object())

        assert after_rotation != before_rotation
        assert revoked == 4
        assert "DELETE FROM sessions" in str(cur.execute.await_args_list[2].args[0])
        assert cur.execute.await_args_list[3].args[1] == (after_rotation,)

    async def test_unchanged_policy_does_not_revoke(self, monkeypatch):
        """Unchanged policy does not revoke."""
        cur = _policy_cursor(stored="same-digest")
        monkeypatch.setattr(policy, "federated_session_policy_fingerprint", lambda: "same-digest")

        with patch.object(policy, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)):
            revoked = await policy.reconcile_federated_session_policy(object())

        assert revoked == 0
        sql_calls = [str(item.args[0]) for item in cur.execute.await_args_list]
        assert len(sql_calls) == 2
        assert not any("DELETE FROM sessions" in query for query in sql_calls)

    async def test_missing_singleton_after_insert_aborts_startup(self, monkeypatch):
        """Missing singleton after insert aborts startup."""
        cur = _policy_cursor(stored=None)
        monkeypatch.setattr(policy, "federated_session_policy_fingerprint", lambda: "digest")

        with (
            patch.object(policy, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            pytest.raises(RuntimeError, match="singleton is missing"),
        ):
            await policy.reconcile_federated_session_policy(object())

    async def test_failed_policy_state_update_aborts_startup(self, monkeypatch):
        """Failed policy state update aborts startup."""
        cur = _policy_cursor(stored="old", delete_count=2, update_count=0)
        monkeypatch.setattr(policy, "federated_session_policy_fingerprint", lambda: "new")

        with (
            patch.object(policy, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            pytest.raises(RuntimeError, match="could not be updated"),
        ):
            await policy.reconcile_federated_session_policy(object())


def _session_row(
    *,
    auth_method="shibboleth",
    active=True,
    status="approved",
    issuer=TRUSTED_ISSUER,
):
    """Build a full-session row with the requested local/federated authority state."""
    row = make_sample_user_row(
        auth_method=auth_method,
        is_active=active,
        email_verified=auth_method == "local",
        shibboleth_issuer=issuer if auth_method == "shibboleth" else None,
        shibboleth_subject_id=("urn:test:subject:alice" if auth_method == "shibboleth" else None),
        federated_status=status if auth_method == "shibboleth" else None,
        federated_approved_at=None,
        federated_approved_by=None,
    )
    row.update(
        {
            "purpose": "full",
            "flash_present": False,
            "session_auth_method": auth_method,
            "session_user_active": active,
            "session_federated_status": status,
            "session_shibboleth_issuer": issuer,
        }
    )
    return row


async def _lookup(row, *, activity_due=False):
    """Resolve a fake session and return lookup plus cursor, optionally exercising activity refresh."""
    now = datetime(2031, 1, 1, tzinfo=UTC)
    if activity_due:
        activity_rows = [
            {
                "expires_at": now + timedelta(hours=1),
                "last_activity_at": now - timedelta(minutes=2),
            },
            {"database_now": now},
            {"id": "stored-session-hash"},
        ]
    else:
        activity_rows = [None, {"id": "stored-session-hash"}]
    cur = make_async_cursor(fetchone=[row, *activity_rows])
    with patch.object(sessions, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)):
        lookup = await sessions.get_session_user(object(), "raw-session-token")
    return lookup, cur


class TestLiveSessionAuthorityAtLookup:
    """Recheck current federation eligibility on every session lookup."""

    @pytest.mark.parametrize("activity_due", [False, True])
    async def test_approved_session_from_exact_trusted_issuer_resolves(
        self, monkeypatch, activity_due
    ):
        """Approved session from exact trusted issuer resolves."""
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [TRUSTED_ISSUER])

        lookup, cur = await _lookup(_session_row(), activity_due=activity_due)

        assert lookup.user is not None
        assert lookup.user.auth_method == "shibboleth"
        assert cur.execute.await_count == (4 if activity_due else 3)
        updates = [
            call
            for call in cur.execute.await_args_list
            if "UPDATE sessions SET last_activity_at" in str(call.args[0])
        ]
        assert len(updates) == int(activity_due)

    @pytest.mark.parametrize(
        ("enabled", "active", "status", "issuer"),
        [
            (False, True, "approved", TRUSTED_ISSUER),
            (True, False, "approved", TRUSTED_ISSUER),
            (True, False, "pending", TRUSTED_ISSUER),
            (True, False, "disabled", TRUSTED_ISSUER),
            (True, True, "unsupported", TRUSTED_ISSUER),
            (True, True, "approved", OTHER_ISSUER),
            (True, True, "approved", f"{TRUSTED_ISSUER}/child"),
            (True, True, "approved", TRUSTED_ISSUER.upper()),
        ],
        ids=[
            "federation_disabled_rejects_otherwise_valid_session",
            "inactive_user_with_approved_status",
            "inactive_user_with_pending_status",
            "inactive_user_with_disabled_status",
            "active_user_with_unknown_status",
            "active_approved_but_untrusted_issuer",
            "active_approved_but_issuer_is_subpath_not_exact_match",
            "active_approved_but_issuer_case_differs_not_exact_match",
        ],
    )
    async def test_ineligible_federated_session_is_deleted_and_rejected(
        self,
        monkeypatch,
        enabled,
        active,
        status,
        issuer,
    ):
        """Ineligible federated session is deleted and rejected."""
        monkeypatch.setattr(settings, "shibboleth_enabled", enabled)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [TRUSTED_ISSUER])

        lookup, cur = await _lookup(_session_row(active=active, status=status, issuer=issuer))

        assert lookup == (None, None, False)
        assert cur.execute.await_count == 2
        delete_call = cur.execute.await_args_list[1]
        assert str(delete_call.args[0]) == "DELETE FROM sessions WHERE id = %s"

    @pytest.mark.parametrize("activity_due", [False, True])
    async def test_local_session_is_independent_of_federation_policy(
        self, monkeypatch, activity_due
    ):
        """Local session is independent of federation policy."""
        monkeypatch.setattr(settings, "shibboleth_enabled", False)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [])

        lookup, cur = await _lookup(
            _session_row(auth_method="local", active=True, status=None, issuer=None),
            activity_due=activity_due,
        )

        assert lookup.user is not None
        assert lookup.user.auth_method == "local"
        assert cur.execute.await_count == (4 if activity_due else 3)

    async def test_inactive_local_session_is_rejected_without_federation_delete(self, monkeypatch):
        """Inactive local session is rejected without federation delete."""
        monkeypatch.setattr(settings, "shibboleth_enabled", False)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [])

        lookup, cur = await _lookup(
            _session_row(auth_method="local", active=False, status=None, issuer=None)
        )

        assert lookup == (None, None, False)
        assert cur.execute.await_count == 1

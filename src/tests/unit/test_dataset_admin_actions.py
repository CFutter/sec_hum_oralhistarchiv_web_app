"""Committed dataset administration and attributable, metadata-free audit events."""

import json
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import create_autospec, sentinel

import pytest
from psycopg import AsyncCursor

from app import services
from app.services import audit, dataset_admin
from app.sources import FixtureConfig, SourceDisplay, configure_sources
from config.logging import JSONFormatter

_HIDDEN_AT = datetime(2026, 10, 18, 12, tzinfo=UTC)
_CONTEXT = dataset_admin.DatasetAdminContext(
    actor_id=13,
    actor_session_id="private-administrator-session-token",
    request_id="request-dataset-action",
    client_ip="203.0.113.9",
)


def _change(before=None, after=None, action="hide"):
    """Build an administrator change with action-dependent default before/after states."""
    if before is None:
        before = dataset_admin.DatasetAdminState(
            "public", None, _HIDDEN_AT if action == "restore" else None
        )
    if after is None:
        after = dataset_admin.DatasetAdminState(
            "public",
            "registered" if action == "raise_tier" else None,
            _HIDDEN_AT if action == "hide" else None,
        )
    return dataset_admin.DatasetAdminChange(
        dataset_id=29,
        source="archive_alpha",
        uuid="public-record-identifier",
        action=action,
        before=before,
        after=after,
    )


class _Capture(logging.Handler):
    """Capture audit records without formatting them."""

    def __init__(self):
        """Initialize the logging handler with an empty record buffer."""
        super().__init__()
        self.records = []

    def emit(self, record):
        """Append the record to the capture buffer."""
        self.records.append(record)


@pytest.fixture
def audit_records():
    """Capture the dedicated audit channel even when it does not propagate."""
    logger = logging.getLogger("audit")
    handler = _Capture()
    saved_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved_level)


def test_durable_override_changes_state_even_when_effective_tier_is_equal():
    """Durable override changes state even when effective tier is equal."""
    before = dataset_admin.DatasetAdminState("vetted", None, None)
    after = dataset_admin.DatasetAdminState("vetted", "vetted", None)
    change = _change(before, after, "raise_tier")
    assert before.effective_tier == after.effective_tier == "vetted"
    assert change.changed


def test_identical_admin_state_is_a_no_op():
    """Identical admin state is a no op."""
    state = dataset_admin.DatasetAdminState("public", None, _HIDDEN_AT)
    assert not _change(state, state).changed


def test_context_repr_never_exposes_the_session_credential():
    """Context repr never exposes the session credential."""
    assert _CONTEXT.actor_session_id not in repr(_CONTEXT)
    assert "actor_id=13" in repr(_CONTEXT)


@pytest.mark.parametrize(
    "name",
    [
        "DatasetAdminContext",
        "DatasetAdminState",
        "DatasetAdminChange",
        "change_dataset_admin_state",
    ],
)
def test_dataset_administration_uses_the_public_service_boundary(name):
    """Dataset administration uses the public service boundary."""
    assert name in services.__all__
    assert getattr(services, name) is getattr(dataset_admin, name)


@pytest.mark.parametrize(
    ("action", "event"),
    [
        ("raise_tier", "admin_dataset_tier_raised"),
        ("hide", "admin_dataset_hidden"),
        ("restore", "admin_dataset_restored"),
    ],
)
def test_audit_contains_exact_identity_and_safe_before_after_states(audit_records, action, event):
    """Audit contains exact identity and safe before after states."""
    change = _change(action=action)
    audit.audit_dataset_admin_action(change, _CONTEXT)
    assert len(audit_records) == 1
    payload = json.loads(JSONFormatter().format(audit_records[0]))
    assert payload["event_type"] == event
    identity = {
        "actor_admin_id": 13,
        "dataset_id": 29,
        "dataset_source": "archive_alpha",
        "dataset_uuid": "public-record-identifier",
        "request_id": _CONTEXT.request_id,
        "client_ip": _CONTEXT.client_ip,
    }
    assert {key: payload[key] for key in identity} == identity
    assert payload["before"] == {
        "stored_tier": "public",
        "admin_tier": None,
        "effective_tier": "public",
        "hidden_at": _HIDDEN_AT.isoformat() if action == "restore" else None,
    }
    assert payload["after"] == {
        "stored_tier": "public",
        "admin_tier": "registered" if action == "raise_tier" else None,
        "effective_tier": "registered" if action == "raise_tier" else "public",
        "hidden_at": _HIDDEN_AT.isoformat() if action == "hide" else None,
    }
    assert _CONTEXT.actor_session_id not in json.dumps(payload)
    assert "target_user_id" not in payload


def test_audit_helper_suppresses_unchanged_state(audit_records):
    """Audit helper suppresses unchanged state."""
    state = dataset_admin.DatasetAdminState("public", None, _HIDDEN_AT)
    audit.audit_dataset_admin_action(_change(state, state), _CONTEXT)
    assert audit_records == []


@pytest.fixture
def mutation(monkeypatch):
    """Run the real mutation with an explicit commit boundary and signature-checked SQL doubles."""
    real_cursor = dataset_admin.get_db_cursor
    real_audit = audit.audit_dataset_admin_action
    real_authorize = dataset_admin._authorize_cur
    real_lock = dataset_admin.acquire_catalogue_write_lock_cur
    real_policy = dataset_admin.federation_policy_is_current_cur

    def install(change=None, *, commit_error=None, write_error=None, authorization_error=None):
        """Patch mutation collaborators; return cursor, post-commit audit spy and lifecycle events."""
        change = change or _change()
        before, after = change.before, change.after
        lifecycle = []
        cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
        cursor.fetchone.side_effect = [
            {
                "id": 29,
                "source": change.source,
                "uuid": change.uuid,
                "visibility_tier": before.stored_tier,
                "record_tier": before.stored_tier,
            },
            None
            if before.admin_tier is None and before.hidden_at is None
            else {"visibility_tier": before.admin_tier, "hidden_at": before.hidden_at},
            {"visibility_tier": after.admin_tier, "hidden_at": after.hidden_at},
        ]

        async def execute(query, _params=None):
            """Raise write_error on INSERT/UPDATE when configured."""
            if str(query).lstrip().startswith(("INSERT", "UPDATE")) and write_error is not None:
                raise write_error

        cursor.execute.side_effect = execute

        @asynccontextmanager
        async def transaction(pool, _row_factory=None):
            """Yield the cursor and record commit/rollback, propagating configured failures."""
            assert pool is sentinel.pool
            try:
                yield cursor
            except BaseException:
                lifecycle.append("rollback")
                raise
            if commit_error is not None:
                lifecycle.append("rollback")
                raise commit_error
            lifecycle.append("commit")

        def committed_audit(result, context):
            """Require completed commit before calling the real audit publisher."""
            assert lifecycle == ["commit"], "change event escaped before commit completed"
            real_audit(result, context)

        spy = create_autospec(real_audit, side_effect=committed_audit, spec_set=True)
        replacements = {
            "get_db_cursor": create_autospec(real_cursor, side_effect=transaction, spec_set=True),
            "_authorize_cur": create_autospec(
                real_authorize, return_value=None, side_effect=authorization_error, spec_set=True
            ),
            "acquire_catalogue_write_lock_cur": create_autospec(
                real_lock, return_value=None, spec_set=True
            ),
            "federation_policy_is_current_cur": create_autospec(
                real_policy, return_value=False, spec_set=True
            ),
        }
        for name, replacement in replacements.items():
            monkeypatch.setattr(dataset_admin, name, replacement)
        monkeypatch.setattr(dataset_admin, "audit_dataset_admin_action", spy)
        return cursor, spy, lifecycle

    return install


@pytest.mark.parametrize("durable_floor", [False, True], ids=["hide", "durable-floor"])
async def test_service_audits_one_change_only_after_commit(mutation, audit_records, durable_floor):
    """Service audits one change only after commit."""
    change = _change()
    if durable_floor:
        change = _change(
            dataset_admin.DatasetAdminState("vetted", None, None),
            dataset_admin.DatasetAdminState("vetted", "vetted", None),
            "raise_tier",
        )
    cursor, spy, lifecycle = mutation(change)
    sources = configure_sources(
        (
            FixtureConfig(
                name="archive_alpha",
                max_visibility="public",
                display=SourceDisplay(label="Archive"),
            ),
        )
    )
    result = await dataset_admin.change_dataset_admin_state(
        sentinel.pool,
        29,
        change.action,
        context=_CONTEXT,
        new_tier="vetted" if durable_floor else None,
        configured_sources=sources,
    )
    assert result == change
    assert cursor.execute.await_args_list[0].args == (
        "SELECT id, source, uuid, stored_tier AS visibility_tier, record_tier "
        "FROM dataset_admin_catalogue WHERE id = %s",
        (29,),
    )
    assert lifecycle == ["commit"]
    spy.assert_called_once_with(change, _CONTEXT)
    assert len(audit_records) == 1
    assert "unpublished metadata" not in JSONFormatter().format(audit_records[0])


@pytest.mark.parametrize("failure", ["commit", "write"])
async def test_failed_transaction_emits_no_change_event(mutation, audit_records, failure):
    """Failed transaction emits no change event."""
    error = RuntimeError(f"{failure} failed")
    _, spy, lifecycle = mutation(**{f"{failure}_error": error})
    with pytest.raises(RuntimeError, match=f"{failure} failed"):
        await dataset_admin.change_dataset_admin_state(
            sentinel.pool, 29, "hide", context=_CONTEXT, configured_sources=()
        )
    assert lifecycle == ["rollback"]
    spy.assert_not_called()
    assert audit_records == []


async def test_rejected_authority_rolls_back_without_a_change_event(mutation, audit_records):
    """Rejected authority rolls back without a change event."""
    cursor, spy, lifecycle = mutation(
        authorization_error=dataset_admin.AdminActionRejected("administrator authority changed")
    )
    with pytest.raises(dataset_admin.AdminActionRejected, match="authority changed"):
        await dataset_admin.change_dataset_admin_state(
            sentinel.pool, 29, "hide", context=_CONTEXT, configured_sources=()
        )
    assert lifecycle == ["rollback"]
    cursor.execute.assert_not_awaited()
    spy.assert_not_called()
    assert audit_records == []


async def test_repeated_hide_neither_writes_nor_audits(mutation, audit_records):
    """Repeated hide neither writes nor audits."""
    state = dataset_admin.DatasetAdminState("public", None, _HIDDEN_AT)
    change = _change(state, state)
    cursor, spy, lifecycle = mutation(change)
    assert (
        await dataset_admin.change_dataset_admin_state(
            sentinel.pool, 29, "hide", context=_CONTEXT, configured_sources=()
        )
        == change
    )
    assert lifecycle == ["commit"]
    assert not any(
        str(call.args[0]).lstrip().startswith(("INSERT", "UPDATE"))
        for call in cursor.execute.await_args_list
    )
    spy.assert_not_called()
    assert audit_records == []


_ISSUER = "https://idp.example.org/shibboleth"
_FEDERATED = {"auth_method": "shibboleth"}


@pytest.mark.parametrize(
    ("overrides", "enabled", "current", "allowed"),
    [
        pytest.param({}, False, False, True, id="local-ignores-federation-policy"),
        pytest.param({"email_verified": False}, True, True, False, id="local-unverified"),
        pytest.param({"totp_recovery_required": True}, True, True, False, id="local-recovery"),
        pytest.param(None, True, True, False, id="actor-disappeared"),
        pytest.param({"auth_method": "unknown"}, True, True, False, id="unknown-authentication"),
        pytest.param(_FEDERATED, True, True, True, id="federated-approved-current-trusted"),
        pytest.param(_FEDERATED, False, True, False, id="federation-disabled"),
        pytest.param(_FEDERATED, True, False, False, id="federation-policy-mismatch"),
        pytest.param(
            {**_FEDERATED, "federated_status": "pending"}, True, True, False, id="pending"
        ),
        pytest.param(
            {**_FEDERATED, "federated_status": "disabled"}, True, True, False, id="disabled"
        ),
        pytest.param(
            {**_FEDERATED, "shibboleth_issuer": "https://other.example.org"},
            True,
            True,
            False,
            id="untrusted-issuer",
        ),
        pytest.param(
            {**_FEDERATED, "shibboleth_issuer": [_ISSUER]}, True, True, False, id="nonscalar-issuer"
        ),
        pytest.param(
            {**_FEDERATED, "shibboleth_subject_id": None}, True, True, False, id="missing-subject"
        ),
        pytest.param(
            {**_FEDERATED, "shibboleth_subject_id": "one,two"},
            True,
            True,
            False,
            id="ambiguous-subject",
        ),
    ],
)
async def test_additional_authority_eligibility_matches_full_session_policy(
    monkeypatch, overrides, enabled, current, allowed
):
    """Isolate the new eligibility rules after the existing admin/session guard succeeds."""
    actor = (
        None
        if overrides is None
        else {
            "auth_method": "local",
            "email_verified": True,
            "totp_recovery_required": False,
            "federated_status": "approved",
            "shibboleth_issuer": _ISSUER,
            "shibboleth_subject_id": "urn:example:approved-subject",
            **overrides,
        }
    )
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    cursor.fetchone.return_value = actor
    real_guard = dataset_admin.guard_current_admin_session_cur
    guard = create_autospec(real_guard, return_value=None, spec_set=True)
    monkeypatch.setattr(dataset_admin, "guard_current_admin_session_cur", guard)
    monkeypatch.setattr(dataset_admin.settings, "shibboleth_enabled", enabled)
    monkeypatch.setattr(dataset_admin.settings, "shibboleth_trusted_issuers", [_ISSUER])
    if allowed:
        await dataset_admin._authorize_cur(cursor, _CONTEXT, federation_current=current)
    else:
        with pytest.raises(dataset_admin.AdminActionRejected, match="administrator access changed"):
            await dataset_admin._authorize_cur(cursor, _CONTEXT, federation_current=current)
    guard.assert_awaited_once_with(
        cursor, actor_id=_CONTEXT.actor_id, actor_session_id=_CONTEXT.actor_session_id
    )
    assert cursor.execute.await_args.args[1] == (_CONTEXT.actor_id,)


@pytest.mark.parametrize(
    ("action", "tier", "dataset_id", "reason"),
    [
        ("delete", None, 29, "invalid_action"),
        ("raise_tier", None, 29, "invalid_tier"),
        ("raise_tier", "unrecognized-private-value", 29, "invalid_tier"),
        ("hide", "public", 29, "invalid_tier"),
        ("restore", "vetted", 29, "invalid_tier"),
        ("hide", None, 0, "dataset_not_found"),
        ("hide", None, True, "dataset_not_found"),
    ],
)
async def test_invalid_action_arguments_fail_before_database_access(
    monkeypatch, audit_records, action, tier, dataset_id, reason
):
    """Invalid action arguments fail before database access."""
    real_cursor = dataset_admin.get_db_cursor
    cursor_factory = create_autospec(real_cursor, spec_set=True)
    monkeypatch.setattr(dataset_admin, "get_db_cursor", cursor_factory)
    with pytest.raises(dataset_admin.DatasetAdminRejected) as caught:
        await dataset_admin.change_dataset_admin_state(
            sentinel.pool,
            dataset_id,
            action,
            context=_CONTEXT,
            new_tier=tier,
            configured_sources=(),
        )
    assert caught.value.reason == reason
    assert str(caught.value) == reason
    cursor_factory.assert_not_called()
    assert audit_records == []

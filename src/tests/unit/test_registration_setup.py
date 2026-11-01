"""Mailbox proof precedes local credential work and registration completion."""

from contextlib import asynccontextmanager, nullcontext
from dataclasses import FrozenInstanceError, asdict
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import create_autospec, patch, sentinel

import pytest
import time_machine
from psycopg import AsyncCursor
from psycopg.sql import Composable

from app.services import registration_setup as setup
from app.services.db import get_db_cursor as _REAL_DB
from app.services.email_verification import generate_verification_token
from app.services.password_work import run_password_work as _REAL_WORK
from app.services.tokens import hash_token
from tests.fixtures import make_sample_user

_EMAIL = "owner@example.org"
_PASSWORD = "Maple-Rivers-739!Quartz"


@pytest.fixture
def token():
    """Generate a signed verification token for the sample mailbox."""
    return generate_verification_token(7, _EMAIL)


def _patch_work(**kwargs):
    """Patch password work with its saved strict specification."""
    return patch.object(
        setup, "run_password_work", create_autospec(_REAL_WORK, spec_set=True, **kwargs)
    )


def test_setup_reference_is_frozen():
    """Check setup reference is frozen (FrozenInstanceError)."""
    reference = setup.RegistrationSetup(7, _EMAIL)
    with pytest.raises(FrozenInstanceError):
        reference.email = "attacker@example.org"


@pytest.mark.parametrize("email", ["", "not-an-email", "owner@example.org\nInjected"])
async def test_invalid_email_is_rejected_before_storage_or_password_work(email):
    """Check invalid email is rejected before storage or password work (ValueError)."""
    with (
        patch.object(setup, "get_db_cursor", create_autospec(_REAL_DB)) as database,
        _patch_work() as work,
        pytest.raises(ValueError),
    ):
        await setup.begin_local_registration(sentinel.pool, email=email)
    database.assert_not_called()
    work.assert_not_awaited()


@pytest.mark.parametrize("field", ["password", "display_name", "totp_secret"])
async def test_initial_registration_cannot_accept_credentials_or_profile(field):
    """Check initial registration cannot accept credentials or profile (TypeError)."""
    with (
        patch.object(setup, "get_db_cursor", create_autospec(_REAL_DB)) as database,
        _patch_work() as work,
        pytest.raises(TypeError, match=field),
    ):
        await setup.begin_local_registration(
            sentinel.pool, email=_EMAIL, **{field: "attacker-value"}
        )
    database.assert_not_called()
    work.assert_not_awaited()


@pytest.fixture
def boundary(monkeypatch):
    """Explicit transaction exits and signature-enforced storage/credential seams."""
    originals = {
        name: getattr(setup, name)
        for name in (
            "enqueue_outbound_email_cur",
            "record_mail_issuance_cur",
            "delete_user_sessions_cur",
            "invalidate_pending_authentication_state_cur",
            "store_verification_token_hash_cur",
        )
    }

    def install(rows, *, commit_error_at=None, enqueue_error=None, revoke_error=None):
        """Install scripted registration rows and failure-injection mocks; return their observations."""
        cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
        cursor.fetchone.side_effect = rows
        exits, transactions = [], 0

        @asynccontextmanager
        async def transaction(pool, _row_factory=None):
            """Yield the cursor and record commit/rollback, injecting a selected commit failure."""
            nonlocal transactions
            assert pool is sentinel.pool
            transactions += 1
            number = transactions
            try:
                yield cursor
            except BaseException:
                exits.append("rollback")
                raise
            if number == commit_error_at:
                exits.append("rollback")
                raise RuntimeError("commit failed")
            exits.append("commit")

        work = create_autospec(_REAL_WORK, return_value="owner-password-hash", spec_set=True)
        doubles = {
            name: create_autospec(real, return_value=None, spec_set=True)
            for name, real in originals.items()
        }
        doubles["enqueue_outbound_email_cur"].side_effect = enqueue_error
        doubles["invalidate_pending_authentication_state_cur"].side_effect = revoke_error
        for name, spy in doubles.items():
            monkeypatch.setattr(setup, name, spy)
        monkeypatch.setattr(
            setup,
            "get_db_cursor",
            create_autospec(_REAL_DB, side_effect=transaction, spec_set=True),
        )
        monkeypatch.setattr(setup, "run_password_work", work)
        monkeypatch.setattr(
            setup,
            "anonymous_mail_issuance_allowed_cur",
            create_autospec(setup.anonymous_mail_issuance_allowed_cur, return_value=True),
        )
        return SimpleNamespace(cursor=cursor, work=work, exits=exits, **doubles)

    return install


@pytest.mark.parametrize("email", ["", "not-an-email", "owner@example.org\nInjected"])
async def test_invalid_resend_returns_before_storage_or_password_work(email):
    """Check invalid resend returns before storage or password work."""
    with (
        patch.object(setup, "get_db_cursor", create_autospec(_REAL_DB)) as database,
        _patch_work() as work,
    ):
        assert await setup.resend_local_registration(sentinel.pool, email=email) is None
    database.assert_not_called()
    work.assert_not_awaited()


async def test_resend_without_an_eligible_row_does_not_rotate_or_queue(boundary):
    """Storage doubles model no eligible row; PostgreSQL tests prove predicates."""
    state = boundary([None])
    assert await setup.resend_local_registration(sentinel.pool, email=" OWNER@EXAMPLE.ORG ") is None
    assert state.cursor.execute.await_args.args[1] == (
        setup.VERIFICATION_TOKEN_MAX_AGE_SECONDS,
        _EMAIL,
    )
    state.store_verification_token_hash_cur.assert_not_awaited()
    state.enqueue_outbound_email_cur.assert_not_awaited()
    state.work.assert_not_awaited()
    assert state.exits == ["commit"]


async def test_resend_rotation_and_mail_share_the_owned_transaction(boundary):
    """Signature-enforced storage doubles exercise the service boundary."""
    state = boundary([{"id": 7, "email": _EMAIL, "verification_live": False}])
    assert await setup.resend_local_registration(sentinel.pool, email=" OWNER@EXAMPLE.ORG ") is None
    assert state.cursor.execute.await_args.args[1] == (
        setup.VERIFICATION_TOKEN_MAX_AGE_SECONDS,
        _EMAIL,
    )
    state.enqueue_outbound_email_cur.assert_awaited_once()
    mail = state.enqueue_outbound_email_cur.await_args.kwargs
    assert state.enqueue_outbound_email_cur.await_args.args == (state.cursor,)
    assert mail["user_id"] == 7 and mail["email"].recipient == _EMAIL
    assert mail["email"].message_type == "email_verification"
    state.store_verification_token_hash_cur.assert_awaited_once_with(
        state.cursor, 7, mail["action"].token_hash, expected_email=_EMAIL
    )
    state.work.assert_not_awaited()
    state.delete_user_sessions_cur.assert_not_awaited()
    state.invalidate_pending_authentication_state_cur.assert_not_awaited()
    assert state.exits == ["commit"]


async def test_failed_resend_enqueue_rolls_back_the_rotation_boundary(boundary):
    """Check failed resend enqueue rolls back the rotation boundary (RuntimeError)."""
    state = boundary(
        [{"id": 7, "email": _EMAIL, "verification_live": False}],
        enqueue_error=RuntimeError("enqueue failed"),
    )
    with pytest.raises(RuntimeError, match="enqueue failed"):
        await setup.resend_local_registration(sentinel.pool, email=_EMAIL)
    state.store_verification_token_hash_cur.assert_awaited_once()
    state.work.assert_not_awaited()
    assert state.exits == ["rollback"]


def _snapshot():
    """Build the registration account snapshot at authentication revision three."""
    return {"id": 7, "email": _EMAIL, "auth_revision": 3}


def _user_row():
    """Build a public mailbox-owner row at the maximum affiliation and country lengths."""
    return asdict(
        make_sample_user(
            id=7,
            email=_EMAIL,
            display_name="Mailbox Owner",
            affiliation="a" * 200,
            country="c" * 100,
            access_tier="public",
            totp_configured=False,
        )
    )


async def _complete(token, **profile):
    """Complete registration for the token using the sample profile with caller overrides."""
    values = {"display_name": "Mailbox Owner", "password": _PASSWORD, **profile}
    return await setup.complete_local_registration(sentinel.pool, token=token, **values)


@pytest.mark.parametrize("duplicate", [False, True], ids=["new", "duplicate"])
async def test_begin_queues_mail_without_password_work_or_credential_replacement(
    boundary, duplicate
):
    """Check begin queues mail without password work or credential replacement."""
    state = boundary(
        [None if duplicate else {"id": 7, "email": _EMAIL, "verification_live": False}]
    )
    assert await setup.begin_local_registration(sentinel.pool, email=" owner@EXAMPLE.ORG ") is None
    assert state.cursor.execute.await_args_list[0].args[1] == (_EMAIL,)
    state.work.assert_not_awaited()
    state.delete_user_sessions_cur.assert_not_awaited()
    state.invalidate_pending_authentication_state_cur.assert_not_awaited()
    assert state.exits == ["commit"]
    if duplicate:
        assert state.cursor.execute.await_count == 1
        state.enqueue_outbound_email_cur.assert_not_awaited()
    else:
        state.enqueue_outbound_email_cur.assert_awaited_once()
        mail = state.enqueue_outbound_email_cur.await_args.kwargs
        assert mail["email"].recipient == _EMAIL
        assert mail["user_id"] == 7
        assert mail["email"].message_type == "email_verification"
        assert state.cursor.execute.await_args.args[1][0] == mail["action"].token_hash


@pytest.mark.parametrize("kind", ["tampered", "empty", "oversized", "expired"])
async def test_invalid_capability_never_reaches_storage_or_password_work(token, kind):
    """Check invalid capability never reaches storage or password work."""
    supplied = {
        "tampered": token + "tampered",
        "empty": "",
        "oversized": "x" * 2001,
        "expired": token,
    }[kind]
    clock = (
        time_machine.travel(datetime.now(UTC) + timedelta(hours=25))
        if kind == "expired"
        else nullcontext()
    )
    with (
        clock,
        patch.object(setup, "get_db_cursor", create_autospec(_REAL_DB)) as database,
        _patch_work() as work,
    ):
        assert await setup.inspect_local_registration(sentinel.pool, supplied) is None
        assert await _complete(supplied) is None
    database.assert_not_called()
    work.assert_not_awaited()


async def test_inspection_is_read_only_and_stale_state_never_reaches_hashing(boundary, token):
    """Check inspection is read only and stale state never reaches hashing."""
    state = boundary([_snapshot(), None])
    assert await setup.inspect_local_registration(sentinel.pool, token) == setup.RegistrationSetup(
        7, _EMAIL
    )
    assert await _complete(token) is None
    statements = [call.args[0] for call in state.cursor.execute.await_args_list]
    assert all(
        (query.as_string() if isinstance(query, Composable) else query)
        .lstrip()
        .startswith("SELECT")
        for query in statements
    )
    state.work.assert_not_awaited()
    state.delete_user_sessions_cur.assert_not_awaited()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("display_name", ""),
        ("display_name", "n" * 201),
        ("display_name", "Bad\x01Name"),
        ("affiliation", "a" * 201),
        ("affiliation", "Bad\x7fOrganization"),
        ("country", "c" * 101),
        ("country", "Bad\x00Country"),
        ("password", "short"),
    ],
)
async def test_invalid_profile_or_password_is_rejected_before_hashing(
    boundary, token, field, value
):
    """Check invalid profile or password is rejected before hashing (ValueError)."""
    state = boundary([_snapshot()])
    with pytest.raises(ValueError):
        await _complete(token, **{field: value})
    state.work.assert_not_awaited()
    state.delete_user_sessions_cur.assert_not_awaited()
    assert state.exits == ["commit"]


async def test_completion_hashes_only_the_proved_owners_password_then_commits_revocation(
    boundary, token
):
    """Check completion hashes only the proved owners password then commits revocation."""
    state = boundary([_snapshot(), {"id": 7}, _user_row()])
    user = await _complete(
        token, display_name=" Mailbox Owner ", affiliation="a" * 200, country="c" * 100
    )
    assert user is not None and user.email_verified and user.is_active
    assert user.access_tier == "public" and not user.is_admin and not user.totp_configured
    state.work.assert_awaited_once_with(setup.password_hasher.hash, _PASSWORD)
    write = state.cursor.execute.await_args.args[1]
    assert write["token_hash"] == hash_token(token) and write["auth_revision"] == 3
    assert write["password_hash"] == "owner-password-hash"
    assert write["display_name"] == "Mailbox Owner"
    assert (len(write["affiliation"]), len(write["country"])) == (200, 100)
    assert _PASSWORD not in write.values()
    state.delete_user_sessions_cur.assert_awaited_once_with(state.cursor, 7)
    state.invalidate_pending_authentication_state_cur.assert_awaited_once_with(state.cursor, 7)
    assert state.exits == ["commit", "commit"]


@pytest.mark.parametrize("stage", ["lock", "update"])
async def test_capability_change_during_hashing_prevents_revocation(boundary, token, stage):
    """Check capability change during hashing prevents revocation."""
    rows = [_snapshot(), None] if stage == "lock" else [_snapshot(), {"id": 7}, None]
    state = boundary(rows)
    assert await _complete(token) is None
    state.work.assert_awaited_once()
    state.delete_user_sessions_cur.assert_not_awaited()
    state.invalidate_pending_authentication_state_cur.assert_not_awaited()


async def test_signed_expiry_is_rechecked_after_hashing_and_row_lock(boundary, token):
    """Check signed expiry is rechecked after hashing and row lock."""
    state = boundary([_snapshot(), {"id": 7}])
    with time_machine.travel(datetime.now(UTC), tick=False) as clock:

        async def hash_after_expiry(*_args):
            """Advance time by twenty-five hours before returning the password hash."""
            clock.shift(timedelta(hours=25))
            return "owner-password-hash"

        state.work.side_effect = hash_after_expiry
        assert await _complete(token) is None
    state.delete_user_sessions_cur.assert_not_awaited()
    assert state.cursor.execute.await_count == 2


async def test_failed_mail_enqueue_rolls_back_initial_registration(boundary):
    """Check failed mail enqueue rolls back initial registration (RuntimeError)."""
    state = boundary(
        [{"id": 7, "email": _EMAIL, "verification_live": False}],
        enqueue_error=RuntimeError("enqueue failed"),
    )
    with pytest.raises(RuntimeError, match="enqueue failed"):
        await setup.begin_local_registration(sentinel.pool, email=_EMAIL)
    assert state.exits == ["rollback"]
    state.work.assert_not_awaited()


@pytest.mark.parametrize("failure", ["commit", "revocation"])
async def test_completion_failure_cannot_return_an_uncommitted_user(boundary, token, failure):
    """Check completion failure cannot return an uncommitted user (RuntimeError)."""
    state = boundary(
        [_snapshot(), {"id": 7}, _user_row()],
        commit_error_at=2 if failure == "commit" else None,
        revoke_error=RuntimeError("revocation failed") if failure == "revocation" else None,
    )
    with pytest.raises(RuntimeError, match=f"{failure} failed"):
        await _complete(token)
    assert state.exits == ["commit", "rollback"]

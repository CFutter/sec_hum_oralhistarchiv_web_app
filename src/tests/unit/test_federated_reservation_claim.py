"""Reservation finalizer branches through public services and reusable cursor doubles."""

import logging
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from psycopg.errors import UniqueViolation

from app.services import federated_authentication as auth
from app.services.crypto import audit_email_hash
from app.services.federated_session_policy import REQUIRED_SHIBBOLETH_AUTHN_CONTEXT
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool, make_sample_user_row

ISSUER = "https://idp.example.org/idp/shibboleth"
EMAIL = "owner@example.org"
EVENT = "federated_email_reservation_claimed"


class ConstraintCollision(UniqueViolation):
    """Represent PostgreSQL's public diagnostic constraint name on a test error."""

    def __init__(self, constraint):
        """Store the constraint name on a synthetic unique-conflict exception."""
        super().__init__("unique conflict")
        self.constraint = constraint

    @property
    def diag(self):
        """Expose the stored constraint name through a psycopg-shaped diagnostic."""
        return SimpleNamespace(constraint_name=self.constraint)


def principal():
    """Build the synthetic federated identity with the required authentication context."""
    return auth.build_federated_principal(
        issuer=ISSUER,
        subject_id="opaque-subject",
        email=EMAIL,
        authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    )


def reservation(**overrides):
    """Return an unverified local reservation with explicit field overrides."""
    row = {
        "id": 19,
        "email": EMAIL,
        "auth_method": "local",
        "email_verified": False,
        "is_admin": False,
    }
    row.update(overrides)
    return row


async def finalize():
    """Finalize the synthetic federated login through a fail-on-use mock pool."""
    return await auth.finalize_shibboleth_login(
        make_mock_pool(), principal=principal(), ip_address="127.0.0.1"
    )


@pytest.fixture(autouse=True)
def policy(monkeypatch, caplog):
    """Enable trusted federation and capture INFO audit events with a current-policy double."""
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER])
    caplog.set_level(logging.INFO, logger="audit")
    with patch.object(auth, "federation_policy_is_current_cur", autospec=True, return_value=True):
        yield


def events(caplog):
    """Return captured reservation-claim events only."""
    return [record for record in caplog.records if record.getMessage() == EVENT]


@pytest.mark.parametrize(
    "protected",
    [
        None,
        reservation(email_verified=True),
        reservation(is_admin=True),
        reservation(auth_method="shibboleth"),
    ],
)
async def test_protected_reservation_is_never_deleted(protected, caplog):
    """Protected reservation is never deleted."""
    cur = make_async_cursor(fetchone=[None, protected])
    with (
        patch.object(auth, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
        patch.object(
            auth,
            "create_shibboleth_user_cur",
            autospec=True,
            side_effect=ConstraintCollision("idx_users_email_lower"),
        ),
    ):
        assert await finalize() == auth.FederatedLoginFailure("account_conflict")
    assert cur.execute.await_count == 2
    assert not events(caplog)


async def test_existing_exact_identity_never_enters_reservation_lookup(caplog):
    """Existing exact identity never enters reservation lookup."""
    cur = make_async_cursor(fetchone={"id": 8})
    with (
        patch.object(auth, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
        patch.object(
            auth,
            "create_shibboleth_user_cur",
            autospec=True,
            side_effect=ConstraintCollision("idx_users_email_lower"),
        ),
    ):
        assert await finalize() == auth.FederatedLoginFailure("account_conflict")
    assert cur.execute.await_count == 1
    assert not events(caplog)


async def test_nonemail_unique_violation_propagates_without_claim_lookup(caplog):
    """Nonemail unique violation propagates without claim lookup."""
    cur = make_async_cursor()
    failure = ConstraintCollision("unrelated_unique_constraint")
    with (
        patch.object(auth, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
        patch.object(auth, "create_shibboleth_user_cur", autospec=True, side_effect=failure),
        pytest.raises(UniqueViolation) as caught,
    ):
        await finalize()
    assert caught.value is failure
    cur.execute.assert_not_awaited()
    assert not events(caplog)


async def test_disappearing_locked_reservation_is_an_error_without_audit(caplog):
    """Disappearing locked reservation is an error without audit."""
    cur = make_async_cursor(fetchone=[None, reservation()], rowcount=0)
    with (
        patch.object(auth, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
        patch.object(
            auth,
            "create_shibboleth_user_cur",
            autospec=True,
            side_effect=ConstraintCollision("idx_users_email_lower"),
        ),
        pytest.raises(RuntimeError, match="Locked email reservation disappeared"),
    ):
        await finalize()
    assert cur.execute.await_count == 3
    assert not events(caplog)


async def test_same_identity_insert_race_raises_through_transaction_before_rejection(caplog):
    """Same identity insert race raises through transaction before rejection."""
    cur = make_async_cursor(fetchone=[None, reservation(), None], rowcount=1)
    rolled_back = []

    @asynccontextmanager
    async def observe_transaction(pool):
        """Yield the cursor and record rollback when an exception leaves the transaction."""
        del pool
        try:
            yield cur
        except Exception:
            rolled_back.append(True)
            raise

    with (
        patch.object(auth, "get_db_cursor", autospec=True, side_effect=observe_transaction),
        patch.object(
            auth,
            "create_shibboleth_user_cur",
            autospec=True,
            side_effect=ConstraintCollision("idx_users_email_lower"),
        ),
    ):
        assert await finalize() == auth.FederatedLoginFailure("account_conflict")
    assert rolled_back == [True]
    assert not events(caplog)


async def test_committed_pending_claim_emits_one_pseudonymous_event_after_commit(caplog):
    """Committed pending claim emits one pseudonymous event after commit."""
    row = make_sample_user_row(
        id=42, email=EMAIL, auth_method="shibboleth", federated_status="pending"
    )
    cur = make_async_cursor(fetchone=[None, reservation(), row], rowcount=1)
    committed = []

    @asynccontextmanager
    async def commit_transaction(pool):
        """Require no claim audit before recording successful commit."""
        del pool
        yield cur
        assert not events(caplog)
        committed.append(True)

    with (
        patch.object(auth, "get_db_cursor", autospec=True, side_effect=commit_transaction),
        patch.object(
            auth,
            "create_shibboleth_user_cur",
            autospec=True,
            side_effect=ConstraintCollision("idx_users_email_lower"),
        ),
        patch.object(auth, "record_federated_review_cur", autospec=True) as review,
        patch.object(auth, "create_session_cur", autospec=True) as session,
    ):
        result = await finalize()
    assert committed == [True]
    assert result.reason == "inactive_account" and result.user.id == 42
    review.assert_awaited_once()
    session.assert_not_awaited()
    (event,) = events(caplog)
    assert event.removed_user_id == 19 and event.user_id == 42
    assert event.email_hash == audit_email_hash(EMAIL)
    assert EMAIL not in repr(event.__dict__)


@pytest.mark.parametrize("constraint", ["idx_users_email_lower", "other_unique_key"])
async def test_unique_violation_during_fresh_insert_rolls_back_without_claim_audit(
    caplog, constraint
):
    """Unique violation during fresh insert rolls back without claim audit."""
    cur = make_async_cursor(fetchone=[None, reservation()], rowcount=1)
    failure = ConstraintCollision(constraint)
    cur.execute.side_effect = [None, None, None, failure]
    rolled_back = []

    @asynccontextmanager
    async def observe_transaction(pool):
        """Yield the cursor and record rollback when an exception leaves the transaction."""
        del pool
        try:
            yield cur
        except Exception:
            rolled_back.append(True)
            raise

    with (
        patch.object(auth, "get_db_cursor", autospec=True, side_effect=observe_transaction),
        patch.object(
            auth,
            "create_shibboleth_user_cur",
            autospec=True,
            side_effect=ConstraintCollision("idx_users_email_lower"),
        ),
    ):
        if constraint == "idx_users_email_lower":
            assert await finalize() == auth.FederatedLoginFailure("account_conflict")
        else:
            with pytest.raises(UniqueViolation) as caught:
                await finalize()
            assert caught.value is failure
    assert rolled_back == [True]
    assert not events(caplog)

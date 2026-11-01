"""Database boundaries for advisory federation review state."""

import psycopg
import pytest
from psycopg.types.json import Jsonb

from app.services.db_drift import (
    assert_table_column_contract,
    assert_table_constraint_contract,
)
from app.services.db_schema_contract import (
    USER_COLUMN_CONTRACT,
    USER_CONSTRAINT_CONTRACT,
)

_ISSUER = "https://idp.test.example/idp/shibboleth"
_OBSERVATION = {
    "issuer": _ISSUER,
    "affiliation": None,
    "entitlement": None,
    "proposal": None,
}


def _federated(user_factory, *, status="pending"):
    """Create a federated fixture user in the requested state."""
    return user_factory(
        auth_method="shibboleth",
        shibboleth_issuer=_ISSUER,
        federated_status=status,
        is_active=status == "approved",
    )


def _store_review(sync_conn, user_id, observation, revision=1, approved=None):
    """Write the federated review, revision and approved proposal without committing."""
    sync_conn.execute(
        """UPDATE users
              SET federated_review = %s,
                  federated_review_revision = %s,
                  federated_approved_proposal = %s
            WHERE id = %s""",
        (
            Jsonb(observation) if observation is not None else None,
            revision,
            Jsonb(approved) if approved is not None else None,
            user_id,
        ),
    )


async def test_federated_review_columns_and_constraint_match_live_catalogs(db_pool):
    """Verify federated review columns and constraint match live catalogs."""
    await assert_table_column_contract(db_pool, "users", USER_COLUMN_CONTRACT)
    await assert_table_constraint_contract(db_pool, "users", USER_CONSTRAINT_CONTRACT)


def test_local_and_legacy_approved_rows_have_no_advisory_state(user_factory, sync_conn):
    """Verify local and legacy approved rows have no advisory state."""
    local = user_factory()
    approved = _federated(user_factory, status="approved")
    rows = sync_conn.execute(
        """SELECT federated_review, federated_review_revision,
                  federated_approved_proposal
             FROM users WHERE id IN (%s, %s) ORDER BY id""",
        (local.id, approved.id),
    ).fetchall()
    assert rows == [(None, 0, None), (None, 0, None)]


@pytest.mark.parametrize(
    "attributes",
    [
        {},
        {"affiliation": "<script>alert(1)</script>", "entitlement": "role;archive"},
        {"affiliation": "a" * 512, "entitlement": "e" * 4096},
        {
            "proposal": {
                "index": 1,
                "match": {"entitlement": {"prefix": "urn:archive:"}},
                "tier": "vetted",
            }
        },
    ],
    ids=["no-match", "printable-markup", "maximum-attributes", "matched-rule"],
)
def test_pending_observation_persists_without_assigning_authority(
    user_factory, sync_conn, attributes
):
    """Verify pending observation persists without assigning authority."""
    pending = _federated(user_factory)
    observation = {**_OBSERVATION, **attributes}
    _store_review(sync_conn, pending.id, observation)
    row = sync_conn.execute(
        """SELECT federated_review, federated_review_revision,
                  access_tier, is_active, is_admin, federated_approved_proposal
             FROM users WHERE id = %s""",
        (pending.id,),
    ).fetchone()
    assert row == (observation, 1, "public", False, False, None)


@pytest.mark.parametrize(
    "observation,revision",
    [
        (None, -1),
        (None, 1),
        (_OBSERVATION, 0),
        ([], 1),
        ("assertion", 1),
        ({}, 1),
        ({**_OBSERVATION, "issuer": None}, 1),
        ({**_OBSERVATION, "issuer": "https://different.example/idp"}, 1),
        ({key: value for key, value in _OBSERVATION.items() if key != "proposal"}, 1),
        ({**_OBSERVATION, "unexpected": "value"}, 1),
        ({**_OBSERVATION, "affiliation": False}, 1),
        ({**_OBSERVATION, "affiliation": ""}, 1),
        ({**_OBSERVATION, "affiliation": "a" * 513}, 1),
        ({**_OBSERVATION, "entitlement": []}, 1),
        ({**_OBSERVATION, "entitlement": ""}, 1),
        ({**_OBSERVATION, "entitlement": "e" * 4097}, 1),
        ({**_OBSERVATION, "proposal": "vetted"}, 1),
    ],
    ids=[
        "negative-revision",
        "missing-observation",
        "unversioned-observation",
        "array-observation",
        "scalar-observation",
        "empty-object",
        "null-issuer",
        "different-issuer",
        "missing-key",
        "extra-key",
        "boolean-affiliation",
        "empty-affiliation",
        "oversized-affiliation",
        "array-entitlement",
        "empty-entitlement",
        "oversized-entitlement",
        "scalar-proposal",
    ],
)
def test_malformed_observation_is_rejected_fail_closed(
    user_factory, sync_conn, observation, revision
):
    """Verify malformed observation is rejected fail closed."""
    pending = _federated(user_factory)
    with (
        pytest.raises(psycopg.errors.CheckViolation, match="users_federated_review_state_check"),
        sync_conn.transaction(),
    ):
        _store_review(sync_conn, pending.id, observation, revision)


def test_local_identity_cannot_store_federated_review(user_factory, sync_conn):
    """Verify local identity cannot store federated review."""
    local = user_factory()
    with (
        pytest.raises(psycopg.errors.CheckViolation, match="users_federated_review_state_check"),
        sync_conn.transaction(),
    ):
        _store_review(sync_conn, local.id, _OBSERVATION)


def test_pending_identity_cannot_store_an_approved_proposal(user_factory, sync_conn):
    """Verify pending identity cannot store an approved proposal."""
    pending = _federated(user_factory)
    with (
        pytest.raises(psycopg.errors.CheckViolation, match="users_federated_review_state_check"),
        sync_conn.transaction(),
    ):
        _store_review(sync_conn, pending.id, _OBSERVATION, approved={"proposal": None})


@pytest.mark.parametrize("status", ["approved", "disabled"])
def test_approved_no_match_remains_distinct_from_no_review(user_factory, sync_conn, status):
    """Verify approved no match remains distinct from no review."""
    approved = _federated(user_factory, status=status)
    _store_review(sync_conn, approved.id, _OBSERVATION, approved={"proposal": None})
    row = sync_conn.execute(
        "SELECT federated_approved_proposal FROM users WHERE id = %s", (approved.id,)
    ).fetchone()
    assert row == ({"proposal": None},)


@pytest.mark.parametrize(
    "observation,approved",
    [
        (None, {"proposal": None}),
        (_OBSERVATION, []),
        (_OBSERVATION, {}),
        (_OBSERVATION, {"proposal": None, "extra": "value"}),
        (_OBSERVATION, {"proposal": "vetted"}),
    ],
    ids=["no-assertion", "array-wrapper", "missing-proposal", "extra-key", "scalar-proposal"],
)
def test_malformed_approval_snapshot_is_rejected(user_factory, sync_conn, observation, approved):
    """Verify malformed approval snapshot is rejected."""
    user = _federated(user_factory, status="approved")
    with (
        pytest.raises(psycopg.errors.CheckViolation, match="users_federated_review_state_check"),
        sync_conn.transaction(),
    ):
        _store_review(
            sync_conn,
            user.id,
            observation,
            revision=0 if observation is None else 1,
            approved=approved,
        )


@pytest.mark.parametrize("approved", [False, True], ids=["current", "approved"])
@pytest.mark.parametrize(
    "proposal",
    [
        {},
        {"index": 1, "match": {"issuer": _ISSUER}},
        {"index": 0, "match": {"issuer": _ISSUER}, "tier": "vetted"},
        {"index": 1.5, "match": {"issuer": _ISSUER}, "tier": "vetted"},
        {"index": 1, "match": [], "tier": "vetted"},
        {"index": 1, "match": {}, "tier": "vetted"},
        {"index": 1, "match": {"issuer": _ISSUER}, "tier": "admin"},
        {"index": 1, "match": {"issuer": _ISSUER}, "tier": "vetted", "extra": True},
    ],
    ids=[
        "empty",
        "missing-tier",
        "zero-index",
        "fractional-index",
        "array-match",
        "empty-match",
        "unknown-tier",
        "extra-key",
    ],
)
def test_malformed_rule_snapshot_is_rejected(user_factory, sync_conn, approved, proposal):
    """Verify malformed rule snapshot is rejected."""
    user = _federated(user_factory, status="approved" if approved else "pending")
    observation = _OBSERVATION if approved else {**_OBSERVATION, "proposal": proposal}
    with (
        pytest.raises(psycopg.errors.CheckViolation, match="users_federated_review_state_check"),
        sync_conn.transaction(),
    ):
        _store_review(
            sync_conn,
            user.id,
            observation,
            approved={"proposal": proposal} if approved else None,
        )

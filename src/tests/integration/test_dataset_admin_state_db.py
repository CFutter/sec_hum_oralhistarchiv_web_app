"""Dataset administration state persists independently of catalogue enforcement and UI."""

from datetime import UTC, datetime

import pytest
from psycopg.errors import CheckViolation, UniqueViolation


def test_state_survives_catalogue_deletion_and_reintroduction(sync_conn, dataset_factory):
    """Local row IDs may change; administrator state follows (source, uuid)."""
    uuid = "admin-state-storage"
    original_id = dataset_factory(source="archive_alpha", uuid=uuid)
    foreign_id = dataset_factory(source="archive_beta", uuid=uuid)
    hidden_at = datetime(2026, 10, 17, tzinfo=UTC)
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, visibility_tier, hidden_at) "
        "VALUES (%s, %s, %s, %s), (%s, %s, %s, %s)",
        ("archive_alpha", uuid, "vetted", hidden_at, "archive_beta", uuid, "registered", None),
    )
    sync_conn.commit()
    query = (
        "SELECT source, uuid, visibility_tier, hidden_at FROM dataset_admin_state ORDER BY source"
    )
    before = sync_conn.execute(query).fetchall()
    assert before == [
        ("archive_alpha", uuid, "vetted", hidden_at),
        ("archive_beta", uuid, "registered", None),
    ]
    sync_conn.execute("DELETE FROM oral_history_datasets WHERE id = %s", (original_id,))
    sync_conn.commit()
    assert sync_conn.execute(query).fetchall() == before
    replacement_id = dataset_factory(source="archive_alpha", uuid=uuid)
    assert replacement_id != original_id
    assert sync_conn.execute(query).fetchall() == before
    assert sync_conn.execute(
        "SELECT id FROM oral_history_datasets WHERE source = %s AND uuid = %s",
        ("archive_beta", uuid),
    ).fetchone() == (foreign_id,)


@pytest.mark.parametrize("tier", [None, "public", "registered", "vetted"])
def test_state_can_precede_catalogue_and_clear_hide_independently(sync_conn, tier):
    """A future restore may clear hiding while retaining an independent tier floor."""
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, visibility_tier, hidden_at) "
        "VALUES (%s, %s, %s, %s)",
        ("archive_alpha", "not-currently-harvested", tier, datetime(2026, 10, 17, tzinfo=UTC)),
    )
    sync_conn.execute(
        "UPDATE dataset_admin_state SET hidden_at = NULL WHERE source = %s AND uuid = %s",
        ("archive_alpha", "not-currently-harvested"),
    )
    assert sync_conn.execute(
        "SELECT visibility_tier, hidden_at FROM dataset_admin_state"
    ).fetchall() == [(tier, None)]
    assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone() == (0,)


@pytest.mark.parametrize("source", ["", "Upper", "archivé", "a" * 33])
def test_invalid_state_source_is_rejected(sync_conn, source):
    """Verify invalid state source is rejected."""
    with pytest.raises(CheckViolation), sync_conn.transaction():
        sync_conn.execute(
            "INSERT INTO dataset_admin_state (source, uuid) VALUES (%s, %s)",
            (source, "identity"),
        )


@pytest.mark.parametrize("tier", ["", "admin", "unknown"])
def test_invalid_state_tier_is_rejected(sync_conn, tier):
    """Verify invalid state tier is rejected."""
    with pytest.raises(CheckViolation), sync_conn.transaction():
        sync_conn.execute(
            "INSERT INTO dataset_admin_state (source, uuid, visibility_tier) VALUES (%s, %s, %s)",
            ("archive_alpha", "identity", tier),
        )


def test_duplicate_state_identity_is_rejected(sync_conn):
    """Verify duplicate state identity is rejected."""
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid) VALUES (%s, %s)",
        ("archive_alpha", "identity"),
    )
    sync_conn.commit()
    with pytest.raises(UniqueViolation), sync_conn.transaction():
        sync_conn.execute(
            "INSERT INTO dataset_admin_state (source, uuid) VALUES (%s, %s)",
            ("archive_alpha", "identity"),
        )

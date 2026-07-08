"""seed_mock_data — prod-refusal guard + seeded-row invariants (TEST-049).

services/seed_mock_data.py was at 0% coverage. Two properties matter:

1. It REFUSES to run when settings.is_production (env_state == 'production'),
   so mock 'restricted' testimony can never be inserted into a real archive.
2. Every seeded row is source='mock', access_level='restricted', and
   visibility_tier='vetted' — a row that landed as visibility_tier='public'
   would surface mock "sensitive" testimony to anonymous users.

Runs against the real DB (it writes rows); the prod-guard test needs no DB
work because the refusal happens before the first query.
"""
from unittest.mock import patch

import pytest

from app.services.seed_mock_data import MOCK_RESTRICTED_DATASETS, seed_mock_data


async def test_seed_mock_data_refuses_in_production(db_pool, sync_conn):
    """The prod guard fires BEFORE any insert: with is_production True the
    call raises RuntimeError and the datasets table stays empty."""
    with patch("app.services.seed_mock_data.settings") as fake_settings:
        fake_settings.is_production = True
        with pytest.raises(RuntimeError, match="dev-only"):
            await seed_mock_data(db_pool)

    count = sync_conn.execute(
        "SELECT COUNT(*) FROM oral_history_datasets"
    ).fetchone()[0]
    assert count == 0


async def test_seed_mock_data_seeds_restricted_vetted_rows(db_pool, sync_conn):
    """Every seeded row is source='mock', access_level='restricted',
    visibility_tier='vetted' — the invariants that keep mock testimony
    invisible to below-tier users. Re-running is an idempotent upsert by uuid
    (count stays at the fixed 3, not 6)."""
    inserted = await seed_mock_data(db_pool)
    assert inserted == len(MOCK_RESTRICTED_DATASETS) == 3

    rows = sync_conn.execute(
        """SELECT source, access_level, visibility_tier
           FROM oral_history_datasets"""
    ).fetchall()
    assert len(rows) == 3
    for source, access_level, visibility_tier in rows:
        assert source == "mock"
        assert access_level == "restricted"
        assert visibility_tier == "vetted"

    # Idempotent: a second seed upserts by uuid, no duplicates.
    await seed_mock_data(db_pool)
    count = sync_conn.execute(
        "SELECT COUNT(*) FROM oral_history_datasets"
    ).fetchone()[0]
    assert count == 3


async def test_seeded_mock_rows_are_invisible_to_public_search(
    db_pool, e2e_client
):
    """End-to-end consequence of the invariants: after seeding, a guest's
    search never surfaces a mock dataset's restricted content — the tier
    filter (exercised for real here) hides all three."""
    await seed_mock_data(db_pool)

    # The mock rows are vetted-tier: a guest full-text search over their
    # (restricted) descriptions returns nothing.
    resp = e2e_client.get("/search", params={"q": "mock"})
    assert resp.status_code == 200
    # Titles may be public (visible fields), but the count reflects tier-
    # visible full-text matches; no restricted description leaks.
    for ds in MOCK_RESTRICTED_DATASETS:
        assert ds.get("description", "ZZZ") not in resp.text

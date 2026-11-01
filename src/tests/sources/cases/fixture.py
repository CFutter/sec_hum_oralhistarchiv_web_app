"""Exercise the real bounded package-data fixture adapter."""

from datetime import UTC, datetime

import pytest

from app.sources import FixtureAdapter
from tests.sources.contracts import Case


def make_case(_monkeypatch: pytest.MonkeyPatch) -> Case:
    """Describe bundled fixture behavior without replacing its implementation."""
    return Case(
        adapter_id="fixture",
        adapter_type=FixtureAdapter,
        values={
            "name": "contract_archive",
            "adapter": "fixture",
            "display": {"label": "Contract archive"},
            "max_visibility": "public",
            "requires_record_tier": True,
            "dataset": "catalogue_v1",
            "max_bytes": 65536,
        },
        document="""[[sources]]
name = "contract_archive"
adapter = "fixture"
label = "Contract archive"
max_visibility = "public"
requires_record_tier = true
dataset = "catalogue_v1"
max_bytes = 65536
""",
        cursor=datetime(2020, 1, 4, tzinfo=UTC),
        boundary=datetime(2020, 1, 2, 12, tzinfo=UTC),
        full_ids=("fixture:public", "fixture:registered", "fixture:vetted"),
        boundary_ids=("fixture:registered", "fixture:vetted"),
        raw_tiers=("public", "registered", "vetted"),
        expected_registered_tiers=("registered", "registered", "vetted"),
        operational_overrides={
            "display": {"label": "Renamed archive", "sensitivity_badge": "Examples"},
            "schedule": {
                "incremental_interval_seconds": 900,
                "rebuild_interval_seconds": 43200,
                "write_timeout_seconds": 240,
            },
            "max_bytes": 128000,
        },
        insufficient_budget={"max_bytes": 1},
        budget_error=ValueError,
        budget_match="max_bytes",
        io_calls=[],
    )

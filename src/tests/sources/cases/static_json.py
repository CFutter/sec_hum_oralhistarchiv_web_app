"""Exercise the toy adapter's real bounded native JSON snapshot."""

from datetime import UTC, datetime

import pytest

from app.sources import StaticJsonAdapter
from tests.sources.contracts import Case


def make_case(_monkeypatch: pytest.MonkeyPatch) -> Case:
    """Use native bundled input without replacing construction or fetching."""
    return Case(
        adapter_id="static_json",
        adapter_type=StaticJsonAdapter,
        values={
            "name": "contract_archive",
            "adapter": "static_json",
            "display": {"label": "Contract archive"},
            "max_visibility": "public",
            "requires_record_tier": True,
            "dataset": "proof_v1",
            "max_bytes": 65536,
        },
        document="""[[sources]]
name = "contract_archive"
adapter = "static_json"
label = "Contract archive"
max_visibility = "public"
requires_record_tier = true
dataset = "proof_v1"
max_bytes = 65536
""",
        cursor=datetime(2020, 1, 4, tzinfo=UTC),
        boundary=datetime(2020, 1, 2, 12, tzinfo=UTC),
        full_ids=("static_json:public", "static_json:registered", "static_json:vetted"),
        boundary_ids=("static_json:registered", "static_json:vetted"),
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

"""Omitted source snapshots are wiring errors, not an empty policy selection."""

from unittest.mock import create_autospec, sentinel

import pytest

from app.services import dataset_admin, dataset_admin_queries


@pytest.mark.parametrize(
    ("module", "service", "args", "kwargs"),
    [
        (dataset_admin_queries, "search_admin_datasets", (sentinel.pool,), {}),
        (dataset_admin_queries, "get_admin_dataset_by_id", (sentinel.pool, 1), {}),
        (
            dataset_admin,
            "change_dataset_admin_state",
            (sentinel.pool, 1, "hide"),
            {"context": dataset_admin.DatasetAdminContext(1, "acting-session")},
        ),
    ],
)
def test_missing_source_snapshot_is_rejected_before_coroutine_creation_or_io(
    monkeypatch, module, service, args, kwargs
):
    """Missing source snapshot is rejected before coroutine creation or I/O."""
    cursor = create_autospec(module.get_db_cursor, spec_set=True)
    monkeypatch.setattr(module, "get_db_cursor", cursor)
    # Dynamic dispatch deliberately exercises the invalid runtime call; a typed
    # caller also receives a missing-argument error from the type checker.
    with pytest.raises(TypeError, match="required keyword-only argument: 'configured_sources'"):
        getattr(module, service)(*args, **kwargs)
    cursor.assert_not_called()

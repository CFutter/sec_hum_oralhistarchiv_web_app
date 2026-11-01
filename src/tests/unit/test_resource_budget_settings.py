"""Finite allocation and search settings remain active in deployed configurations."""

import math

import pytest
from pydantic import ValidationError

from tests.unit.settings_builders import base_kwargs, make_settings, prod_kwargs


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("limiter_counter_capacity", 0),
        ("limiter_counter_capacity", 20001),
        ("limiter_cleanup_batch_size", 0),
        ("limiter_cleanup_batch_size", 1025),
        ("search_statement_timeout_ms", 0),
        ("search_statement_timeout_ms", 2001),
        ("search_operation_timeout_seconds", 0),
        ("search_operation_timeout_seconds", 5.1),
        ("search_pool_timeout_seconds", 0),
        ("search_pool_timeout_seconds", 1.1),
        ("search_global_rate_per_second", 0),
        ("search_global_rate_per_second", math.inf),
        ("search_global_rate_per_second", math.nan),
        ("search_global_burst", 0),
        ("search_global_burst", 1001),
    ],
)
def test_invalid_resource_budgets_are_rejected(name, value):
    """Check invalid resource budgets are rejected (ValidationError)."""
    with pytest.raises(ValidationError):
        make_settings(**base_kwargs(**{name: value}))


@pytest.mark.parametrize(
    "name",
    [
        "limiter_counter_capacity",
        "limiter_cleanup_batch_size",
        "search_statement_timeout_ms",
        "search_operation_timeout_seconds",
        "search_pool_timeout_seconds",
        "search_global_rate_per_second",
        "search_global_burst",
    ],
)
def test_boolean_resource_budgets_are_rejected(name):
    """Check boolean resource budgets are rejected (ValidationError)."""
    with pytest.raises(ValidationError, match="boolean"):
        make_settings(**base_kwargs(**{name: True}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"search_pool_timeout_seconds": 1, "search_operation_timeout_seconds": 1},
        {"search_statement_timeout_ms": 500, "search_operation_timeout_seconds": 0.5},
    ],
)
def test_inner_deadlines_must_fit_in_the_operation(overrides):
    """Check inner deadlines must fit in the operation (ValidationError)."""
    with pytest.raises(ValidationError, match="must be below"):
        make_settings(**base_kwargs(**overrides))


@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize(
    "overrides",
    [
        {"search_global_rate_per_second": 1.0},
        {"search_global_burst": 2},
    ],
)
def test_deployed_headroom_is_required_even_when_client_limits_are_disabled(enabled, overrides):
    """Check deployed headroom is required even when client limits are disabled (ValidationError)."""
    with pytest.raises(ValidationError, match="Deployed search"):
        make_settings(**prod_kwargs(rate_limit_enabled=enabled, **overrides))


def test_deployed_budget_can_be_lowered_without_disabling_admission():
    """Check deployed budget can be lowered without disabling admission."""
    configured = make_settings(
        **prod_kwargs(
            rate_limit_enabled=True,
            search_global_rate_per_second=0.25,
            search_operation_timeout_seconds=2,
        )
    )
    assert configured.search_global_burst == 1
    assert (
        configured.search_global_rate_per_second * configured.search_operation_timeout_seconds
        == 0.5
    )

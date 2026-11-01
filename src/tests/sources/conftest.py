"""Load every registered adapter's case and block live requests HTTP."""

from importlib import import_module
from unittest.mock import create_autospec

import pytest
import requests

from app.sources import registered_adapter_names
from tests.sources.contracts import Case

_REAL_SESSION_REQUEST = requests.sessions.Session.request


@pytest.fixture(params=registered_adapter_names())
def source_case(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> Case:
    """Require an adapter-owned provider for every registered adapter."""
    adapter_id = request.param
    provider = import_module(f"tests.sources.cases.{adapter_id}")
    case = provider.make_case(monkeypatch)
    if not isinstance(case, Case):
        raise TypeError(f"Conformance provider {adapter_id!r} must return Case")
    if case.adapter_id != adapter_id:
        raise ValueError(f"Conformance provider {adapter_id!r} returned a different adapter")

    # Providers capture real method signatures before this shared blocker.
    # Their recorded transports never invoke Session.request().
    monkeypatch.setattr(
        requests.sessions.Session,
        "request",
        create_autospec(
            _REAL_SESSION_REQUEST,
            side_effect=AssertionError(
                "Real HTTP requests are disabled in adapter conformance tests"
            ),
        ),
    )
    return case

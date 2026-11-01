"""Presentation contracts fail before a newly introduced refusal reaches HTTP."""

from typing import Literal

import pytest

from app.reason_contracts import require_reason_coverage
from app.routes.auth import account_deletion, admin, admin_promotion, datasets, email_change

Reason = Literal["invalid", "expired", "session_invalid"]


def test_separately_handled_reason_completes_contract():
    """Check separately handled reason completes contract."""
    require_reason_coverage(
        Reason,
        {"invalid": "Invalid", "expired": "Expired"},
        separately_handled={"session_invalid"},
    )


@pytest.mark.parametrize(
    "messages, separately_handled",
    [
        ({"invalid": "Invalid"}, {"session_invalid"}),
        ({"invalid": "Invalid", "expired": "Expired", "obsolete": "Old"}, {"session_invalid"}),
    ],
)
def test_missing_or_stale_reason_fails(messages, separately_handled):
    """Check missing or stale reason fails (RuntimeError)."""
    with pytest.raises(RuntimeError, match="Service reason presentation is incomplete"):
        require_reason_coverage(Reason, messages, separately_handled=separately_handled)


def test_current_route_maps_are_checked_on_import():
    # Importing these modules executes coverage checks for all typed refusal maps.

    """Check current route maps are checked on import."""
    assert all((account_deletion, admin, admin_promotion, datasets, email_change))

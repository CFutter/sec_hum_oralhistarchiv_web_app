"""Route authority comes from completed middleware resolution, never cookie reparsing."""

import pytest
from fastapi import Request

from app.middleware import get_resolved_session_id, require_resolved_session_id


def _request():
    """Build a request containing an untrusted raw session cookie."""
    return Request({"type": "http", "headers": [(b"cookie", b"session=untrusted-cookie")]})


def test_accessor_uses_resolved_authority_instead_of_cookie():
    """Check accessor uses resolved authority instead of cookie."""
    request = _request()
    request.state.session_resolution_completed = True
    request.state.session_id = "resolved-token"
    assert get_resolved_session_id(request) == "resolved-token"
    assert require_resolved_session_id(request) == "resolved-token"


def test_missing_resolution_is_a_wiring_error():
    """Check missing resolution is a wiring error (RuntimeError)."""
    with pytest.raises(RuntimeError, match="Session resolution must complete"):
        get_resolved_session_id(_request())


def test_completed_anonymous_state_is_distinct_from_protected_precondition():
    """Check completed anonymous state is distinct from protected precondition (RuntimeError)."""
    request = _request()
    request.state.session_resolution_completed = True
    request.state.session_id = None
    assert get_resolved_session_id(request) is None
    with pytest.raises(RuntimeError, match="Protected route reached"):
        require_resolved_session_id(request)

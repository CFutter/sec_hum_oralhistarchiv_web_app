"""Phase-1 proof: the fixed harness authenticates for real.

Guards (backlog §0): the old conftest's entered patch returned the
pre-migration 2-tuple for get_session_user, so EVERY authenticated request
500'd on unpack and auth tests passed for the wrong reason. These tests fail
on that harness (200 != 500) and on any future SessionLookup shape drift.
"""
import inspect

from app.services.sessions import SessionLookup, get_session_user


def test_authenticated_request_succeeds(authenticated_client):
    """An authenticated GET must produce a real 200 page, not a blanket 500."""
    response = authenticated_client.get("/account")
    assert response.status_code == 200
    # The page actually rendered with the session user, proving the middleware
    # unpacked the lookup and populated request.state.user.
    assert "alice@uzh.ch" in response.text


def test_guest_request_succeeds(guest_client):
    response = guest_client.get("/login")
    assert response.status_code == 200


def test_guest_is_redirected_from_protected_page(guest_client):
    """require_login raises a 303 to /login — proves the guest path resolves
    to no user rather than erroring."""
    response = guest_client.get("/account", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=")


def test_get_session_user_returns_sessionlookup_namedtuple():
    """Structural guard: the lookup is a NamedTuple with exactly the fields the
    middleware unpacks. If a field is added/renamed, this and every harness
    construction site fail loudly (the test-side equivalent of the mypy gate)."""
    assert issubclass(SessionLookup, tuple)
    assert SessionLookup._fields == ("user", "purpose", "flash_present")
    hints = inspect.signature(get_session_user).return_annotation
    assert hints is SessionLookup


def test_client_builder_reverse_teardown_part1_builds_two_clients(client_builder):
    """Part 1 of an ORDERED PAIR (file order) pinning client_builder's
    reverse-order teardown. unittest.mock restores the value seen at patch
    START: with forward-order teardown, closing client1 first re-installs
    client1's AsyncMock as what client2's patch will 'restore', so after both
    teardowns the mock is permanently installed over the real function for
    the rest of the process. This test just builds two clients; the fixture's
    own finalizer tears them down after it returns."""
    from tests.fixtures import make_sample_user

    client_builder(session_user=None)
    client_builder(session_user=make_sample_user())


def test_client_builder_reverse_teardown_part2_reals_restored():
    """Part 2 of the ordered pair: after part 1's fixture teardown, the
    middleware module must hold the REAL service functions again (identity
    with the never-patched originals in app.services.sessions), not a leaked
    AsyncMock. Fails when client_builder reverts to forward-order teardown."""
    import app.middleware.session as session_module
    import app.services.sessions as sessions_module

    assert session_module.get_session_user is sessions_module.get_session_user, (
        "client_builder teardown leaked a mock over get_session_user"
    )
    assert session_module.consume_flash is sessions_module.consume_flash, (
        "client_builder teardown leaked a mock over consume_flash"
    )


def test_mock_pool_fails_loudly_when_queried():
    """make_mock_pool's contract: any code path that reaches the pool (via
    pool.connection(), the only route to a cursor) raises instead of silently
    handing back MagicMock results — unit-tier tests must patch the service
    layer. Guards the 'route slipped past the patches and still passed'
    class."""
    import pytest
    from tests.fixtures import make_mock_pool

    pool = make_mock_pool()
    with pytest.raises(AssertionError, match="mock DB pool"):
        pool.connection()


def test_harness_seam_return_shapes_are_pinned():
    """TEST-060 shape guard: the harness hard-codes the return shapes of the
    two functions it patches away (consume_flash -> (message, category) tuple,
    verify_password -> (user, password_ok, locked_until) triple). If either
    annotation changes, this fails and fixtures.py must be updated in the
    same commit — otherwise every client test keeps passing against a stale
    shape while the real middleware/templates break."""
    import typing
    from datetime import datetime

    from app.services.sessions import consume_flash
    from app.services.authentication import verify_password
    from app.services.users import User

    hints = typing.get_type_hints(consume_flash)
    assert hints["return"] == (tuple[str, str] | None), (
        f"consume_flash return shape changed to {hints['return']!r}; "
        "update tests/fixtures.py build_client(flash=...) to match"
    )

    vp_hints = typing.get_type_hints(verify_password)
    assert vp_hints["return"] == tuple[User | None, bool, datetime | None], (
        f"verify_password return shape changed to {vp_hints['return']!r}; "
        "update the login-route client tests to match"
    )

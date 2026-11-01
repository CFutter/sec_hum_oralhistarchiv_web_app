"""Feed-owned HTTP sessions close once and retain no server cookie state."""

import traceback
from unittest.mock import create_autospec
from urllib.request import Request

import pytest
import requests
from urllib3.exceptions import HTTPError

from app.sources import json_feed_http as http
from app.sources.json_feed_protocol import FeedProtocolError

_CANARY = "private-session-failure-and-cookie-canary"
_ENDPOINT = "https://archive.example.edu/feed"


def _session_boundary(monkeypatch):
    """Patch Session construction with a real session and return close/factory spies."""
    real_session = requests.Session
    session = real_session()
    real_close = session.close

    close = create_autospec(
        real_close,
        spec_set=True,
        side_effect=real_close,
    )
    monkeypatch.setattr(session, "close", close)

    factory = create_autospec(
        real_session,
        spec_set=True,
        return_value=session,
    )
    monkeypatch.setattr(http.requests, "Session", factory)

    return session, close, factory, real_close


def test_session_is_configured_once_and_closed_only_at_owner_exit(
    monkeypatch,
):
    """Session is configured once and closed only at owner exit."""
    session, close, factory, _real_close = _session_boundary(monkeypatch)

    with http.feed_http_session() as owned:
        assert owned is session
        assert owned.trust_env is False
        assert owned.adapters["https://"].max_retries.total == 0
        assert owned.cookies.get_policy().allowed_domains() == ()
        close.assert_not_called()

    factory.assert_called_once_with()
    close.assert_called_once_with()


def test_each_factory_scope_has_a_distinct_session():
    """Each factory scope has a distinct session."""
    with (
        http.feed_http_session() as first,
        http.feed_http_session() as second,
    ):
        assert first is not second
        assert first.cookies is not second.cookies


@pytest.mark.parametrize(
    "domain",
    ["archive.example.edu", ".example.edu"],
)
def test_response_cookies_are_rejected_before_the_next_request(domain):
    """Response cookies are rejected before the next request."""
    with http.feed_http_session() as session:
        cookie = requests.cookies.create_cookie(
            "server-state",
            _CANARY,
            domain=domain,
            path="/",
            secure=True,
        )
        session.cookies.set_cookie_if_ok(
            cookie,
            Request(_ENDPOINT),
        )

        assert list(session.cookies) == []

        following = session.prepare_request(requests.Request("GET", _ENDPOINT))
        assert "Cookie" not in following.headers


@pytest.mark.parametrize("stage", ["factory", "mount", "close"])
@pytest.mark.parametrize(
    "error_type",
    [requests.RequestException, HTTPError, OSError],
)
def test_session_lifecycle_errors_are_fixed_and_resources_are_closed(
    monkeypatch,
    stage,
    error_type,
):
    """Session lifecycle errors are fixed and resources are closed."""
    session, close, factory, real_close = _session_boundary(monkeypatch)
    failure = error_type(_CANARY)

    if stage == "factory":
        factory.side_effect = failure
    elif stage == "mount":
        monkeypatch.setattr(
            session,
            "mount",
            create_autospec(
                session.mount,
                spec_set=True,
                side_effect=failure,
            ),
        )
    else:
        close.side_effect = failure

    try:
        with (
            pytest.raises(http.FeedTransportError) as caught,
            http.feed_http_session(),
        ):
            pass

        assert caught.value.error_code == "transport"
        assert _CANARY not in "".join(traceback.format_exception(caught.value))
        assert close.call_count == (0 if stage == "factory" else 1)
    finally:
        real_close()


@pytest.mark.parametrize(
    "failure",
    [
        FeedProtocolError("pagination"),
        ValueError(_CANARY),
        KeyboardInterrupt(),
    ],
)
def test_nontransport_body_errors_keep_their_identity_and_close_the_session(
    monkeypatch,
    failure,
):
    """Nontransport body errors keep their identity and close the session."""
    _session, close, factory, _real_close = _session_boundary(monkeypatch)

    with (
        pytest.raises(type(failure)) as caught,
        http.feed_http_session(),
    ):
        raise failure

    assert caught.value is failure
    factory.assert_called_once_with()
    close.assert_called_once_with()

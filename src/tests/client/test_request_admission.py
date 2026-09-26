"""Request admission before routing: the shared 404/405 sentinel bucket,
cookie-state parity under that bucket, route-resolution/evaluation faults,
the early-response security contract, and audit coverage of early rejection.

All of this runs through the real application (``app.main.app``) over the
full middleware stack; nothing here talks to the mocked database pool.
"""

import logging
from contextlib import contextmanager
from unittest.mock import patch

import itsdangerous.timed
import pytest
from starlette.routing import Mount

import app.middleware.rate_limiting as rl
from app.main import app as fastapi_app
from app.middleware import audit_logging
from app.middleware.cookies import SESSION_SIGNER
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user, sign_session_id

UNMATCHED_METHOD_MISMATCH_PATH = "/logout"  # POST-only route -> GET is a 405


def _unmatched_path(tag: str, i: int) -> str:
    return f"/__no_such_route_{tag}_{i}__"


@contextmanager
def _check_request_limit_raises(exc: BaseException):
    with patch.object(rl.limiter, "_check_request_limit", autospec=True, side_effect=exc):
        yield


class _UnnamedAsgiApp:
    """A callable ASGI app object with no ``__name__`` — unlike a plain
    function, a class instance's ``__call__`` gives _resolve_rate_limit_handler
    no ``endpoint.__name__`` to build a stable per-route bucket from. Must
    never actually run: resolution is expected to fail before call_next
    reaches it."""

    async def __call__(self, _scope, _receive, _send):
        raise AssertionError("an unnamed mount's ASGI app must never run")


@contextmanager
def _temporary_unnamed_mount(path="/__test_admission_unnamed_mount__"):
    """A Mount whose ASGI app carries no stable endpoint identity.

    Mount.matches() puts its ``app`` into the child scope as ``endpoint`` on
    a FULL match (same key Route uses), so _resolve_rate_limit_handler must
    distinguish "no stable identity" itself, by checking for ``__module__``
    and ``__name__`` — present on a function-based mount, absent on a bare
    callable object.
    """
    mount = Mount(path, app=_UnnamedAsgiApp())
    fastapi_app.router.routes.append(mount)
    try:
        yield path
    finally:
        fastapi_app.router.routes.remove(mount)


def _assert_early_rejection_security_contract(response) -> None:
    retry_after = response.headers.get("Retry-After")
    assert retry_after is not None and retry_after.isdigit()
    assert 1 <= int(retry_after) <= 60
    assert response.headers.get("Cache-Control") == "no-store"
    assert response.headers.get("X-Request-ID")
    assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")


class TestUnmatchedAndMethodMismatchShareOneSentinelAllowance:
    """404s (no route) and 405s (method mismatch) draw from one coarse
    per-client bucket, distinct from every named route's own bucket."""

    def test_alternating_404_and_405_traffic_shares_one_allowance(self, authenticated_client):
        for i in range(30):
            if i % 2 == 0:
                response = authenticated_client.get(_unmatched_path("alt", i))
                assert response.status_code == 404, i
                assert "Page not found" in response.text
            else:
                response = authenticated_client.get(
                    UNMATCHED_METHOD_MISMATCH_PATH, follow_redirects=False
                )
                assert response.status_code == 405, i
                assert "Allow" in response.headers
                assert "POST" in response.headers["Allow"]

        response = authenticated_client.get(_unmatched_path("alt", 999))
        assert response.status_code == 429
        assert "Too many requests" in response.text

    def test_named_route_traffic_is_not_drawn_from_the_sentinel_bucket(self, authenticated_client):
        """Positive control: 30 sentinel-charging requests do not touch
        /about's own (identical, but separately keyed) default-limit bucket."""
        for i in range(30):
            authenticated_client.get(_unmatched_path("separate", i))
        assert authenticated_client.get("/about").status_code == 200

    def test_accepted_sentinel_traffic_performs_no_session_lookup(self, authenticated_client):
        authenticated_client.session_spy.reset_mock()
        response = authenticated_client.get(_unmatched_path("accepted", 0))
        assert response.status_code == 404
        assert authenticated_client.session_spy.await_count == 0

    def test_429_on_sentinel_traffic_performs_no_session_lookup(self, authenticated_client):
        for i in range(30):
            authenticated_client.get(_unmatched_path("fill", i))
        authenticated_client.session_spy.reset_mock()
        response = authenticated_client.get(_unmatched_path("fill", 999))
        assert response.status_code == 429
        assert authenticated_client.session_spy.await_count == 0


def _build_cookie_state_client(client_builder, state: str):
    """A client presenting one of the five reviewed session-cookie states."""
    if state == "live":
        # build_client already sets a validly-signed cookie for RAW_SESSION_ID
        # and resolves it to a real user.
        return client_builder(session_user=make_sample_user())

    client = client_builder(session_user=None)
    if state == "absent":
        client.cookies.delete(settings.session_cookie_name)
    elif state == "forged":
        client.cookies.set(settings.session_cookie_name, "garbage-unsigned")
    elif state == "expired_signature":
        stale_epoch = 1_000_000_000  # 2001 — comfortably older than any max_age
        with patch.object(itsdangerous.timed.time, "time", return_value=stale_epoch):
            stale_value = SESSION_SIGNER.dumps(RAW_SESSION_ID)
        client.cookies.set(settings.session_cookie_name, stale_value)
    elif state == "revoked":
        # Validly signed, but get_session_user resolves session_user=None ->
        # SessionLookup(None, None, False), i.e. a dead/revoked session.
        client.cookies.set(settings.session_cookie_name, sign_session_id(RAW_SESSION_ID))
    else:  # pragma: no cover - test-authoring guard
        raise ValueError(f"unknown cookie state {state!r}")
    return client


class TestRejectedRequestsNeverReachTheDatabase:
    """Admission control runs outside session resolution, so a request it
    turns away costs no database work at all.

    Session resolution joins the sessions and users tables, and the pool is
    small. If it ran first, a client holding one valid signed cookie could
    keep taking connections from the pool long after every one of its
    requests was answered with 429 — the rejection would cost the server more
    than it costs the client.
    """

    def test_a_named_route_rejected_by_the_limiter_performs_no_session_lookup(
        self, authenticated_client
    ):
        for request_number in range(30):
            response = authenticated_client.get("/about")
            assert response.status_code == 200, f"request {request_number + 1} was limited early"

        authenticated_client.session_spy.reset_mock()
        rejected = authenticated_client.get("/about")

        assert rejected.status_code == 429
        assert authenticated_client.session_spy.await_count == 0, (
            "a rejected request still resolved its session against the database"
        )

    def test_an_admitted_request_on_the_same_route_does_resolve_its_session(
        self, authenticated_client
    ):
        """Positive control: the lookup is genuinely skipped by the rejection,
        not by the route or the cookie being uninteresting."""
        authenticated_client.session_spy.reset_mock()
        admitted = authenticated_client.get("/about")

        assert admitted.status_code == 200
        assert authenticated_client.session_spy.await_count >= 1


class TestCookieStateParityUnderSentinelAllowance:
    """Every reviewed cookie state — absent, forged, signature-expired,
    validly signed live, and validly signed but revoked — draws from the
    identical coarse sentinel allowance and is limited identically."""

    @pytest.mark.parametrize("state", ["absent", "forged", "expired_signature", "live", "revoked"])
    def test_each_cookie_state_hits_the_same_allowance_and_429(self, client_builder, state):
        client = _build_cookie_state_client(client_builder, state)
        for i in range(30):
            response = client.get(_unmatched_path(f"cookie_{state}", i))
            assert response.status_code == 404, (state, i)

        response = client.get(_unmatched_path(f"cookie_{state}", 999))
        assert response.status_code == 429
        assert 1 <= int(response.headers["Retry-After"]) <= 60
        assert "Too many requests" in response.text

    @pytest.mark.parametrize("state", ["live", "revoked"])
    def test_a_validly_signed_cookie_causes_no_lookup_on_sentinel_traffic(
        self, client_builder, state
    ):
        client = _build_cookie_state_client(client_builder, state)
        client.session_spy.reset_mock()
        response = client.get(_unmatched_path(f"cookie_lookup_{state}", 0))
        assert response.status_code == 404
        assert client.session_spy.await_count == 0


class TestResolutionAndEvaluationFaultsReturn503:
    """A route-resolution failure, a full match on a mount with no stable
    endpoint identity, and a fault inside the limiter's own check all return
    the same fail-closed 503 before the endpoint runs."""

    def test_forced_resolver_exception_returns_503_before_the_endpoint(self, guest_client):
        with patch.object(
            rl, "_resolve_rate_limit_handler", autospec=True, side_effect=RuntimeError("boom")
        ):
            response = guest_client.get("/about")

        assert response.status_code == 503
        assert "rate-limit service temporarily unavailable" in response.text.lower()
        _assert_early_rejection_security_contract(response)

    def test_full_match_on_an_unnamed_mount_returns_503_before_the_endpoint(self, guest_client):
        with _temporary_unnamed_mount() as path:
            response = guest_client.get(f"{path}/anything")

        assert response.status_code == 503
        assert "rate-limit service temporarily unavailable" in response.text.lower()
        _assert_early_rejection_security_contract(response)

    def test_forced_evaluation_fault_returns_503_before_the_endpoint(self, guest_client):
        with _check_request_limit_raises(RuntimeError("evaluation exploded")):
            response = guest_client.get("/about")

        assert response.status_code == 503
        assert "rate-limit service temporarily unavailable" in response.text.lower()
        _assert_early_rejection_security_contract(response)

    def test_healthy_resolution_and_evaluation_completes_the_request(self, guest_client):
        """Positive control for the three fault cases above."""
        response = guest_client.get("/about")
        assert response.status_code == 200
        assert "rate-limit service temporarily unavailable" not in response.text.lower()

    def test_resolver_fault_performs_no_session_lookup(self, authenticated_client):
        authenticated_client.session_spy.reset_mock()
        with patch.object(
            rl, "_resolve_rate_limit_handler", autospec=True, side_effect=RuntimeError("boom")
        ):
            response = authenticated_client.get("/about")
        assert response.status_code == 503
        assert authenticated_client.session_spy.await_count == 0


class TestEarlyRejectionSecurityContract:
    """429 (post-admission) and 503 (pre-admission) responses carry the same
    header contract and never echo route internals or client-controlled
    input back to the caller."""

    def test_429_carries_the_full_early_response_header_contract(self, guest_client):
        for _ in range(30):
            guest_client.get("/about")
        response = guest_client.get("/about")

        assert response.status_code == 429
        _assert_early_rejection_security_contract(response)

    def test_503_carries_the_full_early_response_header_contract(self, guest_client):
        marker = "/__attacker_controlled_path_marker__"
        with patch.object(
            rl, "_resolve_rate_limit_handler", autospec=True, side_effect=RuntimeError("boom")
        ):
            response = guest_client.get(marker)

        assert response.status_code == 503
        _assert_early_rejection_security_contract(response)
        assert marker not in response.text
        assert settings.session_cookie_name not in response.text

    def test_healthy_response_is_the_positive_control_for_the_header_contract(self, guest_client):
        """The 200 case does not carry Retry-After (proving the trio above is
        specific to early rejection, not just always present)."""
        response = guest_client.get("/about")
        assert response.status_code == 200
        assert "Retry-After" not in response.headers
        assert response.headers.get("Cache-Control") == "no-store"


class TestAuditRecordsEarlyRejection:
    """An anonymous early rejection still produces exactly one attributable
    audit record, and a failure in the audit sink itself must not silently
    convert the rejection into a success."""

    def test_anonymous_429_produces_one_audit_record_with_request_id_and_no_user(
        self, guest_client, caplog
    ):
        with caplog.at_level(logging.WARNING, logger="audit"):
            for _ in range(30):
                guest_client.get("/about")
            response = guest_client.get("/about")

        assert response.status_code == 429
        records = [
            r
            for r in caplog.records
            if r.name == "audit"
            and getattr(r, "path", None) == "/about"
            and getattr(r, "status_code", None) == 429
        ]
        assert len(records) == 1
        assert records[0].user_id is None
        assert records[0].request_id == response.headers["X-Request-ID"]

    def test_anonymous_503_produces_one_audit_record_with_request_id_and_no_user(
        self, guest_client, caplog
    ):
        with (
            caplog.at_level(logging.ERROR, logger="audit"),
            patch.object(
                rl, "_resolve_rate_limit_handler", autospec=True, side_effect=RuntimeError("boom")
            ),
        ):
            response = guest_client.get("/about")

        assert response.status_code == 503
        records = [r for r in caplog.records if r.name == "audit" and r.status_code == 503]
        assert len(records) == 1
        assert records[0].user_id is None
        assert records[0].request_id == response.headers["X-Request-ID"]

    def test_a_successful_request_is_still_audited_as_the_positive_control(
        self, guest_client, caplog
    ):
        with caplog.at_level(logging.INFO, logger="audit"):
            response = guest_client.get("/about")

        assert response.status_code == 200
        records = [r for r in caplog.records if r.name == "audit" and r.status_code == 200]
        assert len(records) == 1

    def test_an_audit_sink_failure_does_not_turn_a_429_into_a_success(self, guest_client):
        with patch.object(
            audit_logging.audit_logger,
            "log",
            autospec=True,
            side_effect=RuntimeError("audit sink unavailable"),
        ):
            for _ in range(30):
                guest_client.get("/about")
            response = guest_client.get("/about")

        assert response.status_code != 200
        assert response.status_code >= 500

    def test_an_audit_sink_failure_does_not_turn_a_503_into_a_success(self, guest_client):
        with (
            patch.object(
                audit_logging.audit_logger,
                "log",
                autospec=True,
                side_effect=RuntimeError("audit sink unavailable"),
            ),
            patch.object(
                rl, "_resolve_rate_limit_handler", autospec=True, side_effect=RuntimeError("boom")
            ),
        ):
            response = guest_client.get("/about")

        assert response.status_code != 200
        assert response.status_code >= 500

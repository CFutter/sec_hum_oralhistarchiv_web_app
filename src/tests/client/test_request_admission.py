"""Contract tests for request admission."""

import json
import logging
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from itsdangerous.timed import TimestampSigner
from redis.exceptions import ConnectionError as RedisConnectionError
from starlette.routing import Mount

import app.middleware.rate_limiting as rl
from app.main import app as fastapi_app
from app.middleware import audit_logging
from app.middleware.cookies import SESSION_SIGNER
from config import settings
from config.logging import setup_logging
from tests.fixtures import RAW_SESSION_ID, make_sample_user, sign_session_id

UNMATCHED_METHOD_MISMATCH_PATH = "/logout"


def _unmatched_path(tag: str, i: int) -> str:
    """Build a unique path outside the registered route set."""
    return f"/__no_such_route_{tag}_{i}__"


@contextmanager
def _check_request_limit_raises(exc: BaseException):
    """Make rate-limit checking raise the selected exception within this context."""
    with patch.object(rl.limiter, "_check_request_limit", autospec=True, side_effect=exc):
        yield


class _UnnamedAsgiApp:
    """Cover unnamed ASGI app."""

    async def __call__(self, _scope, _receive, _send):
        """Fail if the unnamed mounted application is ever dispatched."""
        raise AssertionError("an unnamed mount's ASGI app must never run")


@contextmanager
def _temporary_unnamed_mount(path="/__test_admission_unnamed_mount__"):
    """Temporarily mount a callable ASGI object without stable endpoint-name attributes."""
    mount = Mount(path, app=_UnnamedAsgiApp())
    fastapi_app.router.routes.append(mount)
    try:
        yield path
    finally:
        fastapi_app.router.routes.remove(mount)


def _assert_early_rejection_security_contract(response) -> None:
    """Require bounded retry guidance, no caching, request correlation, and framing protection."""
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
        """Check alternating 404 and 405 traffic shares one allowance."""
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
        """Check named route traffic is not drawn from the sentinel bucket (HTTP 200)."""
        for i in range(30):
            authenticated_client.get(_unmatched_path("separate", i))
        assert authenticated_client.get("/about").status_code == 200

    def test_accepted_sentinel_traffic_performs_no_session_lookup(self, authenticated_client):
        """Check accepted sentinel traffic performs no session lookup (HTTP 404)."""
        authenticated_client.session_spy.reset_mock()
        response = authenticated_client.get(_unmatched_path("accepted", 0))
        assert response.status_code == 404
        assert authenticated_client.session_spy.await_count == 0

    def test_429_on_sentinel_traffic_performs_no_session_lookup(self, authenticated_client):
        """Check 429 on sentinel traffic performs no session lookup."""
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
        with patch.object(
            TimestampSigner,
            "get_timestamp",
            autospec=True,
            return_value=stale_epoch,
        ):
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
    """Admission control runs outside session resolution, so a request it turns away costs no database
    work at all.
    """

    def test_a_named_route_rejected_by_the_limiter_performs_no_session_lookup(
        self, authenticated_client
    ):
        """Check a named route rejected by the limiter performs no session lookup."""
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
        """Check an admitted request on the same route does resolve its session (HTTP 200)."""
        authenticated_client.session_spy.reset_mock()
        admitted = authenticated_client.get("/about")

        assert admitted.status_code == 200
        assert authenticated_client.session_spy.await_count >= 1


class TestCookieStateParityUnderSentinelAllowance:
    """Cover cookie state parity under sentinel allowance."""

    @pytest.mark.parametrize("state", ["absent", "forged", "expired_signature", "live", "revoked"])
    def test_each_cookie_state_hits_the_same_allowance_and_429(self, client_builder, state):
        """Check each cookie state hits the same allowance and 429."""
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
        """Check a validly signed cookie causes no lookup on sentinel traffic (HTTP 404)."""
        client = _build_cookie_state_client(client_builder, state)
        client.session_spy.reset_mock()
        response = client.get(_unmatched_path(f"cookie_lookup_{state}", 0))
        assert response.status_code == 404
        assert client.session_spy.await_count == 0


class TestResolutionAndEvaluationFaultsReturn503:
    """Cover resolution and evaluation faults return503."""

    def test_forced_resolver_exception_returns_503_before_the_endpoint(self, guest_client):
        """Check forced resolver exception returns 503 before the endpoint."""
        with patch.object(
            rl, "_resolve_rate_limit_handler", autospec=True, side_effect=RuntimeError("boom")
        ):
            response = guest_client.get("/about")

        assert response.status_code == 503
        assert "rate-limit service temporarily unavailable" in response.text.lower()
        _assert_early_rejection_security_contract(response)

    def test_full_match_on_an_unnamed_mount_returns_503_before_the_endpoint(self, guest_client):
        """Check full match on an unnamed mount returns 503 before the endpoint."""
        with _temporary_unnamed_mount() as path:
            response = guest_client.get(f"{path}/anything")

        assert response.status_code == 503
        assert "rate-limit service temporarily unavailable" in response.text.lower()
        _assert_early_rejection_security_contract(response)

    def test_forced_evaluation_fault_returns_503_before_the_endpoint(self, guest_client):
        """Check forced evaluation fault returns 503 before the endpoint."""
        with _check_request_limit_raises(RuntimeError("evaluation exploded")):
            response = guest_client.get("/about")

        assert response.status_code == 503
        assert "rate-limit service temporarily unavailable" in response.text.lower()
        _assert_early_rejection_security_contract(response)

    def test_healthy_resolution_and_evaluation_completes_the_request(self, guest_client):
        """Check healthy resolution and evaluation completes the request (HTTP 200)."""
        response = guest_client.get("/about")
        assert response.status_code == 200
        assert "rate-limit service temporarily unavailable" not in response.text.lower()

    def test_resolver_fault_performs_no_session_lookup(self, authenticated_client):
        """Check resolver fault performs no session lookup (HTTP 503)."""
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
        """Check 429 carries the full early response header contract."""
        for _ in range(30):
            guest_client.get("/about")
        response = guest_client.get("/about")

        assert response.status_code == 429
        _assert_early_rejection_security_contract(response)

    def test_503_carries_the_full_early_response_header_contract(self, guest_client):
        """Check 503 carries the full early response header contract."""
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
        """Check anonymous 429 produces one audit record with request ID and no user."""
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
        """Check anonymous 503 produces one audit record with request ID and no user."""
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
        """Check a successful request is still audited as the positive control (HTTP 200)."""
        with caplog.at_level(logging.INFO, logger="audit"):
            response = guest_client.get("/about")

        assert response.status_code == 200
        records = [r for r in caplog.records if r.name == "audit" and r.status_code == 200]
        assert len(records) == 1

    def test_an_audit_sink_failure_does_not_turn_a_429_into_a_success(self, guest_client):
        """Check an audit sink failure does not turn a 429 into a success."""
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
        """Check an audit sink failure does not turn a 503 into a success."""
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


class TestFormattedEarlyRejectionPaths:
    """Admission labels survive the real error handler, audit middleware and JSON sink."""

    @pytest.mark.usefixtures("restore_logging")
    @pytest.mark.parametrize("status", [429, 503])
    @pytest.mark.parametrize(
        ("paths", "expected_path"),
        [
            (("/dataset/123456", "/dataset/987654"), "/dataset/{dataset_id}"),
            (("/__unmatched_" + "a" * 3000, "/__unmatched_" + "b" * 3000), "/<unmatched>"),
        ],
        ids=["matched-dataset-ids", "long-unmatched-paths"],
    )
    def test_quota_and_backend_refusals_format_bounded_paths(
        self, guest_client, capsys, status, paths, expected_path
    ):
        # Exercise real route resolution and limit evaluation. Only the storage
        # outcome is controlled; no endpoint/session lookup may run after refusal.
        """Check quota and backend refusals format bounded paths."""
        setup_logging(log_format="json")
        capsys.readouterr()
        guest_client.session_spy.reset_mock()
        backend_error = RedisConnectionError("backend unavailable") if status == 503 else None
        with patch.object(
            rl.limiter.limiter, "hit", autospec=True, return_value=False, side_effect=backend_error
        ):
            responses = [
                guest_client.get(
                    path,
                    headers={
                        "rate_limit_log_path": "/forged-header-label",
                        "X-Rate-Limit-Log-Path": "/forged-header-label",
                    },
                )
                for path in paths
            ]

        assert all(response.status_code == status for response in responses)
        guest_client.session_spy.assert_not_awaited()
        entries = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        diagnostic_logger = "app.main" if status == 429 else "app.middleware.rate_limiting"
        relevant = [entry for entry in entries if entry["logger"] in {"audit", diagnostic_logger}]
        for response in responses:
            request_id = response.headers["X-Request-ID"]
            events = [entry for entry in relevant if entry.get("request_id") == request_id]
            assert len(events) == 2
            assert {entry["logger"] for entry in events} == {"audit", diagnostic_logger}
            assert all(entry["path"] == expected_path for entry in events)
            audit = next(entry for entry in events if entry["logger"] == "audit")
            assert audit["event_type"] == "request"
            assert audit["message"] == f"GET {expected_path} → {status}"
            assert audit["status_code"] == status
            rendered = json.dumps(events)
            assert all(path not in rendered for path in paths)
            assert "/forged-header-label" not in rendered

    @pytest.mark.usefixtures("restore_logging")
    def test_resolution_failure_formats_the_unresolved_label(self, guest_client, capsys):
        """Check resolution failure formats the unresolved label (HTTP 503)."""
        setup_logging(log_format="json")
        capsys.readouterr()
        path = "/__unresolvable_" + "x" * 3000
        with patch.object(
            rl, "_resolve_rate_limit_handler", autospec=True, side_effect=RuntimeError("boom")
        ):
            response = guest_client.get(path)

        assert response.status_code == 503
        entries = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        events = [
            entry
            for entry in entries
            if entry.get("request_id") == response.headers["X-Request-ID"]
        ]
        assert len(events) == 2
        assert all(entry["path"] == "/<unresolved>" for entry in events)
        assert path not in json.dumps(events)

"""Backend-failure handling for the bounded rate-limit admission middleware."""

from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import create_autospec, patch

import pytest
from anyio import WouldBlock
from anyio._backends._asyncio import CapacityLimiter as _AsyncioCapacityLimiter
from limits.errors import ConcurrentUpdateError, ConfigurationError, StorageError
from redis.exceptions import (
    AuthenticationError,
    AuthorizationError,
    MaxConnectionsError,
    OutOfMemoryError,
    ResponseError,
)
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

import app.middleware.rate_limiting as rl
from app.routes.auth import password_reset
from app.services import password_reset as recovery_service
from app.services.email_outbox import (
    enqueue_outbound_email_cur as _real_enqueue_outbound_email_cur,
)
from app.services.password_reset import request_password_reset as _real_request_password_reset
from app.thread_work import ThreadWorkAdmissionTimeout
from app.thread_work import run_thread_work as _real_run_thread_work

FORGOT_PASSWORD_URL = "/forgot-password"

# (case id, exception instance, documented backend_failure_category)
BACKEND_FAILURE_CASES = [
    ("connection", RedisConnectionError("connection refused"), "connection"),
    ("timeout", RedisTimeoutError("socket timeout"), "timeout"),
    ("authentication", AuthenticationError("bad auth"), "authentication"),
    ("authorization", AuthorizationError("no permission"), "authorization"),
    ("command", ResponseError("unknown command"), "command"),
    ("concurrency", ConcurrentUpdateError("oralhistarchiv-rate-limit-key", 3), "concurrency"),
    ("configuration", ConfigurationError("bad config"), "configuration"),
    ("storage", StorageError(RuntimeError("generic storage failure")), "storage"),
    ("capacity_out_of_memory", OutOfMemoryError("OOM"), "capacity"),
    ("capacity_max_connections", MaxConnectionsError("too many connections"), "capacity"),
    ("unexpected", RuntimeError("surprise failure"), "unexpected"),
]


@contextmanager
def _check_request_limit_raises(exc: BaseException) -> Iterator[None]:
    """Force the bounded worker's single limiter check to fail with exc."""
    with patch.object(rl.limiter, "_check_request_limit", autospec=True, side_effect=exc):
        yield


@contextmanager
def _route_service_spies():
    """Autospecced doubles for the two services a real /forgot-password POST
    would reach — proof that the rejected request never got that far."""
    with (
        patch.object(
            password_reset,
            "request_password_reset",
            new=create_autospec(_real_request_password_reset),
        ) as get_user_spy,
        patch.object(
            recovery_service,
            "enqueue_outbound_email_cur",
            new=create_autospec(_real_enqueue_outbound_email_cur),
        ) as enqueue_spy,
    ):
        yield get_user_spy, enqueue_spy


def _submit_forgot_password(client):
    """Submit a CSRF-protected password-reset request for the sample address."""
    return client.post(
        FORGOT_PASSWORD_URL,
        data={"email": "user@example.com", "csrf_token": client.csrf_token},
    )


def _assert_early_rejection_security_contract(response) -> None:
    """Require bounded retry guidance, no caching, request correlation, and framing protection."""
    retry_after = response.headers.get("Retry-After")
    assert retry_after is not None and retry_after.isdigit()
    assert 1 <= int(retry_after) <= 60
    assert response.headers.get("Cache-Control") == "no-store"
    assert response.headers.get("X-Request-ID")
    assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")


def _assert_body_names_nothing_identifying(response, *forbidden: str) -> None:
    """Require a generic backend-failure page without connection or secret details."""
    body = response.text.lower()
    assert "rate-limit service temporarily unavailable" in body
    for value in (*forbidden, "redis://", "6379", "password", "secret"):
        assert value.lower() not in body


class TestStorageBackendFailuresFailClosed:
    """Every documented `_backend_failure_category` outcome returns the same
    fail-closed 503 before the endpoint or the outbox worker runs."""

    @pytest.mark.parametrize(
        ("_case_id", "exc", "category"),
        BACKEND_FAILURE_CASES,
        ids=[case_id for case_id, _, _ in BACKEND_FAILURE_CASES],
    )
    def test_backend_failure_returns_503_without_running_the_endpoint(
        self, guest_client, caplog, _case_id, exc, category
    ):
        """Check backend failure returns 503 without running the endpoint."""
        with (
            caplog.at_level("WARNING", logger="app.middleware.rate_limiting"),
            _route_service_spies() as (get_user_spy, enqueue_spy),
            _check_request_limit_raises(exc),
        ):
            response = _submit_forgot_password(guest_client)

        assert response.status_code == 503
        get_user_spy.assert_not_called()
        enqueue_spy.assert_not_called()

        _assert_early_rejection_security_contract(response)
        _assert_body_names_nothing_identifying(response, guest_client.csrf_token)

        record = next(
            r
            for r in caplog.records
            if r.name == "app.middleware.rate_limiting"
            and getattr(r, "backend_failure_category", None) is not None
        )
        assert record.backend_failure_category == category
        assert record.exception_type == type(exc).__name__
        assert record.path == FORGOT_PASSWORD_URL
        assert not hasattr(record, "client_ip")
        assert str(exc) not in record.getMessage()

    def test_healthy_backend_completes_the_same_request(self, guest_client):
        """Check healthy backend completes the same request (HTTP 200)."""
        with _route_service_spies() as (get_user_spy, enqueue_spy):
            get_user_spy.return_value = None
            response = _submit_forgot_password(guest_client)

        assert response.status_code == 200
        get_user_spy.assert_awaited_once()
        enqueue_spy.assert_not_awaited()

    @pytest.mark.parametrize(
        ("_case_id", "exc"),
        [
            (cid, exc)
            for cid, exc, _ in BACKEND_FAILURE_CASES
            if cid in {"connection", "unexpected"}
        ],
        ids=["connection", "unexpected"],
    )
    def test_backend_failure_performs_no_session_lookup(self, authenticated_client, _case_id, exc):
        """Check backend failure performs no session lookup (HTTP 503)."""
        authenticated_client.session_spy.reset_mock()
        with _check_request_limit_raises(exc):
            response = authenticated_client.get("/about")

        assert response.status_code == 503
        assert authenticated_client.session_spy.await_count == 0


class TestAdmissionAndCapacityFailuresFailClosed:
    """Cover admission and capacity failures fail closed."""

    def test_worker_admission_timeout_returns_503_without_running_the_endpoint(self, guest_client):
        """Check worker admission timeout returns 503 without running the endpoint."""
        with (
            _route_service_spies() as (get_user_spy, enqueue_spy),
            patch(
                "app.middleware.rate_limiting.run_thread_work",
                new=create_autospec(
                    _real_run_thread_work,
                    side_effect=ThreadWorkAdmissionTimeout(0.25),
                ),
            ),
        ):
            response = _submit_forgot_password(guest_client)

        assert response.status_code == 503
        get_user_spy.assert_not_called()
        enqueue_spy.assert_not_called()
        _assert_early_rejection_security_contract(response)

    def test_outstanding_capacity_exhaustion_returns_503_without_running_the_endpoint(
        self, guest_client
    ):
        # BoundedRateLimitMiddleware's outstanding_capacity is a real
        # anyio.CapacityLimiter; its asyncio-backend implementation (not the
        # public facade class) defines acquire_nowait, so that is the
        # concrete class under test.
        """Check outstanding capacity exhaustion returns 503 without running the endpoint."""
        with (
            _route_service_spies() as (get_user_spy, enqueue_spy),
            patch.object(
                _AsyncioCapacityLimiter,
                "acquire_nowait",
                autospec=True,
                side_effect=WouldBlock(),
            ),
        ):
            response = _submit_forgot_password(guest_client)

        assert response.status_code == 503
        get_user_spy.assert_not_called()
        enqueue_spy.assert_not_called()
        _assert_early_rejection_security_contract(response)

    def test_healthy_worker_completes_the_same_request(self, guest_client):
        """Check healthy worker completes the same request (HTTP 200)."""
        with _route_service_spies() as (get_user_spy, enqueue_spy):
            get_user_spy.return_value = None
            response = _submit_forgot_password(guest_client)

        assert response.status_code == 200
        get_user_spy.assert_awaited_once()
        enqueue_spy.assert_not_awaited()

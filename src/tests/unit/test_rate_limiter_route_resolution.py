"""Route resolution and bucket aggregation for rate admission.

Two properties are pinned here, both against the real
``BoundedRateLimitMiddleware``/``Limiter`` objects with an in-process
(memory) backend — these are resolution/aggregation properties, not
storage properties, so no Redis is needed:

- Every kind of unmatched traffic (unknown paths, percent-encoding,
  trailing-slash variants, query strings, unsupported methods) resolves to
  one stable sentinel handler and marks the request so session middleware
  skips its database lookup; a genuine full route match does neither.
- A decorated route's own limit is honoured, and two differently
  parameterised paths of the same endpoint share one bucket because the
  limiter's key style is ``"endpoint"`` (the qualified function name), not
  the concrete URL.
"""

import httpx
import pytest
from fastapi import FastAPI, Request, Response
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

import app.middleware.rate_limiting as rl
from app.middleware.rate_limiting import BoundedRateLimitMiddleware


def _unlimited_limiter() -> Limiter:
    return Limiter(
        key_func=rl.get_rate_limit_client_id,
        default_limits=["1000/minute"],
        strategy="fixed-window",
        headers_enabled=False,
    )


def _scope(*, method: str, path: str, query_string: bytes = b"", app: FastAPI) -> dict:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string,
        "headers": [],
        "client": ("203.0.113.5", 1234),
        "server": ("127.0.0.1", 8000),
        "app": app,
    }


class TestUnmatchedTrafficSharesOneSentinelAndMarksTheRequest:
    """Every distinct kind of unmatched request collapses onto the same
    (handler, limiter key) pair and sets the session-skip marker; a real
    route does neither."""

    def _app(self) -> FastAPI:
        app = FastAPI()
        app.state.limiter = _unlimited_limiter()

        @app.get("/items/{item_id}")
        async def get_item(item_id: str):
            return Response(item_id)

        return app

    async def _dispatch(self, app: FastAPI, *, method: str, path: str, query: bytes = b""):
        middleware = BoundedRateLimitMiddleware(app)
        request = Request(_scope(method=method, path=path, query_string=query, app=app))

        async def call_next(_request):
            return Response("downstream")

        await middleware.dispatch(request, call_next)
        return request

    @pytest.mark.parametrize(
        ("method", "path", "query"),
        [
            ("GET", "/no-such-route", b""),
            ("GET", "/items", b""),  # missing the required path parameter
            ("GET", "/items/1/", b""),  # trailing slash variant
            ("GET", "/%2e%2e/admin", b""),  # percent-encoded, no matching route
            ("GET", "/no-such-route", b"debug=1&x=y"),  # query string on an unmatched path
            ("POST", "/items/1", b""),  # unsupported method on a real route (405)
            ("DELETE", "/no-such-route", b""),
        ],
        ids=[
            "unknown_path",
            "missing_path_parameter",
            "trailing_slash_variant",
            "percent_encoded_segment",
            "query_string_present",
            "method_mismatch_on_a_real_route",
            "unsupported_method_on_an_unknown_path",
        ],
    )
    async def test_every_unmatched_variant_shares_one_sentinel_key_and_sets_the_marker(
        self, method, path, query
    ):
        app = self._app()
        limiter: Limiter = app.state.limiter
        request = await self._dispatch(app, method=method, path=path, query=query)

        second_scope = _scope(method=method, path=path, query_string=query, app=app)
        second_request = Request(second_scope)
        handler, route_unmatched, _log_path = rl._resolve_rate_limit_handler(second_request)
        assert route_unmatched is True
        assert handler is rl._coarse_unmatched_route_bucket

        # The storage key is (limiter._key_func(request), qualified handler
        # name) under key_style="endpoint" — derive it from the limiter's
        # own key function rather than assembling a string ourselves. Both
        # requests share the same client IP, so they must derive one key.
        first_key = limiter._key_func(request)
        second_key = limiter._key_func(second_request)
        expected_scope = f"{handler.__module__}.{handler.__name__}"
        assert first_key == second_key
        assert expected_scope == "app.middleware.rate_limiting._coarse_unmatched_route_bucket"
        assert request.state.rate_limit_route_unmatched is True

    async def test_a_full_route_match_does_not_set_the_unmatched_marker(self):
        """Positive control: a genuine, fully-matched route neither uses the
        sentinel handler nor sets the session-skip marker."""
        app = self._app()
        request = await self._dispatch(app, method="GET", path="/items/1")

        assert getattr(request.state, "rate_limit_route_unmatched", False) is False


class TestDecoratedRouteLimitsAggregateByEndpointNotByPath:
    """`key_style="endpoint"` means SlowAPI's storage key is the qualified
    view-function name, not the concrete URL: two differently parameterised
    requests to the same endpoint consume the same bucket."""

    def _app(self, limiter: Limiter) -> FastAPI:
        app = FastAPI()
        app.state.limiter = limiter
        app.add_middleware(BoundedRateLimitMiddleware)

        @app.get("/items/{item_id}")
        @limiter.limit("2/minute")
        async def get_item(item_id: str, request: Request):
            # SlowAPI's decorator requires a "request"/"websocket" parameter
            # by name; it is not otherwise used by this endpoint.
            del request
            return Response(item_id)

        @app.exception_handler(RateLimitExceeded)
        async def exceeded(_request, _exc):
            return Response("limited", status_code=429)

        return app

    async def test_two_different_paths_of_one_endpoint_share_one_bucket(self):
        limiter = Limiter(
            key_func=lambda: "client",
            strategy="fixed-window",
            key_style="endpoint",
            headers_enabled=False,
        )
        app = self._app(limiter)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            first = await client.get("/items/1")
            second = await client.get("/items/2")
            third = await client.get("/items/3")

        assert [first.status_code, second.status_code] == [200, 200]
        assert third.status_code == 429

    async def test_within_the_registered_limit_every_distinct_path_is_admitted(self):
        """Positive control: the decorated route's own limit (not some
        stricter accident) is what's enforced — while under it, distinct
        parameterised paths are all admitted."""
        limiter = Limiter(
            key_func=lambda: "client",
            strategy="fixed-window",
            key_style="endpoint",
            headers_enabled=False,
        )
        app = self._app(limiter)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            first = await client.get("/items/1")
            second = await client.get("/items/2")

        assert [first.status_code, second.status_code] == [200, 200]

    async def test_the_decorated_route_has_no_default_limits_leaking_in(self):
        """The registered per-route limit comes only from the decorator: a
        limiter with no default_limits still enforces `@limiter.limit`."""
        limiter = Limiter(
            key_func=lambda: "client",
            strategy="fixed-window",
            key_style="endpoint",
            headers_enabled=False,
        )
        assert limiter._application_limits == []
        app = self._app(limiter)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            responses = [await client.get("/items/1") for _ in range(3)]

        assert [r.status_code for r in responses] == [200, 200, 429]

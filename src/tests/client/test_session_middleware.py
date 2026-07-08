"""Session middleware tests — path matching, flash wiring, cookie clearing, TOTP gate.

Covers backlog §2.13 (exact-or-subpath prefix matching for skip/exempt lists),
§2.8 unit-level flash gating (consume-before-call_next ordering), the
clear_session_cookie contract (session + CSRF cookies both die together), and
the TotpGateMiddleware purpose/enrollment gates (which run INSIDE the
security-headers and audit layers).

All tests run against the mocked-pool client harness — no database required.
"""
import http.cookies
from unittest.mock import AsyncMock, patch

import pytest

from config import settings
from app.middleware.csrf import CSRF_COOKIE_NAME
from app.middleware.session import _path_matches, _SESSION_SKIP_PREFIXES, _TOTP_EXEMPT_PREFIXES
from tests.fixtures import make_sample_user, sign_session_id, RAW_SESSION_ID


# ---------------------------------------------------------------------------
# §2.13 — _path_matches pure unit: exact-or-subpath, never bare startswith
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("path", "prefixes", "expected"),
    [
        # /health matches itself and proper sub-paths...
        ("/health", ("/health",), True),
        ("/health/detail", ("/health",), True),
        # ...but NOT the prefix-collision trap: a route merely *starting with*
        # the string must not inherit the skip (the whole point of §2.13).
        ("/healthiness", ("/health",), False),
        # TOTP-exempt list: token sub-path is exempt, name collision is not.
        ("/verify-email/tok123", ("/verify-email",), True),
        ("/verify-emailx", ("/verify-email",), False),
        # Regression guard for the dropped trailing slash on /static: the
        # entry is now bare "/static" and the helper adds the "/" itself.
        ("/static/app.css", ("/static",), True),
        # Exact match works; a lookalike route does not.
        ("/logout", ("/logout",), True),
        ("/logout-fake", ("/logout",), False),
    ],
)
def test_path_matches_exact_or_subpath(path, prefixes, expected):
    """§2.13: _path_matches is `p == path or path.startswith(p + '/')` —
    exact-or-subpath — so prefix-colliding routes never inherit skip/exempt."""
    assert _path_matches(path, prefixes) is expected


def test_registered_prefix_lists_have_no_trailing_slashes():
    """§2.13: the helper appends '/' itself, so entries must be bare.
    A trailing slash on an entry would silently break the exact-match arm."""
    for prefix in _SESSION_SKIP_PREFIXES + _TOTP_EXEMPT_PREFIXES:
        assert not prefix.endswith("/"), prefix


# ---------------------------------------------------------------------------
# §2.13 behavioral — skip list drives real session resolution (or not)
# ---------------------------------------------------------------------------

def test_healthiness_collision_still_resolves_session(authenticated_client):
    """§2.13: '/healthiness' merely *starts with* '/health' — it must NOT
    inherit the skip. Session resolution runs (get_session_user awaited)
    even though the route itself 404s."""
    response = authenticated_client.get("/healthiness")
    assert response.status_code == 404  # no such route, but middleware ran
    assert authenticated_client.session_spy.await_count >= 1


def test_skip_paths_never_touch_session_lookup(authenticated_client):
    """§2.13: '/health', '/health/detail', and '/static/...' skip session
    resolution entirely — no cookie parsing, no DB lookup — even with a
    valid session cookie present."""
    for path in ("/health", "/health/detail", "/static/anything.css"):
        authenticated_client.session_spy.reset_mock()
        authenticated_client.get(path)
        assert authenticated_client.session_spy.await_count == 0, path


# ---------------------------------------------------------------------------
# §2.8 unit-level — flash consumed in middleware BEFORE call_next, gated
# on flash_present
# ---------------------------------------------------------------------------

def test_flash_consumed_before_render_and_visible_in_page(client_builder):
    """§2.8: consume_flash runs in the middleware BEFORE call_next, so the
    template already sees the message when it renders. Guards the
    load-bearing ordering (consume-after-call_next would silently eat it)."""
    client = client_builder(
        session_user=make_sample_user(), flash=("Saved.", "success")
    )
    response = client.get("/account")
    assert response.status_code == 200
    assert client.consume_flash_spy.await_count == 1
    assert "Saved." in response.text


def test_no_flash_skips_consume_entirely(client_builder):
    """§2.8: flash_present=False skips the read-and-clear query — the
    round-trip-saving gate. consume_flash must not be called at all."""
    client = client_builder(session_user=make_sample_user())
    response = client.get("/account")
    assert response.status_code == 200
    assert client.consume_flash_spy.await_count == 0


# ---------------------------------------------------------------------------
# Invalid-cookie clearing — session AND csrf cookies die together
# ---------------------------------------------------------------------------

class _home_db_patch:
    """Neutralise the '/' route's DB calls so the page renders 200. Required
    because the cookie-clearing assertion needs a response that made it back
    THROUGH the middleware — an unhandled 500 unwinds past
    `clear_session_cookie` and would mask the behavior."""

    def __init__(self):
        self._patches = [
            patch("app.routes.pages.get_recent_datasets",
        autospec=True, return_value=([], 0)),
            patch("app.routes.pages.get_last_full_rebuild_date",
        autospec=True, return_value=None),
            patch("app.routes.pages.get_keyword_count",
        autospec=True, return_value=0),
        ]

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        return False


def _deleted_cookie_names(response) -> set[str]:
    """Names of cookies the response deletes (Max-Age=0 per delete_cookie)."""
    deleted = set()
    for header in response.headers.get_list("set-cookie"):
        cookie = http.cookies.SimpleCookie()
        cookie.load(header)
        for name, morsel in cookie.items():
            if morsel.get("max-age") == "0":
                deleted.add(name)
    return deleted


def test_unsigned_garbage_cookie_clears_session_and_csrf(client_builder):
    """A tampered/unsigned session cookie must be actively deleted, and the
    CSRF cookie with it — a stale CSRF token must not survive the session
    boundary (see clear_session_cookie docstring)."""
    client = client_builder(session_user=None)
    client.cookies.set(settings.session_cookie_name, "garbage-unsigned")
    with _home_db_patch():
        response = client.get("/")
    assert response.status_code == 200
    deleted = _deleted_cookie_names(response)
    assert settings.session_cookie_name in deleted
    assert CSRF_COOKIE_NAME in deleted
    # Bad signature never reaches the session lookup.
    assert client.session_spy.await_count == 0


def test_valid_cookie_for_dead_session_clears_session_and_csrf(client_builder):
    """A correctly signed cookie whose session no longer resolves to a user
    (revoked/expired server-side) is also cleared — including the CSRF
    cookie, so the next GET mints a fresh token pair."""
    client = client_builder(session_user=None)  # get_session_user -> user=None
    client.cookies.set(settings.session_cookie_name, sign_session_id(RAW_SESSION_ID))
    with _home_db_patch():
        response = client.get("/")
    assert response.status_code == 200
    # The signature was valid, so the lookup DID run and came back empty.
    assert client.session_spy.await_count >= 1
    deleted = _deleted_cookie_names(response)
    assert settings.session_cookie_name in deleted
    assert CSRF_COOKIE_NAME in deleted


def test_signature_expired_cookie_is_treated_as_guest(client_builder):
    """TEST-057: a cookie whose SIGNATURE has expired (older than
    session_max_age_seconds by the itsdangerous embedded timestamp) is
    rejected by get_session_id_from_cookie's SignatureExpired branch → no
    session lookup, guest page, stale cookie cleared. This is the
    itsdangerous-timestamp layer, distinct from the DB expiry gate. Forged
    with a genuinely back-dated clock so the token is validly signed but
    old."""
    import itsdangerous.timed
    from app.middleware.cookies import SESSION_SIGNER

    # Sign the value with the real signer but a clock set far enough in the
    # past that max_age (session_max_age_seconds) has elapsed by now.
    stale_epoch = 1_000_000_000  # 2001 — comfortably older than any max_age
    with patch.object(itsdangerous.timed.time, "time", return_value=stale_epoch):
        stale_value = SESSION_SIGNER.dumps(RAW_SESSION_ID)

    client = client_builder(session_user=None)
    client.cookies.set(settings.session_cookie_name, stale_value)
    with _home_db_patch():
        response = client.get("/")

    assert response.status_code == 200
    # Expired signature → the session lookup never ran (treated as guest)...
    assert client.session_spy.await_count == 0
    # ...and the stale cookie was cleared.
    assert settings.session_cookie_name in _deleted_cookie_names(response)


# ---------------------------------------------------------------------------
# TOTP gate — runs INSIDE security-headers + audit; exempt paths per §2.13
# ---------------------------------------------------------------------------

def test_totp_setup_purpose_redirect_carries_security_headers(totp_setup_client):
    """A purpose='totp_setup' session is 303'd to /setup-totp, and because
    TotpGateMiddleware sits INSIDE the headers+audit layers, the redirect
    itself carries CSP and X-Request-ID — the whole reason for its position."""
    response = totp_setup_client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/setup-totp"
    assert "content-security-policy" in response.headers
    assert "x-request-id" in response.headers


def test_verify_email_exempt_from_totp_gate(totp_setup_client):
    """/verify-email/{token} is TOTP-exempt: a totp_setup session reaches the
    route (which 400s on a bad token) instead of being 303'd to /setup-totp."""
    response = totp_setup_client.get(
        "/verify-email/sometoken", follow_redirects=False
    )
    assert response.status_code == 400  # route ran; gate did not intercept


def test_logout_exempt_and_usable_during_totp_setup(totp_setup_client):
    """/logout is TOTP-exempt so a purpose-limited session can still end
    itself: POST with valid CSRF reaches the route and 303s home."""
    with patch(
        "app.routes.auth.login.delete_session", new=AsyncMock()
    ) as delete_spy:
        response = totp_setup_client.post(
            "/logout",
            data={"csrf_token": totp_setup_client.csrf_token},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert delete_spy.await_count == 1


def test_local_user_without_totp_gets_enrollment_redirect(client_builder):
    """Defense-in-depth enrollment gate (distinct from the purpose gate): a
    LOCAL user with a full-purpose session but totp_configured=False is
    303'd to /setup-totp on every non-exempt request."""
    client = client_builder(
        session_user=make_sample_user(totp_configured=False)
    )
    response = client.get("/account", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/setup-totp"


def test_shibboleth_user_without_totp_is_not_gated(client_builder):
    """The enrollment gate is LOCAL-only: a Shibboleth user without TOTP
    (their IdP handles MFA) must reach /account normally."""
    client = client_builder(
        session_user=make_sample_user(
            auth_method="shibboleth", totp_configured=False
        )
    )
    response = client.get("/account", follow_redirects=False)
    assert response.status_code == 200

"""Signed double-submit CSRF — cookie minting middleware + verify_csrf dependency.

Covers src/app/middleware/csrf.py (CSRFCookieMiddleware, verify_csrf,
_compute_csrf_token) and its cookies.py identifier plumbing, exercised through
the real middleware stack via the unit-tier TestClient harness.

The property under guard: the CSRF token is HMAC(secret-derived key, identifier)
— NOT a random value — so (a) the cookie rotates automatically whenever the
identifier changes (pre-session -> session), and (b) an attacker who can plant
a matching cookie/form pair but lacks the server secret still fails the HMAC
recompute (the double-submit-with-HMAC upgrade over plain double-submit).

POST /logout is the probe route for verify_csrf: it is TOTP-gate exempt and
carries the standard dependency chain
[validate_form_content_type, verify_csrf] (routes/auth/login.py).
"""

from unittest.mock import patch

from config import settings
from app.middleware.cookies import PRE_SESSION_COOKIE_NAME
from app.middleware.csrf import CSRF_COOKIE_NAME
from tests.fixtures import RAW_SESSION_ID, csrf_token_for, sign_session_id

BOGUS_TOKEN = "deadbeef" * 8  # right length/shape, but not HMAC(secret, id)


def _set_cookie_headers(response, name: str) -> list[str]:
    """All raw Set-Cookie headers for a given cookie name."""
    return [
        h for h in response.headers.get_list("set-cookie")
        if h.startswith(f"{name}=")
    ]


def _cookie_value(header: str) -> str:
    """Extract the cookie value from a raw Set-Cookie header."""
    return header.split(";", 1)[0].split("=", 1)[1].strip('"')


def _is_deletion(header: str) -> bool:
    """True if the Set-Cookie header expires the cookie (delete_cookie)."""
    return "max-age=0" in header.lower()


# ---------------------------------------------------------------------------
# Cookie minting (CSRFCookieMiddleware on GET)
# ---------------------------------------------------------------------------

def test_first_get_mints_pre_session_and_hmac_bound_csrf_cookie(client_builder):
    """A cookie-less GET mints a pre-session id AND a CSRF cookie, and the
    CSRF value is exactly HMAC-bound to that fresh pre-session id — not an
    independent random token. Guards the binding invariant the whole scheme
    rests on (csrf.py dispatch: new_pre_session -> _compute_csrf_token)."""
    client = client_builder(session_user=None)
    client.cookies.clear()

    # /about is a static, DB-free GET — the middleware minting under test
    # runs on every GET, and this route keeps the mocked pool untouched.
    response = client.get("/about")
    assert response.status_code == 200

    pre_headers = _set_cookie_headers(response, PRE_SESSION_COOKIE_NAME)
    csrf_headers = _set_cookie_headers(response, CSRF_COOKIE_NAME)
    assert len(pre_headers) == 1, "expected exactly one pre-session mint"
    assert len(csrf_headers) == 1, "expected exactly one CSRF mint"

    pre_session_value = _cookie_value(pre_headers[0])
    csrf_value = _cookie_value(csrf_headers[0])
    assert pre_session_value, "pre-session id must be non-empty"
    # THE binding assertion: cookie == HMAC(key, just-minted pre-session id).
    assert csrf_value == csrf_token_for(pre_session_value)


def test_second_get_with_valid_cookies_does_not_remint(client_builder):
    """Steady state: once the pre-session + matching CSRF cookies exist, a
    follow-up GET sets NO csrf_token cookie (and no new pre-session). Guards
    against re-minting on every request, which would break multi-tab forms
    and hammer Set-Cookie for no reason."""
    client = client_builder(session_user=None)
    client.cookies.clear()

    first = client.get("/about")
    assert _set_cookie_headers(first, CSRF_COOKIE_NAME)  # minted once
    # TestClient's jar persisted the minted cookies; replay them.
    second = client.get("/about")

    assert second.status_code == 200
    assert _set_cookie_headers(second, CSRF_COOKIE_NAME) == []
    assert _set_cookie_headers(second, PRE_SESSION_COOKIE_NAME) == []


def test_get_transition_deletes_pre_session_and_rebinds_csrf_to_session_id(
    guest_client,
):
    """Identifier transition (pre-session -> session): when a signed session
    cookie appears alongside a stale pre-session cookie, the next GET deletes
    the pre-session cookie and re-mints the CSRF cookie bound to the SESSION
    id. This is the 'automatic rotation on identifier change' property the
    module docstring promises — no explicit rotation call needed at login.

    Note: guest_client's patched get_session_user resolves this session id to
    no user, so the outer SessionResolutionMiddleware ALSO appends
    session/csrf deletion headers (stale-cookie cleanup). We therefore assert
    on the raw Set-Cookie header list, where the CSRF middleware's mint is
    still present and observable."""
    guest_client.cookies.set(
        settings.session_cookie_name, sign_session_id(RAW_SESSION_ID)
    )

    response = guest_client.get("/about", follow_redirects=False)
    assert response.status_code == 200

    pre_headers = _set_cookie_headers(response, PRE_SESSION_COOKIE_NAME)
    assert pre_headers, "pre-session cookie must be deleted on transition"
    assert all(_is_deletion(h) for h in pre_headers)

    csrf_headers = _set_cookie_headers(response, CSRF_COOKIE_NAME)
    minted = [h for h in csrf_headers if not _is_deletion(h)]
    assert len(minted) == 1, "expected exactly one CSRF re-mint"
    # Re-minted token is bound to the session id, not the old pre-session id.
    assert _cookie_value(minted[0]) == csrf_token_for(RAW_SESSION_ID)


# ---------------------------------------------------------------------------
# verify_csrf rejections (POST /logout, guest)
# ---------------------------------------------------------------------------

def test_post_without_csrf_form_field_rejected_403(guest_client):
    """POST with a CSRF cookie but no csrf_token form field -> 403 'Missing
    CSRF token'. Guards the presence check (verify_csrf's first gate)."""
    response = guest_client.post("/logout", data={"unrelated": "field"})

    assert response.status_code == 403
    assert "Missing CSRF token" in response.text


def test_post_with_cookie_form_mismatch_rejected_403(guest_client):
    """POST where the form token differs from the cookie -> 403. Guards the
    double-submit comparison (hmac.compare_digest(cookie, form))."""
    response = guest_client.post("/logout", data={"csrf_token": "wrong"})

    assert response.status_code == 403
    assert "CSRF validation failed" in response.text


def test_post_with_self_minted_matching_pair_rejected_403(guest_client):
    """Cookie and form MATCH but carry a value not derived from the server
    secret -> 403 via the HMAC recompute. This is THE property that upgrades
    plain double-submit: an attacker who can plant a cookie (e.g. via a
    subdomain) still cannot forge a passing pair without the secret."""
    guest_client.cookies.set(CSRF_COOKIE_NAME, BOGUS_TOKEN)

    response = guest_client.post("/logout", data={"csrf_token": BOGUS_TOKEN})

    assert response.status_code == 403
    assert "CSRF validation failed" in response.text


def test_post_with_valid_pair_passes_csrf_as_guest(guest_client):
    """The real HMAC pair (cookie + form, bound to the guest pre-session)
    passes verify_csrf: logout proceeds to its 303 redirect. With no session
    cookie present, get_session_id_from_cookie yields None so delete_session
    is never awaited — CSRF acceptance, not session teardown, is what this
    request exercises."""
    with patch(
        "app.routes.auth.login.delete_session", autospec=True) as mock_delete:
        response = guest_client.post(
            "/logout",
            data={"csrf_token": guest_client.csrf_token},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    mock_delete.assert_not_awaited()


# ---------------------------------------------------------------------------
# Authenticated logout with a valid pair
# ---------------------------------------------------------------------------

def test_authenticated_logout_with_valid_pair_deletes_session_and_rotates_cookies(
    authenticated_client,
):
    """Authenticated POST /logout with the valid session-bound pair -> 303,
    delete_session awaited with (pool, raw session id), and the response
    expires BOTH the session cookie and the CSRF cookie (rotate on logout, so
    a stale token cannot straddle the session boundary)."""
    with patch(
        "app.routes.auth.login.delete_session", autospec=True) as mock_delete:
        response = authenticated_client.post(
            "/logout",
            data={"csrf_token": authenticated_client.csrf_token},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    mock_delete.assert_awaited_once()
    _, session_id_arg = mock_delete.await_args.args
    assert session_id_arg == RAW_SESSION_ID

    session_headers = _set_cookie_headers(response, settings.session_cookie_name)
    assert session_headers and all(_is_deletion(h) for h in session_headers)
    csrf_headers = _set_cookie_headers(response, CSRF_COOKIE_NAME)
    assert csrf_headers and all(_is_deletion(h) for h in csrf_headers)


# ---------------------------------------------------------------------------
# Content-type gate ordering
# ---------------------------------------------------------------------------

def test_json_post_rejected_415_before_csrf_runs(authenticated_client):
    """POST /logout as application/json -> 415, NOT 403: the body carries a
    perfectly valid csrf_token, so a 403 would mean verify_csrf ran (and
    failed on the unparseable-as-form body). Getting 415 pins that
    validate_form_content_type is first in the dependency chain — the
    cheapest-rejection-first convention on every form POST route."""
    response = authenticated_client.post(
        "/logout", json={"csrf_token": authenticated_client.csrf_token}
    )

    assert response.status_code == 415
    assert "Unsupported Media Type" in response.text


# ---------------------------------------------------------------------------
# TEST-019 — anti-cookie-planting: the session id outranks a planted
# pre-session for the HMAC recompute (get_current_identifier precedence)
# ---------------------------------------------------------------------------

def test_planted_pre_session_pair_rejected_for_authenticated_user(
    authenticated_client,
):
    """The property that upgrades double-submit into subdomain-cookie-
    injection resistance: an attacker who harvests a valid GUEST pair
    (pre_session_id + its HMAC token, both self-service) and plants it on an
    AUTHENTICATED victim's browser must still fail — verify_csrf recomputes
    against the SIGNED SESSION id, which outranks the plantable pre-session
    cookie. A one-line 'simplification' flipping get_current_identifier's
    precedence passes the whole existing suite while re-opening this hole."""
    guest_pair_token = csrf_token_for("attacker-harvested-pre-session")
    authenticated_client.cookies.set(
        PRE_SESSION_COOKIE_NAME, "attacker-harvested-pre-session"
    )
    authenticated_client.cookies.set(CSRF_COOKIE_NAME, guest_pair_token)

    response = authenticated_client.post(
        "/logout",
        data={"csrf_token": guest_pair_token},  # cookie == form: double-submit OK
        follow_redirects=False,
    )
    # ...but the HMAC recompute binds to the SESSION identifier → 403.
    assert response.status_code == 403
    assert "CSRF validation failed" in response.text


def test_session_bound_pair_still_passes_with_planted_pre_session(
    authenticated_client,
):
    """Positive control for the precedence pin: with the same hostile
    pre-session cookie planted, the REAL session-bound pair still passes —
    the defence rejects the attacker's token, not the legitimate user's."""
    authenticated_client.cookies.set(
        PRE_SESSION_COOKIE_NAME, "attacker-harvested-pre-session"
    )
    session_token = csrf_token_for(RAW_SESSION_ID)
    authenticated_client.cookies.set(CSRF_COOKIE_NAME, session_token)

    with patch("app.routes.auth.login.delete_session", autospec=True):
        response = authenticated_client.post(
            "/logout",
            data={"csrf_token": session_token},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


# ---------------------------------------------------------------------------
# TEST-058 — malformed CSRF inputs are a clean 403, never a 500
# ---------------------------------------------------------------------------

def test_multipart_file_csrf_token_is_403_not_500(authenticated_client):
    """A multipart form where 'csrf_token' is an uploaded FILE (not a string)
    must be rejected with a clean 403: verify_csrf's isinstance(form_token,
    str) guard turns an UploadFile into 'CSRF validation failed', not an
    unhandled 500 from comparing an UploadFile to the cookie."""
    response = authenticated_client.post(
        "/logout",
        files={"csrf_token": ("t.txt", b"not-a-token", "text/plain")},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert "CSRF validation failed" in response.text


def test_missing_identifier_is_403_not_500(client_builder):
    """When neither a valid session cookie nor a pre-session cookie is present
    (get_current_identifier -> None), a POST that still carries a matching
    cookie+form token pair is rejected 403 at the identifier guard — not a
    500 from recomputing an HMAC over None. Built as a guest, then the
    pre-session cookie is removed so only a self-consistent (cookie==form)
    pair remains with no identifier to bind it to."""
    client = client_builder(session_user=None)
    # A cookie/form pair that matches each other (passes the double-submit
    # equality) but has no identifier cookie behind it.
    orphan = "a" * 64
    client.cookies.clear()
    client.cookies.set(CSRF_COOKIE_NAME, orphan)

    response = client.post(
        "/logout", data={"csrf_token": orphan}, follow_redirects=False
    )
    assert response.status_code == 403
    assert "CSRF validation failed" in response.text

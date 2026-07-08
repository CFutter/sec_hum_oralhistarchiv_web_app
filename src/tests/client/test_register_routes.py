"""Registration + rename routes — backlog §2.17 and the enumeration-neutral
duplicate flow.

Pins, at the route level (real app + middleware, mocked pool):

- §2.17: a display name with a control character gets a FRIENDLY 422 render of
  register.html, never a 500. Two fixed bugs are guarded: `_register_error`
  used to re-validate the preserved input (so the error renderer itself
  crashed), and the route's create_local_user `try` didn't catch the plain
  `ValueError`. The route now validates up front — before any DB/Argon2 work.
- Enumeration guard: a duplicate registration is byte-for-byte
  indistinguishable from a successful one (same page, no Set-Cookie), while
  the *background* effects differ (duplicate notice vs verification email).
- except-ordering: `UserAlreadyExistsError` is a `ValueError` subclass; the
  specific handler must stay ordered before `except ValueError` AND the
  generic handler must still catch plain ValueErrors. Both misorderings are
  distinguishable and tested.
- §2.17 symmetry: /account/change-name rejects the exact same input through
  the same `normalize_display_name` gate, surfacing the message as an
  'error' flash instead of a 422 page.

Rate-limit budget: POST /register is 3/minute in the test env — no test here
issues more than 2 register POSTs (the limiter resets between tests).
"""
from unittest.mock import patch

from config import settings
from app.services import UserAlreadyExistsError
from tests.fixtures import RAW_SESSION_ID, make_sample_user

# Stable markers for which template actually rendered.
REGISTER_PAGE_MARKER = "Create Account"          # register.html <h1>
PENDING_PAGE_MARKER = "Check your email"         # send_verification.html success branch

VALID_FORM = {
    "email": "alice.new@example.com",
    "display_name": "Alice Example",
    "affiliation": "University of Zurich",
    "country": "Switzerland",
    "password": "correct-horse-battery-staple-9",
    "password_confirm": "correct-horse-battery-staple-9",
}


def _post_register(client, **overrides):
    data = {**VALID_FORM, "csrf_token": client.csrf_token, **overrides}
    return client.post("/register", data=data)


# ---------------------------------------------------------------------------
# §2.17 — control characters get a friendly 422, not a 500, before any DB use
# ---------------------------------------------------------------------------

def test_register_control_char_display_name_friendly_422_no_db(guest_client):
    """§2.17: 'Alice\\x07' → 422 register.html with the validator's message and
    the submitted email echoed back. Regression: this used to 500 twice over —
    the route didn't catch normalize_display_name's ValueError, and the error
    renderer re-validated the preserved input and crashed. Fail-fast is pinned
    by asserting the pool was never touched (no wasted Argon2 hash / DB work).
    """
    response = _post_register(guest_client, display_name="Alice\x07")

    assert response.status_code == 422
    assert REGISTER_PAGE_MARKER in response.text
    assert "Display name cannot contain control characters." in response.text
    assert "alice.new@example.com" in response.text  # input preserved for the user
    guest_client.mock_pool.connection.assert_not_called()


def test_register_invalid_email_422_before_pool(guest_client):
    """Syntactically invalid email → 422 register.html with the friendly
    message, decided entirely before any pool use (fail-fast validation)."""
    response = _post_register(guest_client, email="not-an-email")

    assert response.status_code == 422
    assert REGISTER_PAGE_MARKER in response.text
    assert "Please enter a valid email address." in response.text
    guest_client.mock_pool.connection.assert_not_called()


def test_register_password_mismatch_422_before_pool(guest_client):
    """password != password_confirm → 422 register.html, no DB touched."""
    response = _post_register(guest_client, password_confirm="different-horse-battery-staple-9")

    assert response.status_code == 422
    assert REGISTER_PAGE_MARKER in response.text
    assert "Passwords do not match." in response.text
    guest_client.mock_pool.connection.assert_not_called()


def test_register_weak_password_422_with_length_message(guest_client):
    """An 11-char password (one short of the 12 minimum) → 422 with the exact
    length message from validate_password_strength, before any pool use."""
    weak = "Ab1!Ab1!Ab1"  # 11 chars
    response = _post_register(guest_client, password=weak, password_confirm=weak)

    assert response.status_code == 422
    assert REGISTER_PAGE_MARKER in response.text
    assert "Password must be at least 12 characters long." in response.text
    guest_client.mock_pool.connection.assert_not_called()


# ---------------------------------------------------------------------------
# Enumeration guard — duplicate registration indistinguishable from success
# ---------------------------------------------------------------------------

def test_duplicate_registration_indistinguishable_from_success(guest_client):
    """Enumeration guard: the duplicate response (create_local_user raises
    UserAlreadyExistsError) and the success response are the SAME 200
    'send_verification' page with NO Set-Cookie — an attacker probing
    /register learns nothing. Only the background effects differ: the
    duplicate path queues send_duplicate_registration_notice, the success
    path stores a token hash and queues send_verification_email.
    (2 register POSTs — within the 3/minute route limit.)
    """
    with patch("app.routes.auth.register.store_verification_token_hash", autospec=True) as store, \
         patch("app.routes.auth.register.send_duplicate_registration_notice", autospec=True) as notice, \
         patch("app.routes.auth.register.send_verification_email", autospec=True) as send:
        with patch("app.routes.auth.register.create_local_user",
               autospec=True, side_effect=UserAlreadyExistsError("a@b.com")):
            duplicate = _post_register(guest_client)

        # Duplicate path: neutral page, notice queued, no token / no email.
        assert duplicate.status_code == 200
        assert PENDING_PAGE_MARKER in duplicate.text
        assert "already exists" not in duplicate.text  # raw error never leaks
        assert "set-cookie" not in duplicate.headers
        notice.assert_called_once_with("alice.new@example.com")
        send.assert_not_called()
        store.assert_not_awaited()

        user = make_sample_user(email="alice.new@example.com")
        with patch("app.routes.auth.register.create_local_user",
               autospec=True, return_value=user):
            success = _post_register(guest_client)

        assert success.status_code == 200
        assert PENDING_PAGE_MARKER in success.text
        assert "set-cookie" not in success.headers
        send.assert_called_once()
        store.assert_awaited_once()
        notice.assert_called_once()  # still only the one duplicate call

    # The bodies are rendered from the identical template + context (the CSRF
    # token, if rendered, is deterministic per session identifier and both
    # POSTs share one client) — exact equality is the strongest possible
    # "indistinguishable" assertion.
    assert duplicate.text == success.text


def test_plain_valueerror_from_create_user_renders_message_not_neutral_page(guest_client):
    """Except-ordering pin (§2.17): a plain ValueError from create_local_user
    must render register.html (422) WITH the error message. Because
    UserAlreadyExistsError subclasses ValueError, both misorderings are
    detectable: if `except ValueError` came first, duplicates would leak the
    'already exists' message; if `except UserAlreadyExistsError` swallowed all
    ValueErrors, this test would see the neutral pending page instead.
    """
    with patch("app.routes.auth.register.create_local_user",
               autospec=True, side_effect=ValueError("Display name cannot be empty.")):
        response = _post_register(guest_client)

    assert response.status_code == 422
    assert REGISTER_PAGE_MARKER in response.text
    assert "Display name cannot be empty." in response.text
    assert PENDING_PAGE_MARKER not in response.text  # not the neutral page


# ---------------------------------------------------------------------------
# §2.17 — rename goes through the same normalize_display_name gate
# ---------------------------------------------------------------------------

def test_change_name_rejects_control_char_with_error_flash(authenticated_client):
    """§2.17 symmetry: /account/change-name with 'Alice\\x07' is rejected by
    the same normalize_display_name gate as registration — 303 back to
    /account with the validator's message flashed as 'error'. The ValueError
    fires before update_display_name touches the DB (pool untouched apart
    from the patched set_flash).
    """
    with patch("app.routes.auth.account.set_flash", autospec=True) as flash:
        response = authenticated_client.post(
            "/account/change-name",
            data={"display_name": "Alice\x07",
                  "csrf_token": authenticated_client.csrf_token},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/account"
    flash.assert_awaited_once()
    args = flash.await_args.args
    assert args[1] == RAW_SESSION_ID  # flash bound to the caller's session
    assert args[2] == "Display name cannot contain control characters."
    assert args[3] == "error"
    # normalize_display_name raised before the UPDATE ran.
    authenticated_client.mock_pool.connection.assert_not_called()


def test_change_name_happy_path_updates_and_flashes_success(authenticated_client):
    """Happy rename: update_display_name is awaited with the submitted name
    and the user is redirected to /account with a 'success' flash."""
    with patch("app.routes.auth.account.update_display_name", autospec=True) as update, \
         patch("app.routes.auth.account.set_flash", autospec=True) as flash:
        response = authenticated_client.post(
            "/account/change-name",
            data={"display_name": "Alice Renamed",
                  "csrf_token": authenticated_client.csrf_token},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/account"
    update.assert_awaited_once()
    assert update.await_args.args[1] == 1  # authenticated user's id
    assert update.await_args.args[2] == "Alice Renamed"
    flash.assert_awaited_once()
    assert flash.await_args.args[2] == "Display name updated."
    assert flash.await_args.args[3] == "success"


# ---------------------------------------------------------------------------
# Registration disabled — both verbs bounce to /login
# ---------------------------------------------------------------------------

def test_register_disabled_get_and_post_redirect_to_login(guest_client, monkeypatch):
    """With settings.local_auth_enabled=False, GET /register 303s to /login
    and a fully valid POST 303s too, without ever attempting user creation."""
    monkeypatch.setattr(settings, "local_auth_enabled", False)

    get_response = guest_client.get("/register", follow_redirects=False)
    assert get_response.status_code == 303
    assert get_response.headers["location"] == "/login"

    with patch("app.routes.auth.register.create_local_user", autospec=True) as create:
        post_response = guest_client.post(
            "/register",
            data={**VALID_FORM, "csrf_token": guest_client.csrf_token},
            follow_redirects=False,
        )
    assert post_response.status_code == 303
    assert post_response.headers["location"] == "/login"
    create.assert_not_awaited()

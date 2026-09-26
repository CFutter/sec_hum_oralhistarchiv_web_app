"""POST /account/confirm-email — conditional session-cookie clear.

Covers src/app/routes/auth/email_change.py::confirm_email_submit (lines
185-265). This POST is deliberately CSRF-EXEMPT (only
Depends(validate_form_content_type) guards it, see the route's own docstring
at lines 189-197): the signed, single-use, email-bound token IS the
capability, so it must work with no CSRF cookie/form field and — critically —
with NO active session at all (a user may click the link on a different
device than the one they requested the change from, or someone else's
session/no session may simply be the one presenting the request).

That last fact is exactly why an unconditional
`clear_session_cookie(response)` call in this route would be a defect: wiping
the SESSION cookie for whoever happens to be presenting the request — not
necessarily the account being changed — logs out an unrelated party (most
visibly: an admin who opens a user's confirmation link ends up logged out of
their OWN admin session). The clear is gated on
`request.state.user and request.state.user.id == data["user_id"]`
(lines 263-264). This file pins that guard from all three angles: the
match case (cookie clears), the admin/mismatch case (cookie survives), and
the no-session case (cookie survives, no AttributeError on None.id).

Session REVOCATION (`delete_user_sessions`, line 260) is unconditional and
sits ABOVE the cookie-clear guard — it always fires for the token's target
user regardless of who is presenting the request. Every test below pins
that these two are independent: the guard controls only the PRESENTING
response's cookie, never whether the target's sessions get killed.
"""

import logging
from unittest.mock import patch

from app.middleware.csrf import CSRF_COOKIE_NAME
from app.services.tokens import hash_token
from config import settings
from tests.fixtures import make_sample_user

NEW_EMAIL = "new@example.org"
TOKEN = "irrelevant-opaque-token"  # validate_email_change_token is patched, so
# the raw string never gets parsed — any value works as the Form field.

AUTH_REVISION = 12


def _set_cookie_headers(response, name: str) -> list[str]:
    """All raw Set-Cookie headers for a given cookie name."""
    return [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]


def _assert_cookie_deleted(response, name: str) -> None:
    headers = _set_cookie_headers(response, name)
    assert len(headers) == 1, (name, headers)
    assert "max-age=0" in headers[0].lower(), (name, headers[0])


def _assert_cookie_untouched(response, name: str) -> None:
    assert _set_cookie_headers(response, name) == []


def _patch_confirm(*, token_data, confirm_result=True):
    """Patch validation and confirmation with a complete revision payload."""
    complete_token_data = {
        "auth_revision": AUTH_REVISION,
        **token_data,
    }
    return (
        patch(
            "app.routes.auth.email_change.validate_email_change_token",
            autospec=True,
            return_value=complete_token_data,
        ),
        patch(
            "app.routes.auth.email_change.confirm_email_change",
            autospec=True,
            return_value=confirm_result,
        ),
    )


# ---------------------------------------------------------------------------
# GET /account/change-email — local-only page access
# ---------------------------------------------------------------------------


def test_local_full_session_sees_the_change_email_form(authenticated_client):
    """GET renders for a local full session (authenticated_client's default
    sample user is a local account)."""
    response = authenticated_client.get("/account/change-email")
    assert response.status_code == 200
    assert 'name="new_email"' in response.text


def test_federated_session_is_refused_the_local_only_page(client_builder):
    """Positive-control pair: a federated (Shibboleth) full session is 403'd
    — email changes are local-account only; federated attributes come from
    the IdP."""
    federated = make_sample_user(auth_method="shibboleth", federated_status="approved")
    client = client_builder(session_user=federated)
    response = client.get("/account/change-email")
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# GET /account/confirm-email/{token} — SAFE confirmation page
# ---------------------------------------------------------------------------


def test_valid_confirmation_token_renders_the_form_without_consuming_it(guest_client):
    with (
        patch(
            "app.routes.auth.email_change.validate_email_change_token",
            autospec=True,
            return_value={
                "user_id": 1,
                "new_email": NEW_EMAIL,
                "acting_admin_id": None,
                "auth_revision": AUTH_REVISION,
            },
        ),
        patch(
            "app.routes.auth.email_change.pending_email_change_matches",
            autospec=True,
            return_value=True,
        ),
        patch("app.routes.auth.email_change.confirm_email_change", autospec=True) as confirm,
    ):
        response = guest_client.get(f"/account/confirm-email/{TOKEN}")

    assert response.status_code == 200
    assert NEW_EMAIL in response.text
    confirm.assert_not_awaited()


def test_self_service_confirm_redirects_and_clears_session_cookie(authenticated_client):
    """Authenticated_client is user id=1; the token also targets
    user_id=1, so `request.state.user.id == data["user_id"]` (line 263) is
    True and clear_session_cookie (session.py:150-163) fires, deleting BOTH
    the session cookie AND the CSRF cookie — clear_session_cookie clears the
    CSRF cookie too so a stale token can't survive the session boundary.
    Also pins the exact redirect target (line 262) and that session
    revocation (line 260) targets the CORRECT user via the CORRECT pool —
    this is the positive control the negative tests below are
    measured against."""
    token_data = {"user_id": 1, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p as validate, confirm_p:
        response = authenticated_client.post(
            "/account/confirm-email",
            data={"token": TOKEN},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?email_changed=1"
    validate.assert_called_once_with(TOKEN)

    _assert_cookie_deleted(response, settings.session_cookie_name)
    _assert_cookie_deleted(response, CSRF_COOKIE_NAME)


def test_admin_confirming_own_email_change_still_clears_cookie(admin_client):
    """Positive control for the guard itself (not just for "some
    logged-in user"): the mismatch test below (admin_client, id=99,
    confirming a token for user_id=1) must fail to clear the cookie because
    the IDS DIFFER — not because the session happens to belong to an admin.
    Proven here by pointing the SAME admin_client at a token for its OWN
    id (99): the guard is id-equality, not an admin/non-admin branch, so
    the cookie clears exactly as it did for authenticated_client above."""
    token_data = {"user_id": 99, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p, confirm_p:
        response = admin_client.post(
            "/account/confirm-email",
            data={"token": TOKEN},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?email_changed=1"
    _assert_cookie_deleted(response, settings.session_cookie_name)
    _assert_cookie_deleted(response, CSRF_COOKIE_NAME)


def test_admin_session_confirming_other_users_token_keeps_admin_logged_in(admin_client):
    """admin_client is user id=99; the token targets
    user_id=1 (e.g. the admin opened the user's emailed link to help them,
    or is simply the party that happened to click it). request.state.user.id
    (99) != data["user_id"] (1), so the line-263 guard is False and
    clear_session_cookie is SKIPPED entirely — before this branch was
    unconditional and the admin got logged out of their OWN session for
    confirming someone else's change. delete_user_sessions still fires for
    the TARGET (user 1, line 260) — revocation of the changed account is
    unaffected by whose cookie is on the request."""
    token_data = {"user_id": 1, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p, confirm_p:
        response = admin_client.post(
            "/account/confirm-email",
            data={"token": TOKEN},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?email_changed=1"

    _assert_cookie_untouched(response, settings.session_cookie_name)
    _assert_cookie_untouched(response, CSRF_COOKIE_NAME)


# ---------------------------------------------------------------------------
# no presenting session at all
# ---------------------------------------------------------------------------


def test_guest_confirm_no_session_cookie_deletion_header_at_all(guest_client):
    """guest_client has request.state.user is None — the common
    case for this route, since it is explicitly designed to work with no
    app session (route docstring, lines 191-197). `request.state.user and
    request.state.user.id == ...` (line 263) short-circuits on the falsy
    None WITHOUT evaluating `.id` (a naive
    `request.state.user.id == data["user_id"]` with no None-guard would
    raise AttributeError here, 500ing every cross-device confirm). No
    Set-Cookie for either auth cookie appears at all — there is nothing to
    clear and nothing else in this route sets cookies. delete_user_sessions
    still fires for the token's target."""
    token_data = {"user_id": 1, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p, confirm_p:
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": TOKEN},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?email_changed=1"

    _assert_cookie_untouched(response, settings.session_cookie_name)
    _assert_cookie_untouched(response, CSRF_COOKIE_NAME)


# ---------------------------------------------------------------------------
# Failure arms
# ---------------------------------------------------------------------------


def test_invalid_or_expired_token_renders_error_page_before_any_service_call(guest_client):
    """validate_email_change_token returns None for a bad signature or
    expired token (email_change.py:86-88) -> the route short-circuits at
    line 202, rendering error.html's 'Invalid or expired link' copy at 400
    (lines 203-212) WITHOUT ever calling confirm_email_change or
    delete_user_sessions — an invalid token must not be able to revoke
    anyone's sessions."""
    with (
        patch(
            "app.routes.auth.email_change.validate_email_change_token",
            autospec=True,
            return_value=None,
        ) as validate,
        patch("app.routes.auth.email_change.confirm_email_change", autospec=True) as confirm,
    ):
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": "bad-token"},
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "Invalid or expired link" in response.text
    validate.assert_called_once_with("bad-token")
    confirm.assert_not_awaited()
    _assert_cookie_untouched(response, settings.session_cookie_name)


def test_confirm_email_change_failure_logs_audit_event_and_renders_error(guest_client, caplog):
    """confirm_email_change's atomic UPDATE matches zero rows — already
    used, wrong hash, or the address was taken in the meantime
    (email_change.py:113-163) -> False. The route logs an
    'email_change_failed' audit event carrying the token's user_id (route
    lines 219-226) and renders error.html's 'Could not change email' copy
    at 400 (lines 227-237), WITHOUT calling delete_user_sessions — that
    call sits after the `if not success` early return (line 260), so a
    failed confirm must not revoke the target's sessions."""
    token_data = {"user_id": 1, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data, confirm_result=False)
    with (
        validate_p,
        confirm_p as confirm,
        caplog.at_level(logging.INFO, logger="audit"),
    ):
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": "stale-token"},
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "Could not change email" in response.text
    confirm.assert_awaited_once()
    _assert_cookie_untouched(response, settings.session_cookie_name)

    events = [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == "email_change_failed"
    ]
    assert len(events) == 1
    assert events[0].user_id == 1


def test_admin_initiated_success_logs_admin_email_changed_not_email_changed(guest_client, caplog):
    """Positive control distinguishing the two SUCCESS audit branches (route
    lines 239-258): a token carrying acting_admin_id logs
    'admin_email_changed' with actor_admin_id + target_user_id, and must
    NOT also log the self-service 'email_changed' event — the two are
    mutually exclusive on the same request. guest_client stands in for
    'whoever presents the request': this audit branch is driven entirely
    by the TOKEN's acting_admin_id key, not by who is logged in."""
    token_data = {"user_id": 1, "new_email": NEW_EMAIL, "acting_admin_id": 99}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with (
        validate_p,
        confirm_p,
        caplog.at_level(logging.INFO, logger="audit"),
    ):
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": TOKEN},
            follow_redirects=False,
        )

    assert response.status_code == 303

    admin_events = [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == "admin_email_changed"
    ]
    self_events = [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == "email_changed"
    ]
    assert len(admin_events) == 1
    assert admin_events[0].actor_admin_id == 99
    assert admin_events[0].target_user_id == 1
    assert self_events == []


def test_confirm_forwards_signed_auth_revision(guest_client):
    token_data = {
        "user_id": 1,
        "new_email": NEW_EMAIL,
        "auth_revision": 37,
    }
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p, confirm_p as confirm:
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": TOKEN},
            follow_redirects=False,
        )

    assert response.status_code == 303
    confirm.assert_awaited_once_with(
        guest_client.mock_pool,
        1,
        NEW_EMAIL,
        hash_token(TOKEN),
        expected_auth_revision=37,
    )

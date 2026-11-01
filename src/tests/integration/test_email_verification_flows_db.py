"""Real HTTP registration: only the mailbox owner chooses the password."""

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec

import pytest
import time_machine
from argon2.exceptions import VerifyMismatchError
from lxml import html

from app.services import registration_setup
from app.services.crypto import decrypt_outbox_body, password_hasher
from app.services.tokens import action_token_public_id, hash_token
from config import settings
from tests.action_links import action_path, token_from_action_email

EMAIL = "newcomer@example.org"
OWNER_PASSWORD = "Fresh-N3w-Passw0rd!"
ATTACKER_PASSWORD = "An0ther-G00d-Pw!x"
SUCCESS_LOCATION = "/login?notice=registration_complete"


def _request(client, **extra):
    """Submit a CSRF-bound registration request after fetching its form."""
    assert client.get("/register").status_code == 200
    return client.post(
        "/register",
        data={"email": EMAIL, "csrf_token": client.cookies.get("csrf_token"), **extra},
        follow_redirects=False,
    )


def _emailed_setup(sync_conn):
    """Decrypt the latest verification email and return its user ID and validated token."""
    row = sync_conn.execute(
        """SELECT user_id, body_ciphertext, action_token_hash FROM email_outbox
           WHERE message_type = 'email_verification' ORDER BY id DESC LIMIT 1"""
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    body = decrypt_outbox_body(row[1])
    assert body is not None
    prefix = settings.public_base_url + "/verify-email/"
    url = next(line.strip() for line in body.splitlines() if "/verify-email/" in line)
    assert url.startswith(prefix)
    token = token_from_action_email(body, url)
    assert token not in row[1] and hash_token(token) == row[2]
    return row[0], token


def _state(sync_conn, user_id):
    """Read the required user row as JSON and commit the observer transaction."""
    row = sync_conn.execute(
        "SELECT to_jsonb(users) FROM users WHERE id = %s", (user_id,)
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    return row[0]


def _form(client, token):
    """Build a verification form bound to the token and current CSRF cookie."""
    return {
        "token": token,
        "public_id": action_token_public_id(token),
        "csrf_token": client.cookies.get("csrf_token"),
        "display_name": "Mira Cole",
        "affiliation": "Research Centre",
        "country": "GB",
        "password": OWNER_PASSWORD,
        "password_confirm": OWNER_PASSWORD,
    }


def test_email_only_request_ignores_initial_credentials_until_owner_completes(
    e2e_client, sync_conn
):
    """Verify email only request ignores initial credentials until owner completes."""
    fields = html.fromstring(e2e_client.get("/register").text).xpath("//form//input/@name")
    assert "email" in fields and "password" not in fields and "display_name" not in fields
    response = _request(
        e2e_client,
        display_name="Attacker Name",
        affiliation="Attacker Institute",
        country="US",
        password=ATTACKER_PASSWORD,
        password_confirm=ATTACKER_PASSWORD,
        is_admin="true",
        access_tier="vetted",
        email_verified="true",
    )
    assert response.status_code == 200 and "Check your email" in response.text
    user_id, token = _emailed_setup(sync_conn)
    pending = _state(sync_conn, user_id)
    assert not pending["is_active"] and not pending["email_verified"] and not pending["is_admin"]
    assert pending["access_tier"] == "public"
    assert all(
        pending[key] is None for key in ("password_hash", "display_name", "affiliation", "country")
    )
    assert pending["email_verification_token_hash"] == hash_token(token)
    for _ in range(2):
        page = e2e_client.get(action_path("/verify-email", token))
        assert page.status_code == 200
        document = html.fromstring(page.text)
        assert document.xpath('//input[@name="token"]/@value') == [""]
        assert document.xpath('//input[@name="public_id"]/@value') == [
            action_token_public_id(token)
        ]
        assert token not in page.text and EMAIL not in page.text
        assert document.xpath('//input[@name="csrf_token"]/@value') == [
            e2e_client.cookies.get("csrf_token")
        ]
    assert _state(sync_conn, user_id) == pending
    form = _form(e2e_client, token)
    response = e2e_client.post(
        "/verify-email",
        data={**form, "is_admin": "true", "access_tier": "vetted"},
        follow_redirects=False,
    )
    assert response.status_code == 303 and response.headers["location"] == SUCCESS_LOCATION
    completed = _state(sync_conn, user_id)
    assert completed["is_active"] and completed["email_verified"] and not completed["is_admin"]
    assert completed["access_tier"] == "public" and completed["display_name"] == "Mira Cole"
    assert completed["affiliation"] == "Research Centre" and completed["country"] == "GB"
    assert password_hasher.verify(completed["password_hash"], OWNER_PASSWORD)
    with pytest.raises(VerifyMismatchError):
        password_hasher.verify(completed["password_hash"], ATTACKER_PASSWORD)
    assert settings.session_cookie_name not in e2e_client.cookies
    sessions = sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (user_id,)
    ).fetchone()
    assert sessions[0] == 0
    assert e2e_client.get(action_path("/verify-email", token)).status_code == 200
    assert e2e_client.post("/verify-email", data=form).status_code == 400
    assert _state(sync_conn, user_id) == completed


@pytest.mark.parametrize("verified", [False, True])
def test_duplicate_response_matches_new_request_without_password_work(
    e2e_client, sync_conn, monkeypatch, verified
):
    """Verify duplicate response matches new request without password work."""
    real_work = registration_setup.run_password_work
    work = create_autospec(real_work, spec_set=True, side_effect=real_work)
    monkeypatch.setattr(registration_setup, "run_password_work", work)
    first = _request(e2e_client)
    assert first.status_code == 200
    work.assert_not_awaited()
    user_id, token = _emailed_setup(sync_conn)
    if verified:
        assert e2e_client.get(action_path("/verify-email", token)).status_code == 200
        response = e2e_client.post(
            "/verify-email", data=_form(e2e_client, token), follow_redirects=False
        )
        assert response.status_code == 303
    before = _state(sync_conn, user_id)
    hash_calls = work.await_count
    duplicate = _request(e2e_client, password=ATTACKER_PASSWORD, display_name="Attacker Name")
    assert duplicate.status_code == first.status_code and duplicate.text == first.text
    assert work.await_count == hash_calls
    assert _state(sync_conn, user_id) == before
    notice = sync_conn.execute(
        "SELECT message_type, user_id FROM email_outbox ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert notice == ("email_verification", user_id)


@pytest.mark.parametrize(
    "change", ["database_expiry", "signature_expiry", "email", "cancelled", "tampered"]
)
def test_live_form_cannot_complete_after_capability_changes(e2e_client, sync_conn, change):
    """Verify live form cannot complete after capability changes."""
    assert _request(e2e_client).status_code == 200
    user_id, token = _emailed_setup(sync_conn)
    assert e2e_client.get(action_path("/verify-email", token)).status_code == 200
    if change == "database_expiry":
        sync_conn.execute(
            "UPDATE users SET email_verification_created_at = clock_timestamp() - INTERVAL '25 hours' WHERE id = %s",
            (user_id,),
        )
    elif change == "email":
        sync_conn.execute(
            "UPDATE users SET email = 'changed@example.org' WHERE id = %s", (user_id,)
        )
    elif change == "cancelled":
        sync_conn.execute(
            "UPDATE users SET email_verification_token_hash = NULL, email_verification_created_at = NULL WHERE id = %s",
            (user_id,),
        )
    sync_conn.commit()
    before = _state(sync_conn, user_id)
    candidate = token + "tampered" if change == "tampered" else token
    travel = (
        time_machine.travel(datetime.now(UTC) + timedelta(hours=25))
        if change == "signature_expiry"
        else nullcontext()
    )
    with travel:
        assert e2e_client.get(action_path("/verify-email", candidate)).status_code == 200
        form = {**_form(e2e_client, candidate), "password": "weak", "password_confirm": "different"}
        assert e2e_client.post("/verify-email", data=form).status_code == 400
    assert _state(sync_conn, user_id) == before


@pytest.mark.parametrize(
    "failure,expected", [("missing_csrf", 403), ("wrong_csrf", 403), ("json", 415)]
)
def test_completion_transport_guards_preserve_live_capability(
    e2e_client, sync_conn, failure, expected
):
    """Verify completion transport guards preserve live capability."""
    assert _request(e2e_client).status_code == 200
    user_id, token = _emailed_setup(sync_conn)
    assert e2e_client.get(action_path("/verify-email", token)).status_code == 200
    before = _state(sync_conn, user_id)
    form = _form(e2e_client, token)
    if failure == "missing_csrf":
        form.pop("csrf_token")
    elif failure == "wrong_csrf":
        form["csrf_token"] = "wrong"
    response = e2e_client.post(
        "/verify-email", **({"json": form} if failure == "json" else {"data": form})
    )
    assert response.status_code == expected
    assert _state(sync_conn, user_id) == before
    response = e2e_client.post(
        "/verify-email", data=_form(e2e_client, token), follow_redirects=False
    )
    assert response.status_code == 303 and response.headers["location"] == SUCCESS_LOCATION


def test_live_setup_form_still_completes_after_anonymous_resend(e2e_client, sync_conn):
    """Verify live setup form still completes after anonymous resend."""
    assert _request(e2e_client).status_code == 200
    user_id, token = _emailed_setup(sync_conn)
    assert e2e_client.get(action_path("/verify-email", token)).status_code == 200
    before = _state(sync_conn, user_id)
    response = e2e_client.post(
        "/send_verification",
        data={"email": EMAIL, "csrf_token": e2e_client.cookies.get("csrf_token")},
    )
    assert response.status_code == 200
    assert _emailed_setup(sync_conn)[1] == token
    assert _state(sync_conn, user_id) == before
    completion = e2e_client.post(
        "/verify-email", data=_form(e2e_client, token), follow_redirects=False
    )
    assert completion.status_code == 303

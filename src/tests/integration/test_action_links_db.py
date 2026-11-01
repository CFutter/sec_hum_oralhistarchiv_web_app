"""Real action-email URLs reveal no authority until the explicit form POST."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import pyotp
import pytest
import time_machine
from lxml import html

from app.services.crypto import decrypt_outbox_body
from app.services.email_change import stage_admin_email_change, validate_email_change_token
from app.services.email_verification import generate_verification_token, validate_verification_token
from app.services.password_reset import generate_reset_token, validate_reset_token
from app.services.tokens import (
    EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS,
    RESET_TOKEN_MAX_AGE_SECONDS,
    VERIFICATION_TOKEN_MAX_AGE_SECONDS,
    action_token_public_id,
    hash_token,
)
from app.services.totp_crypto import encrypt_value
from config import settings
from tests.action_links import action_path, token_from_action_email

pytestmark = pytest.mark.integration

EMAIL = "action-owner@example.org"
NEW_EMAIL = "action-replacement@example.org"
PASSWORD = "Fresh-Qu3st-Passphrase!9876"
FLOWS = ("/verify-email", "/reset-password", "/account/confirm-email")


@dataclass(frozen=True)
class ActionLinkCase:
    """Action capability, lifetime in seconds and backing account-token column."""

    flow: str
    user_id: int
    url: str = field(repr=False)
    token: str = field(repr=False)
    lifetime: int
    hash_column: str
    totp_secret: str | None = field(default=None, repr=False)


def account_state(conn, user_id):
    """Read the required user row as JSON and commit the observer transaction."""
    state = conn.execute("SELECT to_jsonb(users) FROM users WHERE id=%s", (user_id,)).fetchone()
    conn.commit()
    assert state is not None
    return state[0]


def submit_fields(client, case, **changes):
    """Build action-form fields with the required password, factor and CSRF proof, then apply
    overrides.
    """
    values = {
        "public_id": action_token_public_id(case.token),
        "token": case.token,
        "csrf_token": client.cookies.get("csrf_token"),
    }
    if case.flow in {"/verify-email", "/reset-password"}:
        values.update(password=PASSWORD, password_confirm=PASSWORD)
    if case.flow == "/verify-email":
        values["display_name"] = "Mailbox Owner"
    if case.flow == "/reset-password":
        assert case.totp_secret is not None
        values["totp_code"] = pyotp.TOTP(case.totp_secret).now()
    values.update(changes)
    return values


async def issue_action(flow, client, db_pool, user_factory, admin_actor, sync_conn):
    """Issue actual encrypted mail through the production request/staging flows."""
    totp_secret = None
    if flow == "/verify-email":
        client.get("/register")
        response = client.post(
            "/register", data={"email": EMAIL, "csrf_token": client.cookies.get("csrf_token")}
        )
        assert response.status_code == 200
        message_type = "email_verification"
        lifetime = VERIFICATION_TOKEN_MAX_AGE_SECONDS
        hash_column = "email_verification_token_hash"
        user_id = sync_conn.execute("SELECT id FROM users WHERE email=%s", (EMAIL,)).fetchone()[0]
        sync_conn.commit()
    else:
        if flow == "/reset-password":
            totp_secret = pyotp.random_base32()
            user = user_factory(email=EMAIL, totp_secret=encrypt_value(totp_secret))
        else:
            user = user_factory(email=EMAIL)
        user_id = user.id
        if flow == "/reset-password":
            client.get("/forgot-password")
            response = client.post(
                "/forgot-password",
                data={"email": EMAIL, "csrf_token": client.cookies.get("csrf_token")},
            )
            assert response.status_code == 200
            message_type = "password_reset"
            lifetime = RESET_TOKEN_MAX_AGE_SECONDS
            hash_column = "password_reset_token_hash"
        else:
            await stage_admin_email_change(
                db_pool,
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
                target_user_id=user_id,
                new_email=NEW_EMAIL,
            )
            message_type = "email_change_verification"
            lifetime = EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS
            hash_column = "pending_email_token_hash"
    row = sync_conn.execute(
        """SELECT body_ciphertext, action_token_hash FROM email_outbox
           WHERE user_id=%s AND message_type=%s ORDER BY id DESC LIMIT 1""",
        (user_id, message_type),
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    body = decrypt_outbox_body(row[0])
    assert body is not None
    url = next(
        line.strip()
        for line in body.splitlines()
        if line.startswith(settings.public_base_url + flow + "/")
    )
    token = token_from_action_email(body, url)
    assert hash_token(token) == row[1]
    assert token not in row[0]
    return ActionLinkCase(flow, user_id, url, token, lifetime, hash_column, totp_secret)


@pytest.mark.parametrize("flow", FLOWS)
async def test_emailed_public_url_and_missing_secret_grant_nothing_then_body_proof_is_single_use(
    e2e_client, db_pool, user_factory, admin_actor, sync_conn, flow
):
    """Verify emailed public url and missing secret grant nothing then body proof is single use."""
    case = await issue_action(flow, e2e_client, db_pool, user_factory, admin_actor, sync_conn)
    parsed = urlsplit(case.url)
    assert parsed.path == action_path(flow, case.token)
    assert parsed.query == parsed.fragment == ""
    assert case.token not in case.url
    before = account_state(sync_conn, case.user_id)

    # The user opens the non-secret link before copying the separate email code.
    page = e2e_client.get(parsed.path)
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["referrer-policy"] == "strict-origin"
    assert case.token not in page.text and EMAIL not in page.text and NEW_EMAIL not in page.text
    document = html.fromstring(page.text)
    forms = document.xpath('//form[input[@name="public_id"]]')
    assert len(forms) == (2 if flow == "/reset-password" else 1)
    for form in forms:
        assert form.xpath('.//input[@name="public_id"]/@value') == [
            action_token_public_id(case.token)
        ]
        assert form.xpath('.//input[@name="token"]/@value') == [""]
        assert form.xpath('.//input[@name="token"]/@type') == ["text"]
    assert not document.xpath("//script")
    assert "Security code from your email" in page.text
    assert account_state(sync_conn, case.user_id) == before
    old_style = e2e_client.get(f"{flow}/{case.token}", follow_redirects=False)
    assert old_style.status_code == 404

    missing = submit_fields(e2e_client, case)
    missing.pop("token")
    rejected = e2e_client.post(flow, data=missing, follow_redirects=False)
    assert rejected.status_code == 422
    if flow == "/reset-password":
        without_totp = submit_fields(e2e_client, case)
        without_totp.pop("totp_code")
        rejected_totp = e2e_client.post(flow, data=without_totp, follow_redirects=False)
        assert rejected_totp.status_code == 422
        assert account_state(sync_conn, case.user_id) == before
    mismatched = e2e_client.post(
        flow,
        data=submit_fields(e2e_client, case, public_id=action_token_public_id("another-secret")),
        follow_redirects=False,
    )
    assert mismatched.status_code in {400, 422}
    assert account_state(sync_conn, case.user_id) == before

    result = e2e_client.post(flow, data=submit_fields(e2e_client, case), follow_redirects=False)
    assert result.status_code == 303, result.text
    completed = account_state(sync_conn, case.user_id)
    assert completed[case.hash_column] is None
    if flow == "/account/confirm-email":
        assert completed["email"] == NEW_EMAIL
    elif flow == "/verify-email":
        assert completed["email_verified"] and completed["is_active"]
    replay = e2e_client.post(flow, data=submit_fields(e2e_client, case), follow_redirects=False)
    assert replay.status_code in {400, 422}
    assert account_state(sync_conn, case.user_id) == completed


@pytest.mark.parametrize("flow", FLOWS)
async def test_other_purpose_signature_with_its_matching_identifier_cannot_use_the_link(
    e2e_client, db_pool, user_factory, admin_actor, sync_conn, flow
):
    """Verify other purpose signature with its matching identifier cannot use the link."""
    case = await issue_action(flow, e2e_client, db_pool, user_factory, admin_actor, sync_conn)
    e2e_client.get(action_path(flow, case.token))
    before = account_state(sync_conn, case.user_id)
    foreign = (
        generate_verification_token(case.user_id, EMAIL)
        if flow == "/reset-password"
        else generate_reset_token(case.user_id, EMAIL)
    )
    validator = {
        "/verify-email": validate_verification_token,
        "/reset-password": validate_reset_token,
        "/account/confirm-email": validate_email_change_token,
    }[flow]
    assert validator(foreign) is None
    response = e2e_client.post(
        flow,
        data=submit_fields(
            e2e_client, case, token=foreign, public_id=action_token_public_id(foreign)
        ),
        follow_redirects=False,
    )
    assert response.status_code in {400, 422}
    assert account_state(sync_conn, case.user_id) == before
    accepted = e2e_client.post(flow, data=submit_fields(e2e_client, case), follow_redirects=False)
    assert accepted.status_code == 303


@pytest.mark.parametrize("flow", FLOWS)
async def test_expired_signature_cannot_be_restored_by_its_still_public_landing_page(
    e2e_client, db_pool, user_factory, admin_actor, sync_conn, flow
):
    """Verify expired signature cannot be restored by its still public landing page."""
    case = await issue_action(flow, e2e_client, db_pool, user_factory, admin_actor, sync_conn)
    before = account_state(sync_conn, case.user_id)
    after_expiry = datetime.now(UTC) + timedelta(seconds=case.lifetime + 2)
    with time_machine.travel(after_expiry, tick=False):
        page = e2e_client.get(action_path(flow, case.token))
        assert page.status_code == 200 and case.token not in page.text
        response = e2e_client.post(
            flow, data=submit_fields(e2e_client, case), follow_redirects=False
        )
    assert response.status_code in {400, 422}
    assert account_state(sync_conn, case.user_id) == before

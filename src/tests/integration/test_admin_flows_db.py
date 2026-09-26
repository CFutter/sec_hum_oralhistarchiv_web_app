"""Admin-flow integration tests — real PostgreSQL, real routes, real middleware.

Covers the administrator surface of src/app/routes/auth/admin.py end to end:
admin-initiated email change to a fresh address, the taken-address and
federated-account refusals, the transactional email-outbox boundary and its
delivery metadata, admin action flash messages (set-tier, set-active,
set-admin and their no-ops), set-active session revocation and the
asymmetric lockout clear, set-admin grant-as-invitation and revoke, the
self-action refusals, and require_admin's 404 cloak for non-admins and
anonymous visitors. Membership invariants enforced by app.services.users
(one active admin surviving crossed concurrent changes, stale-actor
rejection, self-removal refusal, and the unverified-administrator reaper)
are covered against the same database in TestMembershipInvariants.

Every route test drives the REAL login form (password + TOTP) so the
session, CSRF token, and flash storage are all the production paths.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pyotp
import pytest
from fastapi import status

from app.middleware.csrf import _compute_csrf_token
from app.services import users
from app.services.crypto import decrypt_outbox_body, encrypt_value
from app.services.email import DeliveryResult
from app.services.email_change import (
    email_change_token_email_metadata,
    validate_email_change_token,
)
from app.services.email_delivery import deliver_email_outbox_batch
from app.services.email_outbox import enqueue_outbound_email_cur
from config import settings
from tests.fixtures import sign_session_id
from tests.integration.conftest import login_admin

_EMAIL_CHANGE_MESSAGE_COUNT = 2

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_row(sync_conn, user_id, columns):
    return sync_conn.execute(f"SELECT {columns} FROM users WHERE id = %s", (user_id,)).fetchone()


def _outbox_messages(sync_conn, user_id):
    """Return this user's queued messages in insertion order."""
    columns = (
        "message_type",
        "recipient",
        "subject",
        "body_ciphertext",
        "status",
    )
    rows = sync_conn.execute(
        """SELECT message_type, recipient, subject, body_ciphertext, status
           FROM email_outbox
           WHERE user_id = %s
           ORDER BY id""",
        (user_id,),
    ).fetchall()
    return [dict(zip(columns, row, strict=True)) for row in rows]


def _decrypt_body(message):
    """Decrypt one persisted body and assert that encryption was real."""
    body = decrypt_outbox_body(message["body_ciphertext"])
    assert body is not None
    assert body != message["body_ciphertext"]
    return body


def _audit_records(caplog, event_type):
    return [
        rec
        for rec in caplog.records
        if rec.name == "audit" and getattr(rec, "event_type", None) == event_type
    ]


class TestAdminEmailChange:
    """Admin-initiated changes to a user's email address."""

    def test_admin_change_email_fresh_address_stages_pending(
        self, e2e_client, user_factory, sync_conn, caplog
    ):
        """Changing a user's email to an address NO account uses stages the
        change (pending_email set, token hash stored), durably queues both
        messages, and flashes that delivery will happen shortly."""
        admin, csrf = login_admin(e2e_client, user_factory)
        target = user_factory()

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                f"/admin/users/{target.id}/change-email",
                data={"new_email": "fresh@uzh.ch", "csrf_token": csrf},
                follow_redirects=False,
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/admin"

        row = _user_row(sync_conn, target.id, "pending_email, pending_email_token_hash")
        assert row[0] == "fresh@uzh.ch"
        assert row[1] is not None

        # Capability link → the NEW address; heads-up notice → the
        # TARGET's current address. Both rows are pending and encrypted at rest.
        messages = _outbox_messages(sync_conn, target.id)
        assert len(messages) == _EMAIL_CHANGE_MESSAGE_COUNT
        by_type = {message["message_type"]: message for message in messages}
        assert set(by_type) == {
            "email_change_verification",
            "email_change_notice",
        }

        verification = by_type["email_change_verification"]
        assert verification["recipient"] == "fresh@uzh.ch"
        verification_body = _decrypt_body(verification)
        assert f"{settings.public_base_url}/account/confirm-email/" in verification_body

        notice = by_type["email_change_notice"]
        assert notice["recipient"] == target.email
        assert "fresh@uzh.ch" in _decrypt_body(notice)
        assert all(message["status"] == "pending" for message in messages)

        # The admin-initiated request leaves an audit trail.
        events = _audit_records(caplog, "admin_email_change_requested")
        assert len(events) == 1
        assert events[0].actor_admin_id == admin.id
        assert events[0].target_user_id == target.id

        # Following the redirect renders the success flash.
        page = e2e_client.get("/admin")
        assert "A confirmation email will be sent shortly" in page.text

    def test_admin_change_email_rolls_back_if_second_enqueue_fails(
        self,
        e2e_client,
        user_factory,
        sync_conn,
        caplog,
    ):
        """Staged state and the first message roll back with enqueue two."""
        _, csrf = login_admin(e2e_client, user_factory)
        target = user_factory()
        enqueue_count = 0

        async def enqueue_then_fail(cur, *, user_id, email, action):
            nonlocal enqueue_count
            enqueue_count += 1

            if enqueue_count == _EMAIL_CHANGE_MESSAGE_COUNT:
                raise RuntimeError("second enqueue failed")

            return await enqueue_outbound_email_cur(
                cur,
                user_id=user_id,
                email=email,
                action=action,
            )

        with (
            patch(
                "app.services.email_change.enqueue_outbound_email_cur",
                autospec=True,
                side_effect=enqueue_then_fail,
            ),
            caplog.at_level(logging.INFO, logger="audit"),
        ):
            resp = e2e_client.post(
                f"/admin/users/{target.id}/change-email",
                data={"new_email": "fresh@uzh.ch", "csrf_token": csrf},
                follow_redirects=False,
            )

        assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert enqueue_count == _EMAIL_CHANGE_MESSAGE_COUNT
        assert _user_row(
            sync_conn,
            target.id,
            "pending_email, pending_email_token_hash, pending_email_created_at",
        ) == (None, None, None)
        assert _outbox_messages(sync_conn, target.id) == []
        assert _audit_records(caplog, "admin_email_change_requested") == []

        assert "An unexpected error occurred" in resp.text

    def test_admin_change_email_taken_address_rejected(self, e2e_client, user_factory, sync_conn):
        """An address ANOTHER account already owns is rejected with the
        'already in use' flash and nothing is staged on the target."""
        _, csrf = login_admin(e2e_client, user_factory)
        target = user_factory()
        user_factory(email="taken@uzh.ch")  # the address's rightful owner

        resp = e2e_client.post(
            f"/admin/users/{target.id}/change-email",
            data={"new_email": "taken@uzh.ch", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        page = e2e_client.get("/admin")
        assert "already in use" in page.text

        row = _user_row(sync_conn, target.id, "pending_email, pending_email_token_hash")
        assert row == (None, None)

    def test_admin_change_email_shibboleth_target_refused(
        self, e2e_client, user_factory, sync_conn
    ):
        """A federated (shibboleth) target is refused — email is owned by the
        IdP — with the 'federated account' flash and nothing staged."""
        _, csrf = login_admin(e2e_client, user_factory)
        target = user_factory(auth_method="shibboleth")

        resp = e2e_client.post(
            f"/admin/users/{target.id}/change-email",
            data={"new_email": "fresh@uzh.ch", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        page = e2e_client.get("/admin")
        assert "federated account" in page.text

        row = _user_row(sync_conn, target.id, "pending_email, pending_email_token_hash")
        assert row == (None, None)

    @pytest.mark.parametrize("eligible_state", [True, False])
    async def test_admin_email_action_metadata_and_delivery(
        self,
        e2e_client,
        db_pool,
        user_factory,
        sync_conn,
        eligible_state,
    ):
        """Admin metadata binds the target/token, including an inactive
        unverified target, and the queued messages really do get delivered
        for an eligible target."""
        admin, csrf = login_admin(e2e_client, user_factory)
        target = user_factory(is_active=eligible_state, email_verified=eligible_state)
        new_email = "admin-new@mail.com"

        response = e2e_client.post(
            f"/admin/users/{target.id}/change-email",
            data={
                "new_email": new_email,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        rows = sync_conn.execute(
            """SELECT message_type, recipient, body_ciphertext, action_token_hash, expires_at
               FROM email_outbox WHERE user_id = %s ORDER BY id""",
            (target.id,),
        ).fetchall()
        if not eligible_state:
            assert rows == []  # Inactive targets cannot acquire a new capability.
            assert sync_conn.execute(
                "SELECT pending_email FROM users WHERE id=%s", (target.id,)
            ).fetchone() == (None,)
            return
        assert len(rows) == 2
        kind, recipient, ciphertext, token_hash, expires_at = rows[0]

        assert kind == "email_change_verification"
        assert recipient == new_email

        body = decrypt_outbox_body(ciphertext)
        assert body is not None

        prefix = f"{settings.public_base_url}/account/confirm-email/"
        links = [word for word in body.split() if word.startswith(prefix)]
        assert len(links) == 1

        token = links[0].removeprefix(prefix)
        payload = validate_email_change_token(token)

        assert payload is not None
        assert payload["user_id"] == target.id
        assert payload["new_email"] == new_email
        assert payload["acting_admin_id"] == admin.id

        metadata = email_change_token_email_metadata(token)
        assert (token_hash, expires_at) == (
            metadata.token_hash,
            metadata.expires_at,
        )
        assert f"expires at {metadata.expires_at:%Y-%m-%d %H:%M:%S UTC}" in body
        assert rows[1][0:2] == ("email_change_notice", target.email)
        assert rows[1][3:] == (None, None)
        sync_conn.commit()

        with patch(
            "app.services.email_delivery.send_claimed_email",
            autospec=True,
            return_value=DeliveryResult(status="sent", reason="test_stub_delivery"),
        ) as smtp:
            await deliver_email_outbox_batch(db_pool)
        assert smtp.call_count == 2
        assert {call.args[0].recipient for call in smtp.call_args_list} == {target.email, recipient}
        assert sync_conn.execute(
            "SELECT status FROM email_outbox WHERE user_id = %s",
            (target.id,),
        ).fetchall() == [("sent",), ("sent",)]


class TestAdminSetTier:
    """set-tier: DB update, flash message and audit trail; the no-op branch."""

    def test_admin_set_tier_updates_db_flashes_and_audits(
        self, e2e_client, user_factory, sync_conn, caplog
    ):
        """POST set-tier on a public user redirects, the follow-up GET /admin
        renders 'Tier changed: public → vetted.', the DB tier is updated, and
        an admin_user_tier_changed audit record carries actor_admin_id and
        target_user_id."""
        admin, csrf = login_admin(e2e_client, user_factory)
        target = user_factory()  # defaults to tier 'public'

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                f"/admin/users/{target.id}/set-tier",
                data={"access_tier": "vetted", "csrf_token": csrf},
                follow_redirects=False,
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/admin"

        assert _user_row(sync_conn, target.id, "access_tier")[0] == "vetted"

        page = e2e_client.get("/admin")
        assert "Tier changed: public → vetted." in page.text

        records = _audit_records(caplog, "admin_user_tier_changed")
        assert len(records) == 1
        rec = records[0]
        assert rec.actor_admin_id == admin.id
        assert rec.target_user_id == target.id
        assert rec.old_value == "public"
        assert rec.new_value == "vetted"

    def test_admin_set_tier_same_tier_is_info_noop(self, e2e_client, user_factory, sync_conn):
        """No-change no-op: setting the tier the user already has flashes the
        'already has tier' INFO message and changes nothing."""
        _, csrf = login_admin(e2e_client, user_factory)
        target = user_factory()  # already 'public'

        resp = e2e_client.post(
            f"/admin/users/{target.id}/set-tier",
            data={"access_tier": "public", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        page = e2e_client.get("/admin")
        assert "already has tier" in page.text
        assert "auth-info" in page.text  # rendered with the 'info' category

        assert _user_row(sync_conn, target.id, "access_tier")[0] == "public"


class TestAdminSetActive:
    """set-active: deactivation revokes sessions; reactivation clears lockout."""

    def test_admin_deactivate_user_revokes_their_sessions(
        self, e2e_client, user_factory, session_factory, sync_conn, caplog
    ):
        """Deactivating a user flips is_active AND hard-revokes their live
        sessions (misuse response — the session row must be GONE, not just
        expired), the success flash renders, and the action is audited as
        admin_user_active_changed with the actor/target/old/new fields."""
        admin, csrf = login_admin(e2e_client, user_factory)
        target = user_factory()
        session_factory(target.id)  # a live session that must not survive

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                f"/admin/users/{target.id}/set-active",
                data={"is_active": "false", "csrf_token": csrf},
                follow_redirects=False,
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        assert _user_row(sync_conn, target.id, "is_active")[0] is False
        count = sync_conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (target.id,)
        ).fetchone()
        assert count[0] == 0

        records = _audit_records(caplog, "admin_user_active_changed")
        assert len(records) == 1
        rec = records[0]
        assert rec.actor_admin_id == admin.id
        assert rec.target_user_id == target.id
        assert rec.old_value is True and rec.new_value is False

        page = e2e_client.get("/admin")
        assert "User deactivated." in page.text

    def test_admin_reactivate_clears_lockout_state(self, e2e_client, user_factory, sync_conn):
        """Reactivation clears failed_login_count and locked_until (the
        asymmetric-clear design: a reactivated user gets a fresh start, while
        deactivation preserves the lockout audit signal)."""
        _, csrf = login_admin(e2e_client, user_factory)
        target = user_factory(is_active=False)
        sync_conn.execute(
            """UPDATE users
               SET failed_login_count = 5,
                   locked_until = CURRENT_TIMESTAMP + INTERVAL '15 minutes'
               WHERE id = %s""",
            (target.id,),
        )
        sync_conn.commit()

        resp = e2e_client.post(
            f"/admin/users/{target.id}/set-active",
            data={"is_active": "true", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        row = _user_row(sync_conn, target.id, "is_active, failed_login_count, locked_until")
        assert row == (True, 0, None)

        page = e2e_client.get("/admin")
        assert "User activated." in page.text

    def test_admin_unlock_active_locked_out_user(
        self, e2e_client, user_factory, session_factory, sync_conn, caplog
    ):
        """An ACTIVE user who is currently locked out (failed_login_count > 0
        and locked_until in the future) gets is_active=true posted, which is
        a no-op on is_active itself (old_value == new_value == True) but the
        SQL in set_user_active unconditionally clears failed_login_count and
        locked_until on every is_active=true write, so
        SetActiveResult.lock_cleared is True. That combination is
        special-cased away from the generic 'No change' info branch into
        'Account unlocked.' (success) plus a dedicated admin_user_unlocked
        audit event — and unlike deactivation, it must NOT revoke the user's
        live sessions (they were never logged out; only the lockout counters
        are reset)."""
        admin, csrf = login_admin(e2e_client, user_factory)
        target = user_factory(is_active=True)
        session_factory(target.id)  # must survive — this is not a revocation path
        sync_conn.execute(
            """UPDATE users
               SET failed_login_count = 3,
                   locked_until = CURRENT_TIMESTAMP + INTERVAL '15 minutes'
               WHERE id = %s""",
            (target.id,),
        )
        sync_conn.commit()

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                f"/admin/users/{target.id}/set-active",
                data={"is_active": "true", "csrf_token": csrf},
                follow_redirects=False,
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/admin"

        row = _user_row(sync_conn, target.id, "is_active, failed_login_count, locked_until")
        assert row == (True, 0, None)

        count = sync_conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (target.id,)
        ).fetchone()
        assert count[0] == 1  # NOT revoked — unlock is not a misuse response

        records = _audit_records(caplog, "admin_user_unlocked")
        assert len(records) == 1
        assert records[0].actor_admin_id == admin.id
        assert records[0].target_user_id == target.id
        # admin_user_active_changed must NOT also fire — this is the dedicated
        # unlock event, not the generic active-state-change one.
        assert _audit_records(caplog, "admin_user_active_changed") == []

        page = e2e_client.get("/admin")
        assert "Account recovery completed." in page.text
        assert "auth-success" in page.text  # rendered with the 'success' category

    def test_admin_cannot_deactivate_own_account(self, e2e_client, user_factory, sync_conn):
        """Self-deactivation is refused: error flash renders, the admin stays
        active, and their session keeps working (GET /admin still 200)."""
        admin, csrf = login_admin(e2e_client, user_factory)

        resp = e2e_client.post(
            f"/admin/users/{admin.id}/set-active",
            data={"is_active": "false", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        page = e2e_client.get("/admin")
        assert page.status_code == status.HTTP_200_OK  # session survived — no self-lockout
        assert "cannot deactivate your own account" in page.text
        assert _user_row(sync_conn, admin.id, "is_active")[0] is True


class TestAdminSetAdmin:
    """set-admin: grant is an invitation, not an immediate grant; revoke is immediate."""

    def test_admin_grant_creates_an_accepted_invitation_not_an_immediate_grant(
        self, e2e_client, user_factory, sync_conn, caplog
    ):
        """set-admin with is_admin=true never flips is_admin directly.

        admin_set_admin (via request_admin_promotion) only creates an
        expiring, target-accepted invitation row in
        admin_promotion_requests: the target must reauthenticate and confirm
        a fresh recovery code themselves before authority activates. The
        grant direction therefore audits admin_promotion_requested, not a
        completed status change, and the target's is_admin stays False until
        they accept. The target must already be an eligible local, active,
        verified account with TOTP configured for the invitation to be
        created at all."""
        admin, csrf = login_admin(e2e_client, user_factory)
        target = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                f"/admin/users/{target.id}/set-admin",
                data={"is_admin": "true", "csrf_token": csrf},
                follow_redirects=False,
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert _user_row(sync_conn, target.id, "is_admin")[0] is False
        page = e2e_client.get("/admin")
        assert "Administrator invitation created." in page.text

        invitation = sync_conn.execute(
            "SELECT requested_by FROM admin_promotion_requests WHERE user_id = %s",
            (target.id,),
        ).fetchone()
        assert invitation == (admin.id,)

        invites = _audit_records(caplog, "admin_promotion_requested")
        assert len(invites) == 1
        assert invites[0].target_user_id == target.id

    def test_admin_revoke_admin_on_another_user_takes_effect_and_is_audited(
        self, e2e_client, user_factory, sync_conn, caplog
    ):
        """Revoking an existing administrator's authority (set_user_admin)
        takes effect in the DB immediately, flashes the status message, and
        audits the actor/target/old/new values — unlike granting, revocation
        needs no acceptance from the target."""
        admin, csrf = login_admin(e2e_client, user_factory)
        target = user_factory(is_admin=True)

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                f"/admin/users/{target.id}/set-admin",
                data={"is_admin": "false", "csrf_token": csrf},
                follow_redirects=False,
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert _user_row(sync_conn, target.id, "is_admin")[0] is False
        page = e2e_client.get("/admin")
        assert "Administrator access revoked." in page.text

        revokes = _audit_records(caplog, "admin_user_admin_revoked")
        assert len(revokes) == 1
        assert revokes[0].actor_admin_id == admin.id
        assert revokes[0].target_user_id == target.id
        assert revokes[0].old_value is True and revokes[0].new_value is False

    def test_admin_cannot_revoke_own_admin_status(self, e2e_client, user_factory, sync_conn):
        """Self-demotion is refused with the error flash; the actor remains
        admin (no lock-yourself-out footgun)."""
        admin, csrf = login_admin(e2e_client, user_factory)

        resp = e2e_client.post(
            f"/admin/users/{admin.id}/set-admin",
            data={"is_admin": "false", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        page = e2e_client.get("/admin")
        assert "cannot remove your own admin status" in page.text
        assert _user_row(sync_conn, admin.id, "is_admin")[0] is True


class TestAdminActionNoops:
    """set-active / set-admin no-op branches (set-tier's own no-op lives in TestAdminSetTier)."""

    @pytest.mark.parametrize(
        ("path", "field", "value"),
        [("set-active", "is_active", "true"), ("set-admin", "is_admin", "false")],
        ids=["already-active", "already-non-admin"],
    )
    def test_admin_noop_when_user_already_in_target_state(
        self, e2e_client, user_factory, sync_conn, path, field, value
    ):
        """Posting the value a user already has is a redundant write, not an
        unauthorised one: set-active's no-op still reports success (it is
        the shared 'recovery completed' branch) and set-admin's reports the
        generic info no-op; neither mutates the row."""
        _, csrf = login_admin(e2e_client, user_factory)
        target = user_factory(is_active=True, is_admin=False)

        resp = e2e_client.post(
            f"/admin/users/{target.id}/{path}",
            data={field: value, "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/admin"

        page = e2e_client.get("/admin")
        expected = (
            "Account recovery completed."
            if path == "set-active"
            else "No change — user already in that state."
        )
        assert expected in page.text
        assert ("auth-success" if path == "set-active" else "auth-info") in page.text

        row = _user_row(sync_conn, target.id, "is_active, is_admin")
        assert row == (True, False)  # untouched


class TestAdminSurfaceHidden:
    """require_admin cloaks the surface behind a 404 for the unauthorized."""

    def test_non_admin_session_gets_404_on_admin_post(
        self, e2e_client, user_factory, session_factory, sync_conn
    ):
        """A non-admin full session gets the cloaked 404 and cannot alter the
        tier. The CSRF token is valid and TOTP is configured, so the
        rejection is attributable to the admin route dependency alone."""
        user = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        target = user_factory()

        raw = session_factory(user.id)
        e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(raw))
        csrf = _compute_csrf_token(raw)
        e2e_client.cookies.set("csrf_token", csrf)

        resp = e2e_client.post(
            f"/admin/users/{target.id}/set-tier",
            data={"access_tier": "vetted", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND
        assert _user_row(sync_conn, target.id, "access_tier")[0] == "public"

    def test_anonymous_get_admin_is_404(self, e2e_client):
        """An unauthenticated GET /admin is a 404 — the dashboard's existence
        is not revealed to guests (require_admin, not require_login)."""
        resp = e2e_client.get("/admin", follow_redirects=False)
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    def test_admin_session_gets_200_on_admin_get(self, e2e_client, user_factory):
        """Positive control for the two 404 cloaks above: a real admin
        session sees the dashboard render, not a 404."""
        _, _csrf = login_admin(e2e_client, user_factory)
        resp = e2e_client.get("/admin", follow_redirects=False)
        assert resp.status_code == status.HTTP_200_OK


class TestMembershipInvariants:
    """app.services.users membership rules against the database: at least one
    active administrator always survives, stale actors are rejected before
    mutation, and unverified administrators are never reaped."""

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            ("set_user_active", "set_user_active"),
            ("set_user_admin", "set_user_admin"),
            ("set_user_active", "set_user_admin"),
        ],
        ids=[
            "both_deactivate",
            "both_demote",
            "one_deactivates_one_demotes",
        ],
    )
    async def test_crossed_admin_changes_leave_one_active_admin(
        self, db_pool, user_factory, session_factory, sync_conn, left, right
    ):
        """Two administrators concurrently acting on each other can only ever
        leave exactly one active administrator standing: one call succeeds,
        the other is rejected as stale, never both."""
        first = user_factory(is_admin=True)
        second = user_factory(is_admin=True)
        sessions = {
            first.id: session_factory(first.id),
            second.id: session_factory(second.id),
        }
        ready = asyncio.Event()

        async def change(name, actor, target):
            await ready.wait()
            return await getattr(users, name)(
                db_pool,
                target.id,
                False,
                actor_id=actor.id,
                actor_session_id=sessions[actor.id],
            )

        tasks = [
            asyncio.create_task(change(left, first, second)),
            asyncio.create_task(change(right, second, first)),
        ]
        ready.set()
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), timeout=10
            )
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        assert sum(isinstance(result, users.AdminActionRejected) for result in results) == 1
        assert sum(not isinstance(result, BaseException) for result in results) == 1
        assert (
            sync_conn.execute("SELECT count(*) FROM users WHERE is_active AND is_admin").fetchone()[
                0
            ]
            == 1
        )

    @pytest.mark.parametrize("service", ["set_user_active", "set_user_admin"])
    @pytest.mark.parametrize(("active", "admin"), [(False, True), (True, False)])
    async def test_stale_actor_is_rejected_before_mutation(
        self, db_pool, user_factory, session_factory, sync_conn, service, active, admin
    ):
        """An actor whose own access changed since they authenticated is
        rejected before the target row is touched."""
        actor = user_factory(is_active=active, is_admin=admin)
        actor_session_id = session_factory(actor.id)
        target = user_factory(is_admin=True)
        with pytest.raises(users.AdminActionRejected, match="access changed"):
            await getattr(users, service)(
                db_pool,
                target.id,
                False,
                actor_id=actor.id,
                actor_session_id=actor_session_id,
            )
        assert sync_conn.execute(
            "SELECT is_active, is_admin FROM users WHERE id = %s", (target.id,)
        ).fetchone() == (True, True)

    @pytest.mark.parametrize("service", ["set_user_active", "set_user_admin"])
    async def test_sole_admin_cannot_remove_self(
        self, db_pool, user_factory, session_factory, service
    ):
        """The sole administrator cannot deactivate or demote themselves."""
        actor = user_factory(is_admin=True)
        actor_session_id = session_factory(actor.id)
        with pytest.raises(users.AdminActionRejected, match="own"):
            await getattr(users, service)(
                db_pool,
                actor.id,
                False,
                actor_id=actor.id,
                actor_session_id=actor_session_id,
            )

    async def test_unverified_administrator_is_never_reaped(self, db_pool, user_factory, sync_conn):
        """The stale-unverified-account reaper skips administrators even when
        they are as old and unverified as an ordinary account it does reap."""
        created = datetime.now(UTC) - timedelta(days=60)
        admin = user_factory(is_admin=True, email_verified=False, created_at=created)
        ordinary = user_factory(email_verified=False, created_at=created)
        assert await users.reap_unverified_accounts(db_pool, max_age_days=7) == 1
        assert sync_conn.execute("SELECT id FROM users ORDER BY id").fetchall() == [(admin.id,)]
        assert ordinary.id != admin.id

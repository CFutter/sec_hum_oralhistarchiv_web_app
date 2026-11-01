"""TOTP enrollment and the two-step rotation protocol — real PostgreSQL, real pyotp codes."""

import asyncio
import re
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import create_autospec, patch

import psycopg
import pyotp
import pytest
import time_machine

from app.services import totp as totp_module
from app.services.db import get_db_cursor
from app.services.session_ids import hash_session_id
from app.services.session_revocation import delete_user_sessions_cur
from app.services.totp import (
    PendingTotpOutcome,
    PendingTotpPurpose,
    TotpEnrollmentOutcome,
    TotpRotationOutcome,
    TotpRotationStartOutcome,
    begin_totp_rotation,
    confirm_totp_rotation,
    get_or_create_pending_totp_secret,
    matched_step,
    verify_and_consume_totp,
    verify_and_enroll_totp,
)
from app.services.totp_crypto import decrypt_value, encrypt_value
from tests.integration.conftest import TEST_DATABASE_URL, do_login

_RACE_POLL_INTERVAL = 0.02
_RACE_TIMEOUT = 5.0

_RECOVERY_CODE_RE = re.compile(r"<code>([0-9A-F-]{20,})</code>")
_NEW_SECRET_RE = re.compile(r'class="totp-key">([A-Z2-7]+)<')


def _extract_recovery_code(text: str) -> str:
    """Pull one displayed recovery code out of setup_totp.html's rendered list."""
    match = _RECOVERY_CODE_RE.search(text)
    assert match, "no recovery code found in rendered page"
    return match.group(1)


def _extract_new_secret(text: str) -> str:
    """Pull the once-disclosed replacement seed out of reset_totp_confirm.html."""
    match = _NEW_SECRET_RE.search(text)
    assert match, "no replacement secret disclosed on the confirm page"
    return match.group(1)


def _totp_account_row(sync_conn, user_id):
    """Read active/pending factors, replay step and display name into a dictionary."""
    row = sync_conn.execute(
        "SELECT totp_secret, pending_totp_secret, last_totp_step, display_name"
        " FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()
    return {
        "totp_secret": row[0],
        "pending_totp_secret": row[1],
        "last_totp_step": row[2],
        "display_name": row[3],
    }


def _session_purpose(sync_conn):
    """Read the first stored session purpose, or None if no session exists."""
    row = sync_conn.execute("SELECT purpose FROM sessions").fetchone()
    return row[0] if row else None


def _csrf_after_get(client, path):
    """Require a successful GET and return its response with the CSRF cookie."""
    resp = client.get(path)
    assert resp.status_code == 200, resp.text
    return client.cookies.get("csrf_token"), resp


def _login_with_totp_secret(e2e_client, user_factory):
    """Login with a real TOTP secret; returns (user, plaintext_secret)."""
    secret = pyotp.random_base32()
    user = user_factory(totp_secret=encrypt_value(secret))
    resp = do_login(e2e_client, user.email, user.password, pyotp.TOTP(secret).now())
    assert resp.status_code == 303, resp.text
    return user, secret


def _fetch_user_columns(sync_conn, user_id, columns):
    """Read raw column values for asserts (bypasses the app's SELECT builder)."""
    row = sync_conn.execute(
        f"SELECT {', '.join(columns)} FROM users WHERE id = %s", (user_id,)
    ).fetchone()
    assert row is not None, f"user {user_id} missing"
    return dict(zip(columns, row, strict=False))


def _fetch_pending_rotation_columns(sync_conn, user_id, columns):
    """Read raw pending_totp_rotations columns for a user (None if absent)."""
    row = sync_conn.execute(
        f"SELECT {', '.join(columns)} FROM pending_totp_rotations WHERE user_id = %s",
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    return dict(zip(columns, row, strict=False))


def _pending_rotation_exists(sync_conn, user_id) -> bool:
    """Check whether a pending rotation row exists for the user."""
    return (
        sync_conn.execute(
            "SELECT 1 FROM pending_totp_rotations WHERE user_id = %s",
            (user_id,),
        ).fetchone()
        is not None
    )


def _totp_secret_and_revision(sync_conn, user_id: int):
    """Read the active encrypted TOTP secret and authentication revision."""
    return sync_conn.execute(
        "SELECT totp_secret, auth_revision FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()


def _active_session_count(sync_conn, user_id: int) -> int:
    """Count stored sessions for the user, including expired rows."""
    return sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s",
        (user_id,),
    ).fetchone()[0]


async def _wait_until_all_blocked_by(observer, active, tasks, leader_pid):
    """Poll a real lock-wait condition instead of sleeping a fixed interval.

    Confirms, from an independent connection, that every task's own backend
    (recorded as it acquires a cursor) has a non-empty ``pg_blocking_pids``:
    since the leader is the only session holding the row lock before it
    commits, any waiter is necessarily queued behind it, whether directly or
    behind another waiter already queued ahead of it.
    """
    deadline = asyncio.get_running_loop().time() + _RACE_TIMEOUT
    blocked: set[asyncio.Task] = set()
    while len(blocked) < len(tasks):
        for task in tasks:
            if task in blocked:
                continue
            if task.done():
                task.result()
                pytest.fail("a confirmation completed before the leading lock was released")
            pid = active.get(task)
            if pid is None:
                continue
            cur = await observer.execute("SELECT cardinality(pg_blocking_pids(%s)) > 0", (pid,))
            row = await cur.fetchone()
            if row is not None and row[0]:
                blocked.add(task)
        if len(blocked) >= len(tasks):
            return
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError(f"not every confirmation blocked on leader pid {leader_pid}")
        await asyncio.sleep(_RACE_POLL_INTERVAL)


class TestEnrollmentSessionAuthorization:
    """Initial enrollment requires a live full or totp_setup session for this user.

    Missing, expired, foreign, and recovery-purpose sessions cannot authorize it.
    """

    @pytest.mark.parametrize(
        "session_state",
        ["missing", "expired", "other_user", "wrong_purpose"],
        ids=[
            "no_session_presented",
            "expired_session",
            "session_belongs_to_another_user",
            "session_has_the_wrong_purpose",
        ],
    )
    async def test_enrollment_requires_the_exact_live_authorizing_session(
        self, db_pool, sync_conn, user_factory, session_factory, session_state
    ):
        """Every forbidden authorization state reports SESSION_EXPIRED and
        leaves the user's pending secret, active secret and auth_revision
        untouched — the gate rejects before any write is attempted."""
        user = user_factory()
        setup_session = session_factory(user.id, purpose="totp_setup")
        pending = await get_or_create_pending_totp_secret(
            db_pool,
            user.id,
            purpose=PendingTotpPurpose.ENROLLMENT,
            session_id=setup_session,
        )
        assert pending.outcome is PendingTotpOutcome.READY
        assert pending.secret is not None
        secret = pending.secret
        recovery_code = pending.recovery_codes[0]

        session_id = "missing"
        if session_state == "expired":
            session_id = session_factory(user.id, purpose="totp_setup", expires_in_seconds=-1)
        elif session_state == "other_user":
            session_id = session_factory(user_factory().id, purpose="totp_setup")
        elif session_state == "wrong_purpose":
            session_id = session_factory(user.id, purpose="totp_recovery")

        result = await verify_and_enroll_totp(
            db_pool,
            user.id,
            pyotp.TOTP(secret).now(),
            recovery_code,
            session_id=session_id,
        )
        assert result is TotpEnrollmentOutcome.SESSION_EXPIRED
        assert sync_conn.execute(
            "SELECT totp_secret, pending_totp_secret IS NOT NULL, auth_revision FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (None, True, 0)


class TestEnrollmentActivationAtomicity:
    """Session revocation and authenticator activation commit as one
    transaction: a mid-transaction database error rolls back both."""

    async def test_session_revocation_database_error_rolls_back_totp_activation(
        self, db_pool, sync_conn, user_factory, session_factory
    ):
        """A failure while revoking setup sessions rolls back the whole activation:
        the pending secret is neither promoted nor cleared, auth_revision does
        not advance, and the original setup session remains unchanged."""
        user = user_factory()
        session_id = session_factory(user.id, purpose="totp_setup")
        pending = await get_or_create_pending_totp_secret(
            db_pool,
            user.id,
            purpose=PendingTotpPurpose.ENROLLMENT,
            session_id=session_id,
        )
        assert pending.outcome is PendingTotpOutcome.READY
        assert pending.secret is not None
        secret = pending.secret
        recovery_code = pending.recovery_codes[0]

        @asynccontextmanager
        async def failing_revocation(pool):
            """Yield a cursor wrapper that raises when deleting sessions."""
            async with get_db_cursor(pool) as cur:

                async def execute(query, params=None):
                    """Reject session deletion with RuntimeError and forward all other SQL."""
                    if str(query).strip().startswith("DELETE FROM sessions"):
                        raise RuntimeError("session revocation failed")
                    return await cur.execute(query, params)

                yield SimpleNamespace(execute=execute, fetchone=cur.fetchone)

        # autospecced against get_db_cursor's real signature so a future
        # parameter it gains (e.g. an added row_factory default) would raise
        # here rather than silently stop being exercised.
        autospecced_get_db_cursor = create_autospec(
            get_db_cursor, spec_set=True, side_effect=failing_revocation
        )
        with (
            patch("app.services.totp.get_db_cursor", new=autospecced_get_db_cursor),
            pytest.raises(RuntimeError, match="session revocation failed"),
        ):
            await verify_and_enroll_totp(
                db_pool,
                user.id,
                pyotp.TOTP(secret).now(),
                recovery_code,
                session_id=session_id,
            )
        assert sync_conn.execute(
            "SELECT totp_secret, pending_totp_secret IS NOT NULL, auth_revision FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (None, True, 0)
        assert sync_conn.execute(
            "SELECT purpose FROM sessions WHERE id=%s", (hash_session_id(session_id),)
        ).fetchone() == ("totp_setup",)


class TestEnrollmentEndToEnd:
    """Password login mints a totp_setup session; a verified code lifts the gate."""

    def test_enrollment_end_to_end_requires_fresh_login_after_factor_activation(
        self, e2e_client, user_factory, sync_conn
    ):
        """Verify enrollment end to end requires fresh login after factor activation."""
        with time_machine.travel(datetime.now(UTC), tick=False):
            user = user_factory()  # local, verified, NO totp secret

            # Password-only login mints a totp_setup session and routes to enrollment.
            login = do_login(e2e_client, user.email, user.password)
            assert login.status_code == 303
            assert login.headers["location"] == "/setup-totp"
            assert _session_purpose(sync_conn) == "totp_setup"

            # GET mints + stores an ENCRYPTED pending secret (never plaintext at rest)
            # and stages one displayed set of recovery codes.
            csrf, page = _csrf_after_get(e2e_client, "/setup-totp")
            stored = _totp_account_row(sync_conn, user.id)
            assert stored["pending_totp_secret"] is not None
            pending = decrypt_value(stored["pending_totp_secret"])
            assert pending is not None
            assert stored["pending_totp_secret"] != pending  # encrypted at rest
            assert pending in page.text  # manual-entry rendering
            recovery_code = _extract_recovery_code(page.text)

            # POST a real code and confirm one displayed recovery code; a hostile
            # form field rides along and must be ignored (the route reads the secret
            # from the DB).
            code = pyotp.TOTP(pending).at(int(time.time()))
            resp = e2e_client.post(
                "/setup-totp",
                data={
                    "totp_code": code,
                    "recovery_code_confirmation": recovery_code,
                    "secret": "EVILATTACKERSECRET",
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            assert resp.status_code == 303
            assert resp.headers["location"] == "/login?notice=totp_setup_completed"

            after = _totp_account_row(sync_conn, user.id)
            assert after["totp_secret"] is not None
            assert decrypt_value(after["totp_secret"]) == pending  # DB secret promoted
            assert after["pending_totp_secret"] is None  # staging cleared
            now_step = int(time.time()) // 30
            assert after["last_totp_step"] == now_step  # replay guard seeded, exact step
            assert _session_purpose(sync_conn) is None

            # Full authority requires a fresh password-and-authenticator login.
            fresh_login = do_login(
                e2e_client,
                user.email,
                user.password,
                pyotp.TOTP(pending).at(int(time.time()) + 30),
            )
            assert fresh_login.status_code == 303
            assert _session_purpose(sync_conn) == "full"
            csrf2, _ = _csrf_after_get(e2e_client, "/account")
            rename = e2e_client.post(
                "/account/change-name",
                data={"display_name": "Enrolled User", "csrf_token": csrf2},
                follow_redirects=False,
            )
            assert rename.status_code == 303
            assert rename.headers["location"] == "/account"
            assert _totp_account_row(sync_conn, user.id)["display_name"] == "Enrolled User"

    def test_enrollment_wrong_code_keeps_gate_down(self, e2e_client, user_factory, sync_conn):
        """Wrong code: 422, nothing promoted, purpose stays totp_setup — and the
        gate still blocks a state-changing POST for real."""
        user = user_factory()
        do_login(e2e_client, user.email, user.password)
        csrf, page = _csrf_after_get(e2e_client, "/setup-totp")
        pending = decrypt_value(_totp_account_row(sync_conn, user.id)["pending_totp_secret"])
        recovery_code = _extract_recovery_code(page.text)
        good = pyotp.TOTP(pending).now()
        wrong = str((int(good) + 1) % 1_000_000).zfill(6)

        resp = e2e_client.post(
            "/setup-totp",
            data={
                "totp_code": wrong,
                "recovery_code_confirmation": recovery_code,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 422
        assert "Invalid authenticator code. Scan the current QR code and try again." in resp.text

        after = _totp_account_row(sync_conn, user.id)
        assert after["totp_secret"] is None  # nothing promoted
        assert _session_purpose(sync_conn) == "totp_setup"  # gate still down

        # The still-gated session cannot execute a mutating POST.
        blocked = e2e_client.post(
            "/account/change-name",
            data={"display_name": "Mallory", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert blocked.status_code == 303
        assert blocked.headers["location"] == "/setup-totp"
        assert _totp_account_row(sync_conn, user.id)["display_name"] == "Test User"


class TestRotationEndToEnd:
    """A freshly authenticated, two-step /account/reset-totp flow through the real routes."""

    def test_reset_totp_end_to_end_rotates_secret(self, e2e_client, user_factory, sync_conn):
        """Rotation is a two-step, freshly authenticated flow (totp.py:603-800):
        POST start discloses a replacement seed once, POST confirm proves it and
        atomically promotes it, deleting every session."""
        with time_machine.travel(datetime.now(UTC), tick=False):
            user, old_secret = _login_with_totp_secret(e2e_client, user_factory)

            csrf, _ = _csrf_after_get(e2e_client, "/account/reset-totp")

            # Login consumed the current step; prove possession with the NEXT step
            # (inside matched_step's ±1 window, above the monotonic consume floor).
            current_code = pyotp.TOTP(old_secret).at(int(time.time()) + 30)
            start = e2e_client.post(
                "/account/reset-totp",
                data={
                    "current_password": user.password,
                    "current_totp_code": current_code,
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            assert start.status_code == 200
            new_secret = _extract_new_secret(start.text)
            assert new_secret != old_secret

            confirm_csrf = e2e_client.cookies.get("csrf_token")
            resp = e2e_client.post(
                "/account/reset-totp/confirm",
                data={
                    "new_totp_code": pyotp.TOTP(new_secret).at(int(time.time())),
                    "csrf_token": confirm_csrf,
                },
                follow_redirects=False,
            )
            assert resp.status_code == 303
            assert resp.headers["location"] == "/login?notice=totp_changed"
            assert _session_purpose(sync_conn) is None  # every session revoked

            after = _totp_account_row(sync_conn, user.id)
            assert decrypt_value(after["totp_secret"]) == new_secret
            now_step = int(time.time()) // 30
            assert after["last_totp_step"] == now_step  # exact step, no ±1 tolerance

    def test_reset_totp_wrong_current_code_keeps_old_secret(
        self, e2e_client, user_factory, sync_conn
    ):
        """Rotation without possession of the CURRENT authenticator is refused at
        the start step: the stored secret stays the old one — a stolen password
        alone cannot displace the second factor."""
        user, old_secret = _login_with_totp_secret(e2e_client, user_factory)

        csrf, _ = _csrf_after_get(e2e_client, "/account/reset-totp")
        stale_current = pyotp.TOTP(old_secret).at(0)  # 1970 — hopelessly stale
        resp = e2e_client.post(
            "/account/reset-totp",
            data={
                "current_password": user.password,
                "current_totp_code": stale_current,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 422
        assert "The password or authenticator code is incorrect." in resp.text

        after = _totp_account_row(sync_conn, user.id)
        assert decrypt_value(after["totp_secret"]) == old_secret  # unchanged


class TestSessionBoundRotationChallenge:
    """begin_totp_rotation mints a challenge; confirm_totp_rotation proves and promotes it."""

    async def test_confirm_rotation_promotes_exact_challenge_secret(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
    ):
        """A successful confirmation promotes the exact begin-minted ciphertext atomically."""
        old_secret = pyotp.random_base32()
        handle = user_factory(totp_secret=encrypt_value(old_secret))
        raw_session = session_factory(handle.id, purpose="full")

        begin_result = await begin_totp_rotation(
            db_pool,
            handle.id,
            handle.password,
            pyotp.TOTP(old_secret).now(),
            session_id=raw_session,
        )
        assert begin_result.outcome is TotpRotationStartOutcome.READY
        new_secret = begin_result.secret

        challenge = _fetch_pending_rotation_columns(sync_conn, handle.id, ["encrypted_secret"])
        pending_ciphertext = challenge["encrypted_secret"]
        assert pending_ciphertext is not None

        new_code = pyotp.TOTP(new_secret).now()
        expected_new_step = matched_step(new_secret, new_code)
        assert expected_new_step is not None

        outcome = await confirm_totp_rotation(db_pool, handle.id, new_code, session_id=raw_session)

        assert outcome is TotpRotationOutcome.ROTATED
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM email_outbox WHERE user_id=%s AND message_type='totp_rotated_notice'",
                (handle.id,),
            ).fetchone()[0]
            == 1
        )

        row = _fetch_user_columns(sync_conn, handle.id, ["totp_secret", "last_totp_step"])
        assert row["totp_secret"] == pending_ciphertext
        assert decrypt_value(row["totp_secret"]) == new_secret
        assert row["last_totp_step"] == expected_new_step
        assert not _pending_rotation_exists(sync_conn, handle.id)

        # The replaced authenticator no longer verifies.
        assert (
            await verify_and_consume_totp(db_pool, handle.id, pyotp.TOTP(old_secret).now()) is False
        )

    async def test_invalid_confirmation_code_does_not_consume_the_pending_challenge(
        self, db_pool, user_factory, session_factory
    ):
        """A failed confirmation proof leaves the begin-minted challenge retryable."""
        old_secret = pyotp.random_base32()
        handle = user_factory(totp_secret=encrypt_value(old_secret))
        raw_session = session_factory(handle.id, purpose="full")

        begin_result = await begin_totp_rotation(
            db_pool,
            handle.id,
            handle.password,
            pyotp.TOTP(old_secret).now(),
            session_id=raw_session,
        )
        assert begin_result.outcome is TotpRotationStartOutcome.READY
        new_secret = begin_result.secret

        first = await confirm_totp_rotation(
            db_pool, handle.id, "not-a-code", session_id=raw_session
        )
        assert first is TotpRotationOutcome.INVALID_NEW_CODE

        # The failed attempt must not have consumed or replaced the challenge.
        second = await confirm_totp_rotation(
            db_pool, handle.id, pyotp.TOTP(new_secret).now(), session_id=raw_session
        )
        assert second is TotpRotationOutcome.ROTATED

    async def test_expired_pending_challenge_cannot_be_rotated_in(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
    ):
        """A rotation challenge past its TTL is rejected without promoting it."""
        old_secret = pyotp.random_base32()
        original_ciphertext = encrypt_value(old_secret)
        handle = user_factory(totp_secret=original_ciphertext)
        raw_session = session_factory(handle.id, purpose="full")

        begin_result = await begin_totp_rotation(
            db_pool,
            handle.id,
            handle.password,
            pyotp.TOTP(old_secret).now(),
            session_id=raw_session,
        )
        assert begin_result.outcome is TotpRotationStartOutcome.READY
        new_secret = begin_result.secret

        # expires_at > created_at is a DB check constraint, so age both fields
        # together rather than pushing expires_at alone before created_at.
        sync_conn.execute(
            """UPDATE pending_totp_rotations
                  SET created_at = CURRENT_TIMESTAMP - INTERVAL '20 minutes',
                      expires_at = CURRENT_TIMESTAMP - INTERVAL '15 minutes'
                WHERE user_id = %s""",
            (handle.id,),
        )
        sync_conn.commit()

        outcome = await confirm_totp_rotation(
            db_pool, handle.id, pyotp.TOTP(new_secret).now(), session_id=raw_session
        )

        assert outcome is TotpRotationOutcome.PENDING_SECRET_MISSING
        row = _fetch_user_columns(sync_conn, handle.id, ["totp_secret"])
        assert row["totp_secret"] == original_ciphertext
        # confirm_totp_rotation deletes a detected-expired challenge on sight.
        assert not _pending_rotation_exists(sync_conn, handle.id)

    async def test_competing_confirmations_cannot_both_succeed(
        self, db_pool, user_factory, session_factory, monkeypatch
    ):
        """Verify competing confirmations cannot both succeed."""
        old_secret = pyotp.random_base32()
        handle = user_factory(totp_secret=encrypt_value(old_secret))
        raw_session = session_factory(handle.id, purpose="full")

        begin_result = await begin_totp_rotation(
            db_pool,
            handle.id,
            handle.password,
            pyotp.TOTP(old_secret).now(),
            session_id=raw_session,
        )
        assert begin_result.outcome is TotpRotationStartOutcome.READY
        new_code = pyotp.TOTP(begin_result.secret).now()

        active: dict[asyncio.Task, int] = {}

        @asynccontextmanager
        async def tracked_cursor(pool, *args, **kwargs):
            """Yield a real cursor while tracking the current task's backend PID; remove it on
            exit.
            """
            async with get_db_cursor(pool, *args, **kwargs) as cur:
                task = asyncio.current_task()
                active[task] = cur.connection.info.backend_pid
                try:
                    yield cur
                finally:
                    active.pop(task, None)

        monkeypatch.setattr(totp_module, "get_db_cursor", tracked_cursor)

        lock_conn = await psycopg.AsyncConnection.connect(TEST_DATABASE_URL)
        tasks: list[asyncio.Task[TotpRotationOutcome]] = []
        try:
            leader_cur = await lock_conn.execute(
                "SELECT pg_backend_pid() FROM users WHERE id = %s FOR UPDATE",
                (handle.id,),
            )
            leader_pid = (await leader_cur.fetchone())[0]
            tasks = [
                asyncio.create_task(
                    confirm_totp_rotation(db_pool, handle.id, new_code, session_id=raw_session)
                )
                for _ in range(2)
            ]

            # Both calls must be waiting behind the deliberately held row lock.
            async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as observer:
                await asyncio.wait_for(
                    _wait_until_all_blocked_by(observer, active, tasks, leader_pid),
                    timeout=_RACE_TIMEOUT + 1,
                )

            await lock_conn.commit()
            outcomes = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)
        finally:
            await lock_conn.close()
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        assert outcomes.count(TotpRotationOutcome.ROTATED) == 1
        assert outcomes.count(TotpRotationOutcome.SESSION_EXPIRED) == 1


class TestRotationRevokesSessions:
    """Factor replacement and session revocation commit as one transaction."""

    async def test_successful_rotation_revokes_every_existing_session(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
    ):
        """Verify successful rotation revokes every existing session."""
        old_secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(old_secret), auth_revision=4)
        session_factory(user.id, purpose="full")
        current_session = session_factory(user.id, purpose="full")

        begin_result = await begin_totp_rotation(
            db_pool,
            user.id,
            user.password,
            pyotp.TOTP(old_secret).now(),
            session_id=current_session,
        )
        assert begin_result.outcome is TotpRotationStartOutcome.READY
        new_secret = begin_result.secret

        outcome = await confirm_totp_rotation(
            db_pool,
            user.id,
            pyotp.TOTP(new_secret).now(),
            session_id=current_session,
        )

        assert outcome is TotpRotationOutcome.ROTATED
        active, revision = _totp_secret_and_revision(sync_conn, user.id)
        assert decrypt_value(active) == new_secret
        assert not _pending_rotation_exists(sync_conn, user.id)
        assert revision == 5
        assert _active_session_count(sync_conn, user.id) == 0

    async def test_session_delete_failure_rolls_back_factor_replacement(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """Verify session delete failure rolls back factor replacement."""
        old_secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(old_secret), auth_revision=9)
        raw_session = session_factory(user.id, purpose="full")

        begin_result = await begin_totp_rotation(
            db_pool,
            user.id,
            user.password,
            pyotp.TOTP(old_secret).now(),
            session_id=raw_session,
        )
        assert begin_result.outcome is TotpRotationStartOutcome.READY
        new_secret = begin_result.secret

        # Snapshot AFTER the begin step (which commits its own challenge row)
        # so this isolates the invariant under test: the CONFIRM transaction's
        # failure must roll back the factor replacement, not the whole flow.
        before = _totp_secret_and_revision(sync_conn, user.id)

        failing_delete = create_autospec(
            delete_user_sessions_cur,
            spec_set=True,
            side_effect=RuntimeError("forced session-delete failure"),
        )
        monkeypatch.setattr("app.services.totp.delete_user_sessions_cur", failing_delete)

        with pytest.raises(RuntimeError, match="forced session-delete failure"):
            await confirm_totp_rotation(
                db_pool,
                user.id,
                pyotp.TOTP(new_secret).now(),
                session_id=raw_session,
            )

        assert _totp_secret_and_revision(sync_conn, user.id) == before
        assert _active_session_count(sync_conn, user.id) == 1
        assert sync_conn.execute(
            "SELECT 1 FROM sessions WHERE id = %s",
            (hash_session_id(raw_session),),
        ).fetchone() == (1,)
        # The begin-side challenge committed independently of confirm's rollback,
        # so a retry with the same replacement secret remains possible.
        assert _pending_rotation_exists(sync_conn, user.id)

"""TOTP enrollment and the two-step rotation protocol — real PostgreSQL, real pyotp codes.

The client tier (client/test_totp_routes.py) pins the route WIRING with mocked
services; this module drives the same protocol end-to-end through the real
routes (login, /setup-totp, /account/reset-totp[/confirm]) AND directly
through app.services.totp's begin_totp_rotation / confirm_totp_rotation, so it
also pins the transaction boundaries the route tests mock away: the
begin-minted challenge in pending_totp_rotations, the row lock that serializes
competing confirmations, the atomic factor-replacement + session-revocation
transaction, and its rollback when session deletion fails mid-transaction.

TOTP timing note: verify_and_consume_totp is monotonic per user (any step <=
last consumed fails), and login itself consumes the current step. Rotation
therefore proves the CURRENT authenticator with the NEXT step's code
(time+30s — inside the ±1 matched_step window, strictly greater than the
consumed step).
"""

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
from app.services.crypto import decrypt_value, encrypt_value
from app.services.db import get_db_cursor
from app.services.session_ids import hash_session_id
from app.services.session_revocation import delete_user_sessions_cur
from app.services.totp import (
    TotpEnrollmentOutcome,
    TotpRotationOutcome,
    TotpRotationStartOutcome,
    begin_totp_rotation,
    confirm_totp_rotation,
    matched_step,
    verify_and_consume_totp,
    verify_and_enroll_totp,
)
from app.services.totp_recovery_codes import (
    generate_recovery_codes,
    stage_recovery_code_set_cur,
)
from tests.account_setup import store_pending_totp_secret
from tests.integration.conftest import TEST_DATABASE_URL, do_login

_RACE_POLL_INTERVAL = 0.02
_RACE_TIMEOUT = 5.0

# A syntactically valid but never-staged recovery code. Every parametrized
# session_state in test_enrollment_requires_the_exact_live_authorizing_session
# is rejected at the session-authorization gate (totp.py's
# _lock_authorizing_session_cur), which runs before the recovery-code
# confirmation is ever read, so no real staged code is needed here.
_UNUSED_RECOVERY_CODE = "AAAAA-BBBBB"

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
    row = sync_conn.execute("SELECT purpose FROM sessions").fetchone()
    return row[0] if row else None


def _csrf_after_get(client, path):
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
    return (
        sync_conn.execute(
            "SELECT 1 FROM pending_totp_rotations WHERE user_id = %s",
            (user_id,),
        ).fetchone()
        is not None
    )


def _totp_secret_and_revision(sync_conn, user_id: int):
    return sync_conn.execute(
        "SELECT totp_secret, auth_revision FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()


def _active_session_count(sync_conn, user_id: int) -> int:
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


async def _stage_one_recovery_code(db_pool, user_id: int) -> str:
    """Stage a real pending recovery-code set and return one displayable code.

    Mirrors what get_or_create_pending_totp_secret does during enrollment
    (totp.py:260-264, 320-326): verify_and_enroll_totp's call to
    activate_pending_recovery_code_set_cur (totp.py:508-512) requires an
    exact match against a currently staged, unused code.
    """
    codes = generate_recovery_codes()
    async with get_db_cursor(db_pool) as cur:
        await stage_recovery_code_set_cur(cur, user_id=user_id, codes=codes)
    return codes[0]


class TestEnrollmentSessionAuthorization:
    """verify_and_enroll_totp only accepts a live totp_setup session that
    authorizes THIS user; every other session state is rejected before the
    recovery-code confirmation is even read."""

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
        secret = pyotp.random_base32()
        await store_pending_totp_secret(db_pool, user.id, secret)
        session_id = "missing"
        if session_state == "expired":
            session_id = session_factory(user.id, purpose="totp_setup", expires_in_seconds=-1)
        elif session_state == "other_user":
            session_id = session_factory(user_factory().id, purpose="totp_setup")
        elif session_state == "wrong_purpose":
            # The schema permits only full/totp_setup; an unknown session is the
            # relevant forbidden authorization state without bypassing constraints.
            session_id = session_factory(user.id, purpose="full") + "tampered"
        result = await verify_and_enroll_totp(
            db_pool,
            user.id,
            pyotp.TOTP(secret).now(),
            _UNUSED_RECOVERY_CODE,
            session_id=session_id,
        )
        assert result is TotpEnrollmentOutcome.SESSION_EXPIRED
        assert sync_conn.execute(
            "SELECT totp_secret, pending_totp_secret IS NOT NULL, auth_revision FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (None, True, 0)


class TestEnrollmentActivationAtomicity:
    """The session upgrade and the authenticator activation commit as one
    transaction: a mid-transaction database error rolls back both."""

    async def test_session_upgrade_database_error_rolls_back_totp_activation(
        self, db_pool, sync_conn, user_factory, session_factory
    ):
        """A failure while upgrading the authorizing session's purpose rolls
        back the whole activation: the pending secret is neither promoted nor
        cleared, auth_revision does not advance, and the session that was being
        upgraded keeps its original totp_setup purpose."""
        user = user_factory()
        secret = pyotp.random_base32()
        await store_pending_totp_secret(db_pool, user.id, secret)
        recovery_code = await _stage_one_recovery_code(db_pool, user.id)
        session_id = session_factory(user.id, purpose="totp_setup")

        @asynccontextmanager
        async def failing_upgrade(pool):
            async with get_db_cursor(pool) as cur:

                async def execute(query, params):
                    if str(query).startswith("UPDATE sessions"):
                        raise RuntimeError("upgrade failed")
                    return await cur.execute(query, params)

                yield SimpleNamespace(execute=execute, fetchone=cur.fetchone)

        # autospecced against get_db_cursor's real signature so a future
        # parameter it gains (e.g. an added row_factory default) would raise
        # here rather than silently stop being exercised.
        autospecced_get_db_cursor = create_autospec(
            get_db_cursor, spec_set=True, side_effect=failing_upgrade
        )
        with (
            patch("app.services.totp.get_db_cursor", new=autospecced_get_db_cursor),
            pytest.raises(RuntimeError, match="upgrade failed"),
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

    def test_enrollment_end_to_end_persists_pending_and_upgrades_session(
        self, e2e_client, user_factory, sync_conn
    ):
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
            assert resp.headers["location"] == "/account"

            after = _totp_account_row(sync_conn, user.id)
            assert after["totp_secret"] is not None
            assert decrypt_value(after["totp_secret"]) == pending  # DB secret promoted
            assert after["pending_totp_secret"] is None  # staging cleared
            now_step = int(time.time()) // 30
            assert after["last_totp_step"] == now_step  # replay guard seeded, exact step
            assert _session_purpose(sync_conn) == "full"  # gate lifted

            # And the lifted gate is real: a state-changing POST now executes.
            csrf2 = e2e_client.cookies.get("csrf_token")
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
            assert resp.headers["location"] == "/login?totp_changed=1"
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
        """The row lock serializes two confirmations of the same challenge.

        An independent transaction first locks the user row so both contenders
        reach the database before either can mutate it. Once released, exactly
        one promotes the pending secret; confirm_totp_rotation re-locks and
        re-reads the exact session row before it re-reads the challenge, and the
        winner's factor-replacement transaction already revoked every session for
        this user — so the loser reports SESSION_EXPIRED, never a second ROTATED.

        Both contenders being blocked on the leader's row lock is observed
        through ``pg_blocking_pids`` from an independent connection, not
        inferred from a fixed sleep.
        """
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

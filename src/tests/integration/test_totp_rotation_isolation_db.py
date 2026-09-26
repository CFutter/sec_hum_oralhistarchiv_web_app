"""Exact-session isolation of ``app.services.totp``'s rotation challenge.

``begin_totp_rotation``/``confirm_totp_rotation`` bind a replacement
authenticator seed to the exact session and authentication revision that
proved possession of the current one (totp.py:603-938). These tests pin
what a mocked cursor cannot: that a second live session of the same user can
neither read nor confirm another session's challenge, that two sessions
racing to start rotation serialize on the real user-row lock without ever
leaving two challenge rows or leaking a seed across sessions, and that
exhausting the confirmation budget never touches unrelated credential or
session state. The integration conftest applies the application's Alembic
migration and skips this module when the configured test database is
unavailable.
"""

import asyncio
import re
from datetime import UTC, datetime, timedelta

import psycopg
import pyotp
import pytest
import time_machine

from app.middleware.cookies import SESSION_SIGNER
from app.services.crypto import decrypt_value, encrypt_value
from app.services.session_ids import hash_session_id
from app.services.totp import (
    PendingTotpPurpose,
    TotpRotationOutcome,
    TotpRotationStartOutcome,
    begin_totp_rotation,
    confirm_totp_rotation,
    get_pending_totp_secret,
    matched_step,
    verify_and_consume_totp,
)
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL, install_active_recovery_codes

pytestmark = pytest.mark.integration

_NEW_SECRET_RE = re.compile(r'class="totp-key">([A-Z2-7]+)<')


def _pending_rotation(sync_conn, user_id: int):
    row = sync_conn.execute(
        """
        SELECT session_id, encrypted_secret, auth_revision, confirmation_attempt_count
        FROM pending_totp_rotations
        WHERE user_id = %s
        """,
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "session_hash": row[0],
        "encrypted_secret": row[1],
        "auth_revision": row[2],
        "confirmation_attempt_count": row[3],
    }


def _pending_rotation_count(sync_conn, user_id: int) -> int:
    return sync_conn.execute(
        "SELECT COUNT(*) FROM pending_totp_rotations WHERE user_id = %s",
        (user_id,),
    ).fetchone()[0]


def _credential_snapshot(sync_conn, user_id: int):
    return sync_conn.execute(
        """
        SELECT totp_secret, auth_revision, failed_login_count, locked_until
        FROM users
        WHERE id = %s
        """,
        (user_id,),
    ).fetchone()


def _session_state(sync_conn, raw_session_id: str):
    return sync_conn.execute(
        "SELECT purpose, expires_at > clock_timestamp() FROM sessions WHERE id = %s",
        (hash_session_id(raw_session_id),),
    ).fetchone()


def _recovery_code_summary(sync_conn, user_id: int):
    return sync_conn.execute(
        """
        SELECT generation, position, used_at, password_attempt_count
        FROM totp_recovery_codes
        WHERE user_id = %s
        ORDER BY generation, position
        """,
        (user_id,),
    ).fetchall()


def _csrf_after_get(client, path):
    resp = client.get(path)
    assert resp.status_code == 200, resp.text
    return client.cookies.get("csrf_token"), resp


class TestRotationRequiresAFreshCurrentProof:
    """A rotation challenge is created only from an unreplayed, correct proof."""

    @pytest.mark.parametrize(
        "proof",
        ["wrong_password", "wrong_current_totp", "replayed_current_totp"],
        ids=["wrong_password", "wrong_current_totp", "replayed_current_totp"],
    )
    async def test_an_invalid_or_replayed_proof_creates_no_challenge(
        self, db_pool, user_factory, session_factory, sync_conn, proof
    ):
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        raw_session = session_factory(user.id, purpose="full")

        if proof == "wrong_password":
            password, code = "definitely-wrong-password", pyotp.TOTP(secret).now()
        elif proof == "wrong_current_totp":
            password = user.password
            # 1970 is hopelessly outside the +/-1 matched_step window.
            code = pyotp.TOTP(secret).at(0)
        else:
            password = user.password
            code = pyotp.TOTP(secret).now()
            consumed = await verify_and_consume_totp(db_pool, user.id, code)
            assert consumed is True

        result = await begin_totp_rotation(db_pool, user.id, password, code, session_id=raw_session)

        assert result.outcome is not TotpRotationStartOutcome.READY
        assert result.secret is None
        assert _pending_rotation_count(sync_conn, user.id) == 0

    async def test_a_fresh_unreplayed_proof_creates_exactly_one_challenge(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        """POSITIVE CONTROL: an honest, unreplayed proof does create one row."""
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        raw_session = session_factory(user.id, purpose="full")

        result = await begin_totp_rotation(
            db_pool,
            user.id,
            user.password,
            pyotp.TOTP(secret).now(),
            session_id=raw_session,
        )

        assert result.outcome is TotpRotationStartOutcome.READY
        assert result.secret is not None
        assert _pending_rotation_count(sync_conn, user.id) == 1


class TestRotationChallengeSessionIsolation:
    """Only the exact session that started a challenge may confirm it."""

    async def test_a_different_session_cannot_confirm_or_rebind_the_challenge(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        session_a = session_factory(user.id, purpose="full")
        session_b = session_factory(user.id, purpose="full")

        begun = await begin_totp_rotation(
            db_pool, user.id, user.password, pyotp.TOTP(secret).now(), session_id=session_a
        )
        assert begun.outcome is TotpRotationStartOutcome.READY
        before = _pending_rotation(sync_conn, user.id)
        assert before is not None
        assert before["session_hash"] == hash_session_id(session_a)

        rejected = await confirm_totp_rotation(
            db_pool, user.id, pyotp.TOTP(begun.secret).now(), session_id=session_b
        )

        assert rejected is TotpRotationOutcome.PENDING_SECRET_MISSING
        # B's rejected attempt left A's challenge exactly as it was: not rebound
        # to B's session and not consumed.
        assert _pending_rotation(sync_conn, user.id) == before

        # POSITIVE CONTROL: the exact authorizing session can confirm it.
        accepted = await confirm_totp_rotation(
            db_pool, user.id, pyotp.TOTP(begun.secret).now(), session_id=session_a
        )
        assert accepted is TotpRotationOutcome.ROTATED


class TestRotationSecretDisclosure:
    """The replacement seed is disclosed only once, to the session that created it."""

    def test_another_sessions_page_never_shows_the_replacement_seed(
        self, e2e_client, user_factory, session_factory
    ):
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        session_a = session_factory(user.id, purpose="full")
        session_b = session_factory(user.id, purpose="full")
        cookie_name = settings.session_cookie_name

        e2e_client.cookies.set(cookie_name, SESSION_SIGNER.dumps(session_b))
        before = e2e_client.get("/account/reset-totp")
        assert before.status_code == 200
        assert _NEW_SECRET_RE.search(before.text) is None

        e2e_client.cookies.set(cookie_name, SESSION_SIGNER.dumps(session_a))
        csrf, _ = _csrf_after_get(e2e_client, "/account/reset-totp")
        start = e2e_client.post(
            "/account/reset-totp",
            data={
                "current_password": user.password,
                "current_totp_code": pyotp.TOTP(secret).now(),
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert start.status_code == 200
        match = _NEW_SECRET_RE.search(start.text)
        assert match, "session A's own start response must disclose its seed"
        new_secret = match.group(1)

        e2e_client.cookies.set(cookie_name, SESSION_SIGNER.dumps(session_b))
        after = e2e_client.get("/account/reset-totp")
        assert after.status_code == 200
        assert new_secret not in after.text
        assert _NEW_SECRET_RE.search(after.text) is None

    async def test_no_service_reader_returns_the_rotation_seed_to_another_session(
        self, db_pool, user_factory, session_factory
    ):
        """No generic pending-secret reader discloses a rotation challenge's seed."""
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        session_a = session_factory(user.id, purpose="full")
        session_b = session_factory(user.id, purpose="full")

        begun = await begin_totp_rotation(
            db_pool, user.id, user.password, pyotp.TOTP(secret).now(), session_id=session_a
        )
        assert begun.outcome is TotpRotationStartOutcome.READY

        for purpose in (PendingTotpPurpose.ENROLLMENT, PendingTotpPurpose.RECOVERY):
            read_by_b = await get_pending_totp_secret(
                db_pool, user.id, session_id=session_b, purpose=purpose
            )
            assert read_by_b is None
            read_by_a = await get_pending_totp_secret(
                db_pool, user.id, session_id=session_a, purpose=purpose
            )
            assert read_by_a is None  # rotation seeds never live in this reader either


class TestConcurrentRotationStarts:
    """Two sessions starting rotation at once serialize on the real user-row lock."""

    async def test_concurrent_starts_never_leave_two_challenges_or_cross_disclose(
        self, user_factory, session_factory, sync_conn
    ):
        """Both proofs are frozen at a fixed instant, so whichever of the two
        genuinely concurrent, independently-connected starts the real
        ``users`` row lock admits first always succeeds (its prior consumed
        step is unset); the other either also succeeds, because its own
        proof is a later step than the winner's, or is correctly rejected as
        a replay of an already-consumed step. Either way the ON CONFLICT
        (user_id) upsert leaves exactly one challenge row, and neither
        response ever discloses the other session's seed.
        """
        frozen = datetime.now(UTC)
        with time_machine.travel(frozen, tick=False):
            secret = pyotp.random_base32()
            user = user_factory(totp_secret=encrypt_value(secret))
            session_a = session_factory(user.id, purpose="full")
            session_b = session_factory(user.id, purpose="full")

            code_a = pyotp.TOTP(secret).at(frozen)
            code_b = pyotp.TOTP(secret).at(frozen + timedelta(seconds=30))

            async def start(session_id, code):
                async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn:
                    return await begin_totp_rotation(
                        conn,  # type: ignore[arg-type] - supported direct-connection path
                        user.id,
                        user.password,
                        code,
                        session_id=session_id,
                    )

            outcome_a, outcome_b = await asyncio.wait_for(
                asyncio.gather(start(session_a, code_a), start(session_b, code_b)),
                timeout=10,
            )

        outcomes = {"a": outcome_a, "b": outcome_b}
        succeeded = {
            name: result
            for name, result in outcomes.items()
            if result.outcome is TotpRotationStartOutcome.READY
        }
        assert succeeded, "at least the first-serialized start must succeed"
        for name, result in succeeded.items():
            other_result = outcomes["b" if name == "a" else "a"]
            if other_result.outcome is TotpRotationStartOutcome.READY:
                assert result.secret != other_result.secret

        for result in outcomes.values():
            if result.outcome is not TotpRotationStartOutcome.READY:
                assert result.outcome is TotpRotationStartOutcome.REPLAYED_CURRENT_CODE
                assert result.secret is None

        # Exactly one challenge row survives, bound to whichever start committed last.
        assert _pending_rotation_count(sync_conn, user.id) == 1
        surviving = _pending_rotation(sync_conn, user.id)
        assert surviving["session_hash"] in {
            hash_session_id(session_a),
            hash_session_id(session_b),
        }
        winning_name = "a" if surviving["session_hash"] == hash_session_id(session_a) else "b"
        assert decrypt_value(surviving["encrypted_secret"]) == succeeded[winning_name].secret


class TestRotationConfirmationExhaustionIsolation:
    """Exhausting the confirmation budget touches only the challenge itself."""

    async def test_exhaustion_leaves_every_unrelated_state_untouched(
        self, db_pool, user_factory, session_factory, sync_conn, monkeypatch
    ):
        monkeypatch.setattr(settings, "totp_rotation_confirmation_attempt_limit", 1)
        old_secret = pyotp.random_base32()
        user = user_factory(
            totp_secret=encrypt_value(old_secret),
            failed_login_count=2,
            locked_until=None,
        )
        install_active_recovery_codes(sync_conn, user.id)

        raw_session = session_factory(user.id, purpose="full")
        sibling_session = session_factory(user.id, purpose="full")
        before_credentials = _credential_snapshot(sync_conn, user.id)
        before_codes = _recovery_code_summary(sync_conn, user.id)

        begun = await begin_totp_rotation(
            db_pool, user.id, user.password, pyotp.TOTP(old_secret).now(), session_id=raw_session
        )
        assert begun.outcome is TotpRotationStartOutcome.READY

        outcome = await confirm_totp_rotation(
            db_pool, user.id, "not-a-code", session_id=raw_session
        )

        assert outcome is TotpRotationOutcome.ATTEMPTS_EXHAUSTED
        assert _pending_rotation_count(sync_conn, user.id) == 0
        assert _credential_snapshot(sync_conn, user.id) == before_credentials
        assert _recovery_code_summary(sync_conn, user.id) == before_codes
        assert _session_state(sync_conn, sibling_session) == ("full", True)
        assert _session_state(sync_conn, raw_session) == ("full", True)

    async def test_a_valid_confirmation_within_budget_does_change_the_active_secret(
        self, db_pool, user_factory, session_factory, sync_conn, monkeypatch
    ):
        """POSITIVE CONTROL: within budget, a correct proof really does rotate."""
        monkeypatch.setattr(settings, "totp_rotation_confirmation_attempt_limit", 3)
        old_secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(old_secret))
        raw_session = session_factory(user.id, purpose="full")

        begun = await begin_totp_rotation(
            db_pool, user.id, user.password, pyotp.TOTP(old_secret).now(), session_id=raw_session
        )
        assert begun.outcome is TotpRotationStartOutcome.READY

        outcome = await confirm_totp_rotation(
            db_pool, user.id, pyotp.TOTP(begun.secret).now(), session_id=raw_session
        )

        assert outcome is TotpRotationOutcome.ROTATED
        after = _credential_snapshot(sync_conn, user.id)
        assert decrypt_value(after[0]) == begun.secret


class TestConcurrentConfirmations:
    """Concurrent confirmations neither lose an increment nor double-rotate."""

    async def test_concurrent_invalid_confirmations_never_lose_an_increment(
        self, user_factory, session_factory, sync_conn, monkeypatch
    ):
        limit = 3
        monkeypatch.setattr(settings, "totp_rotation_confirmation_attempt_limit", limit)
        old_secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(old_secret))
        raw_session = session_factory(user.id, purpose="full")

        async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as setup_conn:
            begun = await begin_totp_rotation(
                setup_conn,  # type: ignore[arg-type] - supported direct-connection path
                user.id,
                user.password,
                pyotp.TOTP(old_secret).now(),
                session_id=raw_session,
            )
        assert begun.outcome is TotpRotationStartOutcome.READY

        caller_count = limit + 4
        barrier = asyncio.Barrier(caller_count)

        async def confirm_invalid_on_independent_connection():
            async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn:
                await barrier.wait()
                return await confirm_totp_rotation(
                    conn,  # type: ignore[arg-type] - supported direct-connection path
                    user.id,
                    "not-a-code",
                    session_id=raw_session,
                )

        outcomes = await asyncio.wait_for(
            asyncio.gather(
                *(confirm_invalid_on_independent_connection() for _ in range(caller_count))
            ),
            timeout=10,
        )

        assert outcomes.count(TotpRotationOutcome.INVALID_NEW_CODE) == limit - 1
        assert outcomes.count(TotpRotationOutcome.ATTEMPTS_EXHAUSTED) == 1
        assert outcomes.count(TotpRotationOutcome.PENDING_SECRET_MISSING) == (caller_count - limit)
        assert _pending_rotation_count(sync_conn, user.id) == 0
        stored = sync_conn.execute(
            "SELECT totp_secret FROM users WHERE id = %s", (user.id,)
        ).fetchone()[0]
        assert decrypt_value(stored) == old_secret

    async def test_a_valid_confirmation_racing_the_exhausting_one_never_yields_both(
        self, user_factory, session_factory, sync_conn, monkeypatch
    ):
        monkeypatch.setattr(settings, "totp_rotation_confirmation_attempt_limit", 1)
        old_secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(old_secret))
        raw_session = session_factory(user.id, purpose="full")

        async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as setup_conn:
            begun = await begin_totp_rotation(
                setup_conn,  # type: ignore[arg-type] - supported direct-connection path
                user.id,
                user.password,
                pyotp.TOTP(old_secret).now(),
                session_id=raw_session,
            )
        assert begun.outcome is TotpRotationStartOutcome.READY
        valid_code = pyotp.TOTP(begun.secret).now()

        barrier = asyncio.Barrier(2)

        async def submit(code):
            async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn:
                await barrier.wait()
                return await confirm_totp_rotation(
                    conn,  # type: ignore[arg-type] - supported direct-connection path
                    user.id,
                    code,
                    session_id=raw_session,
                )

        valid_outcome, invalid_outcome = await asyncio.wait_for(
            asyncio.gather(submit(valid_code), submit("still-not-a-code")),
            timeout=10,
        )

        rotated = valid_outcome is TotpRotationOutcome.ROTATED
        exhausted = invalid_outcome is TotpRotationOutcome.ATTEMPTS_EXHAUSTED
        # Never both: the winner of the row-lock race determines the sole outcome.
        assert not (rotated and exhausted)
        assert rotated or exhausted

        after_secret = sync_conn.execute(
            "SELECT totp_secret FROM users WHERE id = %s", (user.id,)
        ).fetchone()[0]
        if rotated:
            assert decrypt_value(after_secret) == begun.secret
            assert matched_step(begun.secret, valid_code) is not None
        else:
            assert decrypt_value(after_secret) == old_secret

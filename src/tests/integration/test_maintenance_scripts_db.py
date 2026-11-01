"""Maintenance scripts that operate directly on the database."""

import importlib.util
import json
import os
import secrets
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pyotp
import pytest
from cryptography.fernet import InvalidToken

from app.paths import PROJECT_ROOT, SRC_DIR
from app.services.crypto import _derive_fernet, encrypt_outbox_body
from app.services.totp_crypto import decrypt_value, encrypt_value
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL

SCRIPT = PROJECT_ROOT / "scripts" / "reencrypt_totp.py"
VERIFY_SCRIPT = PROJECT_ROOT / "scripts" / "verify_totp_reencryption.py"


def _run_script(
    extra_env: dict[str, Any] | None = None, *, script=SCRIPT
) -> subprocess.CompletedProcess[str]:
    """Execute the development source entrypoint with inherited test settings.

    Production uses the installed-wheel isolated invocation in scripts/README.md;
    this source-tree harness detects script entrypoint errors and models rotation
    state through DATABASE_URL, TOTP_ENCRYPTION_KEYS and extra_env overrides.
    """
    return subprocess.run(
        [sys.executable, str(script)],
        env={**os.environ, "PYTHONPATH": str(SRC_DIR), **(extra_env or {})},
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        timeout=120,
        check=False,  # exit code is an assertion target, not an error
    )


def _load_script_module():
    """Import scripts/reencrypt_totp.py as a module (main() reachable, the
    __main__ guard keeps it from running). Distinct module name so nothing
    collides with a real import of the app packages it pulls in."""
    spec = importlib.util.spec_from_file_location("reencrypt_totp_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _secret_columns(sync_conn, user_id) -> dict[str, Any]:
    """Read encrypted active and pending TOTP secrets into a dictionary."""
    row = sync_conn.execute(
        "SELECT totp_secret, pending_totp_secret FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()
    return {"totp_secret": row[0], "pending_totp_secret": row[1]}


class TestReencryptTotpRotation:
    """scripts/reencrypt_totp.py rotates every TOTP secret onto the front key."""

    def test_clean_run_rotates_every_secret_and_reports_count(self, sync_conn, user_factory):
        """Verify clean run rotates every secret and reports count."""
        old_key = settings.totp_encryption_keys[0].get_secret_value()
        new_key = secrets.token_urlsafe(48)
        totp_context = b"oralhistarchiv-totp-encryption-v1"

        new_fernet = _derive_fernet(
            new_key,
            context=totp_context,
        )
        old_fernet = _derive_fernet(
            old_key,
            context=totp_context,
        )

        plains: dict[int, dict[str, str | None]] = {}
        for _ in range(2):
            secret = pyotp.random_base32()
            user = user_factory(totp_secret=encrypt_value(secret))  # under OLD key
            plains[user.id] = {"totp_secret": secret, "pending_totp_secret": None}

        # One user mid-rotation: pending_totp_secret must be rotated too.
        active, pending = pyotp.random_base32(), pyotp.random_base32()
        both = user_factory(
            totp_secret=encrypt_value(active),
            pending_totp_secret=encrypt_value(pending),
        )
        plains[both.id] = {"totp_secret": active, "pending_totp_secret": pending}

        before = {uid: _secret_columns(sync_conn, uid) for uid in plains}

        result = _run_script(extra_env={"TOTP_ENCRYPTION_KEYS": json.dumps([new_key, old_key])})

        assert result.returncode == 0, result.stdout + result.stderr
        assert "re-encrypted secrets for 3 user(s)" in result.stdout
        assert "SKIPPED" not in result.stdout

        for uid, cols in plains.items():
            after = _secret_columns(sync_conn, uid)
            for col, plaintext in cols.items():
                if plaintext is None:
                    assert after[col] is None  # NULL columns stay NULL
                    continue
                assert after[col] != before[uid][col]  # genuinely rewrapped
                # Re-encrypted under the FRONT (new) key — decrypts under it alone…
                assert new_fernet.decrypt(after[col].encode()).decode() == plaintext
                # …and the old key can now be retired: it no longer decrypts.
                with pytest.raises(InvalidToken):
                    old_fernet.decrypt(after[col].encode())

    def test_undecryptable_row_is_skipped_and_others_still_rotate(self, sync_conn, user_factory):
        """Verify undecryptable row is skipped and others still rotate."""
        healthy_plain = pyotp.random_base32()
        healthy = user_factory(totp_secret=encrypt_value(healthy_plain))
        garbage_ct = "not-a-fernet-token"
        garbage = user_factory(totp_secret=garbage_ct)
        healthy_before = _secret_columns(sync_conn, healthy.id)["totp_secret"]

        result = _run_script()

        assert result.returncode == 1, result.stdout + result.stderr
        assert "re-encrypted secrets for 1 user(s)" in result.stdout
        assert "SKIPPED 1 column(s)" in result.stdout
        assert f"user {garbage.id}: totp_secret (undecryptable" in result.stdout

        # Garbage row untouched; healthy row rotated and still decrypts.
        assert _secret_columns(sync_conn, garbage.id)["totp_secret"] == garbage_ct
        healthy_after = _secret_columns(sync_conn, healthy.id)["totp_secret"]
        assert healthy_after != healthy_before
        assert decrypt_value(healthy_after) == healthy_plain

    async def test_concurrent_write_between_snapshot_and_cas_is_skipped_not_clobbered(
        self, sync_conn, user_factory, monkeypatch, capsys
    ):
        """Verify concurrent write between snapshot and cas is skipped not clobbered."""
        winner_plain = pyotp.random_base32()
        winner = user_factory(totp_secret=encrypt_value(winner_plain))
        racer = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        winner_before = _secret_columns(sync_conn, winner.id)["totp_secret"]
        racer_snapshot_ct = _secret_columns(sync_conn, racer.id)["totp_secret"]

        module = _load_script_module()
        real_rotate = module.rotate_totp_value
        concurrent_plain = pyotp.random_base32()
        concurrent_ct = encrypt_value(concurrent_plain)  # the mid-run re-enrollment
        injected: list[bool] = []

        def rotate_with_concurrent_write(token: str) -> str:
            """Commit a new enrollment between snapshot and compare-and-swap."""
            if token == racer_snapshot_ct and not injected:
                injected.append(True)
                with psycopg.connect(TEST_DATABASE_URL) as conn:
                    conn.execute(
                        "UPDATE users SET totp_secret = %s WHERE id = %s",
                        (concurrent_ct, racer.id),
                    )
                    conn.commit()
            return real_rotate(token)

        monkeypatch.setattr(module, "rotate_totp_value", rotate_with_concurrent_write)

        rc = await module.main()
        out = capsys.readouterr().out

        assert injected, "race was never injected — the seam moved; fix the test"
        assert rc == 1, out
        assert "re-encrypted secrets for 1 user(s)" in out
        assert "SKIPPED 1 column(s)" in out
        assert f"user {racer.id}: totp_secret (changed mid-run (CAS miss))" in out

        # The concurrent write WON — byte-identical, never rewrapped over.
        racer_after = _secret_columns(sync_conn, racer.id)["totp_secret"]
        assert racer_after == concurrent_ct
        assert decrypt_value(racer_after) == concurrent_plain
        # Positive control: the uncontended user's secret still rotated normally.
        winner_after = _secret_columns(sync_conn, winner.id)["totp_secret"]
        assert winner_after != winner_before
        assert decrypt_value(winner_after) == winner_plain


class TestReencryptTotpRotationChallengeCoverage:
    """A key rotation must not leave a pending authenticator-replacement
    challenge (`pending_totp_rotations.encrypted_secret`) readable only
    under the key being retired."""

    def test_active_challenge_ciphertext_is_reencrypted_under_the_new_key(
        self, sync_conn, user_factory, session_factory
    ):
        """Positive control for this same run: the users-table secrets it
        rotates are already pinned by
        ``TestReencryptTotpRotation::test_clean_run_rotates_every_secret_and_reports_count``."""
        old_key = settings.totp_encryption_keys[0].get_secret_value()
        new_key = secrets.token_urlsafe(48)
        totp_context = b"oralhistarchiv-totp-encryption-v1"
        new_fernet = _derive_fernet(new_key, context=totp_context)
        old_fernet = _derive_fernet(old_key, context=totp_context)

        user = user_factory()
        session_factory(user.id)
        session_id = sync_conn.execute(
            "SELECT id FROM sessions WHERE user_id = %s", (user.id,)
        ).fetchone()[0]

        challenge_plain = pyotp.random_base32()
        challenge_ct = encrypt_value(challenge_plain)  # under the OLD key
        sync_conn.execute(
            """
            INSERT INTO pending_totp_rotations
                (user_id, session_id, auth_revision, encrypted_secret, expires_at)
            VALUES (%s, %s, %s, %s, now() + interval '1 hour')
            """,
            (user.id, session_id, 0, challenge_ct),
        )
        sync_conn.commit()

        result = _run_script(extra_env={"TOTP_ENCRYPTION_KEYS": json.dumps([new_key, old_key])})
        assert result.returncode == 0, result.stdout + result.stderr

        after = sync_conn.execute(
            "SELECT encrypted_secret FROM pending_totp_rotations WHERE user_id = %s",
            (user.id,),
        ).fetchone()[0]

        assert after != challenge_ct  # genuinely rewrapped
        assert new_fernet.decrypt(after.encode()).decode() == challenge_plain
        with pytest.raises(InvalidToken):
            old_fernet.decrypt(after.encode())


class TestVerifyTotpReencryptionChallengeCoverage:
    """The verification script must also check pending
    authenticator-rotation challenges: a challenge that still decrypts only
    under the key being retired means that key is not yet removable.

    The user's own `totp_secret` is seeded under the NEW key, so the
    users-table check passes and a failure is attributable to the challenge
    alone. Both tests run the verifier as a subprocess, like the re-encryption tests."""

    @staticmethod
    def _seed_rotation_state(sync_conn, user_factory, session_factory):
        """One user whose totp_secret is under the new key and whose pending
        rotation challenge is under the OLD key only. Returns the user and the
        documented rotation-state environment ``[new, old]``."""
        old_key = settings.totp_encryption_keys[0].get_secret_value()
        new_key = secrets.token_urlsafe(48)
        new_fernet = _derive_fernet(new_key, context=b"oralhistarchiv-totp-encryption-v1")

        user = user_factory(totp_secret=new_fernet.encrypt(pyotp.random_base32().encode()).decode())
        session_factory(user.id)
        session_id = sync_conn.execute(
            "SELECT id FROM sessions WHERE user_id = %s", (user.id,)
        ).fetchone()[0]
        sync_conn.execute(
            """
            INSERT INTO pending_totp_rotations
                (user_id, session_id, auth_revision, encrypted_secret, expires_at)
            VALUES (%s, %s, %s, %s, now() + interval '1 hour')
            """,
            (user.id, session_id, 0, encrypt_value(pyotp.random_base32())),  # OLD key only
        )
        sync_conn.commit()
        return user, {"TOTP_ENCRYPTION_KEYS": json.dumps([new_key, old_key])}

    def test_a_challenge_readable_only_under_the_old_key_fails_verification(
        self, sync_conn, user_factory, session_factory
    ):
        """Verify a challenge readable only under the old key fails verification."""
        user, rotation_env = self._seed_rotation_state(sync_conn, user_factory, session_factory)

        result = _run_script(extra_env=rotation_env, script=VERIFY_SCRIPT)

        assert result.returncode == 1, result.stdout + result.stderr
        assert (
            f"user {user.id}: rotation challenge (not decryptable under the primary key)"
            in result.stdout
        )
        # Exactly one failure: the users-table secret (under the new key) passed.
        assert "FAIL — 1 values" in result.stdout

    def test_reencryption_then_verification_accepts_rewrapped_challenge(
        self, sync_conn, user_factory, session_factory
    ):
        """Positive re-encryption and verification round trip: after reencrypt_totp.py the
        same state verifies clean, and the challenge is counted as checked."""
        _user, rotation_env = self._seed_rotation_state(sync_conn, user_factory, session_factory)

        reencrypt = _run_script(extra_env=rotation_env)
        assert reencrypt.returncode == 0, reencrypt.stdout + reencrypt.stderr

        result = _run_script(extra_env=rotation_env, script=VERIFY_SCRIPT)

        assert result.returncode == 0, result.stdout + result.stderr
        # totp_secret + the rotation challenge; pending_totp_secret is NULL.
        assert "OK — 2 stored TOTP value(s)" in result.stdout


class TestKeyRotationRunbookCancellation:
    """Run the signing-key runbook's maintenance file against real outbox rows."""

    def test_signing_key_runbook_cancels_pending_and_sending_actions_only(
        self, sync_conn, user_factory
    ):
        """Verify signing key runbook cancels pending and sending actions only."""
        user = user_factory()
        message_types = [
            "password_reset",
            "email_verification",
            "email_change_verification",
            "account_locked_notice",
        ]
        for status in ("pending", "sending", "sent", "dead"):
            for message_type in message_types:
                sync_conn.execute(
                    """INSERT INTO email_outbox
                       (user_id, message_type, recipient, subject, body_ciphertext, status,
                        action_token_hash, expires_at, locked_at, lock_token, sent_at,
                        failed_at, terminal_outcome)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        user.id,
                        message_type,
                        user.email,
                        f"{status}:{message_type}",
                        encrypt_outbox_body("body"),
                        status,
                        "a" * 64 if message_type != "account_locked_notice" else None,
                        datetime.now(UTC) + timedelta(hours=1)
                        if message_type != "account_locked_notice"
                        else None,
                        datetime.now(UTC) if status == "sending" else None,
                        "00000000-0000-0000-0000-000000000001" if status == "sending" else None,
                        datetime.now(UTC) if status == "sent" else None,
                        datetime.now(UTC) if status == "dead" else None,
                        "delivery_failed" if status == "dead" else None,
                    ),
                )
        before = dict(
            sync_conn.execute(
                "SELECT subject, to_jsonb(message) FROM email_outbox AS message"
            ).fetchall()
        )
        sync_conn.commit()
        sql_path = "deploy/invalidate-action-email-capabilities.sql"
        runbook = (PROJECT_ROOT / "docs/runbooks/key-rotation.md").read_text(encoding="utf-8")
        assert f"`{sql_path}`" in runbook
        with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as connection:
            connection.execute((PROJECT_ROOT / sql_path).read_text(encoding="utf-8"))
        rows = sync_conn.execute(
            "SELECT subject, to_jsonb(message) FROM email_outbox AS message"
        ).fetchall()
        assert {subject for subject, _ in rows} == before.keys()
        assert sum(row["terminal_outcome"] == "cancelled" for _, row in rows) == 6
        for subject, row in rows:
            original_status, message_type = subject.split(":")
            if (
                original_status in {"pending", "sending"}
                and message_type != "account_locked_notice"
            ):
                assert tuple(
                    row[name]
                    for name in ("status", "terminal_outcome", "locked_at", "lock_token", "sent_at")
                ) == ("dead", "cancelled", None, None, None)
            else:
                assert row == before[subject]

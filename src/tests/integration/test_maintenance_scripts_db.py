"""Maintenance scripts that operate directly on the database.

Two production surfaces, both invoked as scripts or service calls against a
real PostgreSQL database rather than through the web app:

* `scripts/reencrypt_totp.py` — eager TOTP-secret re-encryption for key
  rotation. Re-encrypts every stored `totp_secret` / `pending_totp_secret`
  and `pending_totp_rotations.encrypted_secret` under the front key of the
  current MultiFernet so the old key can be retired
  (`docs/runbooks/key-rotation.md`, Phase B2). Run `scripts/verify_totp_reencryption.py`
  (Phase C) before dropping the old key.
* `app.services.seed_mock_data.seed_mock_data` — inserts sample restricted
  datasets for development and staging so the tiered-visibility system can
  be exercised without the real sensitive data source.

`TestKeyRotationRunbookCancellation` executes the cancellation SQL statement
documented in `docs/runbooks/key-rotation.md` verbatim (extracted from the
runbook text itself, not retyped) against a real `email_outbox` table, so a
runbook edit that silently changes which rows it cancels is caught here
rather than only during a live rotation.

`TestReencryptTotpRotation` runs the script AS A SCRIPT (subprocess over the
`__main__` block) rather than as an imported `main()`: a missing `import sys`
(entry-point NameError) or a missing InvalidToken import (a NameError that
fires only on the first undecryptable row) — an import-and-await test
detects neither. The stdout assertions pin the rotated-user counter (it must
count every rotated user, not stay at zero) and the skipped-column report
(it must not reference an unbound `skipped` name).

The one exception is the CAS-miss branch (a concurrent write between the
script's snapshot SELECT and its per-row compare-and-swap UPDATE): a
subprocess cannot be interleaved deterministically, so that test imports
main() and injects the concurrent write through the module's
`_fernet_instance` seam instead — the same in-process race-injection idea
`test_sync_mutex_race.py` uses. The import-breakage pins above still come
exclusively from the subprocess tests.

`TestSeedMockData` covers `services/seed_mock_data.py`. Two invariants
matter: it refuses to run when `settings.is_production`, so mock
'restricted' testimony can never be inserted into a real archive; and every
seeded row is `source='mock'`, `access_level='restricted'`,
`visibility_tier='vetted'` — a row that landed as `visibility_tier='public'`
would surface mock "sensitive" testimony to anonymous users.
"""

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
from app.services.crypto import _derive_fernet, decrypt_value, encrypt_outbox_body, encrypt_value
from app.services.seed_mock_data import MOCK_RESTRICTED_DATASETS, seed_mock_data
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
    row = sync_conn.execute(
        "SELECT totp_secret, pending_totp_secret FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()
    return {"totp_secret": row[0], "pending_totp_secret": row[1]}


class TestReencryptTotpRotation:
    """scripts/reencrypt_totp.py rotates every TOTP secret onto the front key."""

    def test_clean_run_rotates_every_secret_and_reports_count(self, sync_conn, user_factory):
        """Pins the rotated-user counter (it must count every rotated user,
        not stay at 0) and the clean exit code against entry-point import breakage.

        Run in the DOCUMENTED ROTATION STATE (the script docstring's
        TOTP_ENCRYPTION_KEYS=["<new>", "<old>"], not the test env's single key):
        secrets are seeded under the OLD key, the subprocess sees [new, old], and
        both columns — totp_secret AND pending_totp_secret — must come back
        decryptable under the NEW key ALONE and no longer under the old one.
        A single-key run cannot pin this: Fernet's
        random IV makes even a same-key rewrap change the ciphertext, so
        `after != before` plus a MultiFernet decrypt would pass without any real
        old→new re-encryption — the property Phase C
        (verify_totp_reencryption.py) and key retirement actually depend on."""
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
        """Pins the skip path against the drafts' unbound-`skipped`
        NameError and missing InvalidToken import — both latent until the first
        undecryptable row appears in production. The garbage ciphertext must be
        REPORTED (id, column, reason) and left byte-identical — never overwritten
        with a new wrap of garbage — the healthy neighbour must still rotate
        (positive control), and exit code 1 must demand the rerun."""
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
        """The CAS branch itself — `UPDATE ... WHERE id = %s AND
        {col} = %s` with rowcount 0 → reported as "changed mid-run (CAS miss)",
        exit 1, and the CONCURRENT WRITE WINS. This is the branch the CAS
        predicate exists for: a bare `WHERE id = %s` would silently overwrite a
        secret the user re-enrolled mid-run — locking them out of their new
        authenticator. Driven in-process (see module docstring): the script's
        _fernet_instance is wrapped so that rotating the racer's snapshot
        ciphertext first commits a concurrent re-enrollment, exactly the
        snapshot→UPDATE window the CAS guard closes."""
        winner_plain = pyotp.random_base32()
        winner = user_factory(totp_secret=encrypt_value(winner_plain))
        racer = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
        winner_before = _secret_columns(sync_conn, winner.id)["totp_secret"]
        racer_snapshot_ct = _secret_columns(sync_conn, racer.id)["totp_secret"]

        module = _load_script_module()
        real_fernet = module._fernet_instance
        concurrent_plain = pyotp.random_base32()
        concurrent_ct = encrypt_value(concurrent_plain)  # the mid-run re-enrollment
        injected: list[bool] = []

        class _RaceInjectingFernet:
            """Delegates to the real MultiFernet, but the first rotate() of the
            racer's snapshot ciphertext first commits a concurrent UPDATE to that
            row — landing in the window between the script's snapshot SELECT and
            its per-row CAS UPDATE, deterministically."""

            def rotate(self, token: bytes) -> bytes:
                if token.decode() == racer_snapshot_ct and not injected:
                    injected.append(True)
                    with psycopg.connect(TEST_DATABASE_URL) as conn:
                        conn.execute(
                            "UPDATE users SET totp_secret = %s WHERE id = %s",
                            (concurrent_ct, racer.id),
                        )
                        conn.commit()
                return real_fernet.rotate(token)

        monkeypatch.setattr(module, "_fernet_instance", _RaceInjectingFernet())

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
    """Phase C (`scripts/verify_totp_reencryption.py`) must also check pending
    authenticator-rotation challenges: a challenge that still decrypts only
    under the key being retired means that key is not yet removable.

    The user's own `totp_secret` is seeded under the NEW key, so the
    users-table check passes and a failure is attributable to the challenge
    alone. Both tests run the verifier as a subprocess, like the B2 tests."""

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
        user, rotation_env = self._seed_rotation_state(sync_conn, user_factory, session_factory)

        result = _run_script(extra_env=rotation_env, script=VERIFY_SCRIPT)

        assert result.returncode == 1, result.stdout + result.stderr
        assert (
            f"user {user.id}: rotation challenge (not decryptable under the primary key)"
            in result.stdout
        )
        # Exactly one failure: the users-table secret (under the new key) passed.
        assert "FAIL — 1 values" in result.stdout

    def test_phase_b2_then_phase_c_verifies_the_rewrapped_challenge(
        self, sync_conn, user_factory, session_factory
    ):
        """Positive control and B2 -> C round trip: after reencrypt_totp.py the
        same state verifies clean, and the challenge is counted as checked."""
        _user, rotation_env = self._seed_rotation_state(sync_conn, user_factory, session_factory)

        reencrypt = _run_script(extra_env=rotation_env)
        assert reencrypt.returncode == 0, reencrypt.stdout + reencrypt.stderr

        result = _run_script(extra_env=rotation_env, script=VERIFY_SCRIPT)

        assert result.returncode == 0, result.stdout + result.stderr
        # totp_secret + the rotation challenge; pending_totp_secret is NULL.
        assert "OK — 2 stored TOTP value(s)" in result.stdout


class TestKeyRotationRunbookCancellation:
    """The signing-key-rotation runbook's cancellation SQL
    (`docs/runbooks/key-rotation.md`) against real `email_outbox` rows."""

    def test_signing_key_runbook_cancels_pending_and_sending_actions_only(
        self, sync_conn, user_factory
    ):
        """The runbook's documented UPDATE cancels only action-carrying
        messages (password reset, email verification, email-change
        verification) that are still pending or sending — moving them to
        status='dead', terminal_outcome='cancelled', with sent_at, locked_at
        and lock_token cleared. Already-sent and already-dead rows, and the
        notice-only account_locked_notice type (which carries no signed
        link), are left with their original status untouched."""
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
        sync_conn.commit()
        runbook = (PROJECT_ROOT / "docs/runbooks/key-rotation.md").read_text()
        statement = runbook.split("UPDATE email_outbox", 1)[1].split(
            "RETURNING id, message_type;", 1
        )[0]
        cancelled = sync_conn.execute(
            "UPDATE email_outbox" + statement + "RETURNING id, message_type"
        ).fetchall()
        assert len(cancelled) == 6
        rows = sync_conn.execute(
            "SELECT subject, status, terminal_outcome, locked_at, lock_token, sent_at "
            "FROM email_outbox"
        ).fetchall()
        for subject, status, terminal, locked_at, lock_token, sent_at in rows:
            original_status, message_type = subject.split(":")
            if (
                original_status in {"pending", "sending"}
                and message_type != "account_locked_notice"
            ):
                assert (status, terminal, locked_at, lock_token, sent_at) == (
                    "dead",
                    "cancelled",
                    None,
                    None,
                    None,
                )
            else:
                assert status == original_status


class TestSeedMockData:
    """app.services.seed_mock_data.seed_mock_data — production refusal and
    seeded-row invariants."""

    async def test_seed_mock_data_refuses_in_production(self, db_pool, sync_conn, monkeypatch):
        """The prod guard fires BEFORE any insert: with env_state='production'
        (settings.is_production True) the call raises RuntimeError and the
        datasets table stays empty.

        is_production is a read-only @property derived from env_state
        (config/settings.py ~L208) — monkeypatch.setattr(settings, "is_production",
        ...) would itself raise AttributeError ("property ... has no setter"), so
        going through env_state is the only way to fake it. This also matches the
        suite's established convention for this exact property (see
        test_startup_guards.py, test_security_validators.py, test_password_validation.py)
        rather than replacing the whole settings singleton with a MagicMock."""
        monkeypatch.setattr(settings, "env_state", "production")
        with pytest.raises(
            RuntimeError,
            match="seed_mock_data is dev or staging only; refusing to run in production",
        ):
            await seed_mock_data(db_pool)

        count = sync_conn.execute("SELECT COUNT(*) FROM oral_history_datasets").fetchone()[0]
        assert count == 0

    async def test_seed_mock_data_runs_in_staging(self, db_pool, sync_conn, monkeypatch):
        """The guard is deliberately settings.is_production, NOT
        is_hardened — staging demo environments seed on purpose. Staging
        (env_state='staging') is is_hardened=True but is_production=False, so a
        future "consistency" sweep flipping the guard to is_hardened would refuse
        here and this positive control (for the production-refusal test above)
        must fail."""
        monkeypatch.setattr(settings, "env_state", "staging")
        assert settings.is_hardened is True  # staging: hardened, yet seeding allowed
        assert settings.is_production is False
        inserted = await seed_mock_data(db_pool)
        assert inserted == len(MOCK_RESTRICTED_DATASETS) == 3

        count = sync_conn.execute("SELECT COUNT(*) FROM oral_history_datasets").fetchone()[0]
        assert count == 3

    async def test_seed_mock_data_seeds_restricted_vetted_rows(self, db_pool, sync_conn):
        """Every seeded row is source='mock', access_level='restricted',
        visibility_tier='vetted' — the invariants that keep mock testimony
        invisible to below-tier users. Re-running is an idempotent upsert by uuid
        (count stays at the fixed 3, not 6)."""
        inserted = await seed_mock_data(db_pool)
        assert inserted == len(MOCK_RESTRICTED_DATASETS) == 3

        rows = sync_conn.execute(
            """SELECT source, access_level, visibility_tier
               FROM oral_history_datasets"""
        ).fetchall()
        assert len(rows) == 3
        for source, access_level, visibility_tier in rows:
            assert source == "mock"
            assert access_level == "restricted"
            assert visibility_tier == "vetted"

        # Idempotent: a second seed upserts by uuid, no duplicates.
        await seed_mock_data(db_pool)
        count = sync_conn.execute("SELECT COUNT(*) FROM oral_history_datasets").fetchone()[0]
        assert count == 3

    async def test_seeded_mock_rows_are_invisible_to_public_search(self, db_pool, e2e_client):
        """End-to-end consequence of the invariants: after seeding, a guest's
        search never surfaces a mock dataset's restricted content — the tier
        filter (exercised for real here) hides all three."""
        await seed_mock_data(db_pool)

        # The mock rows are vetted-tier: a guest full-text search over their
        # (restricted) descriptions returns nothing.
        resp = e2e_client.get("/search", params={"q": "mock"})
        assert resp.status_code == 200
        # Titles may be public (visible fields), but the count reflects tier-
        # visible full-text matches; no restricted description leaks.
        for ds in MOCK_RESTRICTED_DATASETS:
            assert ds.get("description", "ZZZ") not in resp.text

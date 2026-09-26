"""Row-level constraint behaviour of the migrated schema.

`test_schema_db.py` proves that the live PostgreSQL catalogs match the
declarative contract in `app.services.db_schema_contract` structurally
(names, types, definitions). This module proves what those structures do to
an actual row: which values a column or constraint accepts and which it
rejects, for the specific facts the migration and the contract commit to
individually rather than only through the aggregate drift sweep.
"""

import psycopg
import pytest

from app.services.db import get_db_cursor
from app.services.db_schema_contract import (
    SYNC_STATUS_COLUMN_CONTRACT,
    USER_COLUMN_CONTRACT,
    USER_CONSTRAINT_CONTRACT,
)


def _stored_session_id(sync_conn, user_id) -> str:
    """Read the hashed session id session_factory actually stored."""
    row = sync_conn.execute(
        "SELECT id FROM sessions WHERE user_id = %s",
        (user_id,),
    ).fetchone()
    return row[0]


class TestSyncStatusSourceFingerprintMatchesTheMigration:
    """`sync_status.source_fingerprint` is a nullable text column, both in
    the migrated database and in the declared column contract."""

    def test_migrated_column_is_nullable_text(self, sync_conn):
        row = sync_conn.execute(
            """
            SELECT data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'sync_status'
              AND column_name = 'source_fingerprint'
            """
        ).fetchone()

        assert row == ("text", "YES")

    def test_column_contract_declares_the_same_shape(self):
        contract = SYNC_STATUS_COLUMN_CONTRACT["source_fingerprint"]

        assert contract.pg_type == "text"
        assert contract.nullable is True


class TestUsersLockoutNoticeColumnAndConstraintMatchTheMigration:
    """`users.lockout_notice_enqueued_at` and the check tying it to
    `failed_login_count` are declared exactly as the migration creates
    them."""

    def test_migrated_column_is_a_nullable_timestamptz(self, sync_conn):
        row = sync_conn.execute(
            """
            SELECT data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'users'
              AND column_name = 'lockout_notice_enqueued_at'
            """
        ).fetchone()

        assert row == ("timestamp with time zone", "YES")

    def test_column_contract_declares_the_same_shape(self):
        contract = USER_COLUMN_CONTRACT["lockout_notice_enqueued_at"]

        assert contract.pg_type == "timestamp with time zone"
        assert contract.nullable is True

    def test_constraint_contract_matches_the_definition_postgresql_reports(self, sync_conn):
        row = sync_conn.execute(
            """
            SELECT pg_get_constraintdef(oid)
            FROM pg_constraint
            WHERE conname = 'users_lockout_notice_state_check'
            """
        ).fetchone()

        assert row is not None, "users_lockout_notice_state_check is missing from the migration"
        migrated_definition = row[0]
        contract = USER_CONSTRAINT_CONTRACT["users_lockout_notice_state_check"]

        assert contract.check_definition == migrated_definition


class TestUsersFailedLoginCountAndLockoutNoticeMarkerCoherence:
    """`users_lockout_notice_state_check` only allows a pending lockout
    notice marker while the failed-login streak that triggered it is still
    on the row."""

    async def test_positive_failed_login_count_with_a_null_marker_is_accepted(
        self, user_factory, sync_conn
    ):
        user = user_factory(failed_login_count=3, lockout_notice_enqueued_at=None)

        row = sync_conn.execute(
            "SELECT failed_login_count, lockout_notice_enqueued_at FROM users WHERE id = %s",
            (user.id,),
        ).fetchone()
        assert row == (3, None)

    async def test_zero_failed_login_count_with_a_marker_set_is_rejected(
        self, db_pool, user_factory
    ):
        user = user_factory()

        with pytest.raises(
            psycopg.errors.CheckViolation,
            match="users_lockout_notice_state_check",
        ):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    "UPDATE users SET failed_login_count = 0, "
                    "lockout_notice_enqueued_at = now() WHERE id = %s",
                    (user.id,),
                )


class TestStagedTotpRotationChallengeConstraints:
    """A staged authenticator-replacement challenge (`pending_totp_rotations`)
    only ever names a nonnegative revision, a real ciphertext, an expiry
    strictly after its own creation, and a session that actually belongs to
    the challenged user."""

    async def test_coherent_challenge_row_is_accepted(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        user = user_factory()
        session_factory(user.id)
        session_id = _stored_session_id(sync_conn, user.id)

        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                """
                INSERT INTO pending_totp_rotations
                    (user_id, session_id, auth_revision, encrypted_secret, expires_at)
                VALUES (%s, %s, %s, %s, now() + interval '1 hour')
                """,
                (user.id, session_id, 0, "challenge-ciphertext"),
            )

        row = sync_conn.execute(
            "SELECT auth_revision, encrypted_secret FROM pending_totp_rotations WHERE user_id = %s",
            (user.id,),
        ).fetchone()
        assert row == (0, "challenge-ciphertext")

    async def test_negative_auth_revision_is_rejected(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        user = user_factory()
        session_factory(user.id)
        session_id = _stored_session_id(sync_conn, user.id)

        with pytest.raises(
            psycopg.errors.CheckViolation,
            match="pending_totp_rotations_auth_revision_check",
        ):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    """
                    INSERT INTO pending_totp_rotations
                        (user_id, session_id, auth_revision, encrypted_secret, expires_at)
                    VALUES (%s, %s, %s, %s, now() + interval '1 hour')
                    """,
                    (user.id, session_id, -1, "challenge-ciphertext"),
                )

    async def test_empty_ciphertext_is_rejected(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        user = user_factory()
        session_factory(user.id)
        session_id = _stored_session_id(sync_conn, user.id)

        with pytest.raises(
            psycopg.errors.CheckViolation,
            match="pending_totp_rotations_encrypted_secret_check",
        ):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    """
                    INSERT INTO pending_totp_rotations
                        (user_id, session_id, auth_revision, encrypted_secret, expires_at)
                    VALUES (%s, %s, %s, %s, now() + interval '1 hour')
                    """,
                    (user.id, session_id, 0, ""),
                )

    async def test_expiry_not_after_creation_is_rejected(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        user = user_factory()
        session_factory(user.id)
        session_id = _stored_session_id(sync_conn, user.id)

        with pytest.raises(
            psycopg.errors.CheckViolation,
            match="pending_totp_rotations_expiry_check",
        ):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    """
                    INSERT INTO pending_totp_rotations
                        (user_id, session_id, auth_revision, encrypted_secret,
                         created_at, expires_at)
                    VALUES (%s, %s, %s, %s, now(), now())
                    """,
                    (user.id, session_id, 0, "challenge-ciphertext"),
                )

    async def test_session_belonging_to_a_different_user_is_rejected(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        user = user_factory()
        other_user = user_factory()
        session_factory(other_user.id)
        other_session_id = _stored_session_id(sync_conn, other_user.id)

        with pytest.raises(
            psycopg.errors.ForeignKeyViolation,
            match="pending_totp_rotations_session_user_fkey",
        ):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    """
                    INSERT INTO pending_totp_rotations
                        (user_id, session_id, auth_revision, encrypted_secret, expires_at)
                    VALUES (%s, %s, %s, %s, now() + interval '1 hour')
                    """,
                    (user.id, other_session_id, 0, "challenge-ciphertext"),
                )

    async def test_missing_user_reference_is_rejected(self, db_pool, user_factory, session_factory):
        user = user_factory()
        raw_session = session_factory(user.id)

        with pytest.raises(
            psycopg.errors.ForeignKeyViolation,
            match="pending_totp_rotations_user_id_fkey",
        ):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    """
                    INSERT INTO pending_totp_rotations
                        (user_id, session_id, auth_revision, encrypted_secret, expires_at)
                    VALUES (%s, %s, %s, %s, now() + interval '1 hour')
                    """,
                    (user.id + 999_000, raw_session, 0, "challenge-ciphertext"),
                )


class TestSyncStatusIncrementalProgressCoherence:
    """Resumable incremental-sync progress (`sync_status.incremental_*`)
    never goes negative, and a staged harvest payload is always paired with
    the instant its incremental run started."""

    async def test_zero_progress_with_no_staged_harvest_is_the_accepted_baseline(self, sync_conn):
        """The row `clean_db` seeds before every test is itself a coherent
        state: no work staged, nothing to resume."""
        row = sync_conn.execute(
            """
            SELECT incremental_position, incremental_affected,
                   incremental_harvest, incremental_started_at
            FROM sync_status WHERE id = 1
            """
        ).fetchone()
        assert row == (0, 0, None, None)

    async def test_positive_progress_with_a_staged_harvest_and_start_time_is_accepted(
        self, db_pool, sync_conn
    ):
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                """
                UPDATE sync_status
                SET incremental_position = 5,
                    incremental_affected = 2,
                    incremental_harvest = %s,
                    incremental_started_at = now()
                WHERE id = 1
                """,
                (b"staged-harvest-payload",),
            )

        row = sync_conn.execute(
            """
            SELECT incremental_position, incremental_affected,
                   incremental_harvest, incremental_started_at IS NOT NULL
            FROM sync_status WHERE id = 1
            """
        ).fetchone()
        assert row == (5, 2, b"staged-harvest-payload", True)

    @pytest.mark.unimplemented
    async def test_negative_incremental_position_is_rejected(self, db_pool):
        with pytest.raises(psycopg.errors.CheckViolation, match="incremental_position"):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute("UPDATE sync_status SET incremental_position = -1 WHERE id = 1")

    @pytest.mark.unimplemented
    async def test_negative_incremental_affected_is_rejected(self, db_pool):
        with pytest.raises(psycopg.errors.CheckViolation, match="incremental_affected"):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute("UPDATE sync_status SET incremental_affected = -1 WHERE id = 1")

    @pytest.mark.unimplemented
    async def test_staged_harvest_without_a_start_time_is_rejected(self, db_pool):
        with pytest.raises(psycopg.errors.CheckViolation, match="incremental_started_at"):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    """
                    UPDATE sync_status
                    SET incremental_harvest = %s, incremental_started_at = NULL
                    WHERE id = 1
                    """,
                    (b"staged-harvest-payload",),
                )

    @pytest.mark.unimplemented
    async def test_nonzero_progress_with_no_staged_harvest_is_rejected(self, db_pool):
        with pytest.raises(psycopg.errors.CheckViolation, match="incremental_position"):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    """
                    UPDATE sync_status
                    SET incremental_position = 3,
                        incremental_harvest = NULL,
                        incremental_started_at = NULL
                    WHERE id = 1
                    """
                )

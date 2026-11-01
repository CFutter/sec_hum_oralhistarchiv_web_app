"""Row-level constraint behaviour of the migrated schema."""

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


class TestDatasetSourceIdentity:
    """Persisted source identity is explicit and follows configured-source names."""

    def test_source_is_required_text_without_a_database_default(self, sync_conn):
        """Verify source is required text without a database default."""
        row = sync_conn.execute(
            """
            SELECT data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'oral_history_datasets'
              AND column_name = 'source'
            """
        ).fetchone()

        assert row == ("text", "NO", None)

    @pytest.mark.parametrize("omitted", [True, False], ids=["omitted", "null"])
    def test_missing_source_is_rejected(self, sync_conn, omitted):
        """Verify missing source is rejected."""
        with (
            pytest.raises(psycopg.errors.NotNullViolation, match="source"),
            sync_conn.transaction(),
        ):
            if omitted:
                sync_conn.execute(
                    "INSERT INTO oral_history_datasets (uuid, title) VALUES (%s, %s)",
                    ("test:missing-source", "Missing source"),
                )
            else:
                sync_conn.execute(
                    """
                    INSERT INTO oral_history_datasets (uuid, source, title)
                    VALUES (%s, %s, %s)
                    """,
                    ("test:missing-source", None, "Missing source"),
                )

    @pytest.mark.parametrize(
        "source",
        ["", "Archive", "archive-name", "archivé", "archive\n", "a" * 33],
        ids=["empty", "uppercase", "hyphen", "non-ascii", "newline", "too-long"],
    )
    def test_invalid_source_name_is_rejected(self, sync_conn, source):
        """Verify invalid source name is rejected."""
        with (
            pytest.raises(
                psycopg.errors.CheckViolation,
                match="datasets_source_check",
            ),
            sync_conn.transaction(),
        ):
            sync_conn.execute(
                """
                INSERT INTO oral_history_datasets (uuid, source, title)
                VALUES (%s, %s, %s)
                """,
                ("test:invalid-source", source, "Invalid source"),
            )

    @pytest.mark.parametrize(
        "source",
        ["a", "0_", "a" * 32],
        ids=["one-character", "digits-and-underscore", "maximum-length"],
    )
    def test_valid_source_name_is_stored_unchanged(self, sync_conn, source):
        """Verify valid source name is stored unchanged."""
        row = sync_conn.execute(
            """
            INSERT INTO oral_history_datasets (uuid, source, title)
            VALUES (%s, %s, %s)
            RETURNING source
            """,
            ("test:valid-source", source, "Valid source"),
        ).fetchone()

        assert row == (source,)


class TestSyncStatusSourceFingerprintMatchesTheMigration:
    """`sync_status.source_fingerprint` is a nullable text column, both in
    the migrated database and in the declared column contract."""

    def test_migrated_column_is_nullable_text(self, sync_conn):
        """Verify migrated column is nullable text."""
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
        """Verify column contract declares the same shape."""
        contract = SYNC_STATUS_COLUMN_CONTRACT["source_fingerprint"]

        assert contract.pg_type == "text"
        assert contract.nullable is True


class TestUsersLockoutNoticeColumnAndConstraintMatchTheMigration:
    """`users.lockout_notice_enqueued_at` and the check tying it to
    `failed_login_count` are declared exactly as the migration creates
    them."""

    def test_migrated_column_is_a_nullable_timestamptz(self, sync_conn):
        """Verify migrated column is a nullable timestamptz."""
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
        """Verify column contract declares the same shape."""
        contract = USER_COLUMN_CONTRACT["lockout_notice_enqueued_at"]

        assert contract.pg_type == "timestamp with time zone"
        assert contract.nullable is True

    def test_constraint_contract_matches_the_definition_postgresql_reports(self, sync_conn):
        """Verify constraint contract matches the definition postgresql reports."""
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
        """Verify positive failed login count with a null marker is accepted."""
        user = user_factory(failed_login_count=3, lockout_notice_enqueued_at=None)

        row = sync_conn.execute(
            "SELECT failed_login_count, lockout_notice_enqueued_at FROM users WHERE id = %s",
            (user.id,),
        ).fetchone()
        assert row == (3, None)

    async def test_zero_failed_login_count_with_a_marker_set_is_rejected(
        self, db_pool, user_factory
    ):
        """Verify zero failed login count with a marker set is rejected."""
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
        """Verify coherent challenge row is accepted."""
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
        """Verify negative auth revision is rejected."""
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
        """Verify empty ciphertext is rejected."""
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
        """Verify expiry not after creation is rejected."""
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
        """Verify session belonging to a different user is rejected."""
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
        """Verify missing user reference is rejected."""
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
            FROM sync_status WHERE source = 'swissubase'
            """
        ).fetchone()
        assert row == (0, 0, None, None)

    async def test_positive_progress_with_a_staged_harvest_and_start_time_is_accepted(
        self, db_pool, sync_conn
    ):
        """Verify positive progress with a staged harvest and start time is accepted."""
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                """
                UPDATE sync_status
                SET incremental_position = 5,
                    incremental_affected = 2,
                    incremental_harvest = %s,
                    incremental_started_at = now()
                WHERE source = 'swissubase'
                """,
                (b"staged-harvest-payload",),
            )

        row = sync_conn.execute(
            """
            SELECT incremental_position, incremental_affected,
                   incremental_harvest, incremental_started_at IS NOT NULL
            FROM sync_status WHERE source = 'swissubase'
            """
        ).fetchone()
        assert row == (5, 2, b"staged-harvest-payload", True)

    async def test_negative_incremental_position_is_rejected(self, db_pool):
        """Verify negative incremental position is rejected."""
        with pytest.raises(psycopg.errors.CheckViolation, match="incremental_position"):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    "UPDATE sync_status SET incremental_position = -1 WHERE source = 'swissubase'"
                )

    async def test_negative_incremental_affected_is_rejected(self, db_pool):
        """Verify negative incremental affected is rejected."""
        with pytest.raises(psycopg.errors.CheckViolation, match="incremental_affected"):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    "UPDATE sync_status SET incremental_affected = -1 WHERE source = 'swissubase'"
                )

    async def test_staged_harvest_without_a_start_time_is_rejected(self, db_pool):
        """Verify staged harvest without a start time is rejected."""
        with pytest.raises(psycopg.errors.CheckViolation, match="incremental_started_at"):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    """
                    UPDATE sync_status
                    SET incremental_harvest = %s, incremental_started_at = NULL
                    WHERE source = 'swissubase'
                    """,
                    (b"staged-harvest-payload",),
                )

    async def test_nonzero_progress_with_no_staged_harvest_is_rejected(self, db_pool):
        """Verify nonzero progress with no staged harvest is rejected."""
        with pytest.raises(psycopg.errors.CheckViolation, match="incremental_position"):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    """
                    UPDATE sync_status
                    SET incremental_position = 3,
                        incremental_harvest = NULL,
                        incremental_started_at = NULL
                    WHERE source = 'swissubase'
                    """
                )

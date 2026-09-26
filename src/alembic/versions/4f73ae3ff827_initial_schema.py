"""Fresh-database schema baseline; no upgrade path from earlier migration histories."""

from collections.abc import Sequence

from alembic import op

revision: str = "4f73ae3ff827"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create ten application tables, search triggers/indexes, and pg_trgm.

    Require a fresh database and a role permitted to create these objects.
    Seed sync_status with id=1 and last_harvest_date=1900-01-01; leave
    source_cursor/source_fingerprint unset, requiring an initial rebuild.
    No existing-data backfill or legacy-schema upgrade is performed.
    DDL/database errors propagate to Alembic.

    The stored search function's SQL comments are part of the exact runtime
    source contract. Its public blob contains title/access_level only; its
    full blob adds description, project fields, keywords, and authors,
    not every metadata field. Changing those embedded comments requires
    a coordinated function migration and db_schema_contract update.
    """
    op.execute("""
        CREATE EXTENSION IF NOT EXISTS pg_trgm;

        CREATE TABLE oral_history_datasets (
            id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            uuid TEXT NOT NULL,
            doi TEXT,
            source TEXT NOT NULL DEFAULT 'swissubase',
            title TEXT,
            project_title TEXT,
            description TEXT,
            resource_description TEXT,
            project_description TEXT,
            bibliographical_citation TEXT,
            authors TEXT[] NOT NULL DEFAULT '{}'::text[],
            keywords TEXT[] NOT NULL DEFAULT '{}'::text[],
            languages TEXT[] NOT NULL DEFAULT '{}'::text[],
            institutions TEXT[] NOT NULL DEFAULT '{}'::text[],
            main_disciplines TEXT[] NOT NULL DEFAULT '{}'::text[],
            resource_type TEXT,
            version TEXT,
            access_level TEXT,
            visibility_tier TEXT NOT NULL DEFAULT 'vetted',
            license_val TEXT,
            license_url TEXT,
            resource_proxies JSONB NOT NULL DEFAULT '[]'::jsonb,
            data JSONB,
            upstream_modified_at TIMESTAMPTZ,
            synced_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            search_text_public TEXT,
            search_text_full   TEXT,
            CONSTRAINT datasets_source_uuid_key UNIQUE (source, uuid),
            CONSTRAINT datasets_source_doi_key UNIQUE (source, doi),
            CONSTRAINT datasets_visibility_tier_check
                CHECK (visibility_tier IN ('public', 'registered', 'vetted'))
        );

        CREATE INDEX idx_datasets_source
            ON oral_history_datasets(source);

        -- Trigger: maintains the public and full search-text columns
        -- on every insert/update. sync.py doesn't need to know about it.
        CREATE FUNCTION update_search_text() RETURNS trigger AS $$
        BEGIN
            -- Public blob: only fields visible to everyone (title + access level),
            -- matching exactly what filter_for_tier leaves on a redacted dataset.
            NEW.search_text_public :=
                COALESCE(NEW.title, '') || ' ' ||
                COALESCE(NEW.access_level, '');
            -- Full blob: everything. Only matched against rows the user is allowed
            -- to fully see (tier gate applied in the query, not here).
            NEW.search_text_full :=
                COALESCE(NEW.title, '') || ' ' ||
                COALESCE(NEW.description, '') || ' ' ||
                COALESCE(NEW.project_title, '') || ' ' ||
                COALESCE(NEW.project_description, '') || ' ' ||
                COALESCE(array_to_string(NEW.keywords, ' '), '') || ' ' ||
                COALESCE(array_to_string(NEW.authors, ' '), '');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER trg_search_text
            BEFORE INSERT OR UPDATE ON oral_history_datasets
            FOR EACH ROW EXECUTE FUNCTION update_search_text();

        -- Trigram GIN index: makes ILIKE '%term%' use an index scan
        -- instead of a sequential scan. Effective for 3+ character terms.
        CREATE INDEX idx_search_text_public_trgm
            ON oral_history_datasets USING GIN (search_text_public gin_trgm_ops);

        CREATE INDEX idx_search_text_full_trgm
            ON oral_history_datasets USING GIN (search_text_full gin_trgm_ops);

        CREATE INDEX ix_datasets_upstream_modified_at
            ON oral_history_datasets (upstream_modified_at DESC NULLS LAST, id DESC);
        CREATE INDEX ix_datasets_keywords_gin
            ON oral_history_datasets USING GIN (keywords);
        CREATE INDEX ix_datasets_languages_gin
            ON oral_history_datasets USING GIN (languages);

        CREATE TABLE sync_status (
            id INT PRIMARY KEY,
            last_harvest_date TIMESTAMPTZ,
            last_sync_error TEXT,
            last_sync_error_at TIMESTAMPTZ,
            last_rebuild_error TEXT,
            last_rebuild_error_at TIMESTAMPTZ,
            last_full_rebuild_date TIMESTAMPTZ,
            source_cursor TIMESTAMPTZ,
            source_fingerprint TEXT,
            incremental_failures JSONB NOT NULL DEFAULT '{}'::jsonb,
            incremental_harvest BYTEA,
            incremental_started_at TIMESTAMPTZ,
            incremental_position INTEGER NOT NULL DEFAULT 0,
            incremental_affected INTEGER NOT NULL DEFAULT 0,
            CONSTRAINT sync_status_incremental_position_check CHECK (
                incremental_position >= 0
                AND (incremental_harvest IS NOT NULL OR incremental_position = 0)
            ),
            CONSTRAINT sync_status_incremental_affected_check CHECK (
                incremental_affected >= 0
                AND (incremental_harvest IS NOT NULL OR incremental_affected = 0)
            ),
            CONSTRAINT sync_status_incremental_started_at_check CHECK (
                incremental_harvest IS NULL OR incremental_started_at IS NOT NULL
            )
        );
        INSERT INTO sync_status (id, last_harvest_date)
        VALUES (1, '1900-01-01');

        CREATE TABLE ingestion_failures (
            source TEXT NOT NULL,
            uuid TEXT NOT NULL,
            message TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (source, uuid)
        );

        CREATE TABLE users (
            id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            email TEXT NOT NULL,
            display_name TEXT,
            affiliation TEXT,
            country TEXT,
            password_hash TEXT,
            auth_revision BIGINT NOT NULL DEFAULT 0,
            totp_secret TEXT,
            last_totp_step BIGINT,
            email_verified BOOLEAN NOT NULL DEFAULT false,
            email_verification_token_hash TEXT,
            email_verification_created_at TIMESTAMPTZ,
            pending_totp_secret TEXT,
            pending_totp_created_at TIMESTAMPTZ,
            pending_email TEXT,
            pending_email_token_hash TEXT,
            pending_email_created_at TIMESTAMPTZ,
            password_reset_token_hash TEXT,
            password_reset_created_at TIMESTAMPTZ,
            auth_method TEXT NOT NULL DEFAULT 'local',
            -- Federated identity; all five columns are NULL on local rows.
            -- The identity KEY for a Shibboleth account is the pair
            -- (shibboleth_issuer, shibboleth_subject_id), enforced by
            -- users_shibboleth_identity_key. A subject (REMOTE_USER /
            -- eduPersonPrincipalName) only identifies someone relative to the
            -- IdP that asserted it, so it is never matched on its own. Email is
            -- a mutable attribute for these rows — addresses change and get
            -- recycled, so keying on mail would hand a departed user's account
            -- (tier included) to whoever inherits the address.
            shibboleth_issuer TEXT,
            shibboleth_subject_id TEXT,
            -- 'pending' | 'approved' | 'disabled'; the allowed combinations with
            -- is_active, access_tier and is_admin live in users_federated_state_check.
            federated_status TEXT,
            federated_approved_at TIMESTAMPTZ,
            federated_approved_by INTEGER,
            access_tier TEXT NOT NULL DEFAULT 'public',
            is_admin BOOLEAN NOT NULL DEFAULT false,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMPTZ,
            failed_login_count INTEGER NOT NULL DEFAULT 0,
            locked_until TIMESTAMPTZ,
            lockout_notice_enqueued_at TIMESTAMPTZ,
            totp_recovery_code_generation BIGINT NOT NULL DEFAULT 0,
            pending_totp_recovery_code_generation BIGINT,
            totp_recovery_required BOOLEAN NOT NULL DEFAULT false,
            totp_recovery_expires_at TIMESTAMPTZ,
            totp_recovery_authorized_at TIMESTAMPTZ,
            totp_recovery_auth_revision BIGINT,
            CONSTRAINT users_local_password_required
                CHECK (auth_method <> 'local' OR password_hash IS NOT NULL),
            CONSTRAINT users_lockout_notice_state_check
                CHECK (
                    failed_login_count > 0
                    OR lockout_notice_enqueued_at IS NULL
                ),
            CONSTRAINT users_access_tier_check
                CHECK (access_tier IN ('public', 'registered', 'vetted')),
            CONSTRAINT users_auth_method_check
                CHECK (auth_method IN ('local', 'shibboleth')),
            CONSTRAINT users_totp_recovery_code_generation_check CHECK (
                totp_recovery_code_generation >= 0
                AND (
                    pending_totp_recovery_code_generation IS NULL
                    OR pending_totp_recovery_code_generation
                        > totp_recovery_code_generation
                )
            ),
            -- Valid recovery states are:
            --   * normal or restricted enrollment with no live authorization;
            --   * administrator-authorized recovery with a complete,
            --     revision-bound expiry window. Recovery codes live in the
            --     generation table and are never exposed to the administrator.
            CONSTRAINT users_totp_recovery_state_check CHECK (
                (
                    totp_recovery_expires_at IS NULL
                    AND totp_recovery_authorized_at IS NULL
                    AND totp_recovery_auth_revision IS NULL
                    AND (
                        NOT totp_recovery_required
                        OR (
                            auth_method = 'local'
                            AND totp_secret IS NULL
                            AND last_totp_step IS NULL
                        )
                    )
                )
                OR
                (
                    auth_method = 'local'
                    AND totp_recovery_required
                    AND totp_secret IS NULL
                    AND last_totp_step IS NULL
                    AND totp_recovery_expires_at IS NOT NULL
                    AND totp_recovery_authorized_at IS NOT NULL
                    AND totp_recovery_auth_revision IS NOT NULL
                    AND totp_recovery_authorized_at < totp_recovery_expires_at
                )
            ),
            CONSTRAINT users_shibboleth_identity_key
                UNIQUE (shibboleth_issuer, shibboleth_subject_id),
            CONSTRAINT users_federated_state_check CHECK (
                (
                    auth_method = 'local'
                    AND shibboleth_issuer IS NULL
                    AND shibboleth_subject_id IS NULL
                    AND federated_status IS NULL
                    AND federated_approved_at IS NULL
                    AND federated_approved_by IS NULL
                )
                OR
                (
                    auth_method = 'shibboleth'
                    AND shibboleth_issuer IS NOT NULL
                    AND shibboleth_issuer <> ''
                    AND shibboleth_issuer = BTRIM(shibboleth_issuer)
                    AND shibboleth_subject_id IS NOT NULL
                    AND shibboleth_subject_id <> ''
                    AND shibboleth_subject_id = BTRIM(shibboleth_subject_id)
                    AND federated_status IS NOT NULL
                    AND NOT email_verified
                    AND (
                        (
                            federated_status = 'pending'
                            AND NOT is_active
                            AND access_tier = 'public'
                            AND NOT is_admin
                            AND federated_approved_at IS NULL
                            AND federated_approved_by IS NULL
                        )
                        OR
                        (
                            federated_status = 'approved'
                            AND is_active
                            AND federated_approved_at IS NOT NULL
                            AND federated_approved_by IS NOT NULL
                        )
                        OR
                        (
                            federated_status = 'disabled'
                            AND NOT is_active
                            AND federated_approved_at IS NOT NULL
                            AND federated_approved_by IS NOT NULL
                        )
                        OR
                        (
                            federated_status = 'legacy_quarantined'
                            AND NOT is_active
                            AND access_tier = 'public'
                            AND NOT is_admin
                            AND federated_approved_at IS NULL
                            AND federated_approved_by IS NULL
                        )
                    )
                )
            )
        );

        CREATE UNIQUE INDEX idx_users_email_lower
            ON users(LOWER(email));

        CREATE TABLE totp_recovery_codes (
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            generation BIGINT NOT NULL,
            position SMALLINT NOT NULL,
            code_hash TEXT NOT NULL,
            password_attempt_count SMALLINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            used_at TIMESTAMPTZ,
            CONSTRAINT totp_recovery_codes_pkey
                PRIMARY KEY (user_id, generation, position),
            CONSTRAINT totp_recovery_codes_user_generation_hash_key
                UNIQUE (user_id, generation, code_hash),
            CONSTRAINT totp_recovery_codes_generation_check
                CHECK (generation > 0),
            CONSTRAINT totp_recovery_codes_position_check
                CHECK (position BETWEEN 1 AND 10),
            CONSTRAINT totp_recovery_codes_password_attempt_count_check
                CHECK (password_attempt_count BETWEEN 0 AND 3)
        );

        CREATE TABLE admin_promotion_requests (
            user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            requested_by INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            expires_at TIMESTAMPTZ NOT NULL,
            expected_auth_revision BIGINT NOT NULL,
            prepared_at TIMESTAMPTZ,
            prepared_session_id TEXT,
            CONSTRAINT admin_promotion_requests_different_users_check
                CHECK (user_id <> requested_by),
            CONSTRAINT admin_promotion_requests_expiry_check
                CHECK (expires_at > requested_at),
            CONSTRAINT admin_promotion_requests_prepared_state_check CHECK (
                (prepared_at IS NULL AND prepared_session_id IS NULL)
                OR (
                    prepared_at IS NOT NULL
                    AND prepared_session_id IS NOT NULL
                    AND prepared_at >= requested_at
                    AND prepared_at < expires_at
                )
            )
        );

        CREATE INDEX idx_admin_promotion_requests_expires_at
            ON admin_promotion_requests(expires_at);

        -- Singleton (id = 1) holding the fingerprint of the active federation
        -- policy. Starts empty; the application writes the row.
        CREATE TABLE federation_policy_state (
            id INTEGER PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            CONSTRAINT federation_policy_state_singleton_check CHECK (id = 1)
        );

        CREATE TABLE email_outbox (
            id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            user_id INT REFERENCES users(id) ON DELETE CASCADE,
            message_type TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_ciphertext TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            attempt_count INT NOT NULL DEFAULT 0,
            next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            locked_at TIMESTAMPTZ,
            lock_token UUID,
            last_error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            sent_at TIMESTAMPTZ,
            failed_at TIMESTAMPTZ,
            terminal_outcome TEXT,
            action_token_hash TEXT,
            expires_at TIMESTAMPTZ,
            CONSTRAINT email_outbox_status_check
                CHECK (status IN ('pending', 'sending', 'sent', 'dead')),
            CONSTRAINT email_outbox_attempt_count_check
                CHECK (attempt_count >= 0),
            CONSTRAINT email_outbox_lock_state_check
                CHECK (
                    (status = 'sending') =
                    (locked_at IS NOT NULL AND lock_token IS NOT NULL)
                ),
            CONSTRAINT email_outbox_sent_state_check
                CHECK (
                    (status = 'sent') =
                    (sent_at IS NOT NULL)
                ),
            CONSTRAINT email_outbox_failed_state_check
                CHECK (
                    (status = 'dead') =
                    (failed_at IS NOT NULL)
                ),
            CONSTRAINT email_outbox_terminal_outcome_check
                CHECK (
                    (status = 'dead') = (terminal_outcome IS NOT NULL)
                    AND (
                        terminal_outcome IS NULL
                        OR terminal_outcome IN (
                            'cancelled', 'delivery_failed', 'body_unreadable'
                        )
                    )
                ),
            CONSTRAINT email_outbox_action_metadata_check
                CHECK (
                    (
                        message_type IN (
                            'password_reset',
                            'email_verification',
                            'email_change_verification'
                        )
                        AND user_id IS NOT NULL
                        AND action_token_hash IS NOT NULL
                        AND expires_at IS NOT NULL
                    )
                    OR
                    (
                        message_type IN (
                            'duplicate_registration_notice',
                            'email_change_notice',
                            'account_credential_fault_notice',
                            'account_locked_notice'
                        )
                        AND action_token_hash IS NULL
                        AND expires_at IS NULL
                    )
                )
        );

        CREATE INDEX idx_email_outbox_deliverable
            ON email_outbox (next_attempt_at, id)
            WHERE status = 'pending';

        CREATE INDEX idx_email_outbox_stale_claims
            ON email_outbox (locked_at, id)
            WHERE status = 'sending';

        CREATE INDEX idx_email_outbox_sent_retention
            ON email_outbox (sent_at, id)
            WHERE status = 'sent';

        CREATE INDEX idx_email_outbox_dead_retention
            ON email_outbox (failed_at, id)
            WHERE status = 'dead';

        CREATE INDEX idx_email_outbox_user_message
            ON email_outbox (user_id, message_type);

        CREATE INDEX idx_email_outbox_pending_age
            ON email_outbox (created_at, id)
            WHERE status = 'pending';

        CREATE INDEX idx_email_outbox_recent_failures
            ON email_outbox (failed_at, id)
            WHERE status = 'dead'
              AND terminal_outcome IN ('delivery_failed', 'body_unreadable');

        CREATE INDEX idx_users_unverified_retention
            ON users (created_at, id)
            WHERE auth_method = 'local' AND NOT email_verified AND NOT is_admin;

        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            purpose VARCHAR(20) NOT NULL,
            flash_message TEXT,
            flash_category VARCHAR(20),
            step_up_attempt_count SMALLINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMPTZ NOT NULL,
            ip_address TEXT,
            CONSTRAINT sessions_id_user_id_key
                UNIQUE (id, user_id),
            CONSTRAINT sessions_purpose_check
                CHECK (purpose IN ('full', 'totp_setup', 'totp_recovery')),
            CONSTRAINT sessions_flash_category_check
                CHECK (flash_category IN ('success', 'error', 'info')),
            CONSTRAINT sessions_step_up_attempt_count_check
                CHECK (step_up_attempt_count >= 0)
        );

        CREATE INDEX idx_sessions_expires_at
            ON sessions(expires_at);
        CREATE INDEX idx_sessions_user_id
            ON sessions(user_id);

        -- A replacement authenticator is staged only after fresh password and
        -- current-TOTP proof. The composite foreign key prevents a challenge
        -- from being associated with a session owned by another user, and
        -- deleting that exact session automatically destroys the challenge.
        CREATE TABLE pending_totp_rotations (
            user_id INT PRIMARY KEY,
            session_id TEXT NOT NULL,
            auth_revision BIGINT NOT NULL,
            encrypted_secret TEXT NOT NULL,
            confirmation_attempt_count SMALLINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            expires_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT pending_totp_rotations_user_id_fkey
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT pending_totp_rotations_session_user_fkey
                FOREIGN KEY (session_id, user_id)
                REFERENCES sessions(id, user_id)
                ON DELETE CASCADE,
            CONSTRAINT pending_totp_rotations_auth_revision_check
                CHECK (auth_revision >= 0),
            CONSTRAINT pending_totp_rotations_encrypted_secret_check
                CHECK (encrypted_secret <> ''),
            CONSTRAINT pending_totp_rotations_confirmation_attempt_count_check
                CHECK (confirmation_attempt_count >= 0),
            CONSTRAINT pending_totp_rotations_expiry_check
                CHECK (expires_at > created_at)
        );

        CREATE INDEX idx_pending_totp_rotations_session_user
            ON pending_totp_rotations(session_id, user_id);
    """)


def downgrade() -> None:
    """Drop all application tables/data, the search function, and pg_trgm.

    Alembic's version table remains. External dependencies can make DROP
    fail; this downgrade also removes a preexisting pg_trgm extension.
    """
    op.execute("""
        DROP TABLE IF EXISTS ingestion_failures;
        DROP TABLE IF EXISTS pending_totp_rotations;
        DROP TABLE IF EXISTS sessions;
        DROP TABLE IF EXISTS email_outbox;
        DROP TABLE IF EXISTS federation_policy_state;
        DROP TABLE IF EXISTS admin_promotion_requests;
        DROP TABLE IF EXISTS totp_recovery_codes;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS sync_status;
        DROP TABLE IF EXISTS oral_history_datasets;
        DROP FUNCTION IF EXISTS update_search_text();
        DROP EXTENSION IF EXISTS pg_trgm;
    """)

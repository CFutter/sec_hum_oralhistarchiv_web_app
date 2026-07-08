"""initial_schema

Revision ID: 4f73ae3ff827
Revises: 
Create Date: 2026-03-31 10:09:04.877827

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '4f73ae3ff827'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None



def upgrade():
    """Create initial schema: datasets, users, sessions, sync status.

    Search architecture:
        Datasets have two trigger-maintained search columns:
          - search_text_public: title + access_level only. Matched on
            every dataset regardless of the searching user's tier.
          - search_text_full:   all searchable fields (description,
            project fields, keywords, authors). Matched ONLY against
            datasets the user's visibility tier permits.
        This keeps every dataset browsable (title + access level) while
        preventing low-tier users from probing redacted metadata via
        free-text search (see search_datasets). A pg_trgm GIN index on
        each column makes ILIKE substring search index-backed. The
        trigger fires on every INSERT/UPDATE, so sync.py and schema.py
        don't need to know about it.

    Tables:
        oral_history_datasets — interview metadata from OAI-PMH sources
        sync_status           — harvest timestamps and error tracking
        users                 — local and Shibboleth accounts
        sessions              — server-side session storage
    """
    op.execute("""
        CREATE EXTENSION IF NOT EXISTS pg_trgm;

        CREATE TABLE IF NOT EXISTS oral_history_datasets (
            id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            uuid TEXT UNIQUE,
            doi TEXT UNIQUE,
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
            last_modified TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            search_text_public TEXT,
            search_text_full   TEXT,
            CONSTRAINT datasets_visibility_tier_check CHECK (visibility_tier IN ('public', 'registered', 'vetted'))
        );

        CREATE INDEX IF NOT EXISTS idx_datasets_source
            ON oral_history_datasets(source);

        -- Trigger: concatenates all searchable fields into search_text
        -- on every insert/update. sync.py doesn't need to know about it.
        CREATE OR REPLACE FUNCTION update_search_text() RETURNS trigger AS $$
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

        CREATE TABLE IF NOT EXISTS sync_status (
            id INT PRIMARY KEY,
            last_harvest_date TIMESTAMPTZ,
            last_sync_error TEXT,
            last_sync_error_at TIMESTAMPTZ,
            last_full_rebuild_date TIMESTAMPTZ
        );
        INSERT INTO sync_status (id, last_harvest_date)
        VALUES (1, '1900-01-01') ON CONFLICT DO NOTHING;

        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            email TEXT NOT NULL,
            display_name TEXT,
            affiliation TEXT,
            country TEXT,
            password_hash TEXT,
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
            access_tier TEXT NOT NULL DEFAULT 'public',
            is_admin BOOLEAN NOT NULL DEFAULT false,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMPTZ,
            failed_login_count INTEGER NOT NULL DEFAULT 0,
            locked_until TIMESTAMPTZ,
            CONSTRAINT users_local_password_required CHECK (auth_method <> 'local' OR password_hash IS NOT NULL),
            CONSTRAINT users_access_tier_check CHECK (access_tier IN ('public', 'registered', 'vetted')),
            CONSTRAINT users_auth_method_check CHECK (auth_method IN ('local', 'shibboleth'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            purpose VARCHAR(20) NOT NULL,
            flash_message TEXT,
            flash_category VARCHAR(20),
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMPTZ NOT NULL,
            ip_address TEXT,
            CONSTRAINT sessions_purpose_check CHECK (purpose IN ('full', 'totp_setup')),
            CONSTRAINT sessions_flash_category_check CHECK (flash_category IN ('success', 'error', 'info'))
        );
        
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
            ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id
            ON sessions(user_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower
            ON users(LOWER(email));
    """)

def downgrade():
    """Drop the initial schema: trigger, function, sessions, users, 
    sync_status, datasets, and the pg_trgm extension."""
    op.execute("""
        DROP TRIGGER IF EXISTS trg_search_text ON oral_history_datasets;
        DROP FUNCTION IF EXISTS update_search_text();
        DROP TABLE IF EXISTS sessions;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS sync_status;
        DROP TABLE IF EXISTS oral_history_datasets;
        DROP EXTENSION IF EXISTS pg_trgm;
    """)
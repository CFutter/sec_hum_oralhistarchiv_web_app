-- Run with psql against oralhistarchiv after migrations, as an administrator
-- authorized to change all affected grants/default privileges. This transaction
-- revokes PUBLIC/runtime/backup table, sequence, and column access, then installs
-- the explicit matrix below; owner-created future objects grant backup SELECT.
-- It does not repair role attributes/memberships; run bootstrap separately.
-- Validate both runtime identities afterward; errors roll back this transaction.
\set ON_ERROR_STOP on

BEGIN;

REVOKE ALL ON DATABASE oralhistarchiv FROM PUBLIC;
REVOKE ALL ON DATABASE oralhistarchiv
    FROM oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup;
GRANT CONNECT ON DATABASE oralhistarchiv
    TO oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup;
REVOKE CREATE, TEMP ON DATABASE oralhistarchiv
    FROM oralhistarchiv_web, oralhistarchiv_scheduler;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public
    FROM oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup;
GRANT USAGE ON SCHEMA public
    TO oralhistarchiv_web, oralhistarchiv_scheduler;
GRANT USAGE ON SCHEMA public TO oralhistarchiv_backup;

REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM PUBLIC, oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
    FROM PUBLIC, oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup;

-- Table-level REVOKE does not erase grants made on individual columns. Remove
-- every legacy column grant before rebuilding the reviewed matrix below.
DO $column_revoke$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT namespace.nspname AS schema_name,
               relation.relname AS relation_name,
               relation.relkind AS relation_kind,
               attribute.attname AS column_name
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        JOIN pg_attribute AS attribute
          ON attribute.attrelid = relation.oid
        WHERE namespace.nspname = 'public'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
        ORDER BY relation.relname, attribute.attnum
    LOOP
        IF target.relation_kind = 'm' THEN
            -- Materialized views accept SELECT, but not the DML/REFERENCES
            -- privilege forms accepted by tables and ordinary views.
            EXECUTE format(
                'REVOKE SELECT (%I) ON TABLE %I.%I FROM PUBLIC, oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup',
                target.column_name,
                target.schema_name,
                target.relation_name
            );
        ELSE
            EXECUTE format(
                'REVOKE SELECT (%I), INSERT (%I), UPDATE (%I), REFERENCES (%I) ON TABLE %I.%I FROM PUBLIC, oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup',
                target.column_name,
                target.column_name,
                target.column_name,
                target.column_name,
                target.schema_name,
                target.relation_name
            );
        END IF;
    END LOOP;
END
$column_revoke$;

-- Trigger execution does not require the statement user to hold EXECUTE on
-- the trigger function. Runtime roles therefore need no direct function
-- execution privilege. Revoke the one application-owned function created by
-- the current migrations without touching pg_trgm's extension-owned API.
REVOKE EXECUTE ON FUNCTION public.update_search_text()
    FROM PUBLIC, oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup;

-- PostgreSQL grants PUBLIC EXECUTE on new functions by default. Remove that
-- default for future functions created by the migration owner; any future
-- callable function must receive an explicit, reviewed GRANT and be added to
-- the runtime-role contract before a service will start.
ALTER DEFAULT PRIVILEGES FOR ROLE oralhistarchiv IN SCHEMA public
    REVOKE EXECUTE ON FUNCTIONS
    FROM PUBLIC, oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup;

-- Restore read-only backup access after the revokes; bootstrap supplies BYPASSRLS.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO oralhistarchiv_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO oralhistarchiv_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE oralhistarchiv IN SCHEMA public
    GRANT SELECT ON TABLES TO oralhistarchiv_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE oralhistarchiv IN SCHEMA public
    GRANT SELECT ON SEQUENCES TO oralhistarchiv_backup;
GRANT SELECT ON TABLE alembic_version, oral_history_datasets, sync_status
    TO oralhistarchiv_web;
GRANT SELECT, INSERT, UPDATE ON TABLE users
    TO oralhistarchiv_web;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE sessions
    TO oralhistarchiv_web;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE totp_recovery_codes
    TO oralhistarchiv_web;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE totp_recovery_codes
    TO oralhistarchiv_web;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE pending_totp_rotations
    TO oralhistarchiv_web;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE admin_promotion_requests
    TO oralhistarchiv_web;
GRANT SELECT, INSERT, UPDATE ON TABLE federation_policy_state
    TO oralhistarchiv_web;
GRANT SELECT, INSERT, UPDATE ON TABLE email_outbox
    TO oralhistarchiv_web;
GRANT USAGE ON SEQUENCE users_id_seq, email_outbox_id_seq
    TO oralhistarchiv_web;

GRANT SELECT ON TABLE alembic_version
    TO oralhistarchiv_scheduler;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE oral_history_datasets
    TO oralhistarchiv_scheduler;
GRANT SELECT, UPDATE ON TABLE sync_status
    TO oralhistarchiv_scheduler;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ingestion_failures
    TO oralhistarchiv_scheduler;
GRANT SELECT, DELETE ON TABLE users
    TO oralhistarchiv_scheduler;
GRANT UPDATE (last_login) ON TABLE users
    TO oralhistarchiv_scheduler;
GRANT SELECT, UPDATE, DELETE ON TABLE email_outbox
    TO oralhistarchiv_scheduler;
GRANT SELECT, DELETE ON TABLE sessions
    TO oralhistarchiv_scheduler;
-- SELECT ... FOR UPDATE SKIP LOCKED in expired-session cleanup needs one
-- UPDATE-capable column. The scheduler never mutates this display-only field.
GRANT UPDATE (flash_category) ON TABLE sessions
    TO oralhistarchiv_scheduler;
GRANT USAGE ON SEQUENCE oral_history_datasets_id_seq
    TO oralhistarchiv_scheduler;

COMMIT;

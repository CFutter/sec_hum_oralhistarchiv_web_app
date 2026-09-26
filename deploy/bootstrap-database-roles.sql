-- Run with psql as a PostgreSQL administrator able to create roles/databases.
-- Create missing owner/web/scheduler/backup roles and database, then reset role
-- attributes/passwords, revoke their memberships, and set database/schema owner.
-- Existing object ownership is not repaired. No transaction wraps the script;
-- errors stop psql but earlier changes remain. Configure peer authentication and
-- run migrations plus database-runtime-grants.sql before starting services.
\set ON_ERROR_STOP on

SELECT 'CREATE ROLE oralhistarchiv LOGIN'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'oralhistarchiv'
) \gexec

SELECT 'CREATE DATABASE oralhistarchiv OWNER oralhistarchiv'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = 'oralhistarchiv'
) \gexec

SELECT 'CREATE ROLE oralhistarchiv_web LOGIN'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'oralhistarchiv_web'
) \gexec

SELECT 'CREATE ROLE oralhistarchiv_scheduler LOGIN'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'oralhistarchiv_scheduler'
) \gexec

SELECT 'CREATE ROLE oralhistarchiv_backup LOGIN'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'oralhistarchiv_backup'
) \gexec

ALTER ROLE oralhistarchiv
    LOGIN PASSWORD NULL NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS;
ALTER ROLE oralhistarchiv_web
    LOGIN PASSWORD NULL NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE oralhistarchiv_scheduler
    LOGIN PASSWORD NULL NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE oralhistarchiv_backup
    LOGIN PASSWORD NULL NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION BYPASSRLS CONNECTION LIMIT 1;

ALTER ROLE oralhistarchiv_web IN DATABASE oralhistarchiv
    SET search_path = pg_catalog, public;
ALTER ROLE oralhistarchiv_scheduler IN DATABASE oralhistarchiv
    SET search_path = pg_catalog, public;

DO $block$
DECLARE
    role_membership record;
BEGIN
    FOR role_membership IN
        SELECT child.rolname AS child_name,
               parent.rolname AS parent_name
        FROM pg_auth_members AS membership_link
        JOIN pg_roles AS child ON child.oid = membership_link.member
        JOIN pg_roles AS parent ON parent.oid = membership_link.roleid
        WHERE child.rolname IN (
            'oralhistarchiv',
            'oralhistarchiv_web',
            'oralhistarchiv_scheduler',
            'oralhistarchiv_backup'
        )
    LOOP
        EXECUTE format(
            'REVOKE %I FROM %I',
            role_membership.parent_name,
            role_membership.child_name
        );
    END LOOP;
END
$block$;

ALTER DATABASE oralhistarchiv OWNER TO oralhistarchiv;
\connect oralhistarchiv
ALTER SCHEMA public OWNER TO oralhistarchiv;
-- Run with psql separately as oralhistarchiv_web and oralhistarchiv_scheduler
-- against the application database after grants. Read-only checks reject extra
-- or missing accessible non-extension public relations/sequences; the scheduler
-- must have session UPDATE only on flash_category. Failure stops psql nonzero.
-- This is not the complete startup role contract: attributes, ownership, function
-- EXECUTE and most exact privilege matrices are checked by database_privileges.py.
\set ON_ERROR_STOP on

DO $access_contract$
DECLARE
    actual_relations text[];
    actual_sequences text[];
    expected_relations text[];
    expected_sequences text[];
BEGIN
    CASE current_user
        WHEN 'oralhistarchiv_web' THEN
            expected_relations := ARRAY[
                'public.admin_promotion_requests',
                'public.alembic_version',
                'public.email_outbox',
                'public.federation_policy_state',
                'public.oral_history_datasets',
                'public.pending_totp_rotations',
                'public.sessions',
                'public.sync_status',
                'public.totp_recovery_codes',
                'public.users'
            ];
            expected_sequences := ARRAY[
                'public.email_outbox_id_seq',
                'public.users_id_seq'
            ];
        WHEN 'oralhistarchiv_scheduler' THEN
            expected_relations := ARRAY[
                'public.alembic_version',
                'public.email_outbox',
                'public.ingestion_failures',
                'public.oral_history_datasets',
                'public.sessions',
                'public.sync_status',
                'public.users'
            ];
            expected_sequences := ARRAY[
                'public.oral_history_datasets_id_seq'
            ];
        ELSE
            RAISE EXCEPTION
                'runtime access verification invoked as unexpected role %',
                current_user;
    END CASE;

    SELECT COALESCE(
               array_agg(format('%I.%I', namespace.nspname, relation.relname)
                         ORDER BY namespace.nspname, relation.relname)
                   FILTER (
                       WHERE relation.relkind <> 'S'
                         AND (
                             has_table_privilege(
                                 current_user,
                                 relation.oid,
                                 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
                             )
                             OR has_any_column_privilege(
                                 current_user,
                                 relation.oid,
                                 'SELECT,INSERT,UPDATE,REFERENCES'
                             )
                         )
                   ),
               ARRAY[]::text[]
           ),
           COALESCE(
               array_agg(format('%I.%I', namespace.nspname, relation.relname)
                         ORDER BY namespace.nspname, relation.relname)
                   FILTER (
                       WHERE relation.relkind = 'S'
                         AND has_sequence_privilege(
                             current_user,
                             relation.oid,
                             'USAGE,SELECT,UPDATE'
                         )
                   ),
               ARRAY[]::text[]
           )
      INTO actual_relations, actual_sequences
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
       AND NOT EXISTS (
           SELECT 1
             FROM pg_depend AS dependency
            WHERE dependency.classid = 'pg_class'::regclass
              AND dependency.objid = relation.oid
              AND dependency.deptype = 'e'
       );

    IF actual_relations IS DISTINCT FROM expected_relations THEN
        RAISE EXCEPTION
            'unexpected relation access for %: actual %, expected %',
            current_user,
            actual_relations,
            expected_relations;
    END IF;
    IF actual_sequences IS DISTINCT FROM expected_sequences THEN
        RAISE EXCEPTION
            'unexpected sequence access for %: actual %, expected %',
            current_user,
            actual_sequences,
            expected_sequences;
    END IF;
END
$access_contract$;

DO $session_cleanup_lock_contract$
DECLARE
    actual_update_columns text[];
BEGIN
    IF current_user = 'oralhistarchiv_scheduler' THEN
        SELECT COALESCE(array_agg(attribute.attname ORDER BY attribute.attname), ARRAY[]::text[])
          INTO actual_update_columns
          FROM pg_attribute AS attribute
         WHERE attribute.attrelid = 'public.sessions'::regclass
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
           AND has_column_privilege(current_user, attribute.attrelid,
                                    attribute.attname, 'UPDATE');

        IF has_table_privilege(current_user, 'public.sessions', 'UPDATE')
           OR actual_update_columns IS DISTINCT FROM ARRAY['flash_category']::text[] THEN
            RAISE EXCEPTION
                'unexpected sessions UPDATE columns for %: actual %, expected {flash_category}',
                current_user, actual_update_columns;
        END IF;
    END IF;
END
$session_cleanup_lock_contract$;

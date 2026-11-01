-- Run with psql separately as oralhistarchiv_web and oralhistarchiv_scheduler
-- against the application database after grants. Read-only checks reject extra
-- or missing accessible non-extension public relations/sequences; the scheduler
-- must have session UPDATE only on flash_category. Failure stops psql nonzero.
-- Direct application-function EXECUTE is checked below. This is not the complete
-- startup contract: attributes, ownership, function sources/configuration and most
-- exact privilege matrices are checked by the Python startup schema/role checks.
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
                'public.anonymous_mail_issuance',
                'public.catalogue_discovery',
                'public.catalogue_search_candidates',
                'public.dataset_admin_catalogue',
                'public.dataset_admin_state',
                'public.email_outbox',
                'public.federation_policy_state',
                'public.ingestion_quarantine',
                'public.oral_history_datasets',
                'public.pending_totp_rotations',
                'public.security_audit_events',
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
                'public.dataset_admin_state',
                'public.email_outbox',
                'public.ingestion_failures',
                'public.ingestion_quarantine',
                'public.oral_history_datasets',
                'public.security_audit_events',
                'public.sessions',
                'public.source_binding_acknowledgements',
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
                                 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'
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

DO $persistent_security_state_access$
DECLARE
    expected record;
    actual_privileges text[];
BEGIN
    FOR expected IN
        SELECT name,
            CASE current_user WHEN 'oralhistarchiv_web' THEN web_privileges
                ELSE scheduler_privileges END AS privileges
        FROM (VALUES
            ('anonymous_mail_issuance', ARRAY['DELETE', 'INSERT', 'SELECT']::text[], ARRAY[]::text[]),
            ('source_security_state', ARRAY[]::text[], ARRAY[]::text[]),
            ('source_binding_acknowledgements', ARRAY[]::text[], ARRAY['SELECT']::text[]),
            ('security_audit_events', ARRAY['INSERT']::text[], ARRAY['INSERT']::text[]),
            ('security_audit_receipts', ARRAY[]::text[], ARRAY[]::text[])
        ) AS contract(name, web_privileges, scheduler_privileges)
    LOOP
        SELECT COALESCE(array_agg(privilege ORDER BY privilege), ARRAY[]::text[])
          INTO actual_privileges
          FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                            'REFERENCES', 'TRIGGER', 'MAINTAIN']) AS item(privilege)
          WHERE has_table_privilege(current_user, 'public.' || expected.name, privilege);
        IF actual_privileges IS DISTINCT FROM expected.privileges THEN
            RAISE EXCEPTION 'unexpected persistent security-state privileges on %', expected.name;
        END IF;
        IF EXISTS (
            SELECT 1 FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS item(privilege)
            WHERE NOT privilege = ANY(expected.privileges)
              AND has_any_column_privilege(current_user, 'public.' || expected.name, privilege)
        ) THEN
            RAISE EXCEPTION 'unexpected persistent security-state column access on %', expected.name;
        END IF;
    END LOOP;
END
$persistent_security_state_access$;

DO $catalogue_function_access_contract$
DECLARE
    actual_functions text[];
    expected_functions text[];
BEGIN
    expected_functions := CASE current_user
        WHEN 'oralhistarchiv_web' THEN ARRAY[
            'public.catalogue_guard_search_policy(p_fingerprint text)',
            'public.catalogue_initialize_search_policy(p_fingerprint text, p_masks jsonb)',
            'public.catalogue_match_ids(p_query jsonb)',
            'public.catalogue_page_ids(p_anchor integer, p_ceiling integer, p_backward boolean, p_limit integer, p_offset integer, p_query jsonb)',
            'public.catalogue_scan_ceiling()',
            'public.catalogue_search_candidates()'
        ]::text[]
        ELSE ARRAY[]::text[]
    END;
    SELECT COALESCE(array_agg(functions.signature ORDER BY functions.signature), ARRAY[]::text[])
      INTO actual_functions
      FROM (
          SELECT format('%I.%I(%s)', namespace.nspname, definition.proname,
                        pg_get_function_identity_arguments(definition.oid)) AS signature
          FROM pg_proc AS definition
          JOIN pg_namespace AS namespace ON namespace.oid = definition.pronamespace
          WHERE namespace.nspname = 'public'
            AND has_function_privilege(current_user, definition.oid, 'EXECUTE')
            AND NOT EXISTS (
                SELECT 1 FROM pg_depend AS dependency
                WHERE dependency.classid = 'pg_proc'::regclass
                  AND dependency.objid = definition.oid
                  AND dependency.deptype = 'e'
            )
      ) AS functions;
    IF actual_functions IS DISTINCT FROM expected_functions THEN
        RAISE EXCEPTION
            'unexpected application-function EXECUTE for %: actual %, expected %',
            current_user, actual_functions, expected_functions;
    END IF;
END
$catalogue_function_access_contract$;

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

DO $scheduler_user_column_contract$
DECLARE
    checked_privilege text;
    actual_columns text[];
    expected_columns text[];
BEGIN
    IF current_user = 'oralhistarchiv_scheduler' THEN
        FOREACH checked_privilege IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
        LOOP
            expected_columns := CASE checked_privilege
                WHEN 'SELECT' THEN ARRAY[
                    'auth_method', 'created_at', 'email', 'email_verification_created_at',
                    'email_verification_token_hash', 'email_verified', 'id', 'is_active',
                    'is_admin', 'password_reset_created_at', 'password_reset_token_hash',
                    'pending_email', 'pending_email_created_at', 'pending_email_token_hash'
                ]::text[]
                WHEN 'UPDATE' THEN ARRAY['last_login']::text[]
                ELSE ARRAY[]::text[]
            END;
            SELECT COALESCE(array_agg(attribute.attname ORDER BY attribute.attname), ARRAY[]::text[])
              INTO actual_columns
              FROM pg_attribute AS attribute
             WHERE attribute.attrelid = 'public.users'::regclass
               AND attribute.attnum > 0
               AND NOT attribute.attisdropped
               AND has_column_privilege(current_user, attribute.attrelid,
                                        attribute.attname, checked_privilege);
            IF has_table_privilege(current_user, 'public.users', checked_privilege)
               OR actual_columns IS DISTINCT FROM expected_columns THEN
                RAISE EXCEPTION 'unexpected users % columns for %: actual %, expected %',
                    checked_privilege, current_user, actual_columns, expected_columns;
            END IF;
        END LOOP;
    END IF;
END
$scheduler_user_column_contract$;

-- Exact RLS and owner-projection contracts complement the privilege inventory.
-- PUBLIC policy targets are intentional: exact current_user predicates allow
-- a fresh development migration before deployment roles exist.
DO $catalogue_rls_contract$
DECLARE
    expected record;
    actual record;
    actual_names text[];
    actual_columns text[];
    managed_tables text[] := ARRAY['anonymous_mail_issuance', 'admin_promotion_requests', 'dataset_admin_state', 'email_outbox', 'federation_policy_state', 'ingestion_failures', 'ingestion_quarantine', 'oral_history_datasets', 'pending_totp_rotations', 'sessions', 'source_security_state', 'source_binding_acknowledgements', 'security_audit_events', 'security_audit_receipts', 'sync_status', 'totp_recovery_codes', 'users'];
BEGIN
    IF EXISTS (
        SELECT 1 FROM unnest(managed_tables) AS managed(name)
        LEFT JOIN pg_class AS relation ON relation.oid = to_regclass('public.' || managed.name)
        WHERE relation.oid IS NULL
           OR relation.relrowsecurity IS DISTINCT FROM (managed.name = 'oral_history_datasets')
           OR relation.relforcerowsecurity
    ) THEN
        RAISE EXCEPTION 'unexpected catalogue row-security flags';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_policy AS policy
        WHERE policy.polrelid = ANY (
            SELECT to_regclass('public.' || managed.name)
            FROM unnest(managed_tables) AS managed(name)
            WHERE managed.name <> 'oral_history_datasets'
        )
    ) THEN
        RAISE EXCEPTION 'unexpected policies on another managed table';
    END IF;
    SELECT array_agg(polname::text ORDER BY polname)
      INTO actual_names FROM pg_policy
      WHERE polrelid = 'public.oral_history_datasets'::regclass;
    IF actual_names IS DISTINCT FROM ARRAY['catalogue_scheduler_all', 'catalogue_web_select'] THEN
        RAISE EXCEPTION 'unexpected catalogue policy inventory: %', actual_names;
    END IF;
    FOR expected IN
        SELECT * FROM (VALUES
            ('catalogue_scheduler_all', '*', '(CURRENT_USER = ''oralhistarchiv_scheduler''::name)', '(CURRENT_USER = ''oralhistarchiv_scheduler''::name)'),
            ('catalogue_web_select', 'r', '((CURRENT_USER = ''oralhistarchiv_web''::name) AND (
CASE visibility_tier
    WHEN ''public''::text THEN 0
    WHEN ''registered''::text THEN 1
    WHEN ''vetted''::text THEN 2
    ELSE 99
END <=
CASE current_setting(''app.viewer_tier''::text, true)
    WHEN ''registered''::text THEN 1
    WHEN ''vetted''::text THEN 2
    ELSE 0
END) AND (NOT (EXISTS ( SELECT 1
   FROM dataset_admin_state admin_state
  WHERE ((admin_state.source = oral_history_datasets.source) AND (admin_state.uuid = oral_history_datasets.uuid) AND ((admin_state.hidden_at IS NOT NULL) OR ((admin_state.visibility_tier IS NOT NULL) AND (
        CASE admin_state.visibility_tier
            WHEN ''public''::text THEN 0
            WHEN ''registered''::text THEN 1
            WHEN ''vetted''::text THEN 2
            ELSE 99
        END >
        CASE current_setting(''app.viewer_tier''::text, true)
            WHEN ''registered''::text THEN 1
            WHEN ''vetted''::text THEN 2
            ELSE 0
        END))))))) AND (NOT (EXISTS ( SELECT 1
   FROM ingestion_quarantine quarantine
  WHERE ((quarantine.source = oral_history_datasets.source) AND (quarantine.uuid = oral_history_datasets.uuid))))))', NULL::text)
        ) AS contract(policy_name, command, using_expression, check_expression)
    LOOP
        SELECT polcmd::text AS command, polpermissive AS permissive, polroles AS roles,
               pg_get_expr(polqual, polrelid, false) AS using_expression,
               pg_get_expr(polwithcheck, polrelid, false) AS check_expression
          INTO actual FROM pg_policy
          WHERE polrelid = 'public.oral_history_datasets'::regclass
            AND polname = expected.policy_name;
        IF actual.command IS DISTINCT FROM expected.command
           OR actual.permissive IS DISTINCT FROM true
           OR actual.roles IS DISTINCT FROM ARRAY[0]::oid[]
           OR actual.using_expression IS DISTINCT FROM expected.using_expression
           OR actual.check_expression IS DISTINCT FROM expected.check_expression THEN
            RAISE EXCEPTION 'unexpected catalogue policy definition: %', expected.policy_name;
        END IF;
    END LOOP;
    FOR expected IN
        SELECT * FROM (VALUES
            ('catalogue_discovery', ARRAY['id:integer', 'uuid:text', 'title:text', 'access_level:text', 'version:text', 'source:text', 'visibility_tier:text']::text[], ' SELECT stored.id,
    stored.uuid,
    stored.title,
    stored.access_level,
    stored.version,
    stored.source,
        CASE
            WHEN ((admin_state.visibility_tier IS NULL) OR (
            CASE stored.visibility_tier
                WHEN ''public''::text THEN 0
                WHEN ''registered''::text THEN 1
                WHEN ''vetted''::text THEN 2
                ELSE 99
            END >=
            CASE admin_state.visibility_tier
                WHEN ''public''::text THEN 0
                WHEN ''registered''::text THEN 1
                WHEN ''vetted''::text THEN 2
                ELSE 99
            END)) THEN stored.visibility_tier
            ELSE admin_state.visibility_tier
        END AS visibility_tier
   FROM (oral_history_datasets stored
     LEFT JOIN dataset_admin_state admin_state ON (((admin_state.source = stored.source) AND (admin_state.uuid = stored.uuid))))
  WHERE ((admin_state.hidden_at IS NULL) AND (NOT (EXISTS ( SELECT 1
           FROM ingestion_quarantine quarantine
          WHERE ((quarantine.source = stored.source) AND (quarantine.uuid = stored.uuid))))));'),
            ('dataset_admin_catalogue', ARRAY['id:integer', 'source:text', 'uuid:text', 'stored_tier:text', 'record_tier:text']::text[], ' SELECT stored.id,
    stored.source,
    stored.uuid,
    stored.visibility_tier AS stored_tier,
        CASE (stored.data -> ''visibility_tier''::text)
            WHEN ''"public"''::jsonb THEN ''public''::text
            WHEN ''"registered"''::jsonb THEN ''registered''::text
            WHEN ''"vetted"''::jsonb THEN ''vetted''::text
            ELSE NULL::text
        END AS record_tier
   FROM (oral_history_datasets stored
     LEFT JOIN dataset_admin_state admin_state ON (((admin_state.source = stored.source) AND (admin_state.uuid = stored.uuid))));'),
            ('catalogue_search_candidates', ARRAY['id:integer']::text[], ' SELECT catalogue_search_candidates() AS id;')
        ) AS contract(view_name, column_spec, definition)
    LOOP
        SELECT relation.relkind, relation.relowner,
               ARRAY(SELECT option FROM unnest(relation.reloptions) AS option ORDER BY option) AS options,
               pg_get_viewdef(relation.oid, false) AS definition
          INTO actual FROM pg_class AS relation
          WHERE relation.oid = to_regclass('public.' || expected.view_name);
        SELECT array_agg(attribute.attname || ':' || format_type(attribute.atttypid, attribute.atttypmod)
                         ORDER BY attribute.attnum)
          INTO actual_columns FROM pg_attribute AS attribute
          WHERE attribute.attrelid = to_regclass('public.' || expected.view_name)
            AND attribute.attnum > 0 AND NOT attribute.attisdropped;
        IF actual.relkind IS DISTINCT FROM 'v'::"char"
           OR actual.relowner IS DISTINCT FROM (SELECT relowner FROM pg_class
               WHERE oid = 'public.oral_history_datasets'::regclass)
           OR actual.options IS DISTINCT FROM ARRAY['security_barrier=true', 'security_invoker=false']
           OR actual.definition IS DISTINCT FROM expected.definition
           OR actual_columns IS DISTINCT FROM expected.column_spec
           OR has_any_column_privilege(current_user,
               to_regclass('public.' || expected.view_name), 'INSERT,UPDATE,REFERENCES') THEN
            RAISE EXCEPTION 'unexpected catalogue view contract: %', expected.view_name;
        END IF;
    END LOOP;
END
$catalogue_rls_contract$;

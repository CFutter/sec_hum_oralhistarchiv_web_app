-- Convert the exact accepted K1 search schema to historical K2 as its owner.
-- This does not install the current audience projections or ordering contract.
-- Requires PostgreSQL16 and psql -v expected_database=the_reviewed_database_name.
-- Run with runtimes stopped after a verified backup. One transaction preserves
-- revision/data and refuses existing/partial K2 objects or an altered K1 trigger.
\set ON_ERROR_STOP on
\if :{?expected_database}
\else
DO $required_database$
BEGIN
    RAISE EXCEPTION 'Refused: supply -v expected_database=the_reviewed_database_name';
END
$required_database$;
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30min';
SET LOCAL search_path = pg_catalog, public;
SELECT pg_catalog.set_config('app.k2_expected_database', :'expected_database', true);

DO $k2_preconditions$
DECLARE
    actual_owner name;
    actual_source text;
BEGIN
    IF pg_catalog.current_database() <> pg_catalog.current_setting('app.k2_expected_database') THEN
        RAISE EXCEPTION 'K2 database name differs from the reviewed target';
    END IF;
    IF pg_catalog.current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999 THEN
        RAISE EXCEPTION 'K2 upgrade requires PostgreSQL 16';
    END IF;
    SELECT role.rolname INTO actual_owner
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_roles AS role ON role.oid = relation.relowner
    WHERE relation.oid = pg_catalog.to_regclass('public.oral_history_datasets');
    IF actual_owner IS DISTINCT FROM current_user
       OR current_user IN ('oralhistarchiv_web', 'oralhistarchiv_scheduler', 'oralhistarchiv_backup') THEN
        RAISE EXCEPTION 'K2 upgrade requires the catalogue migration owner';
    END IF;
    LOCK TABLE public.oral_history_datasets IN ACCESS EXCLUSIVE MODE;
    LOCK TABLE public.dataset_admin_state IN SHARE MODE;
    IF (SELECT pg_catalog.count(*) FROM public.alembic_version) <> 1
       OR (SELECT version_num FROM public.alembic_version) IS DISTINCT FROM '4f73ae3ff827' THEN
        RAISE EXCEPTION 'K2 upgrade requires the accepted initial revision';
    END IF;
    IF pg_catalog.to_regclass('public.catalogue_search_candidates') IS NOT NULL
       OR pg_catalog.to_regclass('public.idx_search_vector_public') IS NOT NULL
       OR pg_catalog.to_regclass('public.idx_search_vector_full') IS NOT NULL
       OR EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute
           WHERE attrelid = 'public.oral_history_datasets'::regclass
             AND attname IN ('search_vector_public', 'search_vector_full')
             AND attnum > 0 AND NOT attisdropped
       ) THEN
        RAISE EXCEPTION 'K2 search objects already exist or are partially installed';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class AS relation
        WHERE relation.oid = 'public.oral_history_datasets'::regclass
          AND relation.relrowsecurity AND NOT relation.relforcerowsecurity
    ) OR pg_catalog.to_regclass('public.catalogue_discovery') IS NULL
       OR pg_catalog.to_regclass('public.idx_search_text_public_trgm') IS NULL
       OR pg_catalog.to_regclass('public.idx_search_text_full_trgm') IS NULL THEN
        RAISE EXCEPTION 'K2 requires the accepted catalogue projection, RLS and substring indexes';
    END IF;
    SELECT function.prosrc INTO actual_source
    FROM pg_catalog.pg_proc AS function
    JOIN pg_catalog.pg_language AS language ON language.oid = function.prolang
    WHERE function.oid = 'public.update_search_text()'::regprocedure
      AND language.lanname = 'plpgsql'
      AND function.prorettype = 'pg_catalog.trigger'::regtype
      AND function.provolatile = 'v' AND NOT function.prosecdef
      AND NOT function.proisstrict AND function.proparallel = 'u'
      AND function.proconfig IS NULL;
    IF actual_source IS DISTINCT FROM $k1_source$
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
        $k1_source$ THEN
        RAISE EXCEPTION 'K2 requires the exact accepted K1 search trigger';
    END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger
        WHERE tgrelid = 'public.oral_history_datasets'::regclass AND NOT tgisinternal) <> 1
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_trigger
           WHERE tgrelid = 'public.oral_history_datasets'::regclass
             AND NOT tgisinternal
             AND pg_catalog.pg_get_triggerdef(oid, false) = 'CREATE TRIGGER trg_search_text BEFORE INSERT OR UPDATE ON public.oral_history_datasets FOR EACH ROW EXECUTE FUNCTION update_search_text()'
       ) THEN
        RAISE EXCEPTION 'K2 requires the sole exact accepted dataset search trigger';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger
        WHERE tgrelid = 'public.oral_history_datasets'::regclass
          AND tgname = 'trg_search_text' AND tgenabled = 'O'
          AND NOT tgisinternal AND tgtype = 23
          AND tgfoid = 'public.update_search_text()'::regprocedure
    ) THEN
        RAISE EXCEPTION 'K2 requires the accepted active BEFORE INSERT OR UPDATE trigger';
    END IF;
END
$k2_preconditions$;

-- The preflight holds both reviewed table locks through commit.
ALTER TABLE public.oral_history_datasets
    ADD COLUMN search_vector_public tsvector,
    ADD COLUMN search_vector_full tsvector;
-- BEFORE-row trigger: replace NEW's legacy search text and simple vectors,
-- then return NEW. Public text uses title/access_level; full text adds only
-- description, project_title, project_description, keywords and authors.
-- Body comments are retained as literal schema-source data: their historical
-- "everything" wording does not mean every metadata field is indexed.
CREATE OR REPLACE FUNCTION public.update_search_text() RETURNS trigger AS $$
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
            NEW.search_vector_public :=
                pg_catalog.to_tsvector('pg_catalog.simple'::regconfig, NEW.search_text_public);
            NEW.search_vector_full :=
                pg_catalog.to_tsvector(
                    'pg_catalog.simple'::regconfig,
                    NEW.search_text_public || ' ' ||
                    COALESCE(NEW.description, '') || ' ' ||
                    COALESCE(NEW.project_title, '') || ' ' ||
                    COALESCE(NEW.project_description, '') || ' ' ||
                    COALESCE(array_to_string(NEW.keywords, ' '), '') || ' ' ||
                    COALESCE(array_to_string(NEW.authors, ' '), '')
                );
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

-- The existing BEFORE trigger recomputes both vectors and the unchanged
-- legacy text. No normalized/raw metadata, identity, cursor or fingerprint
-- column is assigned. Migration head and every other table remain unchanged.
UPDATE public.oral_history_datasets
SET search_vector_public = search_vector_public;
ALTER TABLE public.oral_history_datasets
    ALTER COLUMN search_vector_public SET NOT NULL,
    ALTER COLUMN search_vector_full SET NOT NULL;
CREATE INDEX idx_search_vector_public
    ON public.oral_history_datasets USING GIN (search_vector_public);
CREATE INDEX idx_search_vector_full
    ON public.oral_history_datasets USING GIN (search_vector_full);
CREATE VIEW public.catalogue_search_candidates
WITH (security_barrier = true, security_invoker = false)
AS
WITH search_context_v1 AS MATERIALIZED (
    SELECT
        COALESCE(pg_catalog.current_setting('app.search_term'::text, true), ''::text) AS
            term,
        pg_catalog.current_setting('app.search_pattern'::text, true) AS pattern,
        pg_catalog.current_setting('app.search_mode'::text, true) AS mode,
        CASE pg_catalog.current_setting('app.viewer_tier'::text, true)
            WHEN 'registered'::text THEN 1
            WHEN 'vetted'::text THEN 2
            ELSE 0
        END AS viewer_rank,
        EXISTS (
            SELECT 1
            FROM pg_catalog.jsonb_each(
                CASE WHEN pg_catalog.jsonb_typeof(COALESCE(NULLIF(
                    pg_catalog.current_setting('app.search_field_masks'::text, true),
                    ''::text), '{}'::text)::jsonb) = 'object'::text
                    THEN COALESCE(NULLIF(pg_catalog.current_setting(
                        'app.search_field_masks'::text, true), ''::text), '{}'::text)::jsonb
                        ELSE '{}'::jsonb END
            ) AS masks(source, value)
            WHERE pg_catalog.jsonb_typeof(masks.value) = 'number'::text
              AND masks.value::text ~ '^([1-9]|[1-2][0-9]|30)$'::text
        ) AS has_partial,
        COALESCE(NULLIF(pg_catalog.current_setting('app.search_field_masks'::text, true),
            ''::text), '{}'::text)::jsonb AS field_masks,
        CASE WHEN pg_catalog.current_setting('app.search_mode'::text, true) =
            'literal'::text
            THEN NULL::tsquery
            ELSE pg_catalog.websearch_to_tsquery(
                'pg_catalog.simple'::regconfig,
                COALESCE(pg_catalog.current_setting('app.search_term'::text, true),
                    ''::text)
            )
        END AS ts_query
    WHERE COALESCE(pg_catalog.current_setting('app.search_term'::text, true), ''::text) <>
        ''::text
      AND pg_catalog.current_setting('app.search_mode'::text, true)
          IN ('auto'::text, 'web'::text, 'literal'::text)
),
search_rows AS NOT MATERIALIZED (
    SELECT
        stored.id,
        stored.search_vector_public,
        stored.search_vector_full,
        stored.search_text_public,
        stored.search_text_full,
        context.pattern,
        context.mode,
        context.viewer_rank,
        context.has_partial,
        context.ts_query,
        GREATEST(
            CASE stored.visibility_tier
                WHEN 'public'::text THEN 0
                WHEN 'registered'::text THEN 1
                WHEN 'vetted'::text THEN 2
                ELSE 99
            END,
            CASE
                WHEN admin_state.visibility_tier IS NULL
                    OR admin_state.visibility_tier = 'public'::text THEN 0
                WHEN admin_state.visibility_tier = 'registered'::text THEN 1
                WHEN admin_state.visibility_tier = 'vetted'::text THEN 2
                ELSE 99
            END
        ) AS record_rank,
        CASE
            WHEN pg_catalog.jsonb_typeof(COALESCE(context.field_masks -> stored.source,
                context.field_masks -> '*'::text, '0'::jsonb)) = 'number'::text
             AND (COALESCE(context.field_masks -> stored.source, context.field_masks ->
                 '*'::text, '0'::jsonb))::text ~ '^(0|[1-9]|[1-2][0-9]|3[0-1])$'::text
            THEN (COALESCE(context.field_masks -> stored.source, context.field_masks ->
                '*'::text, '0'::jsonb))::integer
            ELSE 0
        END AS field_mask
    FROM public.oral_history_datasets AS stored
    LEFT JOIN public.dataset_admin_state AS admin_state
        ON admin_state.source = stored.source AND admin_state.uuid = stored.uuid
    CROSS JOIN search_context_v1 AS context
    WHERE admin_state.hidden_at IS NULL
)
SELECT search_rows.id
FROM search_rows
WHERE (search_rows.record_rank > search_rows.viewer_rank OR search_rows.field_mask = 0)
  AND (
      (search_rows.mode <> 'literal'::text AND search_rows.search_vector_public @@
          search_rows.ts_query)
      OR (search_rows.mode <> 'web'::text AND search_rows.search_text_public ILIKE
          search_rows.pattern)
  )
UNION ALL
SELECT search_rows.id
FROM search_rows
WHERE search_rows.record_rank <= search_rows.viewer_rank AND search_rows.field_mask = 31
  AND (
      (search_rows.mode <> 'literal'::text AND search_rows.search_vector_full @@
          search_rows.ts_query)
      OR (
          search_rows.mode <> 'web'::text
          AND (search_rows.search_text_public ILIKE search_rows.pattern OR
              search_rows.search_text_full ILIKE search_rows.pattern)
      )
  )
UNION ALL
SELECT search_rows.id
FROM search_rows
WHERE search_rows.has_partial
  AND search_rows.record_rank <= search_rows.viewer_rank AND search_rows.field_mask BETWEEN
      1 AND 30;
REVOKE ALL ON public.catalogue_search_candidates FROM PUBLIC;
ANALYZE public.oral_history_datasets;
ANALYZE public.dataset_admin_state;
COMMIT;

-- Next, separately reapply the matching database-runtime-grants.sql manifest
-- using the deployment's reviewed administrator identity, then run complete
-- schema and both runtime-role preflights before reopening traffic.
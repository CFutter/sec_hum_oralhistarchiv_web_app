# ruff: noqa: E501
"""Audience-isolated search storage and owner-function SQL contracts.

Only maintenance functions read unrestricted documents. Query functions choose
one physical audience relation before applying any user-controlled predicate.
Changing these strings requires a matching database migration.
"""

from .search_mask_contract import SEARCH_MASK_PROTOCOL_TAG
from .source_contract import SOURCE_NAME_SQL_PATTERN

SEARCH_AUDIENCES = ("public", "registered", "vetted")

SEARCH_PROJECTION_TABLE_DDL = """
CREATE TABLE public.catalogue_search_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    masks jsonb NOT NULL
);
""" + "\n".join(
    f"""
CREATE TABLE public.catalogue_search_{audience} (
    id integer PRIMARY KEY REFERENCES public.oral_history_datasets(id) ON DELETE CASCADE,
    upstream_modified_at timestamptz,
    public_document text NOT NULL,
    literal_document text NOT NULL,
    search_vector tsvector NOT NULL,
    keywords text[] NOT NULL,
    languages text[] NOT NULL,
    access_level text
);
CREATE INDEX idx_catalogue_search_{audience}_vector
    ON public.catalogue_search_{audience} USING gin (search_vector);
CREATE INDEX idx_catalogue_search_{audience}_public_trgm
    ON public.catalogue_search_{audience} USING gin (public_document gin_trgm_ops);
CREATE INDEX idx_catalogue_search_{audience}_literal_trgm
    ON public.catalogue_search_{audience} USING gin (literal_document gin_trgm_ops);
CREATE INDEX idx_catalogue_search_{audience}_keywords
    ON public.catalogue_search_{audience} USING gin (keywords);
CREATE INDEX idx_catalogue_search_{audience}_languages
    ON public.catalogue_search_{audience} USING gin (languages);
CREATE INDEX idx_catalogue_search_{audience}_order
    ON public.catalogue_search_{audience} (upstream_modified_at DESC NULLS LAST, id DESC);
"""
    for audience in SEARCH_AUDIENCES
)

SEARCH_WRITE_LOCK_SOURCE = """
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(1330135379);
    RETURN NULL;
END;
"""

SEARCH_REFRESH_RECORD_SOURCE = "".join(
    (
        "\n-- ",
        SEARCH_MASK_PROTOCOL_TAG,
        """
DECLARE
    stored record;
    masks jsonb;
    audience text;
    viewer integer;
    field_mask integer;
    extra_document text;
BEGIN
    SELECT policy.masks INTO masks FROM public.catalogue_search_policy AS policy
        WHERE policy.singleton;
    IF masks IS NULL THEN RETURN; END IF;
    SELECT dataset.*,
        GREATEST(
            CASE dataset.visibility_tier WHEN 'public' THEN 0
                WHEN 'registered' THEN 1 WHEN 'vetted' THEN 2 ELSE 99 END,
            CASE admin.visibility_tier WHEN 'registered' THEN 1 WHEN 'vetted' THEN 2
                WHEN 'public' THEN 0 ELSE CASE WHEN admin.visibility_tier IS NULL
                THEN 0 ELSE 99 END END
        ) AS effective_rank
    INTO stored
    FROM public.oral_history_datasets AS dataset
    LEFT JOIN public.dataset_admin_state AS admin
        ON admin.source = dataset.source AND admin.uuid = dataset.uuid
    WHERE dataset.id = p_id AND admin.hidden_at IS NULL
      AND NOT EXISTS (SELECT 1 FROM public.ingestion_quarantine AS quarantine
          WHERE quarantine.source = dataset.source AND quarantine.uuid = dataset.uuid);
    IF NOT FOUND THEN
        DELETE FROM public.catalogue_search_public WHERE id = p_id;
        DELETE FROM public.catalogue_search_registered WHERE id = p_id;
        DELETE FROM public.catalogue_search_vetted WHERE id = p_id;
        RETURN;
    END IF;
    FOR viewer IN 0..2 LOOP
        audience := (ARRAY['public', 'registered', 'vetted'])[viewer + 1];
        field_mask := CASE WHEN stored.effective_rank <= viewer THEN
            COALESCE(masks -> viewer::text -> stored.source,
                masks -> viewer::text -> '*')::integer ELSE 0 END;
        extra_document :=
            CASE WHEN (field_mask & 1) <> 0 THEN COALESCE(stored.description, '') ELSE '' END || ' ' ||
            CASE WHEN (field_mask & 2) <> 0 THEN COALESCE(stored.project_title, '') ELSE '' END || ' ' ||
            CASE WHEN (field_mask & 4) <> 0 THEN COALESCE(stored.project_description, '') ELSE '' END || ' ' ||
            CASE WHEN (field_mask & 8) <> 0 THEN COALESCE(pg_catalog.array_to_string(stored.keywords, ' '), '') ELSE '' END || ' ' ||
            CASE WHEN (field_mask & 16) <> 0 THEN COALESCE(pg_catalog.array_to_string(stored.authors, ' '), '') ELSE '' END;
        EXECUTE pg_catalog.format(
            'INSERT INTO public.%I AS existing (id, upstream_modified_at, public_document, '
            'literal_document, search_vector, keywords, languages, access_level) '
            'VALUES ($1, $2, $3, $4, pg_catalog.to_tsvector(''pg_catalog.simple''::regconfig, $5), $6, $7, $8) '
            'ON CONFLICT (id) DO UPDATE SET upstream_modified_at = EXCLUDED.upstream_modified_at, '
            'public_document = EXCLUDED.public_document, literal_document = EXCLUDED.literal_document, '
            'search_vector = EXCLUDED.search_vector, keywords = EXCLUDED.keywords, '
            'languages = EXCLUDED.languages, access_level = EXCLUDED.access_level '
            'WHERE (existing.upstream_modified_at, existing.public_document, existing.literal_document, '
            'existing.search_vector, existing.keywords, existing.languages, existing.access_level) '
            'IS DISTINCT FROM (EXCLUDED.upstream_modified_at, EXCLUDED.public_document, '
            'EXCLUDED.literal_document, EXCLUDED.search_vector, EXCLUDED.keywords, '
            'EXCLUDED.languages, EXCLUDED.access_level)',
            'catalogue_search_' || audience)
        USING stored.id, stored.upstream_modified_at,
            COALESCE(stored.title, '') || ' ' || COALESCE(stored.access_level, ''),
            COALESCE(stored.title, '') || ' ' || extra_document,
            COALESCE(stored.title, '') || ' ' || COALESCE(stored.access_level, '') || ' ' || extra_document,
            CASE WHEN (field_mask & 8) <> 0 THEN COALESCE(stored.keywords, ARRAY[]::text[]) ELSE ARRAY[]::text[] END,
            CASE WHEN (field_mask & 32) <> 0 THEN COALESCE(stored.languages, ARRAY[]::text[]) ELSE ARRAY[]::text[] END,
            stored.access_level;
    END LOOP;
END;
""",
    )
)

SEARCH_REFRESH_TRIGGER_SOURCE = """
DECLARE
    affected_id integer;
BEGIN
    IF TG_TABLE_NAME = 'oral_history_datasets' THEN
        IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND OLD.id IS DISTINCT FROM NEW.id) THEN
            PERFORM public.catalogue_refresh_search_record(OLD.id);
        END IF;
        IF TG_OP <> 'DELETE' THEN PERFORM public.catalogue_refresh_search_record(NEW.id); END IF;
    ELSE
        IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND
            (OLD.source, OLD.uuid) IS DISTINCT FROM (NEW.source, NEW.uuid)) THEN
            FOR affected_id IN SELECT id FROM public.oral_history_datasets
                WHERE source = OLD.source AND uuid = OLD.uuid LOOP
                PERFORM public.catalogue_refresh_search_record(affected_id);
            END LOOP;
        END IF;
        IF TG_OP <> 'DELETE' THEN
            FOR affected_id IN SELECT id FROM public.oral_history_datasets
                WHERE source = NEW.source AND uuid = NEW.uuid LOOP
                PERFORM public.catalogue_refresh_search_record(affected_id);
            END LOOP;
        END IF;
    END IF;
    RETURN NULL;
END;
"""

# The substituted lexical pattern is code-owned; all request values remain bound.
SEARCH_REPLACE_POLICY_SOURCE = r"""
DECLARE
    prior record;
    viewer text;
    item record;
    affected_id integer;
BEGIN
    IF p_fingerprint IS NULL OR p_fingerprint !~ '^[0-9a-f]{64}$'
       OR pg_catalog.jsonb_typeof(p_masks) IS DISTINCT FROM 'object'
       OR NOT (p_masks ?& ARRAY['0', '1', '2'])
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_masks) AS entry(name)
           WHERE name <> ALL (ARRAY['0', '1', '2'])) THEN
        RAISE EXCEPTION 'invalid search projection policy' USING ERRCODE = '22023';
    END IF;
    FOREACH viewer IN ARRAY ARRAY['0', '1', '2'] LOOP
        IF pg_catalog.jsonb_typeof(p_masks -> viewer) IS DISTINCT FROM 'object'
           OR NOT ((p_masks -> viewer) ? '*') THEN
            RAISE EXCEPTION 'invalid search projection masks' USING ERRCODE = '22023';
        END IF;
        FOR item IN SELECT * FROM pg_catalog.jsonb_each(p_masks -> viewer) LOOP
            IF (item.key <> '*' AND item.key !~ '__SOURCE_NAME_PATTERN__')
               OR pg_catalog.jsonb_typeof(item.value) <> 'number'
               OR item.value::text !~ '^(0|[1-9]|[1-5][0-9]|6[0-3])$' THEN
                RAISE EXCEPTION 'invalid search projection mask' USING ERRCODE = '22023';
            END IF;
        END LOOP;
    END LOOP;
    PERFORM pg_catalog.pg_advisory_xact_lock(1330135379);
    SELECT * INTO prior FROM public.catalogue_search_policy WHERE singleton FOR UPDATE;
    IF FOUND THEN
        IF p_expected IS NULL AND prior.fingerprint = p_fingerprint AND prior.masks = p_masks THEN
            RETURN;
        END IF;
        IF p_expected IS NULL OR prior.fingerprint <> p_expected THEN
            RAISE EXCEPTION 'search projection policy changed; explicit replacement required'
                USING ERRCODE = '55000';
        END IF;
    ELSIF p_expected IS NOT NULL THEN
        RAISE EXCEPTION 'search projection policy binding is missing' USING ERRCODE = '55000';
    END IF;
    INSERT INTO public.catalogue_search_policy(singleton, fingerprint, masks)
        VALUES (true, p_fingerprint, p_masks)
        ON CONFLICT (singleton) DO UPDATE SET fingerprint = EXCLUDED.fingerprint,
            masks = EXCLUDED.masks;
    DELETE FROM public.catalogue_search_public;
    DELETE FROM public.catalogue_search_registered;
    DELETE FROM public.catalogue_search_vetted;
    FOR affected_id IN SELECT id FROM public.oral_history_datasets LOOP
        PERFORM public.catalogue_refresh_search_record(affected_id);
    END LOOP;
END;
""".replace("__SOURCE_NAME_PATTERN__", SOURCE_NAME_SQL_PATTERN)  # nosec B608

SEARCH_INITIALIZE_POLICY_SOURCE = """
BEGIN
    PERFORM public.catalogue_replace_search_policy(NULL, p_fingerprint, p_masks);
END;
"""

SEARCH_GUARD_POLICY_SOURCE = """
DECLARE
    bound_fingerprint text;
BEGIN
    -- No serving connection waits behind a maintenance rebuild or catalogue write.
    IF NOT pg_catalog.pg_try_advisory_xact_lock_shared(1330135379) THEN
        RAISE EXCEPTION 'catalogue policy is being updated' USING ERRCODE = '55000';
    END IF;
    SELECT fingerprint INTO bound_fingerprint FROM public.catalogue_search_policy WHERE singleton;
    IF bound_fingerprint IS NULL OR p_fingerprint IS NULL OR bound_fingerprint <> p_fingerprint THEN
        RAISE EXCEPTION 'catalogue policy is not current' USING ERRCODE = '55000';
    END IF;
END;
"""

SEARCH_RELATION_SOURCE = """
DECLARE
    audience text := pg_catalog.current_setting('app.viewer_tier', true);
    bound_fingerprint text;
    bound_masks jsonb;
BEGIN
    IF audience IS NULL OR audience NOT IN ('public', 'registered', 'vetted') THEN
        audience := 'public';
    END IF;
    IF pg_catalog.jsonb_typeof(p_query) IS DISTINCT FROM 'object'
       OR NOT (p_query ?& ARRAY['mode', 'term', 'pattern', 'keyword', 'language', 'access_level', 'masks', 'fingerprint'])
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_each(p_query) AS item(name, value)
           WHERE name <> ALL (ARRAY['mode', 'term', 'pattern', 'keyword', 'language', 'access_level', 'masks', 'fingerprint'])
              OR (name <> 'masks' AND pg_catalog.jsonb_typeof(value) <> 'string'))
       OR p_query ->> 'mode' NOT IN ('empty', 'auto', 'web', 'literal')
       OR ((p_query ->> 'mode' = 'empty') <> (p_query ->> 'term' = '')) THEN
        RAISE EXCEPTION 'invalid catalogue page context' USING ERRCODE = '22023';
    END IF;
    SELECT fingerprint, masks -> CASE audience WHEN 'registered' THEN '1'
        WHEN 'vetted' THEN '2' ELSE '0' END INTO bound_fingerprint, bound_masks
    FROM public.catalogue_search_policy WHERE singleton;
    IF bound_fingerprint IS NULL OR bound_fingerprint <> p_query ->> 'fingerprint' THEN
        RAISE EXCEPTION 'search projection policy is not current' USING ERRCODE = '55000';
    END IF;
    IF p_query -> 'masks' IS DISTINCT FROM bound_masks THEN
        RAISE EXCEPTION 'catalogue field masks do not match the bound policy' USING ERRCODE = '22023';
    END IF;
    RETURN 'catalogue_search_' || audience;
END;
"""

# The query-dependent operators below see only pre-redacted columns from the
# selected physical audience table. No raw record/index appears in this query.
SEARCH_MATCH_WHERE = """
    ($1 = '' OR projection.keywords @> ARRAY[$1])
    AND ($2 = '' OR projection.languages @> ARRAY[$2])
    AND ($3 = '' OR projection.access_level = $3)
    AND ($4 = 'empty'
        OR ($4 <> 'literal' AND projection.search_vector @@ $5)
        OR ($4 <> 'web' AND (projection.public_document ILIKE $6
            OR projection.literal_document ILIKE $6)))
"""

# Only a fixed predicate/protocol is composed; values use EXECUTE USING.
SEARCH_MATCH_IDS_SOURCE = (
    "\n-- "
    + SEARCH_MASK_PROTOCOL_TAG
    + """
DECLARE
    relation_name text := public.catalogue_search_relation(p_query);
    query_ts tsquery;
BEGIN
    IF p_query ->> 'mode' IN ('auto', 'web') THEN
        query_ts := pg_catalog.websearch_to_tsquery('pg_catalog.simple'::regconfig, p_query ->> 'term');
    END IF;
    RETURN QUERY EXECUTE pg_catalog.format(
        'SELECT projection.id FROM public.%I AS projection WHERE __MATCH_WHERE__', relation_name)
    USING p_query ->> 'keyword', p_query ->> 'language', p_query ->> 'access_level',
        p_query ->> 'mode', query_ts, p_query ->> 'pattern';
END;
""".replace("__MATCH_WHERE__", SEARCH_MATCH_WHERE.replace("'", "''"))  # nosec B608
)

SEARCH_CANDIDATES_SOURCE = """
BEGIN
    RETURN QUERY SELECT public.catalogue_match_ids(pg_catalog.jsonb_build_object(
        'mode', COALESCE(NULLIF(pg_catalog.current_setting('app.search_mode', true), ''), 'empty'),
        'term', COALESCE(pg_catalog.current_setting('app.search_term', true), ''),
        'pattern', COALESCE(pg_catalog.current_setting('app.search_pattern', true), ''),
        'keyword', '', 'language', '', 'access_level', '',
        'masks', (SELECT masks -> CASE pg_catalog.current_setting('app.viewer_tier', true)
            WHEN 'registered' THEN '1' WHEN 'vetted' THEN '2' ELSE '0' END
            FROM public.catalogue_search_policy WHERE singleton),
        'fingerprint', COALESCE((SELECT fingerprint FROM public.catalogue_search_policy WHERE singleton), '')
    ));
END;
"""

SEARCH_FUNCTION_SOURCES = {
    "catalogue_projection_write_lock()": SEARCH_WRITE_LOCK_SOURCE,
    "catalogue_refresh_search_record(p_id integer)": SEARCH_REFRESH_RECORD_SOURCE,
    "catalogue_refresh_search_projection()": SEARCH_REFRESH_TRIGGER_SOURCE,
    "catalogue_replace_search_policy(p_expected text, p_fingerprint text, p_masks jsonb)": SEARCH_REPLACE_POLICY_SOURCE,
    "catalogue_initialize_search_policy(p_fingerprint text, p_masks jsonb)": SEARCH_INITIALIZE_POLICY_SOURCE,
    "catalogue_guard_search_policy(p_fingerprint text)": SEARCH_GUARD_POLICY_SOURCE,
    "catalogue_search_relation(p_query jsonb)": SEARCH_RELATION_SOURCE,
    "catalogue_match_ids(p_query jsonb)": SEARCH_MATCH_IDS_SOURCE,
    "catalogue_search_candidates()": SEARCH_CANDIDATES_SOURCE,
}

SEARCH_FUNCTION_RESULTS = {
    "catalogue_projection_write_lock": "trigger",
    "catalogue_refresh_search_record": "void",
    "catalogue_refresh_search_projection": "trigger",
    "catalogue_replace_search_policy": "void",
    "catalogue_initialize_search_policy": "void",
    "catalogue_guard_search_policy": "void",
    "catalogue_search_relation": "text",
    "catalogue_match_ids": "SETOF integer",
    "catalogue_search_candidates": "SETOF integer",
}

SEARCH_STABLE_FUNCTIONS = frozenset(
    {"catalogue_search_relation", "catalogue_match_ids", "catalogue_search_candidates"}
)

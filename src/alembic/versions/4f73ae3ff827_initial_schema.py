"""Fresh-database baseline with frozen SQL; no upgrade from earlier migration histories."""

from collections.abc import Sequence
from typing import Final

from alembic import op

revision: str = "4f73ae3ff827"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Frozen SQL for revision 4f73ae3ff827. Keep literals local: importing current
# application SQL would change historical DDL when runtime code evolves.
# This explicitly reviewed pre-deployment reset includes consumed-snapshot
# progress and credential-security state directly; older baseline databases
# must be recreated as explicitly approved for this pre-deployment reset.
# After the first retained deployment, changes belong in a new revision.

_CATALOGUE_SCAN_CEILING_SOURCE: Final = (
    "\n    SELECT COALESCE((\n        SELECT stored.id\n        FROM public.oral"
    "_history_datasets AS stored\n        WHERE NOT EXISTS (\n            SELEC"
    "T 1 FROM public.dataset_admin_state AS hidden_state\n            WHERE hi"
    "dden_state.source = stored.source AND hidden_state.uuid = stored.uuid\n  "
    "            AND hidden_state.hidden_at IS NOT NULL\n        )\n        AND"
    " NOT EXISTS (\n            SELECT 1 FROM public.ingestion_quarantine AS q"
    "uarantine\n            WHERE quarantine.source = stored.source AND quaran"
    "tine.uuid = stored.uuid\n        )\n        ORDER BY stored.id DESC\n      "
    "  LIMIT 1\n    ), 0);\n"
)

_CATALOGUE_SEARCH_CANDIDATES_DEFINITION: Final = " SELECT catalogue_search_candidates() AS id;"

_CATALOGUE_PAGE_IDS_SOURCE: Final = (
    "\n-- search-mask/v1/43bd7e4b7f12a64ba0895ce5f1b1c29413042463c50ca807e4762"
    "14e91e14505\nDECLARE\n    relation_name text := public.catalogue_search_re"
    "lation(p_query);\n    query_ts tsquery;\n    anchor_identity integer;\n    "
    "anchor_timestamp timestamptz;\n    nonnull_seek text;\n    null_seek text;"
    "\n    traversal text;\n    null_position text;\n    rows_sql text;\n    page"
    "_sql text;\nBEGIN\n    IF p_ceiling IS NULL OR p_ceiling < 0\n       OR p_b"
    "ackward IS NULL\n       OR p_limit IS NULL OR p_limit < 1 OR p_limit > 10"
    "000\n       OR p_offset IS NULL OR p_offset < 0 OR p_offset > 9900\n      "
    " OR (p_anchor IS NOT NULL AND (p_anchor < 1 OR p_anchor > p_ceiling))\n  "
    "     OR (p_anchor IS NOT NULL AND p_offset <> 0)\n       OR (p_backward A"
    "ND p_anchor IS NULL) THEN\n        RAISE EXCEPTION 'invalid catalogue pag"
    "e bounds' USING ERRCODE = '22023';\n    END IF;\n    IF p_query ->> 'mode'"
    " IN ('auto', 'web') THEN\n        query_ts := pg_catalog.websearch_to_tsq"
    "uery(\n            'pg_catalog.simple'::regconfig, p_query ->> 'term');\n "
    "   END IF;\n    IF p_ceiling = 0 THEN RETURN; END IF;\n    -- Each fixed a"
    "udience name identifies its own physical table and indexes.\n    -- User-"
    "controlled predicates never reference the unrestricted record store.\n   "
    " rows_sql := pg_catalog.format($rows$\n        WITH permitted AS NOT MATE"
    "RIALIZED (\n            SELECT projection.id, projection.upstream_modifie"
    "d_at\n            FROM public.%I AS projection\n            WHERE projecti"
    "on.id <= $1\n              AND ($2 = '' OR projection.keywords @> ARRAY[$"
    "2])\n              AND ($3 = '' OR projection.languages @> ARRAY[$3])\n   "
    "           AND ($4 = '' OR projection.access_level = $4)\n              A"
    "ND ($5 = 'empty'\n                OR ($5 <> 'literal' AND projection.sear"
    "ch_vector @@ $6)\n                OR ($5 <> 'web' AND (projection.public_"
    "document ILIKE $7\n                    OR projection.literal_document ILI"
    "KE $7)))\n        )\n    $rows$, relation_name);\n    IF p_anchor IS NOT NU"
    "LL THEN\n        EXECUTE rows_sql || 'SELECT id, upstream_modified_at FRO"
    "M permitted WHERE id = $9'\n        INTO anchor_identity, anchor_timestam"
    "p\n        USING p_ceiling, p_query ->> 'keyword', p_query ->> 'language'"
    ", p_query ->> 'access_level',\n            p_query ->> 'mode', query_ts, "
    "p_query ->> 'pattern', anchor_timestamp, p_anchor;\n        IF anchor_ide"
    "ntity IS NULL THEN RETURN; END IF;\n    END IF;\n    IF p_backward THEN tr"
    "aversal := 'ASC'; null_position := 'NULLS FIRST';\n    ELSE traversal := "
    "'DESC'; null_position := 'NULLS LAST'; END IF;\n    IF p_anchor IS NULL T"
    "HEN nonnull_seek := 'TRUE'; null_seek := 'TRUE';\n    ELSIF anchor_timest"
    "amp IS NULL THEN\n        nonnull_seek := CASE WHEN p_backward THEN 'TRUE"
    "' ELSE 'FALSE' END;\n        null_seek := CASE WHEN p_backward THEN 'id >"
    " $9' ELSE 'id < $9' END;\n    ELSE\n        nonnull_seek := CASE WHEN p_ba"
    "ckward\n            THEN '(upstream_modified_at, id) > ($8, $9)'\n        "
    "    ELSE '(upstream_modified_at, id) < ($8, $9)' END;\n        null_seek "
    ":= CASE WHEN p_backward THEN 'FALSE' ELSE 'TRUE' END;\n    END IF;\n    pa"
    "ge_sql := rows_sql || pg_catalog.format($page$\n        SELECT bounded.id"
    " FROM (\n            (SELECT id, upstream_modified_at FROM permitted\n    "
    "         WHERE upstream_modified_at IS NOT NULL AND (%s)\n             OR"
    "DER BY upstream_modified_at %s %s, id %s LIMIT $10)\n            UNION AL"
    "L\n            (SELECT id, upstream_modified_at FROM permitted\n          "
    "   WHERE upstream_modified_at IS NULL AND (%s)\n             ORDER BY ups"
    "tream_modified_at %s %s, id %s LIMIT $10)\n        ) AS bounded\n        O"
    "RDER BY bounded.upstream_modified_at %s %s, bounded.id %s\n        LIMIT "
    "$11\n    $page$, nonnull_seek, traversal, null_position, traversal,\n     "
    "   null_seek, traversal, null_position, traversal, traversal, null_posit"
    "ion, traversal);\n    IF p_offset > 0 THEN page_sql := page_sql || ' OFFS"
    "ET $12'; END IF;\n    RETURN QUERY EXECUTE page_sql\n    USING p_ceiling, "
    "p_query ->> 'keyword', p_query ->> 'language', p_query ->> 'access_level"
    "',\n        p_query ->> 'mode', query_ts, p_query ->> 'pattern', anchor_t"
    "imestamp, p_anchor,\n        p_limit + p_offset, p_limit, p_offset;\nEND;\n"
)

_SEARCH_PROJECTION_TABLE_DDL: Final = (
    "\nCREATE TABLE public.catalogue_search_policy (\n    singleton boolean PRI"
    "MARY KEY DEFAULT true CHECK (singleton),\n    fingerprint text NOT NULL C"
    "HECK (fingerprint ~ '^[0-9a-f]{64}$'),\n    masks jsonb NOT NULL\n);\n\nCREA"
    "TE TABLE public.catalogue_search_public (\n    id integer PRIMARY KEY REF"
    "ERENCES public.oral_history_datasets(id) ON DELETE CASCADE,\n    upstream"
    "_modified_at timestamptz,\n    public_document text NOT NULL,\n    literal"
    "_document text NOT NULL,\n    search_vector tsvector NOT NULL,\n    keywor"
    "ds text[] NOT NULL,\n    languages text[] NOT NULL,\n    access_level text"
    "\n);\nCREATE INDEX idx_catalogue_search_public_vector\n    ON public.catalo"
    "gue_search_public USING gin (search_vector);\nCREATE INDEX idx_catalogue_"
    "search_public_public_trgm\n    ON public.catalogue_search_public USING gi"
    "n (public_document gin_trgm_ops);\nCREATE INDEX idx_catalogue_search_publ"
    "ic_literal_trgm\n    ON public.catalogue_search_public USING gin (literal"
    "_document gin_trgm_ops);\nCREATE INDEX idx_catalogue_search_public_keywor"
    "ds\n    ON public.catalogue_search_public USING gin (keywords);\nCREATE IN"
    "DEX idx_catalogue_search_public_languages\n    ON public.catalogue_search"
    "_public USING gin (languages);\nCREATE INDEX idx_catalogue_search_public_"
    "order\n    ON public.catalogue_search_public (upstream_modified_at DESC N"
    "ULLS LAST, id DESC);\n\n\nCREATE TABLE public.catalogue_search_registered ("
    "\n    id integer PRIMARY KEY REFERENCES public.oral_history_datasets(id) "
    "ON DELETE CASCADE,\n    upstream_modified_at timestamptz,\n    public_docu"
    "ment text NOT NULL,\n    literal_document text NOT NULL,\n    search_vecto"
    "r tsvector NOT NULL,\n    keywords text[] NOT NULL,\n    languages text[] "
    "NOT NULL,\n    access_level text\n);\nCREATE INDEX idx_catalogue_search_reg"
    "istered_vector\n    ON public.catalogue_search_registered USING gin (sear"
    "ch_vector);\nCREATE INDEX idx_catalogue_search_registered_public_trgm\n   "
    " ON public.catalogue_search_registered USING gin (public_document gin_tr"
    "gm_ops);\nCREATE INDEX idx_catalogue_search_registered_literal_trgm\n    O"
    "N public.catalogue_search_registered USING gin (literal_document gin_trg"
    "m_ops);\nCREATE INDEX idx_catalogue_search_registered_keywords\n    ON pub"
    "lic.catalogue_search_registered USING gin (keywords);\nCREATE INDEX idx_c"
    "atalogue_search_registered_languages\n    ON public.catalogue_search_regi"
    "stered USING gin (languages);\nCREATE INDEX idx_catalogue_search_register"
    "ed_order\n    ON public.catalogue_search_registered (upstream_modified_at"
    " DESC NULLS LAST, id DESC);\n\n\nCREATE TABLE public.catalogue_search_vette"
    "d (\n    id integer PRIMARY KEY REFERENCES public.oral_history_datasets(i"
    "d) ON DELETE CASCADE,\n    upstream_modified_at timestamptz,\n    public_d"
    "ocument text NOT NULL,\n    literal_document text NOT NULL,\n    search_ve"
    "ctor tsvector NOT NULL,\n    keywords text[] NOT NULL,\n    languages text"
    "[] NOT NULL,\n    access_level text\n);\nCREATE INDEX idx_catalogue_search_"
    "vetted_vector\n    ON public.catalogue_search_vetted USING gin (search_ve"
    "ctor);\nCREATE INDEX idx_catalogue_search_vetted_public_trgm\n    ON publi"
    "c.catalogue_search_vetted USING gin (public_document gin_trgm_ops);\nCREA"
    "TE INDEX idx_catalogue_search_vetted_literal_trgm\n    ON public.catalogu"
    "e_search_vetted USING gin (literal_document gin_trgm_ops);\nCREATE INDEX "
    "idx_catalogue_search_vetted_keywords\n    ON public.catalogue_search_vett"
    "ed USING gin (keywords);\nCREATE INDEX idx_catalogue_search_vetted_langua"
    "ges\n    ON public.catalogue_search_vetted USING gin (languages);\nCREATE "
    "INDEX idx_catalogue_search_vetted_order\n    ON public.catalogue_search_v"
    "etted (upstream_modified_at DESC NULLS LAST, id DESC);\n"
)

_SEARCH_FUNCTION_SOURCES: Final = {
    "catalogue_projection_write_lock()": (
        "\nBEGIN\n    PERFORM pg_catalog.pg_advisory_xact_lock(1330135379);\n    RET"
        "URN NULL;\nEND;\n"
    ),
    "catalogue_refresh_search_record(p_id integer)": (
        "\n-- search-mask/v1/43bd7e4b7f12a64ba0895ce5f1b1c29413042463c50ca807e4762"
        "14e91e14505\nDECLARE\n    stored record;\n    masks jsonb;\n    audience tex"
        "t;\n    viewer integer;\n    field_mask integer;\n    extra_document text;\n"
        "BEGIN\n    SELECT policy.masks INTO masks FROM public.catalogue_search_po"
        "licy AS policy\n        WHERE policy.singleton;\n    IF masks IS NULL THEN"
        " RETURN; END IF;\n    SELECT dataset.*,\n        GREATEST(\n            CAS"
        "E dataset.visibility_tier WHEN 'public' THEN 0\n                WHEN 'reg"
        "istered' THEN 1 WHEN 'vetted' THEN 2 ELSE 99 END,\n            CASE admin"
        ".visibility_tier WHEN 'registered' THEN 1 WHEN 'vetted' THEN 2\n         "
        "       WHEN 'public' THEN 0 ELSE CASE WHEN admin.visibility_tier IS NULL"
        "\n                THEN 0 ELSE 99 END END\n        ) AS effective_rank\n    "
        "INTO stored\n    FROM public.oral_history_datasets AS dataset\n    LEFT JO"
        "IN public.dataset_admin_state AS admin\n        ON admin.source = dataset"
        ".source AND admin.uuid = dataset.uuid\n    WHERE dataset.id = p_id AND ad"
        "min.hidden_at IS NULL\n      AND NOT EXISTS (SELECT 1 FROM public.ingesti"
        "on_quarantine AS quarantine\n          WHERE quarantine.source = dataset."
        "source AND quarantine.uuid = dataset.uuid);\n    IF NOT FOUND THEN\n      "
        "  DELETE FROM public.catalogue_search_public WHERE id = p_id;\n        DE"
        "LETE FROM public.catalogue_search_registered WHERE id = p_id;\n        DE"
        "LETE FROM public.catalogue_search_vetted WHERE id = p_id;\n        RETURN"
        ";\n    END IF;\n    FOR viewer IN 0..2 LOOP\n        audience := (ARRAY['pu"
        "blic', 'registered', 'vetted'])[viewer + 1];\n        field_mask := CASE "
        "WHEN stored.effective_rank <= viewer THEN\n            COALESCE(masks -> "
        "viewer::text -> stored.source,\n                masks -> viewer::text -> "
        "'*')::integer ELSE 0 END;\n        extra_document :=\n            CASE WHE"
        "N (field_mask & 1) <> 0 THEN COALESCE(stored.description, '') ELSE '' EN"
        "D || ' ' ||\n            CASE WHEN (field_mask & 2) <> 0 THEN COALESCE(st"
        "ored.project_title, '') ELSE '' END || ' ' ||\n            CASE WHEN (fie"
        "ld_mask & 4) <> 0 THEN COALESCE(stored.project_description, '') ELSE '' "
        "END || ' ' ||\n            CASE WHEN (field_mask & 8) <> 0 THEN COALESCE("
        "pg_catalog.array_to_string(stored.keywords, ' '), '') ELSE '' END || ' '"
        " ||\n            CASE WHEN (field_mask & 16) <> 0 THEN COALESCE(pg_catalo"
        "g.array_to_string(stored.authors, ' '), '') ELSE '' END;\n        EXECUTE"
        " pg_catalog.format(\n            'INSERT INTO public.%I AS existing (id, "
        "upstream_modified_at, public_document, '\n            'literal_document, "
        "search_vector, keywords, languages, access_level) '\n            'VALUES "
        "($1, $2, $3, $4, pg_catalog.to_tsvector(''pg_catalog.simple''::regconfig"
        ", $5), $6, $7, $8) '\n            'ON CONFLICT (id) DO UPDATE SET upstrea"
        "m_modified_at = EXCLUDED.upstream_modified_at, '\n            'public_doc"
        "ument = EXCLUDED.public_document, literal_document = EXCLUDED.literal_do"
        "cument, '\n            'search_vector = EXCLUDED.search_vector, keywords "
        "= EXCLUDED.keywords, '\n            'languages = EXCLUDED.languages, acce"
        "ss_level = EXCLUDED.access_level '\n            'WHERE (existing.upstream"
        "_modified_at, existing.public_document, existing.literal_document, '\n   "
        "         'existing.search_vector, existing.keywords, existing.languages,"
        " existing.access_level) '\n            'IS DISTINCT FROM (EXCLUDED.upstre"
        "am_modified_at, EXCLUDED.public_document, '\n            'EXCLUDED.litera"
        "l_document, EXCLUDED.search_vector, EXCLUDED.keywords, '\n            'EX"
        "CLUDED.languages, EXCLUDED.access_level)',\n            'catalogue_search"
        "_' || audience)\n        USING stored.id, stored.upstream_modified_at,\n  "
        "          COALESCE(stored.title, '') || ' ' || COALESCE(stored.access_le"
        "vel, ''),\n            COALESCE(stored.title, '') || ' ' || extra_documen"
        "t,\n            COALESCE(stored.title, '') || ' ' || COALESCE(stored.acce"
        "ss_level, '') || ' ' || extra_document,\n            CASE WHEN (field_mas"
        "k & 8) <> 0 THEN COALESCE(stored.keywords, ARRAY[]::text[]) ELSE ARRAY[]"
        "::text[] END,\n            CASE WHEN (field_mask & 32) <> 0 THEN COALESCE"
        "(stored.languages, ARRAY[]::text[]) ELSE ARRAY[]::text[] END,\n          "
        "  stored.access_level;\n    END LOOP;\nEND;\n"
    ),
    "catalogue_refresh_search_projection()": (
        "\nDECLARE\n    affected_id integer;\nBEGIN\n    IF TG_TABLE_NAME = 'oral_his"
        "tory_datasets' THEN\n        IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND"
        " OLD.id IS DISTINCT FROM NEW.id) THEN\n            PERFORM public.catalog"
        "ue_refresh_search_record(OLD.id);\n        END IF;\n        IF TG_OP <> 'D"
        "ELETE' THEN PERFORM public.catalogue_refresh_search_record(NEW.id); END "
        "IF;\n    ELSE\n        IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND\n      "
        "      (OLD.source, OLD.uuid) IS DISTINCT FROM (NEW.source, NEW.uuid)) TH"
        "EN\n            FOR affected_id IN SELECT id FROM public.oral_history_dat"
        "asets\n                WHERE source = OLD.source AND uuid = OLD.uuid LOOP"
        "\n                PERFORM public.catalogue_refresh_search_record(affected"
        "_id);\n            END LOOP;\n        END IF;\n        IF TG_OP <> 'DELETE'"
        " THEN\n            FOR affected_id IN SELECT id FROM public.oral_history_"
        "datasets\n                WHERE source = NEW.source AND uuid = NEW.uuid L"
        "OOP\n                PERFORM public.catalogue_refresh_search_record(affec"
        "ted_id);\n            END LOOP;\n        END IF;\n    END IF;\n    RETURN NU"
        "LL;\nEND;\n"
    ),
    "catalogue_replace_search_policy(p_expected text, p_fingerprint text, p_masks jsonb)": (
        "\nDECLARE\n    prior record;\n    viewer text;\n    item record;\n    affecte"
        "d_id integer;\nBEGIN\n    IF p_fingerprint IS NULL OR p_fingerprint !~ '^["
        "0-9a-f]{64}$'\n       OR pg_catalog.jsonb_typeof(p_masks) IS DISTINCT FRO"
        "M 'object'\n       OR NOT (p_masks ?& ARRAY['0', '1', '2'])\n       OR EXI"
        "STS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_masks) AS entry(name)\n"
        "           WHERE name <> ALL (ARRAY['0', '1', '2'])) THEN\n        RAISE "
        "EXCEPTION 'invalid search projection policy' USING ERRCODE = '22023';\n  "
        "  END IF;\n    FOREACH viewer IN ARRAY ARRAY['0', '1', '2'] LOOP\n        "
        "IF pg_catalog.jsonb_typeof(p_masks -> viewer) IS DISTINCT FROM 'object'\n"
        "           OR NOT ((p_masks -> viewer) ? '*') THEN\n            RAISE EXC"
        "EPTION 'invalid search projection masks' USING ERRCODE = '22023';\n      "
        "  END IF;\n        FOR item IN SELECT * FROM pg_catalog.jsonb_each(p_mask"
        "s -> viewer) LOOP\n            IF (item.key <> '*' AND item.key !~ '^[a-z"
        "0-9_]{1,32}$')\n               OR pg_catalog.jsonb_typeof(item.value) <> "
        "'number'\n               OR item.value::text !~ '^(0|[1-9]|[1-5][0-9]|6[0"
        "-3])$' THEN\n                RAISE EXCEPTION 'invalid search projection m"
        "ask' USING ERRCODE = '22023';\n            END IF;\n        END LOOP;\n    "
        "END LOOP;\n    PERFORM pg_catalog.pg_advisory_xact_lock(1330135379);\n    "
        "SELECT * INTO prior FROM public.catalogue_search_policy WHERE singleton "
        "FOR UPDATE;\n    IF FOUND THEN\n        IF p_expected IS NULL AND prior.fi"
        "ngerprint = p_fingerprint AND prior.masks = p_masks THEN\n            RET"
        "URN;\n        END IF;\n        IF p_expected IS NULL OR prior.fingerprint "
        "<> p_expected THEN\n            RAISE EXCEPTION 'search projection policy"
        " changed; explicit replacement required'\n                USING ERRCODE ="
        " '55000';\n        END IF;\n    ELSIF p_expected IS NOT NULL THEN\n        "
        "RAISE EXCEPTION 'search projection policy binding is missing' USING ERRC"
        "ODE = '55000';\n    END IF;\n    INSERT INTO public.catalogue_search_polic"
        "y(singleton, fingerprint, masks)\n        VALUES (true, p_fingerprint, p_"
        "masks)\n        ON CONFLICT (singleton) DO UPDATE SET fingerprint = EXCLU"
        "DED.fingerprint,\n            masks = EXCLUDED.masks;\n    DELETE FROM pub"
        "lic.catalogue_search_public;\n    DELETE FROM public.catalogue_search_reg"
        "istered;\n    DELETE FROM public.catalogue_search_vetted;\n    FOR affecte"
        "d_id IN SELECT id FROM public.oral_history_datasets LOOP\n        PERFORM"
        " public.catalogue_refresh_search_record(affected_id);\n    END LOOP;\nEND;"
        "\n"
    ),
    "catalogue_initialize_search_policy(p_fingerprint text, p_masks jsonb)": (
        "\nBEGIN\n    PERFORM public.catalogue_replace_search_policy(NULL, p_finger"
        "print, p_masks);\nEND;\n"
    ),
    "catalogue_guard_search_policy(p_fingerprint text)": (
        "\nDECLARE\n    bound_fingerprint text;\nBEGIN\n    -- No serving connection "
        "waits behind a maintenance rebuild or catalogue write.\n    IF NOT pg_cat"
        "alog.pg_try_advisory_xact_lock_shared(1330135379) THEN\n        RAISE EXC"
        "EPTION 'catalogue policy is being updated' USING ERRCODE = '55000';\n    "
        "END IF;\n    SELECT fingerprint INTO bound_fingerprint FROM public.catalo"
        "gue_search_policy WHERE singleton;\n    IF bound_fingerprint IS NULL OR p"
        "_fingerprint IS NULL OR bound_fingerprint <> p_fingerprint THEN\n        "
        "RAISE EXCEPTION 'catalogue policy is not current' USING ERRCODE = '55000"
        "';\n    END IF;\nEND;\n"
    ),
    "catalogue_search_relation(p_query jsonb)": (
        "\nDECLARE\n    audience text := pg_catalog.current_setting('app.viewer_tie"
        "r', true);\n    bound_fingerprint text;\n    bound_masks jsonb;\nBEGIN\n    "
        "IF audience IS NULL OR audience NOT IN ('public', 'registered', 'vetted'"
        ") THEN\n        audience := 'public';\n    END IF;\n    IF pg_catalog.jsonb"
        "_typeof(p_query) IS DISTINCT FROM 'object'\n       OR NOT (p_query ?& ARR"
        "AY['mode', 'term', 'pattern', 'keyword', 'language', 'access_level', 'ma"
        "sks', 'fingerprint'])\n       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_e"
        "ach(p_query) AS item(name, value)\n           WHERE name <> ALL (ARRAY['m"
        "ode', 'term', 'pattern', 'keyword', 'language', 'access_level', 'masks',"
        " 'fingerprint'])\n              OR (name <> 'masks' AND pg_catalog.jsonb_"
        "typeof(value) <> 'string'))\n       OR p_query ->> 'mode' NOT IN ('empty'"
        ", 'auto', 'web', 'literal')\n       OR ((p_query ->> 'mode' = 'empty') <>"
        " (p_query ->> 'term' = '')) THEN\n        RAISE EXCEPTION 'invalid catalo"
        "gue page context' USING ERRCODE = '22023';\n    END IF;\n    SELECT finger"
        "print, masks -> CASE audience WHEN 'registered' THEN '1'\n        WHEN 'v"
        "etted' THEN '2' ELSE '0' END INTO bound_fingerprint, bound_masks\n    FRO"
        "M public.catalogue_search_policy WHERE singleton;\n    IF bound_fingerpri"
        "nt IS NULL OR bound_fingerprint <> p_query ->> 'fingerprint' THEN\n      "
        "  RAISE EXCEPTION 'search projection policy is not current' USING ERRCOD"
        "E = '55000';\n    END IF;\n    IF p_query -> 'masks' IS DISTINCT FROM boun"
        "d_masks THEN\n        RAISE EXCEPTION 'catalogue field masks do not match"
        " the bound policy' USING ERRCODE = '22023';\n    END IF;\n    RETURN 'cata"
        "logue_search_' || audience;\nEND;\n"
    ),
    "catalogue_match_ids(p_query jsonb)": (
        "\n-- search-mask/v1/43bd7e4b7f12a64ba0895ce5f1b1c29413042463c50ca807e4762"
        "14e91e14505\nDECLARE\n    relation_name text := public.catalogue_search_re"
        "lation(p_query);\n    query_ts tsquery;\nBEGIN\n    IF p_query ->> 'mode' I"
        "N ('auto', 'web') THEN\n        query_ts := pg_catalog.websearch_to_tsque"
        "ry('pg_catalog.simple'::regconfig, p_query ->> 'term');\n    END IF;\n    "
        "RETURN QUERY EXECUTE pg_catalog.format(\n        'SELECT projection.id FR"
        "OM public.%I AS projection WHERE \n    ($1 = '''' OR projection.keywords "
        "@> ARRAY[$1])\n    AND ($2 = '''' OR projection.languages @> ARRAY[$2])\n "
        "   AND ($3 = '''' OR projection.access_level = $3)\n    AND ($4 = ''empty"
        "''\n        OR ($4 <> ''literal'' AND projection.search_vector @@ $5)\n   "
        "     OR ($4 <> ''web'' AND (projection.public_document ILIKE $6\n        "
        "    OR projection.literal_document ILIKE $6)))\n', relation_name)\n    USI"
        "NG p_query ->> 'keyword', p_query ->> 'language', p_query ->> 'access_le"
        "vel',\n        p_query ->> 'mode', query_ts, p_query ->> 'pattern';\nEND;\n"
    ),
    "catalogue_search_candidates()": (
        "\nBEGIN\n    RETURN QUERY SELECT public.catalogue_match_ids(pg_catalog.jso"
        "nb_build_object(\n        'mode', COALESCE(NULLIF(pg_catalog.current_sett"
        "ing('app.search_mode', true), ''), 'empty'),\n        'term', COALESCE(pg"
        "_catalog.current_setting('app.search_term', true), ''),\n        'pattern"
        "', COALESCE(pg_catalog.current_setting('app.search_pattern', true), ''),"
        "\n        'keyword', '', 'language', '', 'access_level', '',\n        'mas"
        "ks', (SELECT masks -> CASE pg_catalog.current_setting('app.viewer_tier',"
        " true)\n            WHEN 'registered' THEN '1' WHEN 'vetted' THEN '2' ELS"
        "E '0' END\n            FROM public.catalogue_search_policy WHERE singleto"
        "n),\n        'fingerprint', COALESCE((SELECT fingerprint FROM public.cata"
        "logue_search_policy WHERE singleton), '')\n    ));\nEND;\n"
    ),
}

_SEARCH_FUNCTION_RESULTS: Final = {
    "catalogue_projection_write_lock": ("trigger"),
    "catalogue_refresh_search_record": ("void"),
    "catalogue_refresh_search_projection": ("trigger"),
    "catalogue_replace_search_policy": ("void"),
    "catalogue_initialize_search_policy": ("void"),
    "catalogue_guard_search_policy": ("void"),
    "catalogue_search_relation": ("text"),
    "catalogue_match_ids": ("SETOF integer"),
    "catalogue_search_candidates": ("SETOF integer"),
}

_SEARCH_STABLE_FUNCTIONS: Final = (
    "catalogue_match_ids",
    "catalogue_search_candidates",
    "catalogue_search_relation",
)


def upgrade() -> None:
    """Create the fresh baseline: tables, triggers, search functions/views, RLS and pg_trgm.

    Require a fresh database and a role allowed to create these objects. Leave
    sync_status empty for scheduler provisioning; runtime grants are separate.
    No legacy upgrade/backfill is performed; SQL/Alembic errors propagate.

    Frozen SQL comments are part of exact function-source contracts. The legacy
    trigger's "Full blob: everything" comment is inaccurate: it indexes title,
    description, project title/description, keywords and authors. Its full vector
    also includes access_level. Current audience projections enforce disclosure.
    Keep these literal bodies unchanged unless their source contracts are updated
    together; revision-local SQL must remain independent of runtime imports.
    """
    op.execute(
        """
        CREATE EXTENSION IF NOT EXISTS pg_trgm;

        CREATE TABLE oral_history_datasets (
            id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            uuid TEXT NOT NULL,
            doi TEXT,
            source TEXT NOT NULL,
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
            search_vector_public TSVECTOR NOT NULL,
            search_vector_full TSVECTOR NOT NULL,
            CONSTRAINT datasets_source_check
                CHECK (source ~ '^[abcdefghijklmnopqrstuvwxyz0123456789_]{1,32}$'),
            CONSTRAINT datasets_source_uuid_key UNIQUE (source, uuid),
            CONSTRAINT datasets_source_doi_key UNIQUE (source, doi),
            CONSTRAINT datasets_visibility_tier_check
                CHECK (visibility_tier IN ('public', 'registered', 'vetted'))
        );

        CREATE INDEX idx_datasets_source
            ON oral_history_datasets(source);

        -- Trigger: maintains the public and full search-text columns
        -- on every insert/update. ingestion.py doesn't need to know about it.
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

        CREATE TRIGGER trg_search_text
            BEFORE INSERT OR UPDATE ON oral_history_datasets
            FOR EACH ROW EXECUTE FUNCTION update_search_text();

        -- Trigram GIN index: makes ILIKE '%term%' use an index scan
        -- instead of a sequential scan. Effective for 3+ character terms.
        CREATE INDEX idx_search_text_public_trgm
            ON oral_history_datasets USING GIN (search_text_public gin_trgm_ops);

        CREATE INDEX idx_search_text_full_trgm
            ON oral_history_datasets USING GIN (search_text_full gin_trgm_ops);

        CREATE INDEX idx_search_vector_public
            ON oral_history_datasets USING GIN (search_vector_public);
        CREATE INDEX idx_search_vector_full
            ON oral_history_datasets USING GIN (search_vector_full);

        CREATE INDEX ix_datasets_upstream_modified_at
            ON oral_history_datasets (upstream_modified_at DESC NULLS LAST, id DESC);
        CREATE INDEX ix_datasets_keywords_gin
            ON oral_history_datasets USING GIN (keywords);
        CREATE INDEX ix_datasets_languages_gin
            ON oral_history_datasets USING GIN (languages);

        CREATE TABLE dataset_admin_state (
            source TEXT NOT NULL,
            uuid TEXT NOT NULL,
            visibility_tier TEXT,
            hidden_at TIMESTAMPTZ,
            CONSTRAINT dataset_admin_state_pkey PRIMARY KEY (source, uuid),
            CONSTRAINT dataset_admin_state_source_check
                CHECK (source ~ '^[abcdefghijklmnopqrstuvwxyz0123456789_]{1,32}$'),
            CONSTRAINT dataset_admin_state_visibility_tier_check
                CHECK (visibility_tier IN ('public', 'registered', 'vetted'))
        );

        CREATE TABLE source_security_state (
            source TEXT NOT NULL,
            uuid TEXT NOT NULL,
            visibility_tier TEXT NOT NULL,
            CONSTRAINT source_security_state_pkey PRIMARY KEY (source, uuid),
            CONSTRAINT source_security_state_tier_check
                CHECK (visibility_tier IN ('public', 'registered', 'vetted'))
        );

        CREATE FUNCTION public.catalogue_preserve_source_security_state()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public AS $source_security$
        DECLARE
            retained_tier text;
            asserted_tier text := NEW.data->>'visibility_tier';
        BEGIN
            IF asserted_tier IN ('public', 'registered', 'vetted') AND
                array_position(ARRAY['public', 'registered', 'vetted'], asserted_tier)
                > array_position(ARRAY['public', 'registered', 'vetted'], NEW.visibility_tier)
            THEN
                NEW.visibility_tier := asserted_tier;
            END IF;
            INSERT INTO public.source_security_state AS existing (source, uuid, visibility_tier)
            VALUES (NEW.source, NEW.uuid, NEW.visibility_tier)
            ON CONFLICT (source, uuid) DO UPDATE SET visibility_tier = CASE
                WHEN asserted_tier IN ('public', 'registered', 'vetted')
                THEN EXCLUDED.visibility_tier
                WHEN array_position(ARRAY['public', 'registered', 'vetted'],
                                    existing.visibility_tier)
                   > array_position(ARRAY['public', 'registered', 'vetted'],
                                    EXCLUDED.visibility_tier)
                THEN existing.visibility_tier ELSE EXCLUDED.visibility_tier END
            RETURNING visibility_tier INTO retained_tier;
            NEW.visibility_tier := retained_tier;
            RETURN NEW;
        END;
        $source_security$;
        REVOKE ALL ON FUNCTION public.catalogue_preserve_source_security_state() FROM PUBLIC;
        CREATE TRIGGER oral_history_datasets_security_state
            BEFORE INSERT OR UPDATE ON public.oral_history_datasets
            FOR EACH ROW EXECUTE FUNCTION public.catalogue_preserve_source_security_state();

        CREATE TABLE source_binding_acknowledgements (
            source TEXT PRIMARY KEY,
            previous_fingerprint TEXT NOT NULL,
            source_fingerprint TEXT NOT NULL,
            acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            CONSTRAINT source_binding_acknowledgements_previous_check
                CHECK (previous_fingerprint ~ '^[0-9a-f]{64}$'),
            CONSTRAINT source_binding_acknowledgements_target_check
                CHECK (source_fingerprint ~ '^[0-9a-f]{64}$')
        );

        CREATE TABLE security_audit_events (
            event_id UUID PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            event_type TEXT NOT NULL,
            payload JSONB NOT NULL,
            CONSTRAINT security_audit_events_payload_check
                CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 16384)
        );
        CREATE INDEX idx_security_audit_events_created
            ON security_audit_events (created_at, event_id);
        CREATE TABLE security_audit_receipts (
            event_id UUID PRIMARY KEY REFERENCES security_audit_events(event_id) ON DELETE RESTRICT,
            delivered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );

        CREATE FUNCTION public.catalogue_audit_restriction_state()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public AS $restriction_event$
        DECLARE
            event_name text;
            event_payload jsonb;
        BEGIN
            IF TG_TABLE_NAME = 'ingestion_quarantine' THEN
                IF TG_OP = 'DELETE' THEN
                    event_name := 'ingestion_restored';
                    event_payload := jsonb_build_object(
                        'source', OLD.source, 'uuid', OLD.uuid, 'reason', OLD.reason);
                ELSE
                    event_name := 'ingestion_quarantined';
                    event_payload := jsonb_build_object(
                        'source', NEW.source, 'uuid', NEW.uuid, 'reason', NEW.reason);
                END IF;
            ELSE
                IF TG_OP = 'DELETE' THEN
                    event_name := 'source_restriction_removed';
                    event_payload := jsonb_build_object(
                        'source', OLD.source, 'uuid', OLD.uuid, 'old_tier', OLD.visibility_tier);
                ELSE
                    IF TG_OP = 'INSERT' AND NEW.visibility_tier = 'public' THEN
                        RETURN NULL;
                    END IF;
                    IF TG_OP = 'UPDATE' AND NEW.visibility_tier = OLD.visibility_tier THEN
                        RETURN NULL;
                    END IF;
                    IF TG_OP = 'UPDATE' AND
                        array_position(ARRAY['public', 'registered', 'vetted'], NEW.visibility_tier)
                        < array_position(
                            ARRAY['public', 'registered', 'vetted'], OLD.visibility_tier)
                    THEN
                        event_name := 'source_restriction_lowered';
                        event_payload := jsonb_build_object(
                            'source', NEW.source, 'uuid', NEW.uuid,
                            'old_tier', OLD.visibility_tier, 'tier', NEW.visibility_tier);
                    ELSE
                        event_name := 'source_restriction_retained';
                        event_payload := jsonb_build_object(
                            'source', NEW.source, 'uuid', NEW.uuid, 'tier', NEW.visibility_tier);
                    END IF;
                END IF;
            END IF;
            INSERT INTO public.security_audit_events (event_id, event_type, payload)
            VALUES (gen_random_uuid(), event_name, event_payload);
            RETURN NULL;
        END;
        $restriction_event$;
        REVOKE ALL ON FUNCTION public.catalogue_audit_restriction_state() FROM PUBLIC;
        CREATE TRIGGER source_security_state_audit
            AFTER INSERT OR UPDATE OR DELETE ON public.source_security_state
            FOR EACH ROW EXECUTE FUNCTION public.catalogue_audit_restriction_state();

        CREATE TABLE anonymous_mail_issuance (
            id UUID PRIMARY KEY,
            recipient_key TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            CONSTRAINT anonymous_mail_issuance_recipient_check
                CHECK (recipient_key ~ '^[0-9a-f]{64}$')
        );
        CREATE INDEX idx_anonymous_mail_issuance_created
            ON anonymous_mail_issuance (created_at);
        CREATE INDEX idx_anonymous_mail_issuance_recipient
            ON anonymous_mail_issuance (recipient_key, created_at);

        CREATE TABLE sync_status (
            source TEXT PRIMARY KEY,
            last_harvest_date TIMESTAMPTZ,
            last_sync_error TEXT,
            last_sync_error_at TIMESTAMPTZ,
            last_rebuild_error TEXT,
            last_rebuild_error_at TIMESTAMPTZ,
            last_full_rebuild_date TIMESTAMPTZ,
            source_cursor TIMESTAMPTZ,
            source_fingerprint TEXT,
            source_fetch_cursor TIMESTAMPTZ,
            source_fetch_fingerprint TEXT,
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

        CREATE TABLE ingestion_failures (
            source TEXT NOT NULL,
            uuid TEXT NOT NULL,
            message TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (source, uuid)
        );

        CREATE TABLE ingestion_quarantine (
            source TEXT NOT NULL,
            uuid TEXT NOT NULL,
            reason TEXT NOT NULL,
            failed_harvest_at TIMESTAMPTZ NOT NULL,
            failed_source_cursor TIMESTAMPTZ NOT NULL,
            quarantined_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT ingestion_quarantine_pkey PRIMARY KEY (source, uuid),
            CONSTRAINT ingestion_quarantine_reason_check
                CHECK (reason IN ('record_rejected', 'record_write_failed', 'filter_mismatch'))
        );
        CREATE TRIGGER ingestion_quarantine_audit
            AFTER INSERT OR UPDATE OR DELETE ON public.ingestion_quarantine
            FOR EACH ROW EXECUTE FUNCTION public.catalogue_audit_restriction_state();

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
            pending_totp_session_hash TEXT,
            pending_email TEXT,
            pending_email_token_hash TEXT,
            pending_email_created_at TIMESTAMPTZ,
            password_reset_token_hash TEXT,
            password_reset_created_at TIMESTAMPTZ,
            password_reset_attempt_count INTEGER NOT NULL DEFAULT 0,
            password_reset_attempt_window_started_at TIMESTAMPTZ,
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
            -- Advisory trusted-assertion state; never an authority source.
            -- A reviewed explicit no-match is {"proposal": null}, distinct from
            -- no administrator review (SQL NULL).
            federated_review JSONB,
            federated_review_revision BIGINT NOT NULL DEFAULT 0,
            federated_approved_proposal JSONB,
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
            CONSTRAINT users_password_reset_attempt_count_check
                CHECK (password_reset_attempt_count >= 0 AND password_reset_attempt_count <= 5),
            CONSTRAINT users_password_reset_attempt_window_check
                CHECK ((password_reset_attempt_count = 0
                        AND password_reset_attempt_window_started_at IS NULL)
                    OR (password_reset_attempt_count > 0
                        AND password_reset_attempt_window_started_at IS NOT NULL)),
            CONSTRAINT users_local_password_required
                CHECK (
                    auth_method <> 'local' OR password_hash IS NOT NULL
                    OR (NOT is_active AND NOT email_verified AND NOT is_admin)
                ),
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
            CONSTRAINT users_federated_review_state_check CHECK ((
                federated_review_revision >= 0
                AND (
                    (federated_review IS NULL AND federated_review_revision = 0)
                    OR (
                        auth_method = 'shibboleth'
                        AND federated_review_revision > 0
                        AND jsonb_typeof(federated_review) = 'object'
                        AND federated_review ?& ARRAY[
                            'issuer', 'affiliation', 'entitlement', 'proposal'
                        ]
                        AND federated_review - ARRAY[
                            'issuer', 'affiliation', 'entitlement', 'proposal'
                        ] = '{}'::jsonb
                        AND jsonb_typeof(federated_review -> 'issuer') = 'string'
                        AND federated_review ->> 'issuer' = shibboleth_issuer
                        AND length(federated_review ->> 'issuer') BETWEEN 1 AND 2048
                        AND (
                            jsonb_typeof(federated_review -> 'affiliation') = 'null'
                            OR (
                                jsonb_typeof(federated_review -> 'affiliation') = 'string'
                                AND length(federated_review ->> 'affiliation') BETWEEN 1 AND 512
                            )
                        )
                        AND (
                            jsonb_typeof(federated_review -> 'entitlement') = 'null'
                            OR (
                                jsonb_typeof(federated_review -> 'entitlement') = 'string'
                                AND length(federated_review ->> 'entitlement') BETWEEN 1 AND 4096
                            )
                        )
                        AND (
                            federated_review -> 'proposal' = 'null'::jsonb
                            OR (
                                jsonb_typeof(federated_review -> 'proposal') = 'object'
                                AND federated_review -> 'proposal'
                                    ?& ARRAY['index', 'match', 'tier']
                                AND (federated_review -> 'proposal')
                                    - ARRAY['index', 'match', 'tier'] = '{}'::jsonb
                                AND jsonb_typeof(federated_review #> '{proposal,index}') = 'number'
                                AND federated_review #>> '{proposal,index}' ~ '^[1-9][0-9]*$'
                                AND jsonb_typeof(federated_review #> '{proposal,match}') = 'object'
                                AND federated_review #> '{proposal,match}' <> '{}'::jsonb
                                AND federated_review #>> '{proposal,tier}'
                                    IN ('public', 'registered', 'vetted')
                            )
                        )
                    )
                )
                AND (
                    federated_approved_proposal IS NULL
                    OR (
                        auth_method = 'shibboleth'
                        AND federated_status IN ('approved', 'disabled')
                        AND federated_review IS NOT NULL
                        AND jsonb_typeof(federated_approved_proposal) = 'object'
                        AND federated_approved_proposal ? 'proposal'
                        AND federated_approved_proposal - 'proposal' = '{}'::jsonb
                        AND (
                            federated_approved_proposal -> 'proposal' = 'null'::jsonb
                            OR (
                                jsonb_typeof(federated_approved_proposal -> 'proposal') = 'object'
                                AND federated_approved_proposal -> 'proposal'
                                    ?& ARRAY['index', 'match', 'tier']
                                AND (federated_approved_proposal -> 'proposal')
                                    - ARRAY['index', 'match', 'tier'] = '{}'::jsonb
                                AND jsonb_typeof(federated_approved_proposal #> '{proposal,index}')
                                    = 'number'
                                AND federated_approved_proposal #>> '{proposal,index}'
                                    ~ '^[1-9][0-9]*$'
                                AND jsonb_typeof(federated_approved_proposal #> '{proposal,match}')
                                    = 'object'
                                AND federated_approved_proposal #> '{proposal,match}' <> '{}'::jsonb
                                AND federated_approved_proposal #>> '{proposal,tier}'
                                    IN ('public', 'registered', 'vetted')
                            )
                        )
                    )
                )
            ) IS TRUE),
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
                            'account_locked_notice',
                            'password_changed_notice',
                            'totp_enrolled_notice',
                            'totp_rotated_notice',
                            'totp_recovery_authorized_notice',
                            'totp_recovery_redeemed_notice',
                            'totp_recovery_completed_notice',
                            'admin_promotion_accepted_notice'
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
            last_activity_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
    """
    )
    op.execute(_SEARCH_PROJECTION_TABLE_DDL)
    for signature, source in _SEARCH_FUNCTION_SOURCES.items():
        name = signature.split("(", 1)[0]
        volatility = "STABLE" if name in _SEARCH_STABLE_FUNCTIONS else "VOLATILE"
        op.execute(
            f"CREATE FUNCTION public.{signature} RETURNS {_SEARCH_FUNCTION_RESULTS[name]} "
            f"LANGUAGE plpgsql {volatility} SECURITY DEFINER PARALLEL UNSAFE "
            "SET search_path = pg_catalog, public AS $search_projection$"
            + source
            + "$search_projection$"
        )
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
    for table in ("oral_history_datasets", "dataset_admin_state", "ingestion_quarantine"):
        op.execute(
            f"CREATE TRIGGER trg_search_projection_lock BEFORE INSERT OR UPDATE OR DELETE "
            f"ON public.{table} FOR EACH STATEMENT "
            "EXECUTE FUNCTION public.catalogue_projection_write_lock()"
        )
        op.execute(
            f"CREATE TRIGGER trg_search_projection_refresh AFTER INSERT OR UPDATE OR DELETE "
            f"ON public.{table} FOR EACH ROW "
            "EXECUTE FUNCTION public.catalogue_refresh_search_projection()"
        )
    op.execute(
        """
        CREATE VIEW public.catalogue_discovery
        WITH (security_barrier = true, security_invoker = false)
        AS
        SELECT
            stored.id,
            stored.uuid,
            stored.title,
            stored.access_level,
            stored.version,
            stored.source,
            CASE
                WHEN admin_state.visibility_tier IS NULL
                    OR CASE stored.visibility_tier
                        WHEN 'public' THEN 0
                        WHEN 'registered' THEN 1
                        WHEN 'vetted' THEN 2
                        ELSE 99
                    END >= CASE admin_state.visibility_tier
                        WHEN 'public' THEN 0
                        WHEN 'registered' THEN 1
                        WHEN 'vetted' THEN 2
                        ELSE 99
                    END
                THEN stored.visibility_tier
                ELSE admin_state.visibility_tier
            END AS visibility_tier
        FROM public.oral_history_datasets AS stored
        LEFT JOIN public.dataset_admin_state AS admin_state
            ON admin_state.source = stored.source AND admin_state.uuid = stored.uuid
        WHERE admin_state.hidden_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM public.ingestion_quarantine AS quarantine
              WHERE quarantine.source = stored.source AND quarantine.uuid = stored.uuid);

        CREATE VIEW public.catalogue_search_candidates
        WITH (security_barrier = true, security_invoker = false)
        AS
        """
        + _CATALOGUE_SEARCH_CANDIDATES_DEFINITION
        + """

        CREATE VIEW public.dataset_admin_catalogue
        WITH (security_barrier = true, security_invoker = false)
        AS
        SELECT
            stored.id,
            stored.source,
            stored.uuid,
            stored.visibility_tier AS stored_tier,
            CASE stored.data -> 'visibility_tier'
                WHEN '"public"'::jsonb THEN 'public'::text
                WHEN '"registered"'::jsonb THEN 'registered'::text
                WHEN '"vetted"'::jsonb THEN 'vetted'::text
                ELSE NULL::text
            END AS record_tier
        FROM public.oral_history_datasets AS stored
        LEFT JOIN public.dataset_admin_state AS admin_state
            ON admin_state.source = stored.source AND admin_state.uuid = stored.uuid;

        REVOKE ALL ON public.catalogue_discovery, public.catalogue_search_candidates,
            public.dataset_admin_catalogue FROM PUBLIC;

        ALTER TABLE public.oral_history_datasets ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.oral_history_datasets NO FORCE ROW LEVEL SECURITY;

        CREATE POLICY catalogue_web_select ON public.oral_history_datasets
        FOR SELECT TO PUBLIC
        USING (
            CURRENT_USER = 'oralhistarchiv_web'
            AND CASE oral_history_datasets.visibility_tier
                WHEN 'public' THEN 0
                WHEN 'registered' THEN 1
                WHEN 'vetted' THEN 2
                ELSE 99
            END <= CASE pg_catalog.current_setting('app.viewer_tier', true)
                WHEN 'registered' THEN 1
                WHEN 'vetted' THEN 2
                ELSE 0
            END
            AND NOT EXISTS (
                SELECT 1
                FROM public.dataset_admin_state AS admin_state
                WHERE admin_state.source = oral_history_datasets.source
                    AND admin_state.uuid = oral_history_datasets.uuid
                    AND (
                        admin_state.hidden_at IS NOT NULL
                        OR (
                            admin_state.visibility_tier IS NOT NULL
                            AND CASE admin_state.visibility_tier
                                WHEN 'public' THEN 0
                                WHEN 'registered' THEN 1
                                WHEN 'vetted' THEN 2
                                ELSE 99
                            END > CASE pg_catalog.current_setting('app.viewer_tier', true)
                                WHEN 'registered' THEN 1
                                WHEN 'vetted' THEN 2
                                ELSE 0
                            END
                        )
                    )
            )
            AND NOT EXISTS (SELECT 1 FROM public.ingestion_quarantine AS quarantine
                WHERE quarantine.source = oral_history_datasets.source
                  AND quarantine.uuid = oral_history_datasets.uuid)
        );

        CREATE POLICY catalogue_scheduler_all ON public.oral_history_datasets
        FOR ALL TO PUBLIC
        USING (CURRENT_USER = 'oralhistarchiv_scheduler')
        WITH CHECK (CURRENT_USER = 'oralhistarchiv_scheduler');

    """
    )
    op.execute(
        "CREATE FUNCTION public.catalogue_scan_ceiling() RETURNS integer "
        "LANGUAGE sql STABLE SECURITY DEFINER "
        "PARALLEL UNSAFE SET search_path = pg_catalog, public AS $scan_ceiling$"
        + _CATALOGUE_SCAN_CEILING_SOURCE
        + "$scan_ceiling$"
    )

    op.execute(
        "CREATE FUNCTION public.catalogue_page_ids("
        "p_anchor integer, p_ceiling integer, p_backward boolean, "
        "p_limit integer, p_offset integer, p_query jsonb) "
        "RETURNS SETOF integer LANGUAGE plpgsql STABLE SECURITY DEFINER "
        "PARALLEL UNSAFE SET search_path = pg_catalog, public AS $page_ids$"
        + _CATALOGUE_PAGE_IDS_SOURCE
        + "$page_ids$"
    )

    op.execute("REVOKE ALL ON FUNCTION public.catalogue_scan_ceiling() FROM PUBLIC")
    op.execute(
        "REVOKE ALL ON FUNCTION public.catalogue_page_ids("
        "integer, integer, boolean, integer, integer, jsonb) FROM PUBLIC"
    )


def downgrade() -> None:
    """Drop baseline schema objects and pg_trgm, destroying stored application data; SQL errors
    propagate.
    """
    op.execute("DROP VIEW IF EXISTS public.catalogue_search_candidates")
    for table in ("oral_history_datasets", "dataset_admin_state", "ingestion_quarantine"):
        op.execute(f"DROP TRIGGER IF EXISTS trg_search_projection_lock ON public.{table}")
        op.execute(f"DROP TRIGGER IF EXISTS trg_search_projection_refresh ON public.{table}")
    op.execute(
        "DROP FUNCTION IF EXISTS public.catalogue_page_ids("
        "integer, integer, boolean, integer, integer, jsonb)"
    )
    op.execute("DROP FUNCTION IF EXISTS public.catalogue_scan_ceiling()")
    for signature in reversed(_SEARCH_FUNCTION_SOURCES):
        op.execute(f"DROP FUNCTION IF EXISTS public.{signature}")
    op.execute("DROP POLICY IF EXISTS catalogue_web_select ON public.oral_history_datasets")
    op.execute("DROP POLICY IF EXISTS catalogue_scheduler_all ON public.oral_history_datasets")
    op.execute("""
        DROP TABLE IF EXISTS public.catalogue_search_public;
        DROP TABLE IF EXISTS public.catalogue_search_registered;
        DROP TABLE IF EXISTS public.catalogue_search_vetted;
        DROP TABLE IF EXISTS public.catalogue_search_policy;
        DROP VIEW IF EXISTS public.dataset_admin_catalogue;
        DROP VIEW IF EXISTS public.catalogue_discovery;
        DROP TABLE IF EXISTS pending_totp_rotations;
        DROP TABLE IF EXISTS email_outbox;
        DROP TABLE IF EXISTS anonymous_mail_issuance;
        DROP TABLE IF EXISTS federation_policy_state;
        DROP TABLE IF EXISTS admin_promotion_requests;
        DROP TABLE IF EXISTS totp_recovery_codes;
        DROP TABLE IF EXISTS sessions;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS ingestion_quarantine;
        DROP TABLE IF EXISTS ingestion_failures;
        DROP TABLE IF EXISTS sync_status;
        DROP TABLE IF EXISTS source_binding_acknowledgements;
        DROP TABLE IF EXISTS dataset_admin_state;
        DROP TABLE IF EXISTS oral_history_datasets;
        DROP FUNCTION IF EXISTS public.catalogue_preserve_source_security_state();
        DROP TABLE IF EXISTS source_security_state;
        DROP FUNCTION IF EXISTS public.catalogue_audit_restriction_state();
        DROP TABLE IF EXISTS security_audit_receipts;
        DROP TABLE IF EXISTS security_audit_events;
        DROP FUNCTION IF EXISTS update_search_text();
        DROP EXTENSION IF EXISTS pg_trgm;
    """)

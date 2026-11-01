"""Current catalogue SQL for page/count paths and runtime drift checks.

These strings are database contracts. Keep SQL values bound, owner relations
qualified, and private catalogue ordering inside the reviewed function boundary.
Historical Alembic revisions retain their own literal SQL snapshots. Changes
here require a corresponding reviewed migration; revisions must not import this
module to obtain their SQL."""

from .search_mask_contract import SEARCH_MASK_PROTOCOL_TAG

CATALOGUE_SCAN_CEILING_SOURCE = """
    SELECT COALESCE((
        SELECT stored.id
        FROM public.oral_history_datasets AS stored
        WHERE NOT EXISTS (
            SELECT 1 FROM public.dataset_admin_state AS hidden_state
            WHERE hidden_state.source = stored.source AND hidden_state.uuid = stored.uuid
              AND hidden_state.hidden_at IS NOT NULL
        )
        AND NOT EXISTS (
            SELECT 1 FROM public.ingestion_quarantine AS quarantine
            WHERE quarantine.source = stored.source AND quarantine.uuid = stored.uuid
        )
        ORDER BY stored.id DESC
        LIMIT 1
    ), 0);
"""

# A compatibility view delegates to the same audience-isolated query boundary.
CATALOGUE_SEARCH_CANDIDATES_DEFINITION = " SELECT catalogue_search_candidates() AS id;"

CATALOGUE_PAGE_IDS_SOURCE = "".join(
    (
        "\n-- ",
        SEARCH_MASK_PROTOCOL_TAG,
        r"""
DECLARE
    relation_name text := public.catalogue_search_relation(p_query);
    query_ts tsquery;
    anchor_identity integer;
    anchor_timestamp timestamptz;
    nonnull_seek text;
    null_seek text;
    traversal text;
    null_position text;
    rows_sql text;
    page_sql text;
BEGIN
    IF p_ceiling IS NULL OR p_ceiling < 0
       OR p_backward IS NULL
       OR p_limit IS NULL OR p_limit < 1 OR p_limit > 10000
       OR p_offset IS NULL OR p_offset < 0 OR p_offset > 9900
       OR (p_anchor IS NOT NULL AND (p_anchor < 1 OR p_anchor > p_ceiling))
       OR (p_anchor IS NOT NULL AND p_offset <> 0)
       OR (p_backward AND p_anchor IS NULL) THEN
        RAISE EXCEPTION 'invalid catalogue page bounds' USING ERRCODE = '22023';
    END IF;
    IF p_query ->> 'mode' IN ('auto', 'web') THEN
        query_ts := pg_catalog.websearch_to_tsquery(
            'pg_catalog.simple'::regconfig, p_query ->> 'term');
    END IF;
    IF p_ceiling = 0 THEN RETURN; END IF;
    -- Each fixed audience name identifies its own physical table and indexes.
    -- User-controlled predicates never reference the unrestricted record store.
    rows_sql := pg_catalog.format($rows$
        WITH permitted AS NOT MATERIALIZED (
            SELECT projection.id, projection.upstream_modified_at
            FROM public.%I AS projection
            WHERE projection.id <= $1
              AND ($2 = '' OR projection.keywords @> ARRAY[$2])
              AND ($3 = '' OR projection.languages @> ARRAY[$3])
              AND ($4 = '' OR projection.access_level = $4)
              AND ($5 = 'empty'
                OR ($5 <> 'literal' AND projection.search_vector @@ $6)
                OR ($5 <> 'web' AND (projection.public_document ILIKE $7
                    OR projection.literal_document ILIKE $7)))
        )
    $rows$, relation_name);
    IF p_anchor IS NOT NULL THEN
        EXECUTE rows_sql || 'SELECT id, upstream_modified_at FROM permitted WHERE id = $9'
        INTO anchor_identity, anchor_timestamp
        USING p_ceiling, p_query ->> 'keyword', p_query ->> 'language', p_query ->> 'access_level',
            p_query ->> 'mode', query_ts, p_query ->> 'pattern', anchor_timestamp, p_anchor;
        IF anchor_identity IS NULL THEN RETURN; END IF;
    END IF;
    IF p_backward THEN traversal := 'ASC'; null_position := 'NULLS FIRST';
    ELSE traversal := 'DESC'; null_position := 'NULLS LAST'; END IF;
    IF p_anchor IS NULL THEN nonnull_seek := 'TRUE'; null_seek := 'TRUE';
    ELSIF anchor_timestamp IS NULL THEN
        nonnull_seek := CASE WHEN p_backward THEN 'TRUE' ELSE 'FALSE' END;
        null_seek := CASE WHEN p_backward THEN 'id > $9' ELSE 'id < $9' END;
    ELSE
        nonnull_seek := CASE WHEN p_backward
            THEN '(upstream_modified_at, id) > ($8, $9)'
            ELSE '(upstream_modified_at, id) < ($8, $9)' END;
        null_seek := CASE WHEN p_backward THEN 'FALSE' ELSE 'TRUE' END;
    END IF;
    page_sql := rows_sql || pg_catalog.format($page$
        SELECT bounded.id FROM (
            (SELECT id, upstream_modified_at FROM permitted
             WHERE upstream_modified_at IS NOT NULL AND (%s)
             ORDER BY upstream_modified_at %s %s, id %s LIMIT $10)
            UNION ALL
            (SELECT id, upstream_modified_at FROM permitted
             WHERE upstream_modified_at IS NULL AND (%s)
             ORDER BY upstream_modified_at %s %s, id %s LIMIT $10)
        ) AS bounded
        ORDER BY bounded.upstream_modified_at %s %s, bounded.id %s
        LIMIT $11
    $page$, nonnull_seek, traversal, null_position, traversal,
        null_seek, traversal, null_position, traversal, traversal, null_position, traversal);
    IF p_offset > 0 THEN page_sql := page_sql || ' OFFSET $12'; END IF;
    RETURN QUERY EXECUTE page_sql
    USING p_ceiling, p_query ->> 'keyword', p_query ->> 'language', p_query ->> 'access_level',
        p_query ->> 'mode', query_ts, p_query ->> 'pattern', anchor_timestamp, p_anchor,
        p_limit + p_offset, p_limit, p_offset;
END;
""",
    )
)

__all__ = [
    "CATALOGUE_PAGE_IDS_SOURCE",
    "CATALOGUE_SCAN_CEILING_SOURCE",
    "CATALOGUE_SEARCH_CANDIDATES_DEFINITION",
]

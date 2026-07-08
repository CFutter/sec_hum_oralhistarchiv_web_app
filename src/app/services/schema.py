"""Single source of truth for the oral_history_datasets column list.

Used by datasets.py (SELECT), sync.py (INSERT/UPSERT), and
seed_mock_data.py to avoid maintaining parallel column lists.
"""
from psycopg import sql

# Columns selected and inserted by application code.
# Does NOT include 'id' (auto-generated) or 'data'/'last_modified'
# (set only during writes, not selected in standard reads).
DATASET_COLUMNS = [
    "uuid", "title", "project_title", "description",
    "resource_description", "languages", "project_description",
    "authors", "keywords", "resource_proxies", "license_val",
    "license_url", "access_level", "institutions", "version",
    "doi", "resource_type", "main_disciplines",
    "bibliographical_citation", "source", "visibility_tier",
]

# Columns used in SELECT queries (no institutions/main_disciplines
# since they're not on the Dataset dataclass)
DATASET_SELECT_COLUMNS = [
    "id", "uuid", "title", "project_title", "description",
    "resource_description", "languages", "project_description",
    "authors", "keywords", "resource_proxies", "license_val",
    "license_url", "access_level", "version", "doi", "resource_type",
    "bibliographical_citation", "source", "visibility_tier",
]

# Pre-built SQL fragments
DATASET_SELECT_SQL = sql.SQL(", ").join(map(sql.Identifier, DATASET_SELECT_COLUMNS))

# For INSERT: column list + matching placeholders
DATASET_INSERT_COLUMNS = DATASET_COLUMNS + ["data", "last_modified"]
DATASET_INSERT_SQL = sql.SQL(", ").join(map(sql.Identifier, DATASET_INSERT_COLUMNS))
DATASET_INSERT_PLACEHOLDERS = sql.SQL(", ").join([sql.Placeholder()] * len(DATASET_INSERT_COLUMNS))

# Fields on Dataset that are computed in _parse_dataset(),
# not read directly from a database column.
DATASET_COMPUTED_FIELDS = {"download_url", "landing_page_url"}

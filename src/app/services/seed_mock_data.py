"""Seed restricted demonstration records in development or staging.

SEED_MOCK_DATA enables calls from the development web lifespan or
staging scheduler after preflight; staging web workers do not write them.
"""

import logging
from datetime import datetime
from typing import Any, cast

from psycopg.rows import tuple_row
from psycopg_pool import AsyncConnectionPool

from config import settings

from .access_tiers import AccessTier
from .db import get_db_cursor
from .schema import PARSER_OWNED, build_record_params
from .sync import upsert_dataset

logger = logging.getLogger(__name__)

MOCK_RESTRICTED_DATASETS = [
    {
        "uuid": "mock:restricted:001",
        "title": "Memories of Forced Migration - Restricted Mock Data",
        "project_title": "Displacement and Identity",
        "description": "Anonymized oral history interviews documenting experiences of forced displacement during the 1990s. Contains sensitive biographical accounts.",
        "resource_description": "12 anonymized interview transcripts, 45 hours total.",
        "languages": ["German", "Russian", "Spanish"],
        "project_description": "A research project documenting the long-term psychological and social impact of forced migration on displaced communities.",
        "authors": ["Dr. Alice Meier", "Prof. Peter Muster"],
        "keywords": [
            "forced migration",
            "displacement",
            "trauma",
            "identity",
            "refugees",
        ],
        "resource_proxies": [],
        "license_val": "Restricted access — ethics board approval required",
        "license_url": None,
        "access_level": "restricted",
        "institutions": ["Oral History Archive University of Zurich"],
        "version": "1.0",
        "doi": "https://doi.org/10.48656/mock-restricted-001",
        "resource_type": "Corpus",
        "main_disciplines": ["History", "Migration Studies"],
        "bibliographical_citation": "Meier, A. & Muster, P. (2025). Memories of Forced Migration (Version 1.0) [Data set].",
        "source": "mock",
        "visibility_tier": "vetted",
        "upstream_modified_at": "2025-05-24T08:55:33Z",
    },
    {
        "uuid": "mock:restricted:002",
        "title": "Voices from ... - Restricted Mock Data",
        "project_title": "Swiss Contract Children Oral Histories",
        "description": "Deeply personal testimonies from placement in compulsory labor during the 20th century. Contains accounts of abuse and institutional neglect.",
        "resource_description": "8 full-length interview recordings with transcripts, 32 hours total.",
        "languages": ["German", "Swiss German"],
        "project_description": "An oral history documentation project preserving the voices of surviving  commissioned by the Independent Expert Commission on Administrative Coercion.",
        "authors": ["Anonymous"],
        "keywords": ["institutional abuse", "Swiss history", "coerced labor"],
        "resource_proxies": [],
        "license_val": "Restricted access — vetted researchers only",
        "license_url": None,
        "access_level": "restricted",
        "institutions": ["Oral History Archive University of Zurich"],
        "version": "2.0",
        "doi": "https://doi.org/10.48656/mock-restricted-002",
        "resource_type": "Corpus",
        "main_disciplines": ["History", "Social Work"],
        "bibliographical_citation": "Anonymous (2024). Voices from ... (Version 2.0) [Data set].",
        "source": "mock",
        "visibility_tier": "vetted",
        "upstream_modified_at": "2024-01-08T07:53:15Z",
    },
    {
        "uuid": "mock:restricted:003",
        "title": "Survivor Testimonies — Zurich Collection - Restricted Mock Data",
        "project_title": "Living Memory: Swiss Oral Histories",
        "description": "First-person accounts from survivors who settled in Switzerland. Contains highly sensitive biographical and family history information.",
        "resource_description": "15 video-recorded interviews with transcripts in multiple languages, 68 hours total.",
        "languages": ["German", "French"],
        "project_description": "A comprehensive documentation of survivor experiences with focus on integration in society and intergenerational memory transmission.",
        "authors": ["Prof. Ruth Doe", "Dr. Hans Meier"],
        "keywords": ["survivors", "testimony", "memory", "post-war"],
        "resource_proxies": [],
        "license_val": "Restricted access — requires institutional approval and ethics clearance",
        "license_url": None,
        "access_level": "restricted",
        "institutions": ["Oral History Archive University of Zurich"],
        "version": "3.0",
        "doi": "https://doi.org/10.48656/mock-restricted-003",
        "resource_type": "Corpus",
        "main_disciplines": ["History", "Memory Studies"],
        "bibliographical_citation": "Doe, R. & Meier, H. (2023). Holocaust Survivor Testimonies — Zurich Collection (Version 3.0) [Data set].",
        "source": "mock",
        "visibility_tier": "vetted",
        "upstream_modified_at": "2023-11-17T14:45:53Z",
    },
]


async def seed_mock_data(pool: AsyncConnectionPool) -> int:
    """Upsert the mock records atomically and return the number processed, including updates.

    Raise RuntimeError in production; validation and database errors
    propagate. The caller controls whether SEED_MOCK_DATA enables this call.
    """

    if settings.is_production:
        raise RuntimeError("seed_mock_data is dev or staging only; refusing to run in production")

    count = 0

    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        for record in MOCK_RESTRICTED_DATASETS:
            parsed: dict[str, Any] = {key: record[key] for key in PARSER_OWNED}
            parsed["upstream_modified_at"] = datetime.fromisoformat(
                cast(str, parsed["upstream_modified_at"])
            )
            params = build_record_params(
                parsed,
                access_level=cast(str, record["access_level"]),
                source="mock",
                visibility_tier=cast(AccessTier, record.get("visibility_tier", "vetted")),
            )
            await upsert_dataset(cur, params)
            count += 1
    logger.info("Seeded/refreshed %d mock restricted datasets.", count)

    return count

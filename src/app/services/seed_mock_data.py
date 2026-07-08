"""Mock data seeder — inserts sample restricted datasets for development.

Invoked from the application lifespan when FASTAPI_DEBUG is true; there
is no standalone CLI entry point. seed_mock_data(pool) refuses to run
in production.

These records simulate Phase 2 "Source B" data with restricted access
levels, allowing development and testing of the tiered visibility
system without requiring the actual sensitive data source.
"""

import logging

from psycopg_pool import AsyncConnectionPool
from psycopg.rows import tuple_row
from typing import cast

from .db import get_db_cursor
from .access_tiers import AccessTier

# Internal function import, for seed_mock_data.py will be deleted before prod.
from .sync import _build_record_params, _upsert_dataset
from config import settings

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
        "keywords": ["forced migration", "displacement", "trauma", "identity", "refugees"],
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
        "keywords": [ "institutional abuse", "Swiss history", "coerced labor"],
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
    },
]


async def seed_mock_data(pool: AsyncConnectionPool) -> int:
    """Insert mock restricted datasets into the database."""

    if settings.is_production:
        raise RuntimeError("seed_mock_data is dev-only; refusing to run in production")

    count = 0

    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        for record in MOCK_RESTRICTED_DATASETS:
            params = _build_record_params(
                record,
                access_level=cast(str, record["access_level"]),
                source="mock",
                visibility_tier=cast(AccessTier, record.get("visibility_tier", "vetted")),
            )
            await _upsert_dataset(cur, params)
            count += 1
    logger.info("Seeded/refreshed %d mock restricted datasets.", count)

    return count
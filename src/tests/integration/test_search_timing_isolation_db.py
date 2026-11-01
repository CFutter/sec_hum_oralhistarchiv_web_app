"""Forbidden term frequency cannot enter lower-audience search indexes or plans."""

import json
import random
import statistics
import time
from collections import defaultdict

import psycopg
import pytest
from psycopg.rows import tuple_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.services.db import get_catalogue_cursor
from tests.integration import test_search_plans_db
from tests.source_fixtures import legacy_source

_SOURCE = "timing_source"
_FORBIDDEN = "hiddenneedle"
_ABSENT = "absentneedle"
_RECORDS = 5000
_MODES = ("web", "literal", "keyword", "language")

deployed_database = test_search_plans_db.deployed_database
match_plan_probe = test_search_plans_db.match_plan_probe


def _projection_signature(owner, audience):
    """Read logical and physical fingerprints of one audience search projection."""
    return owner.execute(
        f"SELECT count(*), md5(string_agg(row_to_json(projection)::text, '' ORDER BY id)), "
        f"md5(string_agg(projection.ctid::text || ':' || projection.xmin::text, '' ORDER BY id)) "
        f"FROM public.catalogue_search_{audience} AS projection"
    ).fetchone()


def _query(policy, viewer, mode, needle):
    """Build the audience-specific JSON query context for the selected search mode."""
    rank = ("public", "registered", "vetted").index(viewer)
    return Jsonb(
        {
            "mode": mode if mode in {"web", "literal"} else "empty",
            "term": needle if mode in {"web", "literal"} else "",
            "pattern": f"%{needle}%" if mode in {"web", "literal"} else "%%",
            "keyword": needle if mode == "keyword" else "",
            "language": needle if mode == "language" else "",
            "access_level": "",
            "masks": dict(policy.page_masks[rank]),
            "fingerprint": policy.fingerprint,
        }
    )


def _plan_values(node, name):
    """Yield every value for the named key in a nested JSON plan."""
    if isinstance(node, dict):
        if name in node:
            yield node[name]
        for value in node.values():
            yield from _plan_values(value, name)
    elif isinstance(node, list):
        for value in node:
            yield from _plan_values(value, name)


async def _count(cursor, context):
    """Count matching catalogue IDs for the supplied query context."""
    await cursor.execute("SELECT count(*) FROM public.catalogue_match_ids(%s)", (context,))
    row = await cursor.fetchone()
    assert row is not None
    return row[0]


async def _measure_and_explain(pool, policy, viewer):
    """Compare hidden and absent terms using counts, plans and timing samples."""
    measurements = {}
    async with get_catalogue_cursor(pool, viewer, row_factory=tuple_row) as cursor:
        for mode in _MODES:
            contexts = {
                needle: _query(policy, viewer, mode, needle) for needle in (_FORBIDDEN, _ABSENT)
            }
            for context in contexts.values():
                assert await _count(cursor, context) == 0
                await cursor.execute("SELECT public.catalogue_match_plan_probe(%s)", (context,))
                row = await cursor.fetchone()
                assert row is not None
                plan = row[0]
                detail = json.dumps(plan, indent=2)
                assert set(_plan_values(plan, "Relation Name")) == {f"catalogue_search_{viewer}"}, (
                    detail
                )
                assert all(
                    index.startswith(f"idx_catalogue_search_{viewer}_")
                    or index == f"catalogue_search_{viewer}_pkey"
                    for index in _plan_values(plan, "Index Name")
                ), detail

            # Equal-sized interleaved samples avoid giving one term a systematic
            # warm-cache or scheduling advantage. Warmups are not measurements.
            order = [_FORBIDDEN, _ABSENT] * 12
            random.Random(20261027).shuffle(order)
            samples = defaultdict(list)
            for needle in order:
                started = time.perf_counter()
                assert await _count(cursor, contexts[needle]) == 0
                samples[needle].append(time.perf_counter() - started)
            medians = {needle: statistics.median(values) for needle, values in samples.items()}
            lower, upper = sorted(medians.values())
            # Structural checks establish the privacy property. This broad
            # threshold also catches a substantial accidental latency split
            # without treating sub-millisecond host jitter as an information leak.
            assert upper <= max(0.015, lower * 4), (viewer, mode, medians)
            measurements[mode] = medians
    return measurements


@pytest.mark.usefixtures("match_plan_probe")
async def test_forbidden_frequency_preserves_lower_projection_and_actual_web_search_work(
    deployed_database, bind_catalogue_policy, record_testsuite_property
):
    """Verify forbidden frequency preserves lower projection and actual web search work."""
    sources = (legacy_source(name=_SOURCE, max_visibility="public"),)
    owner_url = deployed_database["oralhistarchiv"]
    policy = bind_catalogue_policy(sources, database_url=owner_url)
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "INSERT INTO public.oral_history_datasets "
            "(source, uuid, title, description, keywords, languages, access_level, visibility_tier) "
            "SELECT %s, 'timing-' || n, 'Public discovery title', 'ordinarycontext', "
            "ARRAY['ordinarykeyword'], ARRAY['de'], 'public', 'vetted' "
            "FROM generate_series(1, %s) AS fixture(n)",
            (_SOURCE, _RECORDS),
        )
        before = {
            audience: _projection_signature(owner, audience)
            for audience in ("public", "registered")
        }
        owner.execute(
            "UPDATE public.oral_history_datasets SET description = repeat(%s || ' ', 16), "
            "keywords = ARRAY[%s], languages = ARRAY[%s] WHERE source = %s",
            (_FORBIDDEN, _FORBIDDEN, _FORBIDDEN, _SOURCE),
        )
        assert before == {
            audience: _projection_signature(owner, audience)
            for audience in ("public", "registered")
        }
        assert all(signature[0] == _RECORDS for signature in before.values())
        owner.commit()
        owner.autocommit = True
        for audience in ("public", "registered", "vetted"):
            owner.execute(f"VACUUM (ANALYZE) public.catalogue_search_{audience}")

    measurements = {}
    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_web"], min_size=1, max_size=1, open=False
    ) as pool:
        await pool.wait(timeout=5)
        for viewer in ("public", "registered"):
            measurements[viewer] = await _measure_and_explain(pool, policy, viewer)
        # The contrasting corpus really contains the term in all protected
        # records, and the higher audience can retrieve those matches.
        async with get_catalogue_cursor(pool, "vetted", row_factory=tuple_row) as cursor:
            for mode in _MODES:
                assert await _count(cursor, _query(policy, "vetted", mode, _FORBIDDEN)) == _RECORDS
                assert await _count(cursor, _query(policy, "vetted", mode, _ABSENT)) == 0
    record_testsuite_property(
        "audience_search_timing_seconds", json.dumps(measurements, sort_keys=True)
    )

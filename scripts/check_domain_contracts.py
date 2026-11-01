"""Check audience projection SQL against shared tier/source facts without settings.

Frozen migrations remain independent and are checked against runtime SQL by the
schema preflight. These checks catch independently changed current domain facts.
"""

import re
from typing import get_args

from app import SEARCH_FUNCTION_SOURCES
from app.ingestion_contracts import ACCESS_TIER_RANK, AccessTier
from app.source_contract import SOURCE_NAME_SQL_PATTERN

_TIER_CASE = re.compile(r"WHEN\s+'(public|registered|vetted)'(?:::text)?\s+THEN\s+(\d+)")
_SOURCE_MASK_PATTERN = re.compile(r"item\.key !~ '([^']+)'")
_AUDIENCE_ARRAY = re.compile(r"audience := \(ARRAY\[([^]]+)\]\)\[viewer \+ 1\]")
_AUDIENCE_ALLOWLIST = re.compile(r"audience NOT IN \(([^)]+)\)")


def _quoted_values(value: str) -> tuple[str, ...]:
    """Return single-quoted substrings in encounter order; SQL escape sequences are not decoded."""
    return tuple(re.findall(r"'([^']+)'", value))


def verify_domain_sql(projection_sql: str, policy_sql: str, relation_sql: str) -> None:
    """Verify record ranks, audience partition selection and source mask syntax."""
    expected_ranks = dict(ACCESS_TIER_RANK)
    if set(expected_ranks) != set(get_args(AccessTier)):
        raise ValueError("Access tier declarations and ranks differ")
    found = _TIER_CASE.findall(projection_sql)
    if not found or {tier for tier, _rank in found} != set(expected_ranks):
        raise ValueError("Projection SQL is missing a declared access tier")
    if any(expected_ranks[tier] != int(rank) for tier, rank in found):
        raise ValueError("Projection SQL access tier ranks differ")
    audiences = tuple(sorted(expected_ranks, key=expected_ranks.__getitem__))
    projected = _AUDIENCE_ARRAY.findall(projection_sql)
    accepted = _AUDIENCE_ALLOWLIST.findall(relation_sql)
    if len(projected) != 1 or _quoted_values(projected[0]) != audiences:
        raise ValueError("Projection SQL audience order differs")
    if len(accepted) != 1 or _quoted_values(accepted[0]) != audiences:
        raise ValueError("Query SQL audience allowlist differs")
    if _SOURCE_MASK_PATTERN.findall(policy_sql) != [SOURCE_NAME_SQL_PATTERN]:
        raise ValueError("Projection policy SQL source syntax differs")


def main() -> int:
    """Fail the authoring gate when current SQL disagrees with shared contracts."""
    try:
        verify_domain_sql(
            SEARCH_FUNCTION_SOURCES["catalogue_refresh_search_record(p_id integer)"],
            SEARCH_FUNCTION_SOURCES[
                "catalogue_replace_search_policy(p_expected text, "
                "p_fingerprint text, p_masks jsonb)"
            ],
            SEARCH_FUNCTION_SOURCES["catalogue_search_relation(p_query jsonb)"],
        )
    except ValueError as error:
        print(str(error))
        return 1
    print("Shared domain facts match current audience projection SQL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

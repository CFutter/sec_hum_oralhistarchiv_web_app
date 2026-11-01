# JSON-feed records and harvest assembly

The builder combines [authenticated pages](json-feed-transport.md),
[page-chain validation](json-feed-pages.md) and native metadata checks into
bounded harvest bytes. The [adapter](json-feed-adapter.md) runs this work
in one terminating child.

## Validate records

The native validator enforces the v1 field set, nullable/text/list bounds,
controlled license labels, numeric release labels and canonical metadata tiers.
DOI values are nullable but limited to 512 characters, matching the shared
record contract and keeping indexed values within the database write budget.
Unknown or wrongly typed fields are refused without coercion. URL values use
lowercase HTTP(S) schemes and a nonempty hostname. Ports, when supplied, must
parse successfully; user information, whitespace, controls and backslashes are
refused. Any NUL or unpaired Unicode surrogate in a string is
quarantined for UTF-8/PostgreSQL representability. Labels also reject C0/DEL;
other C0 controls remain permitted in general nullable text.
The producer schema alone does not cover these native checks. It remains a
development check; runtime does not use `jsonschema`.

`modified_at` must be a whole UTC second within the inclusive normalized `since`
to snapshot-cutoff interval; a rebuild has no lower bound. The engine already
supplies its overlap. The validator rounds that supplied boundary down to a
whole second and does not subtract another overlap.

Candidate serialization revalidates accepted metadata through `ParsedRecord`.
`project_title` uses the source's `max_project_title_chars` (default 4,096,
range 1–16,384); the shared contract accepts the full 16,384-character ceiling.
An identifiable over-limit title yields `record_metadata`, preserving valid
neighbours through serialization. Other identifiable shape, tier, timestamp, metadata and
duplicate-key failures yield identity-only fixed reasons; rejected metadata is discarded.
Malformed or ambiguous identities still abort the complete chain. These rules
establish structural validity, not source-owner approval for public disclosure.
Reason precedence is identity failure, duplicate key, `record_shape`, `record_tier`,
`record_timestamp`, then `record_metadata`; identity failures abort the chain.

## Assemble a candidate

```python
from datetime import UTC, datetime

from app.sources import JsonFeedHarvestBuilder

# config and authenticated_page come from the preceding preparation/page APIs.
builder = JsonFeedHarvestBuilder(config, since=None)
builder.accept(authenticated_page, now=datetime.now(UTC))
if builder.complete:
    candidate_bytes = builder.finish()
else:
    continuation = builder.next_cursor
```

This is a page fragment, not a complete runtime fetch. `accept()` returns no
partial harvest. Follow `next_cursor` until completion, with the same lower bound
and fresh authenticated requests. `finish()` succeeds once, only after the full
page chain passes. It returns serialized, validated `HarvestResult` bytes and
enforces `max_result_bytes` against their actual length, including quarantine
identifiers/reasons and withdrawals. The first page's cutoff is `source_cursor`.

Rejections become `uncertain_records`, retaining only identities and fixed
reasons for later reconciliation. The engine withholds any existing serving
copy until a valid fresh correction commits; see [persistence](json-feed-persistence.md).
The builder emits no rejected metadata. A fatal failure,
incomplete finish or reuse discards accumulated metadata and invalidates the
builder; no partial candidate is returned.

## Remaining acceptance

Candidate bytes do not persist rows, advance the committed cursor, emit database
audit events or apply stored/admin tier floors. Those remain engine/application
responsibilities. B6 adds its committed-cutoff guard before staging, replay writes
and full-apply removals.

The [B6 adapter](json-feed-adapter.md) encloses direct HTTP, this builder and
serialization in one terminating child. Parent reconstruction is size-bounded
with deadline checks, without separate forced termination.
[Application checks](json-feed-acceptance.md) cover persistence, audit, catalogue
and synthetic recovery; real-source approval and representative restore remain
separate. See [Feed Contract v1](feed-contract-v1.md).

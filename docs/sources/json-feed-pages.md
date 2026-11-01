# JSON-feed page validation

Validate [authenticated bytes](json-feed-transport.md), envelopes and public
identities while preserving original record bytes.
[Record validation](json-feed-records.md) assembles a harvest; the
[adapter](json-feed-adapter.md) encloses both in one terminating worker.

## Validate an authenticated page

Use the owning-package API with a fixed configuration and inclusive lower bound.
Only pass pages authenticated by the transport: the input DTO alone is not proof
of a valid signature. This fragment is not a complete runtime fetch:

```python
from datetime import UTC, datetime

from app.sources import JsonFeedPageValidator

# transport and feeds come from the B2/B3 preparation examples.
validator = JsonFeedPageValidator(feeds[0], since=None)
authenticated = transport.read_page(since=None)
page = validator.accept(authenticated, now=datetime.now(UTC))
if validator.complete:
    cutoff = validator.finish()
else:
    continuation = validator.next_cursor
```

Continuation requests must use the validator's next cursor and a fresh nonce.
`since`, when supplied, and `now` must be aware datetimes. The lower bound uses the transport's
UTC whole-second normalization. `accept()` returns an immutable
`ValidatedFeedPage`: request, snapshot ID, aware cutoff, records, quarantine
markers, withdrawals, next cursor and completion flag.

`finish()` returns only the cutoff after a complete chain. It does not produce
`HarvestResult`, reconcile records, advance durable state or write the database.
Finishing an incomplete chain fails. A fatal page error, incomplete finish or
attempt to accept another page after completion poisons the validator; start a
new instance for a new attempt. Successful finish does not reopen the chain.

## JSON, request binding and pagination

UTF-8 decoding is strict. A BOM, trailing data, invalid JSON and non-JSON numeric
constants such as NaN or Infinity are refused. Lossless object pairs preserve
duplicate evidence, including escaped aliases for the same decoded key. Valid
JSON numbers such as `1e999` remain legal syntax rather than being silently
converted into infinity; B5 then classifies them against the metadata field type.

The envelope has exactly eight keys and its request has exactly three. Version
is integer 1, without boolean or floating-point substitution. UUIDs are canonical
lowercase UUIDv4; protocol timestamps are real UTC whole seconds in the v1 shape.
The echoed nonce, since and cursor must exactly match the transport request.
Each nonce is new, each continuation follows the previous cursor, and repeated
cursors are refused. All pages retain one snapshot ID and cutoff.

At every page, the cutoff must be within 600 seconds of the supplied current UTC
time and cannot precede `since`. Completion and next-cursor state must agree.
These checks bind an authenticated response to this page chain; durable committed
cursor rollback protection is not supplied here. B5 separately checks record
timestamps against the inclusive selection interval.

## Record identities and quarantine markers

Every record must be an object with exactly one valid public UUID. Repeated
identities anywhere in records, withdrawals or prior pages abort the chain,
including identities already marked for quarantine. Withdrawals are canonical
UUIDs. Duplicate envelope/request keys and duplicate record identity keys are
fatal even when their values agree.

A duplicate nonidentity record key, including one inside nested metadata, yields
`FeedRecordRejection(uuid, reason="duplicate_record_key")`. Its incoming metadata
is discarded. This marker is not yet a persisted quarantine entry or a proof of
last-known-good retention; later integration must preserve that identity.

Other records become `FeedRecordInput(uuid, body)`: the exact original UTF-8
object bytes, excluded from representations. Title, tier, labels, metadata shape
and `modified_at` remain unvalidated at this boundary. Pass them to the
[B5 record/harvest builder](json-feed-records.md); do not persist or render this
DTO directly. The producer JSON Schema remains a development/producer check,
not a runtime `jsonschema` dependency or a replacement for native validation.

## Budgets and remaining acceptance

Page and aggregate bytes, original record bytes, total record/withdrawal count
and page count are bounded, including quarantined input. Original bytes include
whitespace and escapes; records are not reserialized for byte accounting.
Fixed protocol error codes contain no upstream values or body fragments.

B4's pure call has no terminating deadline. The [B6 adapter](json-feed-adapter.md)
encloses it with direct HTTP, record validation and serialization in one
terminating outer worker, without nesting B3 page workers. Parent reconstruction
is bounded and checks the same deadline. B6 also supplies fingerprint/runtime
wiring and committed-cutoff guards. [Application acceptance](json-feed-acceptance.md)
covers persistence, audit, catalogue and synthetic recovery; source approval and
representative deployed recovery remain separate. See the
[v1 evidence map](feed-contract-v1.md#synthetic-examples-and-executable-evidence).
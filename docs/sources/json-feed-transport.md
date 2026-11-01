# JSON-feed transport

`JsonFeedTransport` reads bounded, authenticated page bytes.
[Page](json-feed-pages.md) and [record](json-feed-records.md) validation are
separate; the production [adapter](json-feed-adapter.md) runs the complete
fetch in one worker.

The [B6 adapter](json-feed-adapter.md) runs the complete source fetch in one
worker, using direct HTTP without nesting this page-worker API. The registry
contains four runnable adapters, including `json_feed`; real-source acceptance
remains separate.

Use [configuration and credential preparation](json-feed-configuration.md)
with the [v1 wire contract](feed-contract-v1.md).

## Supported API audience

`JsonFeedTransport` is a supported lower-level API for integration and protocol
conformance tools that need authenticated page bytes. It is not a second
ingestion implementation: production uses `JsonFeedAdapter` and one worker for
the complete transport/validation/serialization deadline. Page users own the B4
and B5 validation steps and must not submit a page directly as a harvest.

The page and full-fetch workers share one fixed transport-error vocabulary and
encoder. Their distinct `E` and `T` frame prefixes remain compatible with their
respective parents; only the complete-fetch worker carries `P` protocol refusals.

## Read authenticated bytes

`JsonFeedTransport(config, credentials)` accepts a `JsonFeedConfig` and its
matching `JsonFeedCredentials` snapshot. Construction starts one absolute
monotonic deadline. Create a fresh instance for each transport attempt;
reusing it does not reset the deadline or aggregate budgets.

```python
from app.sources import JsonFeedTransport

# feeds and credentials come from B2's explicit preparation example.
transport = JsonFeedTransport(feeds[0], credentials[0])
page = transport.read_page(since=None)
authenticated_bytes = page.body
request = page.request
```

`read_page(*, since, cursor=None)` returns `AuthenticatedFeedPage`, containing
`FeedRequest(nonce, since, cursor)` and the exact authenticated body bytes.
The body is excluded from the page representation. Do not log or decode it as
trusted metadata: HMAC verification establishes integrity, not schema validity
or public-disclosure suitability.

Each request receives a fresh 32-byte random nonce encoded as lowercase hex.
An aware `since` is normalized to UTC and rounded down to a whole second,
widening the inclusive lower bound; naive datetimes are rejected. A cursor is
an opaque bounded query value, never a request-selected URL. There are no
automatic retries.

Nonce creation alone does not establish replay protection:
[B4 page validation](json-feed-pages.md) must also compare the signed request echo
and check freshness and page-chain continuity before the page is accepted.

## Transport checks and budgets

Requests use only the configured HTTPS endpoint, explicit bearer authorization,
JSON accept headers and identity encoding. TLS certificate verification remains
enabled. Redirects are never followed and only status 200 is accepted.
`trust_env=false` excludes ambient proxy, netrc and CA-bundle overrides.

Response headers are checked before body processing. The signature must have
exactly one `X-Feed-Signature` value with the v1 lowercase-hex shape. Only the
contract's JSON content type and absent/identity encoding are accepted.
The body is read as raw bytes without automatic decompression. Page and remaining
aggregate byte limits apply while reading. HMAC-SHA256 is verified over the exact
bytes in constant time before any UTF-8 decoding or JSON parsing.

| Enforced by the page transport | Scope |
|---|---|
| `max_page_bytes` | One raw response body |
| `max_total_bytes` | All response bodies read by this transport instance |
| `max_pages` | All page requests through this instance |
| `fetch_deadline_seconds` | Constructor-owned deadline shared by page reads |

The read-only `pages_requested` and `response_bytes` counters expose transport
accounting. [B4 page validation](json-feed-pages.md) additionally enforces
`max_record_bytes` and `max_records`, including quarantined entries and
withdrawals. [B5 harvest assembly](json-feed-records.md) enforces
`max_result_bytes` against the actual serialized candidate.

The [B6 adapter](json-feed-adapter.md) applies all seven budgets to a complete
source fetch. This page API remains a separate lower-level boundary.

## Termination and failure handling

Each page runs in a real spawned worker. The parent deadline covers DNS lookup,
sockets and stalled or partial worker IPC. The child must exit normally within
the deadline before its result is accepted. Failed or blocked workers are
terminated, killed if necessary, and reaped with bounded cleanup.

Socket inactivity timeouts alone are not the deadline. After a transport or
worker failure, the transport cannot be reused. Invalid caller arguments are
rejected before starting a request.

Transport errors use fixed reason codes: `transport`, `http_status`, `headers`,
`signature`, `resource_limit` or `worker`. They do not include upstream body
text or credential values.

## Validation boundaries and remaining acceptance

B3 itself does not check the signed echo, freshness, snapshot continuity,
page-chain completion, record identities or duplicate JSON keys.
[B4 page validation](json-feed-pages.md) supplies that boundary and identity-only
duplicate-key rejection markers. [B5 record validation](json-feed-records.md)
adds metadata classification and bounded candidate assembly. B3/B4 alone do
not produce a harvest or write the database.

The [B6 adapter](json-feed-adapter.md) puts direct HTTP, JSON parsing, validation
and serialization in one terminating outer worker, without nesting this page
worker. Parent reconstruction is size-bounded and checks the same absolute
deadline; it is not separately force-terminable.

For `JsonFeedConfig` sources, B6 also checks the committed source cursor before
new staging, pending replay writes and full-apply removals, including the
zero-match path. Older cutoffs are rejected; equality is allowed.

Database retention, audit and catalogue behavior have
[application coverage](json-feed-acceptance.md). Source-owner approval and
representative recovery remain deployment requirements under the
[Sensitive Source Contract](../architecture/source-b-ingestion-contract.md).
Authenticated bytes alone do not establish them.
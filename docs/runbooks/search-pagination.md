# Catalogue search and opaque continuation

Search uses bounded catalogue reads and opaque continuation.

Normal search navigation fetches a bounded page and a lookahead row. It does
not compute an exact result count or a catalogue-wide ordering window. The
database keeps the timestamp ordering key private; the application receives
dataset IDs and the seven-field public discovery envelope.

## Numbered pages and continuation

Pages 1–100 use a bounded numbered offset. The service accepts genuine integer
page numbers in that range and page sizes from 1 to 100. A direct numbered
page above 100 receives HTTP 422. A lookahead row determines whether **Next**
is available; the interface shows the current page without claiming a total
number of pages or results. An empty numbered page after page 1 redirects to
page 1 with the same filters and a fixed empty-page notice.

At page 100, the service captures the current identity ceiling and original
scan time. If another row exists, **Next** contains an opaque continuation
bookmark. Cursor requests seek from an identity boundary and use zero offset;
their displayed page counter cannot request an arbitrary deep OFFSET.

**Previous** seeks in reverse while the application restores ordinary catalogue
display order. Returning to page 100 can lead back to numbered page 99.
Submitting a new search or changing/clearing filters discards the bookmark.
Continuation pages offer **Start again** with the current query and filters.
A still-eligible anchor with no remaining rows produces an ordinary empty tail,
not an expired-bookmark error.

## Private ordering boundary

`catalogue_discovery` exposes exactly `id`, `uuid`, `title`, `access_level`,
`version`, `source` and effective `visibility_tier`. It excludes hidden identities
and contains neither a timestamp nor a global ordinal.

The owner-backed functions provide ordering without adding those values to the
public view:

- `catalogue_scan_ceiling()` returns the greatest current nonhidden ID, or zero
  for an empty catalogue.
- `catalogue_page_ids(p_anchor, p_ceiling, p_backward, p_limit, p_offset, p_query)`
  returns a bounded sequence of IDs. It resolves the anchor's current timestamp
  inside PostgreSQL, checks bounds and query context, and applies administrator
  hiding, effective record tier, current field/source masks and exact matching
  filters before limiting candidates.

The order is `upstream_modified_at DESC NULLS LAST, id DESC`. Non-NULL and NULL
timestamp ranges are handled separately in both traversal directions, with
bounded branch results before their final merge. The existing timestamp/ID
index supports that ordering. `WITH ORDINALITY` numbers only the returned page
IDs; it does not rank the whole catalogue. A rare match can still require
examining many candidates, so bounded output is not a constant-time guarantee.

The functions also supply recent-record reads and the 200-ID facet sample.
Their maximum row limit is 10,000; numbered offsets are bounded at 9,900.
Normal search requests at most 101 IDs, including the lookahead row.

Only the web runtime receives direct EXECUTE on these two application functions.
The scheduler and backup identities do not need that privilege. The trusted
application supplies viewer context and source masks; these functions do not
claim to protect against arbitrary SQL executed under the shared web role.
The initial migration keeps immutable revision-local SQL snapshots. Current
startup contracts use the configuration-free `app.catalogue_sql` definitions.
A future SQL change requires a new migration and matching runtime contracts;
editing current application SQL does not change historical migration replay.

## Bookmark contract

Token format version 2 uses a distinct encryption domain and payload version.
Version 1 bookmarks are rejected. Application context version 3 binds each
request to a precomputed digest of the complete immutable catalogue policy;
bookmarks issued with the earlier context restart at page one after upgrade.
The encrypted/authenticated token
carries the anchor ID, identity ceiling, direction, page counter and original
issue time. It contains a context digest rather than plaintext query or
account/session identifiers. Its key is derived from the current `SECRET_KEY`
in a separate HKDF/Fernet domain; changing that key invalidates old bookmarks.

A bookmark is navigation state, not an access grant. Its context binds:

- Parsed query mode/term and keyword, language and access-level filters.
- Current viewer tier, page size and audience, including the signed-in
  account/session binding where applicable.
- Current code/source field minima and selected source policy.

The deadline is one hour from the original page-100 scan time. Every generated
link retains that time. Future/expired times, wrong context, malformed types,
duplicate JSON keys, noncanonical base64 and unsupported versions fail closed.

A normally shaped invalid, expired or now-ineligible-anchor bookmark redirects
once to page 1 with this generic notice:

> This search bookmark has expired or no longer matches. Showing page 1.

The response does not distinguish authentication, context, expiry or anchor
eligibility failures. Inputs exceeding the 2,048-character route limit receive
HTTP 422 before the continuation service runs.

## Exact counts

`count_search_datasets()` is a separate, optional exact-count operation. Its
default requested statement timeout is 2,000 ms; a shorter existing positive
timeout is preserved. A zero existing timeout means unlimited, so the requested
budget applies. Successful nested use restores the previous setting; errors
propagate and the transaction/savepoint rollback restores local settings.

The compatibility `search_datasets()` API fetches its page and requests that
count separately. Concurrent changes can make the count differ from the page.
The HTTP search route uses `search_catalogue_page()`, whose total is `None`, and
does not call the exact-count API merely to render navigation or an empty page.

## Current-state and concurrency limits

Current anchor eligibility and the requested slice share one statement snapshot.
Each request reapplies current search/filter predicates, source/field minima,
administrator hiding, RLS and final Python redaction. A deleted, hidden or
no-longer-matching anchor invalidates a bookmark.

The ceiling excludes higher IDs introduced after handoff. It is not a commit
snapshot: a transaction that allocated a lower ID earlier but committed later
can become visible within that ceiling. Such a row is returned only when its
current logical order falls beyond the current boundary. Updates can move
existing rows across boundaries, causing repeats or omissions between requests.
This is neither a frozen export nor an exactly-once enumeration contract.

## Fresh schema and deployment

The complete view and function definitions are folded into the single initial
revision `4f73ae3ff827`. This package targets the agreed fresh database; it adds
no second revision and supplies no retained-data conversion. Applying the
Python file-update script does not itself execute DDL or reset a database.

An earlier database stamped with this revision will not be changed by
`upgrade head`. Recreate only the explicitly disposable/agreed fresh database,
apply the initial migration and matching deny-first runtime grants, then run
schema and both runtime-role preflights before serving requests. Never stamp
the revision to hide missing objects. The historical
`deploy/upgrade-search-k2.sql` alone does not install this package's ordering
functions or new contracts; retaining a database requires a separately reviewed
conversion procedure.

## Targeted validation

Use Python 3.11, locked dependencies and explicitly disposable PostgreSQL 18
and Redis services. The actual-role fixtures need an isolated cluster without
retained deployment roles or an `oralhistarchiv` database. The unsuffixed test
URL lets pytest select its worker databases.

```bash
export ENV_STATE=dev
export DATABASE_URL='postgresql://test:test@localhost:5432/oralhistarchiv_test'
export REDIS_URL='redis://localhost:6379/0'
export TEST_RATE_LIMIT_REDIS_DB=0
export REQUIRE_DB=1 REQUIRE_REDIS=1

uv run pytest src/tests/unit/test_search_cursor.py \
  src/tests/unit/test_search_pagination_bounds.py \
  src/tests/client/test_search_pagination_routes.py \
  src/tests/integration/test_search_pagination_db.py \
  src/tests/integration/test_catalogue_rls_migration_db.py \
  -n 0 -p no:randomly -q -rs
```

Required evidence includes fresh upgrade/downgrade/re-upgrade; exact schema and
web/scheduler role preflights; page 1/2/99/100 and deep forward/reverse traversal;
mixed/all-NULL timestamp ordering; ties; hidden/deleted/changed anchors; current
field masks and phrase/negation filters; lower-ID late commits; and separate
count timeout/restoration tests. Actual-role tests must exercise function
EXECUTE as well as SELECT. Mocks must validate query parameters and current
result fields rather than accepting the former ordinal/count shape.

Capture real plans for the bounded owner query and retain role, data size,
parameters and settings. Check index availability and absence of global
`WindowAgg`/whole eligible-set materialization. Planner choice and rare-filter
work remain data dependent; synthetic evidence alone does not establish
production throughput.


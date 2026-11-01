# Field-aware full-text search

Search uses independently indexed audience projections and preserves the
private, bounded ordering boundary.

The query modes and allowed-document rules below apply to both the ordered
page function and the separate exact-count API. Normal HTTP navigation does
not request an exact count. See the [pagination contract](search-pagination.md)
for the private timestamp/ID seek, version 2 bookmarks and concurrency limits.

## Query modes

The service trims outer whitespace while preserving the term's spelling, case
and internal whitespace. It selects the following modes in this precedence:

| Input | Mode and matching |
|---|---|
| Empty after trimming | No free-text restriction; other filters still apply |
| Any `%`, `_` or backslash, even alongside quotes or OR | Literal case-insensitive substring, with SQL wildcard/backslash escaping |
| Any double quote, OR between terms in any case, or a leading/whitespace-separated minus immediately before a term | PostgreSQL web-search matching only; no literal fallback |
| Only alphanumeric characters and whitespace | Full-text AND matching or the former escaped literal-substring match |
| Other punctuation without explicit web syntax | Literal case-insensitive substring |

Examples:

| Query | Interpretation |
|---|---|
| `oral history` | Both full-text words must occur in the allowed document, or its legacy text contains the literal phrase |
| `"oral history"` | An ordered phrase in the allowed full-text document |
| `oral OR history` | Either full-text alternative |
| `oral -closed` | The allowed document must match oral and exclude closed |
| `100%`, `case_name`, `path\name` | Literal characters; they do not become SQL wildcards or web operators |
| `oral-history`, `C++` | Literal punctuation unless another explicit web-syntax marker selects web mode |

The full-text document and query both use explicit `pg_catalog.simple`, rather
than the server's default text-search configuration. There is no stemming,
accent folding, language detection or relevance-ranking change. PostgreSQL's
simple configuration and `ILIKE` provide the applicable case-insensitive
matching; the application does not rewrite the submitted term into a different
case or accent spelling. In web mode, PostgreSQL interprets quotes, OR and
minus; other punctuation is subject to its web-query parser.

## One permitted document per row

| Document | Fields, in order |
|---|---|
| Public full-text document | Title, access level |
| Full full-text document | The public document, description, project title, project description, keywords, authors |
| Partially visible full-text document | The public document, then only the permitted members of the five extra fields, in the same order |

The extra fields retain their independent effective record/code/source minima.
A hidden field contributes nothing. A query is evaluated against one permitted
document for that row, including for phrases and negation. For example,
`oral -closed` must not change its result merely because closed occurs only in
a hidden description. A phrase may span the ordinary separators between
permitted fields; hidden words cannot satisfy it.

The database stores separate public, registered and vetted search projections.
Each has its own full-text, trigram, keyword, language and ordering indexes.
Projection documents contain only the audience's permitted fields; user terms
never probe the unrestricted catalogue's stored text/vector/filter indexes.
Literal matching preserves the two historical document layouts, and full-text
matching uses one permitted document so hidden words cannot affect negation.

Record, administrator-state and quarantine triggers refresh these projections
in the mutation transaction. The current source floor and independent source
field minima are compiled into the bound projection policy. Above-tier records
retain their intentionally public discovery text; hidden/quarantined rows have
no serving projection. Policy replacement rebuilds all projections atomically,
and stale worker fingerprints fail closed.

`catalogue_page_ids()` selects one physical audience relation before applying
text and filter predicates, then performs the bounded timestamp/ID seek. The
separate exact-count path uses `catalogue_match_ids()` over the same projection.
Both require the complete bound policy fingerprint in `p_query`. The retained
`catalogue_search_candidates` view delegates to the current audience projection
for compatibility; it does not expose the original shared indexes.

The field-mask protocol remains versioned in
`src/app/search_mask_contract.py`. The language bit is `32` and does not add
languages to the text document. The projection builder, policy fingerprint,
SQL function contracts and bookmarks must remain consistent after protocol
changes. Full-text and literal/index choices still depend on permitted data,
and broad queries still require the separate execution/admission budgets.

See [search policy operations](search-policy.md) for initial binding, explicit
owner-only policy replacement, rolling-worker behavior and verification.

The same private ordering boundary selects recent records and the 200-ID facet
sample. Facets inspect only visible values from those IDs. The home page shows
the live nonhidden dataset total and at most three recent redacted records; it
does not calculate whole-catalogue language or keyword counts. The compatibility
`search_datasets()` API fetches a page and requests an exact count separately;
those statements may
observe concurrent changes. `count_search_datasets()` defaults to a 2,000 ms
requested timeout, preserves a shorter existing positive limit and restores the
prior setting after success. Normal HTTP search uses lookahead and reports no
exact total, including on empty pages.

## Fresh schema and deployment

Search columns, indexes, triggers, projections and ordering functions are
included in the initial revision `4f73ae3ff827`.
This package targets the agreed fresh database and adds no second revision.
The complete function SQL and candidate selectors live in the configuration-free
`app.catalogue_sql` module for current startup contracts. The initial revision
keeps immutable revision-local copies of its SQL; it does not import the current
application definitions. Future changes need a new migration and matching runtime
contracts. Current page functions and count views share candidate branches.
Web receives explicit
EXECUTE on `catalogue_scan_ceiling()` and `catalogue_page_ids()`; scheduler and
backup do not. Reapply the matching deny-first grants and require complete
schema and both runtime-role preflights before serving requests.

`upgrade head` does not rerun an already recorded revision. Stamping cannot
install changed objects or populate derived search state. The historical
`deploy/upgrade-search-k2.sql` does not install this package's ordering functions
or current contracts and is not a retained-database conversion for WP002.
Retaining a database requires a separately reviewed procedure. The file-update
script performs no DDL, reset, backfill, harvest or service action. Recreate only
the explicitly agreed fresh/disposable database as part of the operator's
migration procedure; never point destructive fixtures at a retained catalogue.

Follow the existing [upgrade and rollback boundaries](../configuration/deployment.md#upgrades)
when applying any owner-only database action. There is no generic safe downgrade
of the initial revision that preserves application data.

## Validation and evidence

Use Python 3.11, locked dependencies, PostgreSQL 18 and Redis 7. Supply the
unsuffixed disposable test URL so pytest can select worker databases:

```bash
export ENV_STATE=dev
export DATABASE_URL='postgresql://test:test@localhost:5432/oralhistarchiv_test'
export REDIS_URL='redis://localhost:6379/0'
export TEST_RATE_LIMIT_REDIS_DB=0
export REQUIRE_DB=1 REQUIRE_REDIS=1

uv run pytest src/tests/unit/test_search_query.py \
  src/tests/integration/test_search_fts_db.py \
  src/tests/integration/test_search_plans_db.py \
  src/tests/integration/test_search_page_indexing_db.py \
  src/tests/integration/test_search_pagination_db.py -p no:randomly -n 0
```

Required matching cases include each query mode, phrase/negative terms across
independently permitted fields, above-tier public discovery, exact filters,
hidden identities and source minima. A withheld first candidate must not consume
a page slot before field filtering. Compare the separate exact count with the
current permitted rows, and test count timeout/restoration independently of
page retrieval. The [pagination validation](search-pagination.md#targeted-validation)
also covers fresh migration, grants, NULL/tie ordering and cursor concurrency.

Explain the query actually being assessed, with the real web role and trusted
viewer/source context. Both paths expose public/full GIN opportunities. An outer
`Function Scan` alone cannot show the nested page SQL's access paths. The page
plan tests copy the installed owner function into a temporary test-only probe.
The probe returns JSON and is VOLATILE to permit EXPLAIN; it retains the exact
page SQL construction, bindings, owner and search_path. The real STABLE function
is exercised first. Retain plans for the bounded inner query, with role,
parameters, settings, data size and execution/buffer statistics. Verify selective public/full searches
use indexes without an additional whole-table fallback, and keep correctness
coverage for partial masks. Empty and common-term queries need not use GIN.
Planner choice and rare-filter work are data dependent. No production speedup
follows from index creation, bounded output or a synthetic plan alone.

Record current PostgreSQL 18 commands, runtime versions, measured counts,
unavailable checks and query plans against the reviewed source and CI run.
Historical PostgreSQL 16 results do not validate the current engine or queries.
Full-suite coverage and deployed performance remain separate evidence.

## Capacity and load acceptance

All HTTP search modes share the same start and execution budgets. The shared
start gate runs before session lookup. Admitted requests use the dedicated
one-connection search pool, immediately acquire a local permit, and try the
fixed PostgreSQL transaction advisory lock without waiting. The transaction
holds the lock through result selection and facet queries. The positive SQL
timeout and complete-operation deadline also cover empty browsing, filtered
pages, cursor continuation and page-one restart paths. No refusal, timeout or
backend failure may fall back to the ordinary request pool or a second query
mode. Cleanup follows the operation deadline. Rollback has a separate one-second
deadline; connection close/pool return can extend cleanup. The local permit is
retained until that cleanup finishes. Ordinary authentication/session work
continues to use its own pool. Development without Redis has a process-local start budget and must
retain its single-worker configuration.

Use a disposable deployment with the deployed web worker count, the actual web
role, PostgreSQL 18 and dedicated Redis 7. Record the effective search settings,
connection counts, host limits, catalogue size, source/field masks and the
following measured outcomes:

1. Establish baseline login, session-bearing detail and authorized health-detail
   latency and error rates, including their p95/p99 values.
2. Drive simultaneous searches from distinct synthetic client identities through
   the trusted test proxy. Include empty, common/rare terms, literal punctuation,
   quoted/negative terms, keyword/language filters, deep numbered pages and
   cursor continuation. Use the least selective representative masks too.
3. Verify the start rate is shared across workers, only one PostgreSQL search
   transaction is active, and rejected search work does not enter the ordinary
   pool. Excess starts/busy operations return retryable non-cacheable 503.
4. Continue the baseline ordinary traffic during saturation. Check its approved
   latency/error envelope, PostgreSQL CPU/I/O, active sessions, both pool
   occupancies and search timeout/refusal counts. Retain observations rather
   than claiming that a separate pool alone guarantees responsiveness.
5. Interrupt a search, exhaust its pool, hold the search lock in another test
   connection, and exercise statement/operation deadlines. Confirm rollback
   releases the lock and local permit and subsequent ordinary work succeeds.
   Repeat with ordinary per-client rate limiting disabled: the search controls
   must still refuse excess work.

Defaults are one start every two seconds, burst one, a 500 ms statement timeout,
a one-second operation deadline and 100 ms pool acquisition. Staging/production
requires burst one and a rate/deadline product no greater than 0.5. The acquisition
and statement budgets must each be strictly shorter than the operation deadline. Tighten
budgets or improve measured query plans when acceptance fails; increasing pool
size, allowing a local fallback, or permitting broader search bursts would
remove the intended containment. Keep the existing visibility/cursor tests
alongside these availability checks.

## PostgreSQL references

The project-specific mode selection and visibility rules above are application
contracts. PostgreSQL's own behavior is described in the version 18 documentation:

- [Query parsing and `websearch_to_tsquery`](https://www.postgresql.org/docs/18/textsearch-controls.html#TEXTSEARCH-PARSING-QUERIES)
- [Dictionaries, including the simple dictionary](https://www.postgresql.org/docs/18/textsearch-dictionaries.html#TEXTSEARCH-SIMPLE-DICTIONARY)
- [GIN and other full-text index types](https://www.postgresql.org/docs/18/textsearch-indexes.html)

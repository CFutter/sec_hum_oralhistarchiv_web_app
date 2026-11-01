# Resource access and audit

## Source configuration

`log_resource_access` is a strict boolean in each source's TOML configuration.
When omitted it defaults to the value of `requires_record_tier`: sources with
mandatory record tiers use audited links by default. An explicit `false` keeps
direct safe resource/landing links on the detail page. Changing the flag does
not alter the ingestion fingerprint or require a rebuild.

```toml
requires_record_tier = true
log_resource_access = true
```

For OAI/CMDI, keep `requires_record_tier=false` and set
`log_resource_access=true` explicitly when audited links are wanted.

For an unknown or currently unselected source with retained catalogue rows,
detail pages conservatively use the audited internal link. They retain the
existing resource/landing action when a safe stored URL is available.

## Redirect boundary

`GET /dataset/{dataset_id}/resource/{proxy_index}` selects the original,
zero-based position in the stored `resource_proxies` list. It accepts only a
`Resource` or `LandingPage` entry at that position; filtering entries never
renumbers them. The request cannot supply a destination URL.

| Condition | Result |
|---|---|
| Served record, viewer meets every field requirement, supported proxy and safe stored HTTP(S) URL | `303` to the stored destination, using standard HTTP `Location` encoding |
| Missing, hidden or quarantined record; insufficient field access; invalid index/proxy/URL | `404`, with no resource-access event |

Guests may follow public records' links. A public-tier administrator has the
same metadata boundary as another public viewer; administrator authority does
not bypass it. The route re-reads current catalogue state, so a prior detail
page does not authorize access after the record is hidden or its tier rises.

The route applies `is_safe_http_url` to the stored destination and performs no
upstream fetch or proxying. Control characters and surrounding whitespace are
rejected; legacy URLs with surrounding whitespace no longer produce an action.
Unicode or spaces within accepted URLs receive the response library's normal
percent encoding; already encoded URLs retain their escapes. The external repository enforces access to recordings
and other material. A successful redirect records an attempted visit, not proof
that a file was downloaded or that the upstream granted access.

## Detail links and events

With logging enabled, the resource/landing action links to the internal route.
Its anchor and rendered HTML do not expose the raw upstream resource/landing URL.
The existing preference for a resource link, with a landing-page fallback, is
preserved. License and DOI links retain their own existing behavior.

Every successful redirect emits exactly one `resource_access` event containing
`dataset_id`, `source`, `user_id`, `user_tier` and `proxy_index`. `user_id` is null
for a guest. The event excludes the target URL, proxy payload and metadata
values. Refusals emit no `resource_access` event; ordinary request audit remains.
Calling the internal route directly still audits a successful redirect when
the source explicitly uses `log_resource_access=false`.

## Acceptance

Tests must cover below-tier cloaking, guest access to public records, full-tier
redirects to the safe stored destination, hidden records, invalid indices,
unsupported/unsafe entries and administrator tier independence. They must also
check event contents/counts, configured defaults and overrides, retained-source
fallback, unchanged fingerprints and the absence of raw target URLs in logged
detail-page HTML.

Synthetic source fixtures are sufficient for these application checks. Real-feed
availability is not a prerequisite. WP B's source-owner approval, real-feed
acceptance and representative encrypted restore remain separate operational
obligations in the [feed acceptance record](../sources/json-feed-acceptance.md).
See [Access control and visibility](access-control.md) for the metadata boundary.

## D2 application evidence

`src/tests/integration/test_resource_access_db.py` exercises signed synthetic
feed ingestion, real PostgreSQL catalogue reads, stored full sessions and HTTP
requests through the application. It reuses the existing signed-feed harness,
which substitutes HTTP transport and the isolated worker boundary. It is not
real-feed or deployed audit-stream evidence.

| Test function | Acceptance covered |
|---|---|
| `test_real_catalogue_tiers_and_sessions_audit_only_successful_redirects` | Guests, all metadata tiers and public-tier administrators; exact redirect targets; invalid/missing records; one metadata-free event per success and none for refusals; no raw target in logged detail HTML |
| `test_stale_links_obey_durable_hide_restore_and_tier_changes_per_source` | Previously obtained links after committed tier raises, hide and restore; subsequent request rechecks; same UUID in another source remains unaffected; exact event counts |
| `test_source_tier_corrections_recheck_the_same_session_and_stale_link` | Incremental/full ingestion tightens and relaxes valid explicit tiers; the same session and saved link recheck current permission |
| `test_native_proxy_selection_preserves_original_indexes_and_hides_targets` | Nullable native proxies, original indexes, safe Resource preference and LandingPage fallback; internal detail links and absent raw targets |

The existing exact `Dataset` field-release assertions remain in
`src/tests/integration/test_sensitive_source_pages_db.py`. D1's client tests
continue to cover malformed stored proxies and unsafe URLs that valid native
feed ingestion rejects before storage.

Run against a disposable test database and Redis:

```bash
tests=(
  src/tests/integration/test_resource_access_db.py
  src/tests/integration/test_sensitive_source_pages_db.py
  src/tests/integration/test_pages_e2e.py
  src/tests/client/test_resource_access.py
  src/tests/unit/test_resource_logging_config.py
  src/tests/unit/test_route_guards.py
  src/tests/client/test_route_coverage.py
)
REQUIRE_DB=1 REQUIRE_REDIS=1 uv run pytest -p no:randomly \
  -rs --no-fold-skipped "${tests[@]}"
REQUIRE_DB=1 REQUIRE_REDIS=1 uv run pytest -p randomly -n 3 \
  --randomly-seed=20261019 -rs --no-fold-skipped "${tests[@]}"
uv run pytest --collect-only -q
```


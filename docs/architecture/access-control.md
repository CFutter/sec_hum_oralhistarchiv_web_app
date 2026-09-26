# Access Control & Visibility

The visibility model is small enough to summarise in three sentences:

1. Every user has an `access_tier` of `public`, `registered`, or `vetted`, ranked low to high.
2. Every dataset has a `visibility_tier` of `public`, `registered`, or `vetted`, initially supplied or constrained by its source policy. An administrator may raise the stored tier; synchronization preserves the stricter of the stored and incoming tiers.
3. A user whose tier rank is at least the dataset's visibility tier rank sees the full dataset; everyone else sees the deliberately public discovery envelope in `PUBLIC_DISCOVERY_FIELDS` — `id`, `uuid`, `title`, `access_level`, `version`, `source`, `visibility_tier` — with every other field redacted. (`assert_redaction_total()` enforces that this set plus the redacted set exactly partitions the Dataset fields.)


## The tier hierarchy

`public < registered < vetted`, ranked 0, 1, and 2 in `services/access_tiers.py`. `can_access()` compares ranks; `can_view_full()` applies that comparison to `dataset.visibility_tier`. An unknown tier raises `ValueError`. User metadata tiers are independent of administrator privileges.

## Where the check runs

Routes resolve `request.state.user.access_tier`, defaulting guests to `public`, and pass it to dataset services. `search_datasets`, `get_recent_datasets`, and `get_dataset_by_id` redact before returning. Internal database rows are unredacted, so new callers must use these tier-aware services or call `filter_for_tier` before exposing data.

### Search and facets

- Public title/access-level text is searchable on every record; full-text metadata matches only records visible at the user's tier.
- Keyword/language filters and suggestions are tier-gated; access-level filtering is public.
- Suggestions come from a bounded recent-record sample, not a complete catalogue vocabulary. Home language/keyword counts are tier-scoped aggregates.

Templates receive redacted fields as `None`/empty lists, but still use the visibility tier to present restricted-detail notices.

## What gets redacted

When the user's tier is insufficient, `filter_for_tier` returns a fresh `Dataset` containing the application's explicit public discovery envelope:

| Survives redaction | Removed by redaction |
|---|---|
| `id`, `uuid` | `description`, `resource_description` |
| `title` | `project_title`, `project_description` |
| `access_level` | `authors`, `keywords`, `languages` |
| `version` | `resource_access_url`, `landing_page_url`, `resource_proxies` |
| `source`, `visibility_tier` | `license_val`, `license_url`, `doi`, `resource_type`, `bibliographical_citation` |

That is the complete list. Every surviving value, the fact that the record exists, and the fields considered in combination must be safe for unrestricted public disclosure. In particular, titles are deliberately displayed and searchable; `uuid` must be a public dataset identifier rather than a participant identifier, private lookup key, or credential. The redacted `Dataset` is a fresh dataclass instance, not a wrapper or proxy: the sensitive fields literally hold `None` or `[]`, so there is no `__getattr__` trick to subvert. A startup check (`assert_redaction_total`) verifies that every `Dataset` field is classified into exactly one of the two columns above and that `PUBLIC_SEARCH_FIELDS` remains inside the public envelope.

This is a semantic source contract as well as a code-level field set. Automated tests can prove which values the application releases, but they cannot decide whether a human-language title identifies a participant. Source A relies on its upstream open-metadata policy and upstream correction/withdrawal. Source B must independently adopt and validate the [Source B Ingestion Contract](source-b-ingestion-contract.md) before it is implemented or enabled.

## Why `visibility_tier` and `access_level` are different

| Field | Meaning | Authority |
|---|---|---|
| `visibility_tier` | Minimum tier for full metadata | Source classification constrained by `SourcePolicy` |
| `access_level` | Displayed classification of material access | Source-specific classifier |

Only `visibility_tier` gates metadata. `access_level` is a public label/filter, not an application download permission. SWISSUbase resource/landing links are displayed when full metadata and a URL are available, regardless of that label; the external repository enforces material access. Public discovery fields remain visible even for vetted metadata, so they must never contain confidential identifiers or titles.

## How `access_level` gets set

`services/sync.py:_classify_swissubase_access()` returns `restricted` when the lowercased license starts with `restricted access`; every other value, including missing or whitespace-prefixed labels, becomes `public`. This is a fail-open display classification, not proof that downloading is permitted. The repository does not establish that upstream always omits protected links; validate the source contract operationally. Every future `SourcePolicy` must supply its own classifier.

## How `visibility_tier` gets set

At ingest, every source is bound to a `SourcePolicy` whose `max_visibility` is the most *permissive* tier at which its records may be published. Source A is an open SWISSUbase OAI catalogue and does not carry an application tier per record; `resolve_tier(None, policy)` therefore supplies `SWISSUBASE_MAX_VISIBILITY` for new records. For an existing `(source, uuid)`, the upsert atomically retains the more restrictive of its stored `visibility_tier` and the incoming policy-resolved tier. Incremental sync and full rebuild use this same rule, so synchronization may tighten a classification but never lower it. The ordering remains `public < registered < vetted`, defined by `_TIER_RANK` in `services/access_tiers.py`.

Source B is different: every record must carry a source-owned canonical tier, and every value in its public discovery envelope must be approved as unrestricted-public metadata. Its future adapter must validate both boundaries before persistence and call `resolve_required_source_tier()`, which rejects missing and unknown tiers rather than defaulting them, then applies the application ceiling only to make a tier more restrictive. The shared upsert also preserves any stricter stored classification. The complete, transport-independent acceptance criteria are in the [Source B Ingestion Contract](source-b-ingestion-contract.md).

Phase 1 dataset administration uses direct database updates by an authorised operator, scoped to the exact `(source, uuid)`. For example, replace the example UUID below with the reviewed upstream identifier and verify that exactly one row is returned:

```sql
UPDATE oral_history_datasets
SET visibility_tier = 'vetted'
WHERE source = 'swissubase' AND uuid = 'oai:swissubase.ch:example'
RETURNING id, source, uuid, visibility_tier;
```

Record the decision and verify anonymous detail and search responses after committing. The admin dashboard manages user access tiers and does not change dataset classifications. Tier-sensitive reads query the database directly, so a dataset-tier change needs no cache invalidation.

The existing `visibility_tier` stores the effective classification, so preserving its stricter value needs no new column or migration. It does not separately record whether a restriction came from an administrator or an earlier source policy. Consequently, a more permissive source revision or configuration does not automatically lower an existing tier. Genuine withdrawals and stale-row deletion still remove the row; a later reintroduction or a new UUID is a new insert and receives the then-current source-policy tier.

Metadata corrections and withdrawals remain upstream responsibilities. An operator may delete an exact `(source, uuid)` as documented in the [Emergency Dataset Withdrawal](../runbooks/emergency-dataset-withdrawal.md), but ingestion must remain paused until the authoritative source is fixed or the row may return. Raising a tier still exposes the public discovery envelope and is insufficient when that envelope itself must disappear. Mock restricted rows seeded in non-production exercise presentation-layer tier filtering only; they do not implement or test the Source B ingestion contract.

## What gets logged

The dataset detail handler emits `dataset_access` when `visibility_tier != public`, including dataset ID/UUID/tier, user ID/tier, and `access_granted`; request ID and client IP come from the audit helper. Search/home cards do not emit this dataset-level event. Audit output goes through configured logging; the supplied deployment captures stdout with journald, not a separate `audit.log`.

## Administrative user access

`is_admin` is independent of `access_tier`. Admin routes require an eligible full-session administrator, and local administrators also need usable recovery codes. Missing/nonadmin principals receive 404. Admin write services recheck current authority/session under locks. Administrator status does not grant vetted metadata access; an administrator must assign that tier separately.

## Limitations

There is no per-field visibility, access expiry, in-app per-dataset request workflow, or PostgreSQL row-level security. Administrators assign user tiers manually; sources own dataset classification. Emergency removal is temporary unless the source is corrected or ingestion stays paused. Application tier checks do not protect direct SQL access by the database role.
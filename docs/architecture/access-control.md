# Access Control & Visibility

The visibility model is small enough to summarise in three sentences:

1. Every user has an `access_tier` of `public`, `registered`, or `vetted`, ranked low to high.
2. Every dataset has a `visibility_tier` of `public`, `registered`, or `vetted`, set at ingest by the source's policy ceiling and adjustable per dataset by an administrator.
3. A user whose tier rank is at least the dataset's visibility tier rank sees the full dataset; everyone else sees a redacted version with little more than the title and access level.

This page explains how that simple rule is enforced, where the redaction happens, and why the system distinguishes `visibility_tier` from `access_level`.

## The tier hierarchy

Tiers form a strict total order:

```text
public  <  registered  <  vetted
```

In code (`services/access_tiers.py`):

```python
_TIER_RANK = {"public": 0, "registered": 1, "vetted": 2}

def can_access(user_tier, required_tier):
    return _TIER_RANK[user_tier] >= _TIER_RANK[required_tier]
```

A vetted user can see everything. A registered user can see public and registered content. A public (or guest) user can see only public content. There is no orthogonal capability — only this single ladder. `can_view_full(dataset, user_tier)` in `datasets.py` is a thin wrapper that calls `can_access(user_tier, dataset.visibility_tier)`, and `tier_rank()` supplies the same numeric ranking to the SQL queries.

## Where the check runs

Visibility filtering is enforced in the **service layer** — partly inside the SQL queries themselves, partly in `filter_for_tier` — not in the routes and not in the templates. Routes only pass the user's tier down:

```python
user_tier = _get_user_tier(request)   # request.state.user.access_tier or "public"
results, total = await search_datasets(pool, user_tier, ...)   # already redacted
dataset = await get_dataset_by_id(pool, dataset_id, user_tier) # already redacted
```

`search_datasets`, `get_recent_datasets`, and `get_dataset_by_id` all apply `filter_for_tier` to every row **before returning**, so no caller can ever hold an unredacted dataset for a below-tier viewer. The template never sees the hidden fields and never has to know about tiers. A future template change cannot accidentally leak a sensitive field — the field literally is not in the object the template was given.

The `_get_user_tier` helper defaults to `"public"` for unauthenticated requests, so the same code path serves guests and authenticated public-tier users without branching.

### Search cannot be used as an oracle

Redacting the *returned* fields is not enough — a below-tier user could otherwise probe hidden metadata by watching which filters *match*. The queries close this:

- **Free-text search** matches two trigger-maintained columns. `search_text_public` (title + access level — exactly what survives redaction) is matched on **every** dataset, keeping the catalogue browsable. `search_text_full` (descriptions, project fields, keywords, authors) is matched **only** on datasets the user's tier permits.
- **The `keyword` and `language` filters** are tier-gated in SQL for the same reason: those values are redacted for below-tier users, so an un-gated filter would confirm a guessed keyword or language on a hidden dataset by presence/absence.
- **The `access_level` filter is deliberately *not* gated** — access level is shown even on redacted rows, so filtering on it reveals nothing the user cannot already see.
- **Facet lists and the home-page keyword count** are tier-scoped in SQL as well, so the sidebar cannot enumerate values that occur only in datasets above the user's tier.

## What gets redacted

When the user's tier is insufficient, `filter_for_tier` returns a fresh `Dataset` in which only the bare minimum needed to acknowledge the dataset's existence survives:

| Survives redaction | Removed by redaction |
|---|---|
| `id`, `uuid` | `description`, `resource_description` |
| `title` | `project_title`, `project_description` |
| `access_level` | `authors`, `keywords`, `languages` |
| `version` | `download_url`, `landing_page_url`, `resource_proxies` |
| `source`, `visibility_tier` | `license_val`, `license_url`, `doi`, `resource_type`, `bibliographical_citation` |

That is the complete list — `access_level` and `version` survive (so the UI can still show whether the materials are restricted and which version exists), but the landing page URL, license, resource type, and every descriptive field are removed. The redacted `Dataset` is a fresh dataclass instance, not a wrapper or proxy: the sensitive fields literally hold `None` or `[]`, so there is no `__getattr__` trick to subvert. A startup check (`assert_redaction_total`) verifies that every `Dataset` field is classified into exactly one of the two columns above, so a newly added field cannot silently slip through unclassified.

## Why `visibility_tier` and `access_level` are different

This is the part most people get wrong on first reading. The `Dataset` dataclass carries two fields that look similar:

| Field | Set by | Question it answers |
|---|---|---|
| `visibility_tier` | Ingest policy ceiling; administrators can override per dataset (in the DB) | "Who can read about this dataset?" |
| `access_level` | Sync layer (derived from upstream license) | "Who can download the actual materials?" |

Conflating them would force a single yes/no decision on a question that has two independent answers. Examples:

- A dataset of public-domain transcripts: both fields are `public`. Anyone can read about it and anyone can download it.
- A dataset whose materials require a request to the source repository, but whose metadata is freely browsable: `access_level='restricted'`, `visibility_tier='public'`. The whole point of having metadata in the archive is to help researchers discover what exists and decide whether to make a request.
- A dataset whose materials are technically public-domain audio, but whose metadata names interview subjects who later asked to be unlisted: `access_level='public'`, `visibility_tier='vetted'`. The metadata is sensitive, the materials are not.

`access_level` controls download. `visibility_tier` controls metadata visibility. The redaction logic only touches `visibility_tier`. Whether a user can actually fetch the materials behind `download_url` is governed by the source repository, plus the application's `access_level` display, plus future Phase 2 enforcement.

## How `access_level` gets set

During sync, `services/sync.py:_classify_access_level` looks at the upstream license string:

```python
def _classify_access_level(license_val, source):
    if source != "swissubase":
        raise NotImplementedError(...)   # each source must define its own gating
    if (license_val or "").lower().startswith("restricted access"):
        return "restricted"
    return "public"
```

That is the entire rule today. SWISSUbase uses free-text license fields, and the only label they use to mark restriction is `Restricted access...`. If they ever change their convention, this is the single function to update — every other access-level handling reads from `Dataset.access_level`. The classifier is deliberately **fail-open for Source A only** (SWISSUbase omits restricted download links upstream, so a misclassification cannot expose a link); the guard clause forces any future source to make its own explicit access-level decision rather than inheriting this rule.

## How `visibility_tier` gets set

At ingest, the tier is resolved through a **source policy**, never hardcoded. Each ingest source is bound to a `SourcePolicy` whose `max_visibility` is the most *permissive* tier that source's records may be published at. For SWISSUbase the ceiling comes from the `SWISSUBASE_MAX_VISIBILITY` setting (the code default is the most restrictive, `vetted`; a deployment ingesting only a public catalogue sets it to `public` — see `.env.example`). `resolve_tier(record_tier, policy)` then takes the more restrictive of the record's own tier claim and the ceiling; a record with no tier, or an unrecognised value, gets the ceiling.

After ingest, administrators can change a dataset's tier per record — today by editing the database directly; there is not yet an admin UI for per-dataset tier editing. Mock restricted datasets are seeded in debug mode by `services/seed_mock_data.py` (with `source="mock"`, `visibility_tier="vetted"`) so the tier filtering can be exercised without sensitive data.

In Phase 2, when Source B (sensitive metadata) lands, it will get its own `SourcePolicy` with an appropriately restrictive ceiling, likely with a per-field visibility matrix layered on top of the per-dataset tier.

## What gets logged

When a route serves a dataset whose `visibility_tier` is anything other than `public`, the page handler emits a structured `dataset_access` audit event regardless of whether access was granted:

```text
event_type: dataset_access
dataset_id: 4711
dataset_uuid: ...
dataset_visibility_tier: registered
user_id: 42            # null for guests
user_tier: registered
access_granted: true
```

This is the audit hook for restricted-content access. Combined with the audit middleware's per-request log, every restricted-content request is traceable to a request ID, an IP, a user, and an outcome. These records go to stdout and are captured by systemd-journald (and optionally forwarded off-host by a host-level rsyslog agent); there is no separate `audit.log` file. (The redacted `Dataset` deliberately keeps its `visibility_tier` so this audit decision can still be derived after redaction.)

## Admin overrides

Administrators are authorised independently of the visibility tier system, via the `is_admin` boolean on `users`. The `require_admin` dependency on `/admin/*` routes checks that flag (raising 404 for non-admins, so the area is not even revealed) and is unrelated to `access_tier`. An administrator who is not also `vetted` does not gain vetted-tier visibility — they would have to assign themselves the tier explicitly.

## Things this model does *not* do today

- **Per-field visibility.** A dataset is either fully visible or reduced to the surviving minimum. There is no "show authors but hide subjects". The Phase 2 visibility matrix will introduce that.
- **Time-bound access.** Vetted access is granted permanently until an administrator removes it. There is no automatic expiry.
- **Per-dataset access requests.** Users cannot request access to a specific dataset through the application. Requests go via email to the administrators.
- **An admin UI for dataset tiers.** Per-dataset tier changes are made directly in the database.
- **PostgreSQL Row-Level Security.** Today, enforcement is at the application layer. Phase 2 will add PostgreSQL RLS as a defense-in-depth layer so that even a compromised application database account cannot bypass tier restrictions through direct SQL.

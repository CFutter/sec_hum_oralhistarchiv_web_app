# Data Model

PostgreSQL stores catalogue, account, session, delivery, and recovery state. Dataclasses expose selected fields; startup checks compare their contracts with the schema.

## Tables

| Table | Identity and stored state |
|---|---|
| `oral_history_datasets` | Local `id`; explicit non-null source name of 1–32 lowercase ASCII letters, digits or underscores, with no database default; unique `(source, uuid)` and `(source, doi)`; normalized metadata, raw JSONB, visibility, upstream/local timestamps, and generated search text. |
| `dataset_admin_state` | Durable `(source, uuid)` identity; nullable administrator tier floor and `hidden_at`; no catalogue foreign key. Catalogue reads enforce restrictions; administrator routes manage them. |
| `sync_status` | Primary key `source`; per-source cursor/fingerprint, local timestamps/errors, and staged harvest bytes/start/progress. Initially empty; the scheduler provisions unbound rows after runtime validation. |
| `ingestion_failures` | Primary key `(source, uuid)`; unresolved diagnostic and update time. |
| `ingestion_quarantine` | Durable `(source, uuid)` serving exclusion, fixed reason and rejected harvest/cutoff boundaries; survives catalogue deletion. |
| `source_security_state` | Last accepted source/UUID tier, independent of cached metadata and administrator state. |
| `source_binding_acknowledgements` | Owner-approved exact previous/target source-fingerprint transition. |
| `security_audit_events` | Stable event UUID, timestamp and bounded metadata-free mutation evidence; no account/catalogue foreign key. |
| `security_audit_receipts` | Owner-private sink acknowledgement per event. |
| `anonymous_mail_issuance` | Bounded recipient/global mail-issuance accounting independent of client IP. |
| `catalogue_search_policy` | Singleton fingerprint and compiled source/audience masks. |
| `catalogue_search_public`, `catalogue_search_registered`, `catalogue_search_vetted` | Independently indexed audience search/filter/order projections, maintained transactionally. |
| `alembic_version` | Applied migration revision. |
| `users` | Local ID; case-insensitive unique email and unique federated `(issuer, subject)`; account authority, credentials, action-token hashes/times, lockout and recovery state. |
| `sessions` | SHA-256 token ID, user, purpose, expiry, flash state, IP, and durable step-up attempts; deletion cascades from user. |
| `pending_totp_rotations` | One encrypted challenge per user, bound to the exact `(session_id, user_id)` and credential revision; user/session deletion cascades. |
| `totp_recovery_codes` | Primary key `(user_id, generation, position)`; digest, use time, and per-code password attempts constrained to 0–3; deletion cascades from user. |
| `admin_promotion_requests` | One invitation per target user; requester, expiry, expected revision, and optional prepared session; deletion cascades from target/requester. |
| `federation_policy_state` | Enforced `id=1`; policy fingerprint and update time. Starts empty. |
| `email_outbox` | ID, optional user, message content with encrypted body, action binding/expiry, due time, attempts, lease, and terminal timestamps/outcome; user deletion cascades. Status is `pending`, `sending`, `sent`, or `dead`; terminal outcomes are `cancelled`, `delivery_failed`, or `body_unreadable`. |

Catalogue writers must supply their source identity explicitly. The database
enforces the same source-name vocabulary as `SourceConfig`; omitted, null
or malformed source names are rejected. This constraint does not register
a source or activate runtime ingestion.

The reviewed fresh-install baseline `4f73ae3ff827` includes the catalogue row
boundary and private ordering functions directly. It enables RLS on
`oral_history_datasets` and includes these non-updatable, owner-backed
security-barrier views with `security_invoker=false`:

| View | Read projection |
|---|---|
| `catalogue_discovery` | Exactly the seven approved public fields, with effective stored/administrator tier; hidden identities excluded; no timestamp, ordinal or metadata/search blob |
| `dataset_admin_catalogue` | Only ID, source, UUID, stored tier and canonical persisted record tier, including hidden identities; application administrator authorization still required |

Services join discovery to the RLS-protected base row to obtain metadata only
at the trusted viewer's record tier. The table's `FORCE ROW LEVEL SECURITY` flag
is false so the owner can supply these narrow views and run development/migration
operations. Exact-current-user policies distinguish web SELECT from scheduler
ingestion. Startup and deployment checks pin view definitions/columns/options,
RLS flags and policy definitions; role grants alone do not establish this
boundary. See [Access Control](access-control.md#postgresql-row-level-enforcement).

`update_search_text()` and the existing insert/update trigger maintain both
legacy text blobs and the new non-null `tsvector` columns. Legacy
`search_text_public` remains title plus access level; `search_text_full` remains
title, description, project title, project description, keywords and authors,
without access level. Their field order, separators and existing trigram
indexes are retained.

`search_vector_public` uses the public text. `search_vector_full` uses that
public prefix plus description, project title, project description, keywords
and authors. Both use explicit `pg_catalog.simple`, with no stemming or accent
folding. `idx_search_vector_public` and `idx_search_vector_full` are GIN indexes.
Request search uses separate public, registered and vetted projection tables,
whose indexes contain only each audience's permitted values. Page/count
functions require the bound policy fingerprint; the compatibility
`catalogue_search_candidates` view delegates to the same projections. Raw
text/vector indexes are not request predicates. See [search policy](../runbooks/search-policy.md).

Keyword/language filters retain exact membership and independent field gates.
The owner-backed `catalogue_page_ids()` resolves private timestamp/ID boundaries,
applies exact field-aware matching and filters before each bounded branch, and
returns IDs in traversal order. Separate non-NULL/NULL ranges preserve
`upstream_modified_at DESC NULLS LAST, id DESC` in both directions without a
global `row_number()` window. `catalogue_scan_ceiling()` supplies the greatest
current nonhidden ID. Neither function exposes the timestamp in the public view.
Only web receives direct EXECUTE on these functions; runtime privilege checks
pin that exact set, and startup schema checks pin their full definitions.
Canonical function SQL lives in `app.catalogue_sql` and is exported through
`app.__init__` for both migration and contract use.

Numbered search pages stop at 100, then version 2 opaque bookmarks continue
from current identity boundaries. Normal navigation uses lookahead and reports
no exact total. The separate `count_search_datasets()` operation defaults to a
2,000 ms requested timeout, preserves a shorter existing limit and restores it
after success. `search_datasets()` retains compatibility by fetching a page
and exact count separately. Recent records and the 200-ID facet sample use the
same private ordering boundary. See the
[pagination contract](../runbooks/search-pagination.md) and
[search contract](../runbooks/search-fulltext.md). Plans and performance must be
measured separately; an index or bounded output is not a throughput result.

These objects are folded into the same initial revision `4f73ae3ff827` for the
agreed fresh database. `upgrade head` does not rerun an already recorded revision,
and stamping cannot install changed objects. The file-update script does not
reset a database or run DDL. Apply the complete baseline and matching runtime
grants to the agreed fresh/disposable database before preflight. The historical
`deploy/upgrade-search-k2.sql` alone does not install the current ordering functions;
a retained database needs a separately reviewed conversion procedure.

Action-token hashes live on users; complete links also exist inside encrypted outbox bodies and in recipient messages. Protect outbox keys separately from database dumps. Session cookies carry a signed plaintext random token; session rows store its hash. See [Authentication](auth.md) for credential/session transitions and [Access Control](access-control.md) for disclosure policy.

## Dataclasses

The `services/` layer wraps SQL rows in dataclasses before passing them up to the routes. Two are central.

### `Dataset`

Defined in `services/datasets.py`. Every field on this class corresponds to a column read in `DATASET_SELECT_COLUMNS` (defined in `services/schema.py`), with two exceptions: `resource_access_url` and `landing_page_url` are computed in `_parse_dataset()` from the `resource_proxies` JSONB blob. Note that `institutions` and `main_disciplines` are harvested and stored in the table but are **not** on the `Dataset` dataclass and are not selected in normal reads, so they never reach a template.

`Dataset.source` is a required keyword-only field. Construction and row decoding
reject invalid source identities; decoding a row without the source column
raises `KeyError`. Valid identities pass through reads and tier redaction
unchanged, including identities of sources no longer selected for ingestion.

The two classification fields are intentionally orthogonal:

| Field | Set by | Means |
|---|---|---|
| `access_level` | Source-specific ingestion classifier | Public resource-access label for display/filtering; current adapters emit `public` or `restricted` according to their exact input contracts. The upstream service enforces access. |
| `visibility_tier` | Source policy and the latest explicit upstream tier; omitted tiers retain their prior restriction; durable administrator floors can raise it | Which **metadata** fields you can see. `public`, `registered`, or `vetted`. Valid explicit upstream corrections may lower the source tier; administrator restrictions continue to apply. |

Metadata visibility and material access are independent: public descriptions
can link to restricted recordings. OAI/CMDI uses an immutable exact license-label
mapping with restricted fallback; see the
[all-adapter table](../sources/index.md#resource-access-classification).
Its fingerprint binds that mapping and fallback. Changed bindings need owner
acknowledgement and an authoritative rebuild; deployment alone does not rewrite
stored `access_level` values.

`filter_for_tier(dataset, user_tier, *, configured_sources=...)` enforces the
visibility side for every field. Protected fields require the strictest
effective stored/administrator record tier, code minimum and source minimum.
Below the record tier, only `id`, `uuid`, `title`, `access_level`, `version`,
`source`, and `visibility_tier` survive. Above it, a stricter field minimum can
still remove individual values. Refused scalar fields become `None`; list fields
become fresh empty lists. The service query functions apply the same filter and
trusted configured-source scope before returning data to routes. The immutable
22-field code matrix lives in the pure `app.field_visibility` module and remains
available through the public `app.services` facade. Source read overrides are
process configuration, not stored classification or a schema migration; see the
[field-policy contract](field-visibility.md).

### `User`

Defined in `services/users.py`. Every field corresponds to a column on `users` except `totp_configured` and `totp_recovery_codes_available`. Those booleans are computed in SQL from the encrypted-secret presence and an indexed existence check for an unused code in the active generation. Neither the raw secret nor any code digest is exposed on the dataclass.

`auth_method` distinguishes local accounts (`"local"`, password + TOTP, email
verification required) from federated accounts (`"shibboleth"`, assertions
accepted only from the Shibboleth trust boundary). Federated identity is the
exact pair of `shibboleth_issuer` and `shibboleth_subject_id`. Local rows have
null federation identity, status, approval and review fields, with review
revision zero.

`users_local_password_required` permits a NULL local password only while the
account is inactive, unverified and nonadministrator. Mailbox-first registration
creates that pending state at public tier with no profile fields or password.
An active, verified or administrator local account still requires a password.
Administrator activation rejects passwordless pending accounts; credential setup
must consume the current mailbox capability first. Inactive pending accounts
cannot log in or request/use password reset, and the unverified-account reaper
already covers them.

Federated `federated_status` is `pending`, `approved` or `disabled`. Pending
accounts are public, inactive, non-admin and unverified, with both approval
fields null. Approved accounts are active; disabled accounts are inactive and
retain their approval history. Approved and disabled rows carry
`federated_approved_at` and the logical approving user ID in
`federated_approved_by`. The latter is an integer audit field without a database
foreign-key constraint in the current migration.

`federated_review` is a nullable JSONB observation containing the latest trusted
normalized `issuer`, `affiliation`, escaped `entitlement` serialization and
`proposal`. The proposal is null for no matching rule, or a rule snapshot with
its one-based index, predicates and proposed tier. `federated_review_revision`
is a nonnegative bigint, initially zero; a changed observation advances it.
Repeated identical observations do not invalidate the review form. These fields
are read through a separate administrator projection, not the session `User`
snapshot. They can refresh for pending or disabled identities without changing
profile or authority.

At dedicated approval, `federated_approved_proposal` retains a JSONB wrapper
`{"proposal": ...}` from the locked review. Its explicit null proposal records
that no rule matched at approval; SQL NULL means no stored approval baseline.
A later proposal mismatch is derived by comparing the latest proposal with this
baseline, not with the administrator's independently chosen `access_tier`.
Legacy approved rows without a review baseline do not acquire one implicitly.

A first assertion does not confer access. An eligible administrator must use
the dedicated approval action under the enabled, currently trusted federation
policy. It re-matches the exact identity pair and current review revision,
requires an observed trusted assertion, assigns the explicitly selected tier,
records the reviewed proposal and approval, advances `auth_revision` and deletes every target session in
one transaction. Only a later trusted assertion can create a usable session.
Generic administrator actions cannot approve a pending identity. Neither tier
nor administrator status comes from assertion headers. `access_tier` controls
metadata disclosure; `is_admin` controls administrative authority. Mailbox
verification gates local login and TOTP setup and remains false for federated
rows.

The fresh-install baseline defines the current account, E3 and F2 schema contracts;
it does not convert earlier prototype accounts or reconcile historical
identities. An already initialized database
from an earlier body of `4f73ae3ff827` needs operator recreation/rebuild because
`upgrade head` does not rerun an already recorded revision. Stamping alone cannot
install the changed schema. Any data to retain requires a separately reviewed
conversion or isolated import plan. Re-establish a usable local administrator
and its authenticator recovery path, reconcile exact issuer/subject pairs, and
revoke superseded federated sessions before changing identity contracts.
Unresolved historical identities cannot be imported as current serving users.
Follow the [deployment procedure](../configuration/deployment.md); application
and updater tools do not recreate existing databases. Disposable test databases,
including each parallel worker database, must also be built from the current
baseline before running F2 database tests; a recorded old head cannot install
these columns. Keep any existing development database containing retained data
intact until its separate conversion or rebuild plan is agreed.
### `federation_policy_state`

This singleton table (`id = 1`) stores only `fingerprint` and `updated_at`. At
web startup the service locks it and compares a SHA-256 digest over the current
federation-enabled flag, sorted exact issuer set, fixed MFA context, policy
version, and callback secret. An empty table or changed digest causes all
Shibboleth sessions to be deleted before the new fingerprint commits in the
same transaction; local sessions are outside the delete predicate. Neither the
plaintext callback secret nor a separately reusable component digest is stored
or logged.

### Smaller dataclasses

`Author` is a thin wrapper around `{name: str}` so the template can iterate `dataset.authors` and call `.name` consistently, regardless of whether the upstream source delivered authors as plain strings or as objects.

## The schema invariant

`services/schema.py` defines dataset insert/select/computed columns. `validate_dataset_schema()` compares selected and computed fields with `Dataset`; `validate_dataset_insert_schema()` checks parser-owned keys and a synthetic record's parameter count. `validate_user_schema()` compares the user projection with both computed booleans excluded. `assert_field_visibility_total()` requires a complete field-minimum matrix, an exact discovery/redaction partition, canonical tiers and compatible public-search/resource-target classifications. Other startup contracts include outbox projections, application SQL columns, and live managed schema objects.

Every dataset/user SQL column list must also contain unique names. The shared
dataclass guard rejects repeated projection fields, and the insert validator
rejects duplicate targets before constructing a synthetic parameter tuple.
Application preflight checks each select, insert, trigger and computed-source
list independently, preserving legitimate overlap between different lists.

To add a catalogue field:

1. Before the first production database exists, update the fresh-install baseline and `db_schema_contract.py` (and runtime grants if needed); operators recreate older initialized baselines. After that production freeze point, add a reviewed Alembic revision instead of editing the baseline.
2. Update column lists in `schema.py`. Parser-owned fields also require `ParsedRecord`, parser output, and persisted-contract version/recovery changes.
3. If selected, add the `Dataset` field; `_parse_dataset()` forwards selected columns automatically, with explicit transformations where needed.
4. Update `build_record_params()` in `schema.py` for special serialization or application-owned values.
5. Give every Dataset field an explicit `FIELD_VISIBILITY` entry and classify it in `PUBLIC_DISCOVERY_FIELDS` or `_redacted_values()`. Public disclosure requires source-policy approval. Keep resource-target representations at the same minimum and update SQL/template contracts with any active field-policy change.
6. Run the relevant schema/parser/redaction tests and validate against a freshly migrated PostgreSQL database. Startup checks reject declared-contract mismatches; they cannot prove semantic correctness.

## Durable dataset administrator state

`dataset_admin_state` belongs to the stable `(source, uuid)`, independently of
any current catalogue row or local dataset ID. `visibility_tier = NULL` means
no administrator floor; `hidden_at = NULL` means no administrator hide.
Both may be NULL. There are no foreign keys to catalogue rows or users.

Serving catalogue reads join this state by both identity fields, exclude hidden
identities, and uses the stricter stored/administrator tier for SQL matching and
returned metadata. The state survives incremental updates, rebuild pruning,
withdrawals and reintroduction of the same identity. A different UUID is a
different identity. The public Dataset contract does not expose hide state.

The web role has SELECT, INSERT and UPDATE on administrator state; the scheduler
has SELECT only. The web role retains SELECT only on raw catalogue rows.
`change_dataset_admin_state()` owns authorized mutation transactions and emits
committed-change audit events. Administrator dataset pages show identity/state
and the public title from `catalogue_discovery` for nonhidden records. Hidden
titles and protected metadata remain unavailable in these controls. The pages
delegate writes to that service; the withdrawal runbook uses the UI.
Existing stored tiers are not copied into administrator state because they
have no administrator provenance.

## Where data is created

The scheduler owns catalogue/status/failure writes, email delivery/retries/retention, session cleanup, and unverified-account reaping. Web account flows update users, sessions, recovery/invitation/challenge state, and enqueue mail transactionally. Web startup reconciles federation policy and may revoke federated sessions. Bundled fixture records are catalogue input to the scheduler's normal ingestion path; web startup does not populate the catalogue.

Hardened deployments use separate web/scheduler roles with exact privilege checks; migrations use the owner. See [Authentication](auth.md), [Sync](sync.md), and [Deployment](../configuration/deployment.md) for operation-specific transactions and setup.

## Catalogue change timestamp

`oral_history_datasets.synced_at` records the most recent persisted content change
(or first insert) for that identity. Ingestion compares all persisted input
columns except this stamp after applying explicit upstream assertions or retaining an omitted tier.
An unchanged record preserves its ID and stamp without running the search trigger.
Source observation/rebuild freshness comes from `sync_status`, not from the newest
per-row stamp. Unchanged rows retain their previous ingestion stamp until the
next real content change.

## Quarantined ingestion progress

The single fresh-install baseline `4f73ae3ff827` includes nullable
`sync_status.source_fetch_cursor` and `source_fetch_fingerprint` directly.
New source rows start with NULL clean and consumed cursors/fingerprints;
there is no retained-data backfill or forward migration in this release.
Consumed progress records a validated snapshot whose writes
and durable quarantine completed, including a partial outcome. Existing
`source_cursor`, `source_fingerprint`, and completion timestamps continue to
record clean completion; partial work does not claim a clean rebuild. A changed
interpretation is clean only after its full reconciliation succeeds.

Every unresolved identity remains in `ingestion_failures`. Incremental polling
uses consumed progress; scheduled full rebuilds retry all quarantined identities
regardless of their modification timestamps. No new unparseable identity is
silently discarded. Downgrading the single baseline to `base` removes all
application tables and data. Databases created from an older baseline body need
operator recreation before using this release.

## Credential-security state in the initial schema

The explicitly approved pre-deployment reset keeps revision `4f73ae3ff827` as the
only Alembic revision. Its initial users table includes
`password_reset_attempt_count` and `password_reset_attempt_window_started_at`;
constraints permit an empty budget or one to five reserved attempts with an
anchored window. Token replacement does not reset the account-wide budget.
The initial encrypted-outbox constraint accepts `password_changed_notice`
without action-token metadata.

Initialize an empty database with `upgrade head`, apply matching runtime grants
and use the matching backup script. Databases created from an older body of the
initial revision must be recreated; an existing revision label or stamping does
not install the changed schema. Downgrading the sole revision to `base` removes
all application tables and data. No forward upgrade or partial credential-state
downgrade is supplied for this approved reset.

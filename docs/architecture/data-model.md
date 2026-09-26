# Data Model

PostgreSQL stores catalogue, account, session, delivery, and recovery state. Dataclasses expose selected fields; startup checks compare their contracts with the schema.

## Tables

| Table | Identity and stored state |
|---|---|
| `oral_history_datasets` | Local `id`; unique `(source, uuid)` and `(source, doi)`; normalized metadata, raw JSONB, visibility, upstream/local timestamps, and generated search text. |
| `sync_status` | Application uses `id=1` (not constrained to a singleton); source cursor/fingerprint, local timestamps/errors, and staged harvest bytes/start/progress. `incremental_failures` remains in the schema but active ingestion uses the table below. |
| `ingestion_failures` | Primary key `(source, uuid)`; unresolved diagnostic and update time. |
| `users` | Local ID; case-insensitive unique email and unique federated `(issuer, subject)`; account authority, credentials, action-token hashes/times, lockout and recovery state. |
| `sessions` | SHA-256 token ID, user, purpose, expiry, flash state, IP, and durable step-up attempts; deletion cascades from user. |
| `pending_totp_rotations` | One encrypted challenge per user, bound to the exact `(session_id, user_id)` and credential revision; user/session deletion cascades. |
| `totp_recovery_codes` | Primary key `(user_id, generation, position)`; digest, use time, and per-code password attempts constrained to 0–3; deletion cascades from user. |
| `admin_promotion_requests` | One invitation per target user; requester, expiry, expected revision, and optional prepared session; deletion cascades from target/requester. |
| `federation_policy_state` | Enforced `id=1`; policy fingerprint and update time. Starts empty. |
| `email_outbox` | ID, optional user, message content with encrypted body, action binding/expiry, due time, attempts, lease, and terminal timestamps/outcome; user deletion cascades. Status is `pending`, `sending`, `sent`, or `dead`; terminal outcomes are `cancelled`, `delivery_failed`, or `body_unreadable`. |

The search trigger fills `search_text_public` from title/access level and `search_text_full` from title, description, project title/description, keywords, and authors. Queries tier-gate only the full text. Trigram GIN indexes permit indexed substring search; the planner may still choose a scan. Keyword/language GIN indexes support array membership filters.

Action-token hashes live on users; complete links also exist inside encrypted outbox bodies and in recipient messages. Protect outbox keys separately from database dumps. Session cookies carry a signed plaintext random token; session rows store its hash. See [Authentication](auth.md) for credential/session transitions and [Access Control](access-control.md) for disclosure policy.

## Dataclasses

The `services/` layer wraps SQL rows in dataclasses before passing them up to the routes. Two are central.

### `Dataset`

Defined in `services/datasets.py`. Every field on this class corresponds to a column read in `DATASET_SELECT_COLUMNS` (defined in `services/schema.py`), with two exceptions: `resource_access_url` and `landing_page_url` are computed in `_parse_dataset()` from the `resource_proxies` JSONB blob. Note that `institutions` and `main_disciplines` are harvested and stored in the table but are **not** on the `Dataset` dataclass and are not selected in normal reads, so they never reach a template.

The two authorization fields are intentionally orthogonal:

| Field | Set by | Means |
|---|---|---|
| `access_level` | Source-specific ingestion classifier | Resource-access label for display/filtering; Source A emits `public` or `restricted`. The upstream service enforces access. |
| `visibility_tier` | Source policy on insertion; the stricter of the stored and incoming tiers on synchronization; authorised operators may raise it directly | Which **metadata** fields you can see. `public`, `registered`, or `vetted`. This is the effective classification, and synchronization never lowers it for an existing row. |

Metadata visibility and upstream resource access are independent; a public description may link to restricted material.

`filter_for_tier(dataset, user_tier)` enforces the visibility side. It compares the user's tier rank against the dataset's `visibility_tier`. If the user's rank is below the requirement, it returns a new `Dataset` with the sensitive fields nulled out — only `id`, `uuid`, `title`, `access_level`, `version`, `source`, and `visibility_tier` survive. Everything else (authorship, descriptions, languages, keywords, citations, license, DOI, resource type, and the download/landing URLs) is removed. The service-layer query functions apply this filter themselves before returning, so routes never hold an unredacted row for a below-tier user.

### `User`

Defined in `services/users.py`. Every field corresponds to a column on `users` except `totp_configured` and `totp_recovery_codes_available`. Those booleans are computed in SQL from the encrypted-secret presence and an indexed existence check for an unused code in the active generation. Neither the raw secret nor any code digest is exposed on the dataclass.

`auth_method` distinguishes local accounts (`"local"`, password + TOTP, email
verification required) from federated accounts (`"shibboleth"`, assertions
accepted only from the Shibboleth trust boundary). Federated identity is the
exact composite of `shibboleth_issuer` and `shibboleth_subject_id`.
`federated_status` is one of `pending`, `approved`, `disabled`, or
`legacy_quarantined`; an approved row also records
`federated_approved_at` and the logical approving user ID in
`federated_approved_by`. The latter is intentionally not described as a
database foreign key: the current migration creates an `INTEGER` audit field
without a referential constraint. A first assertion does not confer access:
the new row is public, inactive, non-admin, unverified and pending until an
administrator uses the dedicated approval action. Neither tier nor
administrator status is read from assertion headers. `access_tier` controls
what metadata the user can see, `is_admin` controls `/admin/*`, and
`email_verified` gates local login and TOTP setup (it remains false for
federated rows). Approval also increments the target's `auth_revision` and
deletes every target session in the same transaction, so only a later trusted
assertion can establish a usable session.

The schema permits `legacy_quarantined`, but this fresh-install baseline does not transform earlier accounts. Existing deployments need a reviewed migration and an active local administrator recovery path before changing identity contracts.

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

`services/schema.py` defines dataset insert/select/computed columns. `validate_dataset_schema()` compares selected and computed fields with `Dataset`; `validate_dataset_insert_schema()` checks parser-owned keys and a synthetic record's parameter count. `validate_user_schema()` compares the user projection with both computed booleans excluded. `assert_redaction_total()` requires each Dataset field to have exactly one disclosure policy. Other startup contracts include outbox projections, application SQL columns, and live managed schema objects.

To add a catalogue field:

1. Add a new Alembic migration and update `db_schema_contract.py` (and runtime grants if needed).
2. Update column lists in `schema.py`. Parser-owned fields also require `ParsedRecord`, parser output, and persisted-contract version/recovery changes.
3. If selected, add the `Dataset` field; `_parse_dataset()` forwards selected columns automatically, with explicit transformations where needed.
4. Update `build_record_params()` in `schema.py` for special serialization or application-owned values.
5. Classify selected fields in `PUBLIC_DISCOVERY_FIELDS` or `_redacted_values()`. Public disclosure requires source-policy approval. Update search SQL/contracts if search behavior changes.
6. Run the relevant schema/parser/redaction tests and validate against a freshly migrated PostgreSQL database. Startup checks reject declared-contract mismatches; they cannot prove semantic correctness.

## Where data is created

The scheduler owns catalogue/status/failure writes, email delivery/retries/retention, session cleanup, and unverified-account reaping. Web account flows update users, sessions, recovery/invitation/challenge state, and enqueue mail transactionally. Web startup reconciles federation policy and may revoke federated sessions. Development web startup and the staging scheduler can seed mock catalogue rows.

Hardened deployments use separate web/scheduler roles with exact privilege checks; migrations use the owner. See [Authentication](auth.md), [Sync](sync.md), and [Deployment](../configuration/deployment.md) for operation-specific transactions and setup.

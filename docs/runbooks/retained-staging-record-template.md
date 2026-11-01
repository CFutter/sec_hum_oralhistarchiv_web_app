# Restricted retained-staging record template

Copy this blank template into the approved private evidence system, outside the
application repository. Follow the [inventory runbook](retained-staging-inventory.md).
Completed records and reports are restricted. Use version/custody references,
never secret values, account/record lists, raw source payloads or error text.
Unchecked fields are pending; this template supplies no host acceptance.

## Identities and capture boundary

| Fact | Reviewed private reference/result |
|---|---|
| Installed artifact identity, source commit, digest and installation path | Pending |
| Candidate source/lock/artifact identities (separate from installed release) | Pending |
| Installed and candidate private configuration/source-binding versions | Pending |
| Collector file digest, interpreter/dependency identity and operator | Pending |
| Expected/observed database, PostgreSQL version, current/session user | Pending |
| Capture UTC time, report digest and private location | Pending |
| Alembic rows alongside actual catalog comparison | Pending |
| Shared deployment lock; independent DDL/configuration freeze agreement | Pending |
| Snapshot completeness, unreadable/missing objects and unresolved differences | Pending |

Compare actual schema, views/functions/triggers/policies/RLS, owners, grants,
roles/memberships, settings and configured source bindings. A revision label
alone cannot establish equivalence. Configuration/role changes outside the
database snapshot need their own versioned references.

## Preservation decisions

| Retained state | Required disposition and isolated before/after proof |
|---|---|
| Users, roles, password hashes, administrator access | Pending: preserved identities and usable approved administrator path |
| Active/pending TOTP, recovery codes and pending rotations | Pending: exact retained state plus decryption/authentication proof; separate key-version/custody references |
| Sessions, pending action links and outbox | Pending: explicit preservation or reviewed revoke/reissue decision; no real mail on restore |
| Catalogue IDs, source bindings, raw/protected values | Pending: identity and content comparison on approved data |
| Durable administrator hides and access tiers | Pending: exact retained overrides and enforcement proof |
| Source fingerprints and source cursors | Pending: exact value comparison privately; report hashes are not backups |
| Staged incremental bytes, start time, position and affected count | Pending: exact comparison and controlled resume/rebuild decision |
| Harvest/rebuild progress and timestamps | Pending: expected transition and no unexplained reset |
| Ingestion quarantine/failures | Pending: retained entries and controlled retry policy; no raw messages here |
| Federation reservations/policy and deletion/retention obligations | Pending: approved preservation/expiry disposition |

Record the source-specific normal authoritative rebuild needed for a K1
interpretation change. Never edit a fingerprint/cursor or discard staging to
bypass that mechanism. Specify which derived catalogue values can change during
the rebuild and which durable state must remain exact.

## Reviewed forward procedure

| Decision/evidence | Result |
|---|---|
| Actual starting contract: current / exact accepted K1 / older-partial-unknown | Pending |
| Object-by-object differences and data implications | Pending |
| Applicable reviewed asset or separately reviewed retained-data conversion | Pending |
| Exact preconditions, role, locks and commands | Pending |
| Writer quiescence and maintenance boundary | Pending |
| Isolated rehearsal and before/after preservation comparison | Pending |
| Runtime schema and separate web/scheduler privilege acceptance | Pending |
| Candidate application/search/source resumption acceptance | Pending |
| Recovery decision, triggers, compatible artifact range and cutover | Pending |

`deploy/upgrade-search-k2.sql` requires PostgreSQL 16 and its specified K1
contract; it cannot convert this PostgreSQL 18 target. Stamping, baseline downgrades or recreating
the retained target are not accepted procedures.

## Recovery point and isolated target

| Evidence | Result |
|---|---|
| Approved data use and recovery target isolation/access controls | Pending |
| Pre-change maintenance boundary and stated RPO/RTO/loss boundary | Pending |
| Encrypted archive identity/digest, creation result and off-host receipt | Pending |
| Separate archive-decryption identity and application-key version/custody references | Pending |
| Archive inspection result (separate from actual restore) | Pending |
| Isolated restore execution, timing and exact restored artifact/configuration | Pending |
| Provisioned role attributes/memberships, peer maps and database settings | Pending |
| Mail/feed/scheduler effects disabled or controlled before any target startup | Pending |
| Account/TOTP/protected-field decryption and approved login checks | Pending |
| Exact catalogue/admin/source/staged/quarantine comparisons | Pending |
| Controlled ingestion resumption/rebuild and representative access checks | Pending |
| Recovery result, discrepancies, accepted remedy and secure target disposal | Pending |

Logical dumps do not by themselves reproduce cluster roles, OS peer mappings or
all database settings. A successful archive verification or listing does not
prove restoration, decryption or application usability. Record the actual
restore and comparisons before calling the recovery point verified.

## BS4 acceptance

- [ ] Actual installed/candidate identities and complete starting contract reviewed.
- [ ] Every preservation decision approved, including sensitive staging data use.
- [ ] Forward procedure fits the observed starting state and passes isolated rehearsal.
- [ ] Pre-change recovery point restored and verified on the isolated target.
- [ ] Recovery action, authority and stop/go criteria recorded.
- [ ] Remaining issues and BS5/BS6 handoff explicitly recorded.

Responsible operator/reviewer references, approval time and unresolved evidence:
**Pending**.

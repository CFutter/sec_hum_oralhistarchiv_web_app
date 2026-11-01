# Point-in-time recovery template

**PITR is not supplied.** Approve an operating copy and toolchain, then pass an
isolated replay drill before claiming capability. The shipped encrypted logical
backup is a separate path; its local marker proves neither WAL continuity,
off-host custody nor point-in-time recoverability.

## Ownership, objectives and adoption

| Decision | Approved value or restricted reference |
|---|---|
| Service, PostgreSQL cluster and environments in scope | `<service-cluster-and-environment-inventory>` |
| Database operator, backup owner and deputy | `<operator-owner-and-deputy-reference>` |
| Recovery authority and independent reviewer | `<recovery-approval-and-review-roles>` |
| Recovery-point and recovery-time objectives | `<approved-rpo-and-rto-reference>` |
| Covered failure, compromise and availability scenarios | `<recovery-scenario-and-assumption-record>` |
| Physical-backup, archive, transfer and restore tools/versions | `<reviewed-toolchain-and-version-record>` |
| Encryption recipients, private-key custody and provenance controls | `<key-custody-and-provenance-reference>` |
| Off-host retention, access, holds and disposal | `<approved-archive-retention-and-access-policy>` |
| Capacity, alerts, escalation and response owner | `<capacity-monitoring-and-escalation-reference>` |
| Drill frequency, last result and next review | `<drill-schedule-and-acceptance-reference>` |

Keep records, infrastructure details, credentials and data comparisons in
`<restricted-recovery-record-location>`; public examples must be synthetic. Use
the [processing register](../compliance/processing-register.md) and
[incident procedure](../compliance/incident-response.md) for ownership/evidence
templates, then obtain institutional approval.

## 1. Choose the physical recovery boundary

PostgreSQL PITR replays WAL onto a physical base backup of the whole cluster.
The shipped `pg_dump`/`age` archives are logical dumps and cannot be that base.
Record `<physical-cluster-and-tablespace-scope>`; recovering one selected
database is not the physical restore operation described here.

Use PostgreSQL 18-compatible physical backup and recovery tooling. A reviewed
`pg_basebackup` workflow requires its own replication authority and connection
policy. Do not grant replication or write privileges to the existing
`oralhistarchiv_backup` role: that role is the separate, read-only logical-dump
identity. Record `<physical-backup-identity-and-peer-or-network-policy>`.

Inventory tablespaces, storage paths, PostgreSQL configuration, extensions,
service identities, application releases and historical key dependencies in
`<physical-recovery-dependency-inventory>`. WAL replay does not reconstruct
external configuration or keys that were never part of the backup. Follow the
[deployment overview](../configuration/deployment.md) for the existing role,
configuration and logical-recovery boundaries.

## 2. Establish and verify archiving before the base

Choose and approve a complete archive/restore implementation; this repository
does not supply one. Document how it handles these conditions:

| Requirement | Reviewed implementation and evidence |
|---|---|
| Required WAL level, archive mode and restart/change procedure | `<wal-configuration-and-change-review>` |
| Archive namespace bound to the intended cluster and history | `<cluster-identity-and-archive-namespace-control>` |
| Encryption, durable publication and off-host acknowledgement | `<archive-encryption-publication-and-transfer-control>` |
| Duplicate archive requests, concurrency and conflicting objects | `<idempotency-concurrency-and-conflict-test-reference>` |
| Base/WAL/history inventory and chain-completeness checks | `<chain-inventory-and-verification-reference>` |
| Restore retrieval, decryption, provenance and failure handling | `<restore-wrapper-and-negative-test-reference>` |
| Low-write periods, archive lag and capacity exhaustion | `<lag-capacity-and-low-write-test-reference>` |

An archive acknowledgement permits PostgreSQL to recycle the source WAL.
Return success only after the reviewed durability boundary is met. A repeated
request may succeed for identical, fully persisted content; conflicting
content must fail. Do not use a command that reports success without archiving.
Failed archival accumulates `pg_wal` and can exhaust its filesystem. Monitor
the archiver and capacity through the [monitoring checklist](monitoring.md).

Only completed segments are archived. Review `archive_timeout` against
`<low-write-archive-lag-budget>`; shorter intervals increase archive volume and
do not themselves prove timely off-host durability. Exercise failure, full
storage, interruption and retry behaviour before taking the first retained
base backup. Record `<archive-readiness-and-failure-test-result>`.

## 3. Protect base backups, WAL and custody independently

Encrypt physical base objects, archived WAL, timeline history and associated
sensitive manifests before they leave the approved protected boundary. Do not
create a long-lived plaintext staging copy as an undocumented convenience.
Record `<encryption-before-transfer-and-temporary-copy-control>`.

The application's TOTP/outbox encryption and archive encryption are separate
layers. Private archive identities stay under independent off-host recovery
custody, with access approval and a tested emergency retrieval process. Do not
give the web, scheduler or archive-writing host a recovery private key merely
to report status. Follow [key rotation](key-rotation.md) for retained key
versions and separation from stored archives.

Recipient encryption does not establish the archive producer's identity.
Verify provenance through `<authenticated-origin-manifest-and-transfer-control>`
before extraction or replay. A checksum stored beside an untrusted object is
not independent authentication. Verify off-host receipt, object identity,
access restrictions and recoverability; a successful local upload command or
status marker is insufficient evidence.

Record the base identity, start/end boundaries, manifest and required WAL range
in `<base-and-wal-chain-inventory>`. Preserve every segment and relevant history
file required by each retained base and supported target. Retention must also
preserve the keys and configuration needed to recover those sets. Do not prune
a shared archive by object age alone or apply a single restore's cleanup rule
to multiple retained bases. Approve the complete retained chain and exceptions
through `<retention-chain-review-and-disposal-authorization>`.

## 4. Prepare an isolated replay drill

Obtain `<drill-authorization-and-data-handling-reference>`. Use new, explicitly
disposable recovery infrastructure, a new empty PGDATA and separate tablespace
destinations. Never reset, truncate, migrate or overwrite a retained application
database or reuse the production data directory for a drill.

Before acquiring plaintext, verify:

- `<recovery-host-and-filesystem-isolation-result>` establishes restricted local
  access, capacity, ownership and disposal arrangements for restored data.
- `<network-and-service-isolation-result>` blocks production login traffic,
  source feeds, SMTP and other side effects; recovery uses separate sockets,
  ports and archive destinations with no production overwrite authority.
- `<base-wal-key-and-provenance-verification-result>` identifies the chosen
  complete chain, private-key versions and approved decryption procedure.
- `<release-configuration-and-role-review-result>` identifies the matching
  application release, configuration, identities and verification plan.

Use the selected tool's reviewed restore procedure against those isolated
paths. Where supported, run `pg_verifybackup` against the restored physical
base and manifest with the matching PostgreSQL tool version. Its integrity
checks do not replace starting the server, replaying to the target and checking
the recovered data. Record `<base-integrity-verification-result>`.

## 5. Select and verify the recovery target

Record `<target-time-lsn-or-restore-point-and-rationale>` and the required
inclusion/exclusion of the boundary transaction. Use synthetic before/after
witnesses in a disposable rehearsal to prove the intended stopping point.
Do not derive a transaction boundary solely from an application log timestamp.

Configure the reviewed restore wrapper and exactly one PostgreSQL recovery
target. Set the intended `recovery_target_timeline` explicitly in the drill
record; its default `latest` may select a different branch than intended.
Use a physical base that supports the selected branch and retain its history.
Create `recovery.signal` only inside the isolated target; check that an unwanted
`standby.signal` does not take precedence. The restore wrapper must fail for
missing or invalid objects and handle history files as well as WAL segments.

Choose `<approved-target-action-and-inspection-procedure>` deliberately:
`pause` permits inspection when `hot_standby` is enabled; `shutdown` leaves
`recovery.signal` in place and needs a reviewed subsequent-start decision.
Do not promote or resume replay merely to clear a warning. An unreachable
configured target is a failed drill, even if some earlier data is readable.

Inspect the PostgreSQL recovery logs and actual recovered state. Confirm the
selected timeline, replay boundary and synthetic witnesses, then record
`<target-state-and-before-after-witness-results>`. Measure from incident/drill
start through verified readiness, including retrieval, decryption, replay and
application checks. Record `<observed-recovery-point-and-time-results>` and
compare them with the approved RPO/RTO and assumptions.

## 6. Reconcile later changes before any reopening

Recovered database state can predate completed deletion requests, corrected
source metadata, durable hides, credential/session revocations and identity
reviews. Keep login, mail and source side effects isolated while their owners
review `<post-target-request-and-security-change-register>`.

Apply the approved [retention/DSAR reconciliation](retention-dsar-template.md#restore-reconciliation)
and [visibility/recovery acceptance](visibility-recovery-acceptance.md). Review
account deletion, local/federated reservation and approval history, current
authentication revisions, rotated or compromised keys, action authority, source
corrections, effective tiers and durable `(source, uuid)` restrictions. Do not
blindly restore a compromised signer, withdrawn record or earlier privilege.
Queued mail must be reviewed before delivery resumes.

Record `<reconciliation-execution-and-independent-review-result>`. Verify the
current role, catalogue, session and mail boundaries under the actual recovery
identities. A successful replay proves neither public-disclosure approval nor
safe application reopening. Promotion, production replacement and traffic
reopening require a separately approved deployment/incident recovery decision.

## 7. Evidence, failure and cleanup record

| Drill record | Restricted value or reference |
|---|---|
| Authorization, operator, reviewer and timestamps/timezone | `<drill-authorization-people-and-times>` |
| Source base, WAL range, timeline and key versions | `<reviewed-backup-chain-and-key-reference>` |
| Isolation, provenance, decryption and integrity checks | `<isolation-and-input-verification-results>` |
| Target, boundary witnesses and PostgreSQL replay result | `<target-witness-and-replay-result>` |
| RPO/RTO comparison, uncertainties and bottlenecks | `<measured-objectives-and-gap-analysis>` |
| Post-target reconciliation and application verification | `<reconciliation-and-application-check-results>` |
| Failures, unresolved actions, owners and due dates | `<action-owner-and-retest-record>` |
| Reopening decision or continued isolation | `<authorized-release-or-isolation-decision>` |
| Temporary copies, key access and secure disposal | `<cleanup-and-custody-verification-reference>` |

Preserve evidence and retained recovery sets; dispose of drill plaintext,
temporary exports/access under the approved schedule. Assign failed/incomplete
checks an owner and retest criterion.

## PostgreSQL 18 references

- [Continuous archiving and PITR](https://www.postgresql.org/docs/18/continuous-archiving.html)
- [WAL, archive recovery and recovery targets](https://www.postgresql.org/docs/18/runtime-config-wal.html)
- [Physical base backups](https://www.postgresql.org/docs/18/app-pgbasebackup.html)
- [Base-backup integrity verification](https://www.postgresql.org/docs/18/app-pgverifybackup.html)

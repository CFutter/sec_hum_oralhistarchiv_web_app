# JSON-feed evidence and recovery acceptance

**Status: B9 executable evidence and synthetic recovery checks.** B7 persistence
and B8 catalogue checks are accepted. B9 links the stable requirements to actual
tests and adds an encrypted synthetic restore. Real-source activation still
requires the independent operational records below.

## Requirement evidence

[source-b-evidence.json](source-b-evidence.json) maps every one of the 22
`SB-DISC-*`, `SB-VIS-*` and `SB-TRANS-*` requirements to pytest function nodes.
A base function node includes all its parameter cases. Each mapped function's
docstring carries the literal requirement ID; the evidence tests check those
references against real collection and reject skip/xfail placeholders.

Collection proves that the references resolve. Passing behavior tests, their
service prerequisites and retained execution results establish the automated
evidence. The map does not record an owner approval or a production restore as
complete merely because a related synthetic test passes.

The structural-disclosure counterexample deliberately uses a synthetic title
that passes schema validation while lacking public-disclosure approval. It is
never ingested. This pins the limit of structural validation: source governance
must approve human-language values and the complete public envelope.

## Backup preflight and permissions

The backup preflight verifies database/login identity, its pinned Alembic head,
read-only access to every nonextension public relation and these required
relations: `alembic_version`, `oral_history_datasets`, `dataset_admin_state`,
`sync_status`, `ingestion_failures`, `ingestion_quarantine`,
`source_security_state`, `source_binding_acknowledgements`,
`security_audit_events`, `security_audit_receipts`, `anonymous_mail_issuance`,
`catalogue_search_policy`, `catalogue_search_public`,
`catalogue_search_registered`, `catalogue_search_vetted`, `users`,
`totp_recovery_codes`, `admin_promotion_requests`, `federation_policy_state`,
`email_outbox`, `sessions` and `pending_totp_rotations`.

Quarantine is part of recovery state. Staged bytes, positions and committed
cutoffs live in `sync_status`; durable floors/hides live in
`dataset_admin_state`. A healthy whole-database dump already includes these
tables. The completeness gate refuses an incomplete schema before publication;
a rejected preflight must preserve previously retained encrypted archives.

The composed deployment test checks the real backup login and read-only grants
in addition to the web and scheduler identities. Its test transport is TCP;
production OS peer mappings and deployed identity separation still need their
own operational checks.

## Encrypted synthetic round trip

`src/tests/integration/test_source_b_backup_db.py` ingests signed native fixtures,
creates quarantine/last-known-good state, applies real administrative
restrictions and interrupts a real staged incremental application. It streams
the whole custom-format dump through `age`, then decrypts and restores it into
a newly created disposable database. No plaintext dump file is written.

The test compares complete source-owned snapshots for two sources sharing a
UUID. Restored state must include rows/raw metadata, source binding/cutoff,
quarantine, durable floors/hides and staged bytes/progress. Resuming the restored
stage must use no network fetch, preserve the other source and clear only the
successfully reconciled staging/failures.

Snapshot equality and the retained source-tier ledger are checked before
replay. Replaying a valid explicit upstream tier correction may then lower the
source classification under its configured floor. The encrypted round trip
covers both a `public` correction resolved to a `registered` source floor and an
unchanged `vetted` assertion. Durable administrator floors and hides must remain
unchanged in both cases.

The test requires `age`, `age-keygen`, `pg_dump` and `pg_restore` on `PATH`.
For this round trip into the same cluster, both PostgreSQL clients must match
the server's major version, which must be 18. CI pins Ubuntu 24.04 and installs/selects
the PostgreSQL 18 clients and `age`. Missing or mismatched tools fail the test
rather than turn recovery evidence into a skip.

Use the normal disposable PostgreSQL/Redis test services and a test database
named `*_test` or `*_test_gwN`. The test login needs the same database-creation
authority used by the parallel test harness. Only the newly created restore
database is removed during cleanup; the test never drops the input database.

```bash
REQUIRE_DB=1 REQUIRE_REDIS=1 uv run pytest -q \
  src/tests/unit/test_source_b_evidence.py \
  src/tests/unit/test_runtime_preflight.py \
  src/tests/integration/test_source_b_backup_db.py
```

Run the normal complete serial and randomized parallel suites, coverage floors,
typing, lint and documentation gates before accepting B9. The CI round trip
uses synthetic data, a disposable key and the test login for dump/restore. It
does not prove production backup/recovery role separation, off-host custody or
representative private-feed recovery. The existing archive verifier checks
decryption and `pg_restore --list`; that remains separate from data restoration.

## Final operational record

Keep dated records for all three obligations named in the evidence map:

| Record | Required evidence |
|---|---|
| `source_owner_approval` | Reviewed public values/mappings and samples; explicit approval of combinations, existence, enumeration, ordering, counts and detail responses; reviewer and approved source/configuration version |
| `real_feed_acceptance` | Actual configured schema and signed full/incremental chains; correction, withdrawal and quarantine/recovery behavior; configuration fingerprint and execution result without credentials or private payloads |
| `representative_encrypted_restore` | Trusted archive provenance; separate backup/recovery identities and off-host key custody; encrypted isolated restore with representative native state; backup-time comparison, staged recovery, applicable application-key checks and cleanup result |

Use the deployment backup/restore runbook on a disposable recovery environment
that cannot reach production. Check the deployed backup role can read every
relevant relation, including quarantine and any enabled RLS boundary. Compare
approved backup-time state with restored state; a table-of-contents listing or
successful decryption alone is insufficient. Preserve application encryption
key versions required by the archive without putting their values in evidence.

Record the archive/storage identity, release revision, source configuration
fingerprint, reviewer/operator, date and pass/fail result. Keep row contents,
capability tokens, credentials and private keys out of the acceptance record.
Retain the last restore-verified archive according to the approved retention
policy until a successor is verified.

B9 prepares these checks; WP B closes only when the automated evidence and all
three operational records are accepted. See the
[Sensitive Source Contract](../architecture/source-b-ingestion-contract.md),
[Feed Contract v1](feed-contract-v1.md) and
[deployment overview](../configuration/deployment.md).

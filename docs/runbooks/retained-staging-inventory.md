# Retained staging inventory and recovery preparation

Treat existing staging as a retained-state upgrade rehearsal; use a separate
disposable target for fresh installation. Do not recreate the retained database
to make a candidate start. Use the [private worksheet](retained-staging-record-template.md)
to record the observed contract, preservation decisions, forward procedure and
verified recovery before approving changes.

## Establish the actual starting point

Record the installed artifact digest/source identity and private configuration
version separately from the candidate. Record the reviewed collector's SHA-256
as well: an older installed release does not contain this new script. Run the
reviewed standalone file from an approved operator path with Python 3.11 and the
locked project's `psycopg` dependency available. Do not replace the installed
application or start candidate services to collect an inventory.
The standalone file can live directly under `/tmp` or another approved directory;
its installation prefix is not treated as an application checkout. A copy still
inside this project's `scripts/` directory automatically excludes that checkout
when its `pyproject.toml` and `src/app` layout are present.

The single baseline revision is `4f73ae3ff827`. Earlier bodies of that revision
and the manual K2 upgrade can share the same Alembic label. Compare actual
columns, constraints, indexes, views, routines, triggers, RLS, policies, owners,
grants, roles and source bindings. `alembic upgrade head` or a matching label
alone does not prove equivalence. Never stamp the revision to bypass a mismatch.

The collector imports no application settings or services. It uses libpq
connection configuration (`PGSERVICE` or reviewed `PGHOST`, `PGPORT`,
`PGDATABASE`, `PGUSER` and authentication), with fixed connection/query/lock
timeouts and a fresh read-only repeatable-read transaction. It requires
PostgreSQL 18, the expected database name and matching current/session users.
It also sets and verifies `row_security=off`: PostgreSQL then errors if a
policy would filter a query, rather than silently returning a partial count.
This setting does not bypass row security.
Use the reviewed migration/database owner identity, outside runtime environments;
a web role can see an RLS-filtered catalogue and cannot establish retained totals.
Do not grant privileges or change peer mappings merely to make a capture pass.

## Capture a private report

Choose the host's actual connection and deployment-lock paths. The laptop
example's port is not evidence of the retained host's configuration. Do not put
passwords, connection strings or application key values in command arguments.
Use the approved libpq authentication mechanism and operator OS identity.

Set these nonsecret shell variables to reviewed absolute paths and the expected
database before running the command:

- `bs4_python`: interpreter with the reviewed locked `psycopg` dependency.
- `bs4_tool`: reviewed standalone `inventory_staging.py` file.
- `bs4_record_dir`: new private evidence directory outside every source checkout.
- `bs4_exclude_root`: an existing source checkout or other directory that must
  never contain the report. Use an absolute path without `..`; repeat
  `--exclude-root` for each reviewed exclusion. For standalone execution with
  no source checkout or additional exclusion on the host, omit that option.
- `bs4_deploy_lock`: the existing deployment lock used by the retained services
  and migrator (the shipped deployment uses `/run/lock/oralhistarchiv-deploy.lock`).
- `bs4_expected_database`: the approved retained database name.

As the approved collector OS identity:

```bash
umask 077
install -d -m 0700 "$bs4_record_dir"
/usr/bin/flock --shared --nonblock --no-fork "$bs4_deploy_lock" \
  "$bs4_python" -I "$bs4_tool" \
  --expected-database "$bs4_expected_database" \
  --exclude-root "$bs4_exclude_root" \
  --output "$bs4_record_dir/retained-before.json"
sha256sum "$bs4_tool" "$bs4_record_dir/retained-before.json"
```

Verify the directory is owned by that OS identity and mode `0700`. The collector
validates the destination and reviewed exclusions before connecting to PostgreSQL.
It requires a private parent, creates a new `0600` report exclusively and refuses
an existing destination, symlink or output within any inferred or explicitly
excluded root. The validated directory descriptor remains pinned through
collection and publication. Standalone mode does not discover unrelated source
checkouts: list them with `--exclude-root` when present. Never overwrite
an earlier capture; use a new reviewed filename. A refusal or query error exits
nonzero with a static diagnostic. Investigate privately rather than publishing
database error text or repeatedly changing permissions.
After an I/O failure inspect the private destination before retrying; do not
assume a failure means no report or temporary file exists.

The shared lock permits the running services' shared locks while excluding the
cooperating exclusive migrator/installer. Stop if the lock or its use has not
been established. Arrange no independent DDL, grants, role or configuration
changes during capture; the lock cannot prevent uncooperative SQL. Ordinary data
writes may continue and the report reflects one database snapshot. That snapshot
is not a maintenance boundary or a recoverable backup.

## Interpret without exposing retained data

The report includes database/role identities, catalog metadata, definition and
setting digests, bounded managed-table counts and allowlisted source progress.
Definitions/defaults/settings are hashed; source fingerprints are hashed and
staged bytes are represented by presence/length only. It excludes account rows,
catalogue payloads, error messages and ciphertext. It still contains restricted
operational information: retain it privately, do not commit it or paste it into
a public issue. Digests do not make low-entropy configuration anonymous.

Missing objects/columns, unreadable tables, unsafe row visibility, unexpected
column types and bounded-result refusals require review. A missing or unknown
value is not zero. The collector is not the application's complete schema or
runtime-role validator and does not declare compatibility. Counts and catalog
digests do not prove all retained row values were preserved.

On an isolated restored copy with no concurrent DDL, use the existing
`validate_schema_against_db` comparison and runtime-role validation to establish
candidate compatibility. Follow the [deployment procedure](../configuration/deployment.md)
and [visibility/recovery acceptance](visibility-recovery-acceptance.md). The
schema helper uses separate read transactions; do not treat it as an atomic
snapshot or invoke application startup against retained staging for inventory.

Classify the starting state before approving any write:

| Actual starting state | Next action |
|---|---|
| Actual contract already matches the candidate | Record exact comparison and role/grant evidence; still rehearse artifact/configuration change and preservation |
| Earlier K1 search-owner contract | Prepare a separately reviewed conversion; the historical `deploy/upgrade-search-k2.sql` requires PostgreSQL 16 and cannot upgrade this PostgreSQL 18 target |
| Older, partial, altered or unknown contract | Prepare a separately reviewed retained-data conversion; do not recreate, stamp or run the K2 asset speculatively |

The historical K2 owner asset also refuses already-upgraded or conflicting states.
It is not a PostgreSQL 18 conversion or generic baseline repair. K1 source-interpretation changes use the
normal authoritative rebuild procedure; never rewrite fingerprints/cursors or
discard a staged harvest to force acceptance. Record what that rebuild will
legitimately replace and what durable state must survive.

## Prepare upgrade and recovery evidence

Copy the blank worksheet into the private evidence system. Preserve accounts,
authenticator/recovery state, catalogue identifiers/protected values, durable
hides/tiers and exact ingestion progress/quarantine. Record a deliberate policy
for sessions, pending actions and queued mail, plus separate key-version/custody
references. Do not copy keys into the worksheet.

A verified pre-change recovery point requires an actual restore and retained
state/decryption checks on an approved isolated target. Successful archive
creation, digest comparison, off-host receipt or `pg_restore --list` alone does
not prove recovery. Keep mail delivery and external source effects disabled on
the target; reproduce required roles, peer mappings and database settings under
review. See [key rotation](key-rotation.md),
[recovery acceptance](visibility-recovery-acceptance.md) and the
[PITR decision/runbook](point-in-time-recovery.md).

Choose a supported recovery action: compatible application rollback, reviewed
forward repair, or isolated encrypted recovery with an approved cutover. Never
use an ad-hoc destructive downgrade of the shared baseline. Record expected
outage, loss boundary, acceptance comparisons and the point beyond which an old
application artifact is no longer compatible.

Acceptance requires the actual artifact/configuration/database inventory,
preservation decisions, reviewed forward procedure and restore-verified recovery
point. Share only a reviewed summary of completion, PostgreSQL/revisions,
missing/unknown categories, contract differences and the private evidence
reference; keep the full report and row data private.

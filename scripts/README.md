# Operational scripts

Application maintenance scripts import the application from the installed release wheel.
Pytest's `pythonpath = ["src"]` does not configure ordinary Python scripts.
Editable installs and `PYTHONPATH=src` are development-only workflows.

## Retained staging inventory

`inventory_staging.py` is a standalone read-only operator tool using stdlib and
the locked `psycopg` dependency; it does not import application settings/services.
Follow the [retained staging runbook](../docs/runbooks/retained-staging-inventory.md)
for reviewed libpq authentication, database identity, shared deployment lock and
private exclusive output. It does not migrate, declare schema compatibility or
verify a recovery point. Record the reviewed file digest separately from the
installed release. Never start candidate application services to obtain an inventory.
The CLI requires `--expected-database NAME --output /absolute/private/report.json`.

For authors/CI, `python scripts/check_staging_inventory.py` compares the literal
managed-table inventory (plus Alembic's version table) with all current table
contracts and the selected safe progress fields/types with the sync contract.
Diagnostic error fields are explicitly excluded; new sync fields require a
classification. This offline checker imports current application contracts,
while `inventory_staging.py` remains standalone. Older databases may lack listed
tables/columns: the runtime inventory still records those observations using its
existing missing/unsupported status paths; the authoring check does not remove
that backwards-inspection support or certify those databases for service.

Add repeatable `--exclude-root /absolute/checkout` options for reviewed source
checkouts or directories that must not contain evidence. Exclusions must exist
and have no parent-traversal components. Checkout execution also excludes this
project automatically; a standalone copy infers no checkout from its installation
prefix, including when it is directly under `/tmp`. Destination/exclusion checks
run before any database connection, and publication retains the validated parent
directory descriptor. See the runbook for the complete locked invocation.

## Catalogue search policy

`rebuild_search_policy.py` is included in the installed release alongside the
application wheel. Follow the [search-policy runbook](../docs/runbooks/search-policy.md)
to rebuild the audience projections during maintenance with an explicit expected
fingerprint and owner database credentials. The command compares and replaces the
binding atomically; ordinary web startup does not perform this rebuild.

## TOTP key maintenance

Follow [key rotation](../docs/runbooks/key-rotation.md#5-rotating-totp_encryption_keys),
including maintenance mode, backup verification and stopping both writers.
Load root-owned `common.env` and least-privileged `web.env`, never
`migration.env`, a release-local `.env`, or shell-sourced production secrets.

Run the installed script under a transient unit. Its exclusive deployment lock
prevents concurrent runtime startup, release replacement or schema migration:

```bash
sudo systemd-run --wait --pipe --collect \
  --uid=oralhistarchiv \
  --working-directory=/opt/oralhistarchiv \
  --property=EnvironmentFile=/etc/oralhistarchiv/common.env \
  --property=EnvironmentFile=/etc/oralhistarchiv/web.env \
  --property=UnsetEnvironment='PYTHONPATH PYTHONHOME VIRTUAL_ENV' \
  /usr/bin/flock --exclusive --nonblock --no-fork \
  /run/lock/oralhistarchiv-deploy.lock \
  /opt/oralhistarchiv/.venv/bin/python -I \
  /opt/oralhistarchiv/scripts/reencrypt_totp.py --batch-size 500
```

Keep `TOTP_ENCRYPTION_KEYS=[new, old]` configured with the new key first. After
successful re-encryption, run the same command with
`/opt/oralhistarchiv/scripts/verify_totp_reencryption.py` as its script argument.
The verifier uses only the primary key even while fallback keys remain.
Remove old keys only after verification exits zero and after accounting for
historical backups that still need them.

Both scripts cover active/pending user secrets and `pending_totp_rotations.encrypted_secret`. They page by user ID with `--batch-size` from 1 to 5000 (default 500) and a 60-second statement timeout. Re-encryption commits each page and compare-and-swaps ciphertext; verification reads only. Exit 1 reports skipped/unreadable values; other errors also exit nonzero. Investigate and rerun re-encryption and verification before restarting writers.


## Release builds and CI checks

From a clean Git checkout at the reviewed commit, use Python 3.11 and uv 0.12.11. The output directory must not exist; dependency distributions must be available from the configured package sources/cache.

```bash
python3.11 scripts/build_release.py \
  --commit-sha "$(git rev-parse HEAD)" \
  --output-dir /tmp/oralhistarchiv-release
```

The builder validates the lock, builds an sdist and wheel, installs hash-locked binary runtime dependencies in isolation, smoke-tests packaged assets, and writes a release archive. A ZIP without Git provenance cannot build a release. `run_wheel_smoke.py` performs the same build using `GITHUB_SHA` and discards temporary output; `smoke_installed_wheel.py` and `wheel_smoke_env.py` are internal helpers used by the builder.

The three offline installed-wheel probes (packaged assets, migration heads and
offline migration SQL) share an environment built by `wheel_smoke_env.py`.
It preserves only these host variables, matching their names case-insensitively:
`PATH`, `HOME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TMPDIR`, `TEMP`, `TMP`,
`SYSTEMROOT`, `WINDIR`, `COMSPEC`, `PATHEXT`, and `USERPROFILE`.
Fixed development smoke settings are then added. Active, retired and unknown
application variables are excluded; new optional application settings therefore
use their declared defaults. New required settings must be added to the smoke
fixtures. Importing application settings is not needed to filter the environment.

Build and dependency-install commands keep the builder's separate environment,
including package-source, proxy and certificate configuration. Those variables
are excluded from the offline probes. Add any additional host requirement to
the explicit allowlist, its tests and this reference together.

Repository gates:

```bash
bash scripts/check-no-site-refs.sh
bash scripts/check-no-opaque-refs.sh
set -o pipefail
pytest -rs --no-fold-skipped 2>&1 | tee /tmp/oralhistarchiv-pytest.log &&
  bash scripts/check-skips-are-expected.sh /tmp/oralhistarchiv-pytest.log
```

The site-reference gate covers indexed and new unignored files across the entire
repository.
The opaque-reference gate scans tests, docs, workflows, and `pyproject.toml`. The skip gate reads a completed pytest log from its argument or stdin. Outside CI it accepts exact entries in `scripts/expected-skips.txt` (override with `EXPECTED_SKIPS_FILE`); under CI it accepts no skips. It checks skip policy, not test success; the command chain above preserves pytest failures.


## Dependency advisory checks

`audit_dependencies.py --output-dir NEW_DIRECTORY` checks locked runtime and all
optional dependency extras, then builds a wheel in an isolated hash-constrained
environment and scans its actual installed inventory. Run it with the locked
development environment and network access. Advisories and incomplete scans both
fail; UTC metadata, inventories, requirements and diagnostics remain available.
The main security job and weekly dependency workflow retain this evidence. See
[the dependency advisory runbook](../docs/runbooks/dependency-advisories.md).

# Dependency advisory checks

The main CI security job and a weekly dependency workflow run the same
`scripts/audit_dependencies.py` command. The weekly workflow can also be started
manually. It checks new advisory information against unchanged pins, rather
than depending on a source change to trigger another scan.

Run the check with the locked development tools on a networked Python 3.11
runner:

```sh
uv sync --locked --extra dev --no-install-project
.venv/bin/python scripts/audit_dependencies.py --output-dir dependency-advisories
```

The output directory must be new. Do not reuse an earlier successful result
after an interrupted or failed invocation. The command checks three scopes:

1. Runtime requirements exported from `uv.lock`.
2. All optional dependency extras, including development and documentation,
   exported from the same lock.
3. An actual isolated environment that builds the current wheel. It installs
   the hash-constrained `build-requirements.txt` packages and the lock's exact
   hashed pip version, then inventories and scans that interpreter's installed
   site-packages. Backend requirements must match the declared constraints;
   additional dynamic backend requirements fail until explicitly constrained.

The scanner environment is installed without building the application. The
separate build proof calls the declared backend in the environment whose
inventory is retained. Exporting extras alone would not cover this backend or
its transitive dependencies. Build-tool pins and hashes remain independent of
the runtime export. The pinned uv executable version is retained in command
evidence; Python package scanning does not assess every host binary or action.

Each run saves UTC start/end times, the source commit supplied by CI, lock and
constraint hashes, per-command outcomes, three scanner reports when available,
and the resolved build inventory. CI retains JSON, requirements and diagnostic
logs for 30 days, including failed runs. It does not upload the generated
environment or wheel. Archive evidence under the institution's retention policy
if a release decision requires it longer than the CI retention period.

Known advisories, skipped packages, missing or malformed reports, inventory
mismatches, network errors and command timeouts fail the command. A failed scan
is incomplete evidence; it does not establish that packages are unaffected.
The scanner does not automatically edit dependencies or ignore advisories.
Review affected ranges and supported upgrades, update the relevant pins/locks,
then obtain a complete successful run. Record any approved exception explicitly
with its advisory identifier, affected package/version, justification and expiry
before adding a narrowly scoped exception mechanism.

The default command deadline is five minutes per subprocess. A bounded local
diagnostic run may use `--timeout-seconds 30`; a timeout still fails. An offline
or restricted runner can exercise contract tests but cannot establish current
advisory status. Successful unit tests verify the failure policy and inventory
selection; a complete live scan remains required for release evidence.

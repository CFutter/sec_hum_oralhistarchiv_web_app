# Operational scripts

Production scripts import the application from the installed release wheel.
Pytest's `pythonpath = ["src"]` does not configure ordinary Python scripts.
Editable installs and `PYTHONPATH=src` are development-only workflows.

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

Repository gates:

```bash
bash scripts/check-no-opaque-refs.sh
set -o pipefail
pytest -rs --no-fold-skipped 2>&1 | tee /tmp/oralhistarchiv-pytest.log &&
  bash scripts/check-skips-are-expected.sh /tmp/oralhistarchiv-pytest.log
```

The reference gate scans tests, docs, workflows, and `pyproject.toml`. The skip gate reads a completed pytest log from its argument or stdin. Outside CI it accepts exact entries in `scripts/expected-skips.txt` (override with `EXPECTED_SKIPS_FILE`); under CI it accepts no skips. It checks skip policy, not test success; the command chain above preserves pytest failures.
# Deployment identities, locks and release environments

## Deployment lock participation

Provision a dedicated system group before installing the tmpfiles rule:

```sh
sudo groupadd --system --force oralhistarchiv-deploy-lock
sudo usermod --append --groups oralhistarchiv-deploy-lock oralhistarchiv
sudo usermod --append --groups oralhistarchiv-deploy-lock oralhistarchiv-scheduler
sudo usermod --append --groups oralhistarchiv-deploy-lock oralhistarchiv-migrate
sudo usermod --append --groups oralhistarchiv-deploy-lock oralhistarchiv_backup
sudo install -o root -g root -m 0644 deploy/oralhistarchiv-tmpfiles.conf \
  /etc/tmpfiles.d/oralhistarchiv.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/oralhistarchiv.conf
```

The stable `/run/lock/oralhistarchiv-deploy.lock` inode is root-owned and mode
`0640`, with group `oralhistarchiv-deploy-lock`. Group members need read access
to take a lock; they do not need write access. The shipped runtime, migration
and backup units explicitly request this supplementary group. OS membership
also supports reviewed direct maintenance commands. Restart affected services
after provisioning membership. Do not add nginx, parser workers, interactive
users or unrelated services to the group.

Do not unlink or replace an in-use lock file. Runtime services hold shared
locks for their entire lifetime; deployment and migrations require exclusive
locks. Each runtime/migration start waits at most 60 seconds, then returns exit
status 75 if a conflicting operation remains. Inspect the active holders and
retry after the intended maintenance operation completes. The installer keeps
its nonblocking acquisition and backup keeps its existing bounded acquisition.

The ordinary tests execute the shipped lock prefixes to verify bounded failure
and successful retry. Qualify group exclusion with real kernel identities on a
disposable Linux host as root:

```sh
sudo env RUN_DEPLOYMENT_LOCK_TESTS=1 \
  /path/to/qa/.venv/bin/python -m pytest --no-cov -q \
  src/tests/host_proofs/deployment_lock.py
```

This explicit test uses temporary files and unused numeric UIDs/GIDs, without
changing installed accounts or the real lock. A container without identity
switching privileges cannot establish this host property.

## Runtime database reads

The scheduler reads only account identity, delivery eligibility, action-token
state and stale-account cleanup columns. It cannot select password hashes,
active or pending authenticator ciphertext, or unrelated account authority
fields. Its account-row locking permission remains limited to `last_login`.
Adding an eligibility field to delivery or cleanup requires reviewing the
column grant, application privilege contract and standalone SQL verifier
together. Do not restore table-wide account SELECT to resolve a startup error.

New owner-created functions receive no PUBLIC execution by default. Callable
runtime routines require explicit grants and matching startup contracts. This
default applies globally within the database; schema-local grants remain
additive. Existing-routine revocations and runtime verification remain required.

## Installer-owned Python environments

Authenticate the outer release artifact through the independent provenance
workflow before running the installer. The internal manifest checks payload
consistency and does not establish authenticity.

Incoming archives and manifest entries may not contain a `.venv` path component
at any depth. All incoming files participate in manifest validation. The
installer then creates the root `.venv` at its final absolute release path,
refusing a preexisting directory or symlink before invoking Python or pip.
Only this exact generated root environment is excluded from later payload
checks. A nested environment in another payload directory is always rejected.

An interrupted incomplete release is preserved separately for investigation;
its environment is never merged into the fresh installation. Completed
root-managed releases may be reused after payload and installed-import checks.
Keep release directories and their generated environments writable only by the
deployment administrator.

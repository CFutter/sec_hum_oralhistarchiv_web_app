# Runbook — Secret and Key Rotation

**Applies to:** Digital Oral History Archive (`oralhistarchiv`)

**Audience:** Operators with access to the deployment host and its secret configuration.

## 0. First deployment and secret inventory

For a fresh database, configure independent encryption keys:

```dotenv
TOTP_ENCRYPTION_KEYS=["<independently-generated-totp-key>"]
OUTBOX_ENCRYPTION_KEYS=["<independently-generated-outbox-key>"]
```

Generate different values for these two settings and for `SECRET_KEY` and `SESSION_SECRET`. Use the same outbox key ring in every web and scheduler process within an environment; use different secrets between environments.

The initial schema creates the outbox. No legacy key migration or SECRET_KEY fallback is supplied; existing encrypted data requires a reviewed preservation plan.

The rotation procedures below apply after data starts being retained. They are not steps required to initialize a fresh database.

| Secret | Purpose | Effect of changing or removing it |
| --- | --- | --- |
| `TOTP_ENCRYPTION_KEYS` | Encrypts active and pending TOTP secrets using HKDF-derived Fernet keys and `MultiFernet` | An old key must remain available while stored secrets depend on it. Dropping it early can prevent TOTP login or enrollment. |
| `OUTBOX_ENCRYPTION_KEYS` | Encrypts stored email-outbox bodies using a separate HKDF context and `MultiFernet` | An old key must remain available while retained bodies depend on it. Undecryptable claimed messages are marked `dead` by the delivery worker. |
| `SECRET_KEY` | Signs action links; derives audit-email and limiter-client HMAC keys | Invalidates outstanding links, changes audit correlation and starts a new limiter-client namespace; TOTP/outbox encryption is unchanged |
| `SESSION_SECRET` | Signs session cookies and authenticates CSRF tokens | Existing session cookies become invalid; users must log in again. CSRF cookies refresh through the normal request flow. |
| PostgreSQL peer mappings and role grants | Bind each service OS identity to one passwordless database role with an exact privilege contract | Treat any OS-user, PostgreSQL-role, socket, HBA/ident-map, or grant change as a reviewed database trust-boundary migration; runtime startup rejects a mismatched role or grant set. |
| `SMTP_PASSWORD` | Authenticates to the mail provider, when configured | Delivery fails until provider and application credentials match; outbox attempts can progress to retries or `dead`. |
| `SHIBBOLETH_INTERNAL_SECRET` | Bearer credential on the nginx-to-web SSO trust boundary | A holder who can reach the Gunicorn socket can assert any allowed issuer/subject/MFA header set and impersonate a federated identity. Rotation temporarily disables SSO; the required web restart detects the changed policy fingerprint and revokes every Shibboleth session transactionally, leaving local sessions untouched. |
| `HEALTH_DETAIL_TOKEN` | Authorizes `/health/detail` requests | Monitoring clients must receive the new token. |
| `REDIS_URL` password | Optional general Redis | Catalogue-statistics invalidation is disrupted; dev may also use it for limiting |
| `RATE_LIMIT_REDIS_URL` password | Dedicated hardened-web limiter Redis | Admission fails with 503 until credentials match |
| `ADMIN_SEED_PASSWORD` / `ADMIN_SEED_EMAIL` | Bootstraps the first administrator | Remove after initial setup; these are not the existing administrator's ongoing password configuration. |
| Backup `age` private identity | Decrypts logical `*.dump.age` database archives; only its public recipient is provisioned to the backup unit | Loss prevents recovery. Exposure reveals every archive made for that recipient, including database fields not protected by application-level encryption. It is not an application setting and must remain off-host. |

### Cryptographic domains

| Key material | HKDF context or signing domain |
| --- | --- |
| Each `TOTP_ENCRYPTION_KEYS` entry | `oralhistarchiv-totp-encryption-v1` |
| Each `OUTBOX_ENCRYPTION_KEYS` entry | `oralhistarchiv-email-outbox-body-v1` |
| `SECRET_KEY` for audit hashing | `oralhistarchiv-audit-email-hash-v1` |
| `SESSION_SECRET` for session cookies | Signer salt `session-cookie-v1` |
| `SESSION_SECRET` for CSRF | HMAC prefix `csrf-hmac-v1|` |

Changing a context string changes the derived key even when the configured secret is unchanged. Treat context changes as key changes with the same data-preservation requirements.

## 1. Rules before rotation

1. **Keep both encryption key rings non-empty.** Both settings are required `list[SecretStr]` fields with `min_length=1`.
2. **Keep every decryption key that retained data still needs.** This includes `users.pending_totp_secret` and outbox bodies retained in `sent` or `dead` rows.
3. **Restart every process that uses changed secrets.** Crypto objects are cached at module import. Editing configuration or reloading nginx does not rebuild the application's keys.
4. **Prevent mixed key configurations.** The procedures here use a maintenance window with all web and scheduler instances stopped before changing a signing key or activating an encryption key. Include ad-hoc producers, delivery workers, and maintenance jobs.
5. **Retain both recovery layers until verification is complete.** Account for backups and retained snapshots before destroying an application encryption key. A database archive does not contain the application key needed to decrypt its TOTP/outbox ciphertext, and the separately escrowed backup `age` identity is needed before the archive can be opened at all. Never co-locate either private layer with the archives.
6. **Do not roll back by discarding a key that has already encrypted data.** A routine rollback may change which key is first, but must retain all still-required decryptors. Do not restore a compromised key as an active signer or encryptor.

Rotate on confirmed or suspected exposure, host or secret-store compromise, changes in authorized access, and the organization's established rotation policy. For an exposure, prioritize containment; retaining a compromised decryptor temporarily preserves availability but does not repair confidentiality of previously exposed data.

## 2. Generating and applying secrets

Generate a fresh value for each signing secret, optional access token, and each encryption-key entry:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(64))'
```

To generate the complete JSON value for a new one-key ring:

```bash
python -c 'import json, secrets; print(json.dumps([secrets.token_urlsafe(64)]))'
```

Generate each secret separately. Placeholders in this runbook and `.env.example` are not deployment values.

`validate_security_settings()` checks `SECRET_KEY`, `SESSION_SECRET`, every entry in both encryption key rings, and optional `HEALTH_DETAIL_TOKEN` and `SHIBBOLETH_INTERNAL_SECRET` values when configured. Its length, diversity, entropy, and blocklist checks reject obviously weak values; they do not prove randomness. Ordinary weak or placeholder secrets block startup in staging and production and produce warnings in development. Federated authentication is stricter: whenever `SHIBBOLETH_ENABLED=true`, a weak, reused, missing, or blank `SHIBBOLETH_INTERNAL_SECRET` fails settings construction in **every** environment. Missing or empty encryption key rings also fail settings validation in every environment.

### Configuration source

- **Development:** Pydantic reads the repository-root `.env` when the OS-level `ENV_STATE` selects development, or is unset and defaults to development.
- **Staging and production:** both runtime services load root-owned mode-`0600` `common.env`; web additionally 
  loads `web.env` and the optional web-only `shibboleth.env`, while scheduler loads `scheduler.env`. `DATABASE_URL` is absent from `common.env`. The manual migration unit loads only `migration.env`; no runtime or maintenance process may load it.
- **Maintenance commands:** TOTP scripts use the installed-wheel invocation in
  scripts/README.md with common.env and web.env; never source migration.env.
  For this runbook's interactive SQL, use the web peer role after stopping the
  required services:

  ```console
  sudo -u oralhistarchiv /usr/bin/psql -X --no-password \
    --host=/var/run/postgresql --dbname=oralhistarchiv \
    --username=oralhistarchiv_web --set=ON_ERROR_STOP=1
  ```

  Confirm the database/role before executing SQL; quit with `\q` afterward.

### Maintenance window

For this deployment, put the site into maintenance mode and stop both services before changing active key configuration:

```bash
sudo systemctl stop oralhistarchiv.service oralhistarchiv-scheduler.service
```

Confirm that all instances and any separate jobs have stopped. Let in-flight work finish where possible; do not assume stopping an SMTP worker can retract an email already accepted by the relay.

After the relevant procedure is complete, start both services with the final configuration:

```bash
sudo systemctl start oralhistarchiv.service oralhistarchiv-scheduler.service
journalctl -u oralhistarchiv.service -u oralhistarchiv-scheduler.service -n 100 --no-pager
```

Confirm clean startup and the procedure-specific checks before reopening traffic. These commands assume the service names in the current deployment guide.

## 3. Rotating `SECRET_KEY`

**Effect:** Invalidates signed links, including queued links; changes audit hashes and limiter-client identifiers, giving clients fresh counters. TOTP/outbox encryption and session signatures use other keys.

| Token | Maximum age in the current code |
| --- | --- |
| Password reset | 30 minutes (`RESET_TOKEN_MAX_AGE_SECONDS`) |
| Email change | 1 hour (`EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS`) |
| Email verification | 24 hours (`VERIFICATION_TOKEN_MAX_AGE_SECONDS`) |

An outbox body being decryptable does not mean its signed link is valid. The key-ring change does not add automatic cancellation of emails carrying invalidated links.

### Procedure

1. Enter the maintenance window and stop all producers and delivery workers, as described in [Maintenance window](#maintenance-window).
2. Generate and provision a new `SECRET_KEY`. Keep `TOTP_ENCRYPTION_KEYS`, `OUTBOX_ENCRYPTION_KEYS`, and `SESSION_SECRET` unchanged for this operation.
3. Cancel outstanding messages carrying links signed with the previous key before restarting delivery. In the current schema, cancellation uses `dead` with an explicit reason; there is no `cancelled` status. Run the following against the intended database while the application remains stopped:

   ```sql
   BEGIN;

   UPDATE email_outbox
      SET status = 'dead',
          terminal_outcome = 'cancelled',
          failed_at = CURRENT_TIMESTAMP,
          sent_at = NULL,
          locked_at = NULL,
          lock_token = NULL,
          last_error = 'Cancelled: signing-key rotation invalidated the link'
    WHERE status IN ('pending', 'sending')
      AND message_type IN (
          'password_reset',
          'email_verification',
          'email_change_verification'
      )
   RETURNING id, message_type;

   COMMIT;
   ```

   Preserve non-token notices, including account-lock and credential-fault notices. The query does not delete ciphertext, alter already-sent rows, or retry previously dead messages. Do not manually requeue an old token-bearing body after this rotation; generate a fresh request and message instead.

4. Start every service with the new signing key and verify clean startup.
5. Request a fresh password-reset email and verify the complete delivery and link flow. Confirm that an old outstanding link is rejected and that an ordinary queued notice remains deliverable.

Users with invalidated links must request new ones. During a compromise rotation, do not restore the previous signing key: doing so can make old signatures valid again.

## 4. Rotating `SESSION_SECRET`

**Effect:** Existing session cookies fail signature validation, and users must log in again. CSRF cookies refresh through the normal request flow. Changing this secret does not delete server-side session rows; those remain until revoked or cleaned up.

1. Enter the maintenance window.
2. Generate and provision a new `SESSION_SECRET`.
3. Start both services and verify clean startup.
4. Confirm that an existing session cookie no longer authenticates, a fresh login succeeds, and a form submission works with a fresh CSRF cookie.

Use this to invalidate existing signed session cookies. For account-specific revocation, use the application's session-revocation functions instead of rotating a global secret.

## 5. Rotating `TOTP_ENCRYPTION_KEYS`

`_get_fernet()` builds a `MultiFernet`: the first configured key encrypts, and every configured key can decrypt. Changing the first key does not automatically rewrite existing rows.

### Phase A — activate the new key with old decryptors retained

1. Enter the maintenance window and stop all application instances and writers.
2. Generate a new independent TOTP encryption key.
3. Configure the ring with the new key first and every still-required old key retained:

   ```dotenv
   TOTP_ENCRYPTION_KEYS=["<new-key>", "<old-key>"]
   ```

4. Keep application writers stopped through Phases B2 and C. Provision the same rotation-state configuration for the maintenance process.

### Phase B2 — re-encrypt active and pending secrets

No lazy rotation occurs on login. scripts/reencrypt_totp.py rotates users.totp_secret, users.pending_totp_secret and pending_totp_rotations.encrypted_secret with compare-and-update guards.

Use the complete installed-wheel maintenance invocation in repository file `scripts/README.md` (TOTP key maintenance).
It loads both root-owned environment files, uses isolated Python, and holds the
exclusive deployment lock. Keep the new key first and all required old keys in
the ring. `--batch-size` bounds reads and per-page writes.

The command must exit successfully. A nonzero exit reports skipped values, including undecryptable ciphertext or a concurrent change. Investigate those rows and rerun after addressing the cause. Do not remove old keys on partial success.

### Phase C — verify all retained ciphertext with the primary key alone

Verification with the complete `[new, old]` `MultiFernet` ring cannot prove that the old key is removable: fallback decryption could conceal values that were not successfully re-encrypted.

Keep application writers stopped and retain the rotation-state configuration used during Phase B2:

```dotenv
TOTP_ENCRYPTION_KEYS=["<new-key>", "<old-key>"]
```

The first entry must be the intended new key. The committed verification script checks every non-null `totp_secret`, `pending_totp_secret` and `pending_totp_rotations.encrypted_secret` using only that first key; it deliberately bypasses all configured fallback keys.

Use that same maintenance invocation from `scripts/README.md`,
replacing the script argument with
`/opt/oralhistarchiv/scripts/verify_totp_reencryption.py`. Do not change or
shell-export the production key ring for verification; the verifier ignores
fallback keys itself.

Interpret the result as follows:

* Exit code `0` means every retained active and pending TOTP ciphertext decrypts under the primary key alone.
* Exit code `1` identifies each user and column that is not decryptable under the primary key.

If verification fails, do not remove any old key. Keep `[new, old]` configured, investigate the reported values, rerun `scripts/reencrypt_totp.py`, and repeat verification until it succeeds.

Pending secrets have a validity window, but expiry does not remove their ciphertext from the database. The verifier therefore checks every retained pending value, including expired values.

After verification succeeds:

1. Account separately for backups or other retained copies that may still require the old key. Opening an encrypted archive requires the backup `age` identity first; that identity does not replace this historical TOTP decryptor.

2. Change the application configuration to:

   ```dotenv
   TOTP_ENCRYPTION_KEYS=["<new-key>"]
   ```

3. Start the web and scheduler services with the new-only configuration.

4. Confirm clean startup and complete a real login using an existing TOTP authenticator.

5. Record the rotation and verification result without recording key material.


### Routine rollback

If some data has already been encrypted with the new key, retain it as a decryptor. To resume writing with an uncompromised old key, use `[old, new]`, not `[old]`, and restart all affected processes under the maintenance procedure. Partial re-encryption does not justify removing either key.

## 6. Managing `OUTBOX_ENCRYPTION_KEYS`

`OUTBOX_ENCRYPTION_KEYS` encrypts stored email bodies independently of `SECRET_KEY`. The first key encrypts; retained keys decrypt. Keep an old key until all retained bodies that depend on it have been re-encrypted or removed, including retained sent/dead messages. Before a future rolling rotation starts writing with a new key, every reader must already know that key. Rotating `SECRET_KEY` still invalidates signed links inside queued messages.

### Initial deployment

Start with one independently generated key, as described in [First deployment and secret inventory](#0-first-deployment-and-secret-inventory). Supply it to every process that imports the application settings, including maintenance scripts. There is no SECRET_KEY fallback or legacy-data migration.

### Future rotation

The key ring supports writing with a new key while reading bodies encrypted with retained keys. It does not automatically re-encrypt existing rows.

1. Enter the maintenance window and stop all producers and delivery workers.
2. Generate a new independent outbox key.
3. Provision `[new, old]`, retaining any additional keys still needed by stored bodies, in every application process.
4. Start all processes with that configuration. Verify that a newly queued message and a previously queued notice both decrypt and deliver.
5. Retain old keys until their ciphertext dependencies have been removed or a verified re-encryption workflow has replaced them.

No outbox re-encryption or verification script is supplied. Retain old decryptors until every dependent ciphertext and backup is accounted for.

Before retiring an old key:

- Cover every retained `body_ciphertext`, including `pending`, `sending`, `sent`, and `dead` rows. An empty deliverable queue is not an empty ciphertext store.
- Ensure all producers write with the new key before the final verification. Under this runbook's maintenance procedure, stop them during any future bulk re-encryption and verification work.
- If re-encrypting, verify every retained body using the new key alone. A successful decrypt using the complete key ring is insufficient.
- If removing historical messages under an established retention policy, verify that no retained body still depends on the key. Merely marking a message `sent` or `dead` does not remove its ciphertext.
- Account for backups separately before destroying the key material. Backup-recipient rotation does not rewrite or re-encrypt the outbox ciphertext inside an archive.

A future re-encryption tool must preserve message content, status, lease ownership, attempt counters, and delivery timestamps. It must not resend messages or turn `dead` messages back into `pending`. Changing `OUTBOX_ENCRYPTION_KEYS` does not change the validity of signed links inside the messages.

For a routine rollback after new ciphertext has been written, retain both keys and change the order to `[old, new]` only if returning to the old encryptor is appropriate. Do not drop the new key while stored bodies still depend on it.

### If rolling deployment is introduced later

The maintenance-window procedures above avoid mixed configurations. A future rolling rotation needs an explicit preparation phase: distribute `[old, new]` to every reader before any writer activates `[new, old]`. Complete the writer switch before re-encryption and retirement verification. Changing one process directly from `[old]` to `[new, old]` while other readers still know only `[old]` can strand newly written ciphertext on those readers.

## 7. Rotating the backup archive recipient

The backup encryption identity is deliberately outside the application
environment files.
The database host receives only an `age1...` public recipient through the
root-owned `/etc/oralhistarchiv-backup.conf`; the private identity remains in an
independently controlled off-host recovery store. Never reuse an application
signing/encryption secret as an `age` identity.

The public recipient is not a signing key: anyone who knows it can create a
ciphertext that the private identity can decrypt. `age` protects confidentiality
and detects ciphertext modification, while producer provenance comes from the
authenticated transfer identity and the versioned/immutable archive-store
record. Where storage writers are not fully trusted, verify a separately
controlled detached signature or storage-native signed provenance before
restoring; a bare checksum is not producer authentication.

For routine rotation:

1. Generate the successor identity on a trusted recovery host and escrow its
   private half before changing production.
2. Replace only `BACKUP_AGE_RECIPIENT` on the database host, then run
   `oralhistarchiv-backup.service` manually. No application restart is needed.
3. Copy the new archive off-host and verify decryption and archive structure
   with `deploy/oralhistarchiv-backup-verify.sh`.
4. Complete an isolated restore using the application key-ring versions needed
   by that archive.
5. Keep the old private identity and the last restore-verified old-recipient
   archive until a successor-recipient archive has passed an isolated restore.
   Then retain or expire them under the approved data-retention policy. Do not
   infer key retirement from decryption/TOC inspection or the age of the live
   database.

If a backup private identity is exposed, treat every retained archive encrypted
for it as disclosed. Changing the public recipient protects only subsequent
archives. Preserve evidence, restrict the archive store, re-encrypt retained
archives on a trusted recovery system where policy permits, and follow the
incident-response process. Never overwrite the only recovery copy during
re-encryption.

## 8. Operational credentials

Coordinate changes at the provider and the application, then restart every process that uses the credential.

- **Database authentication:** production application roles have `PASSWORD NULL` and authenticate only through the exact local peer mappings documented in `Deployment.md`. Changing an OS identity, PostgreSQL role, socket path, or peer map is a migration of the trust boundary: stop both services, verify `pg_hba_file_rules`, apply the mapping, and require each service's runtime role preflight before restoring traffic. The owner mapping remains exclusive to the manual migration OS user. The separate read-only backup mapping and its `BYPASSRLS` recovery role remain intact.
- **SMTP password:** Change the provider credential and application configuration. Verify actual outbox delivery of a fresh message. Inspect delivery errors and retries; after fixing credentials, separately review messages that already exhausted their attempts.
- **Shibboleth internal secret:** Follow the fail-closed procedure below. Never rotate it with an exposed callback. Changing a file alone revokes nothing: the web restart is mandatory so startup can reconcile the changed policy fingerprint and delete all federated sessions.
- **Health-detail token:** Change the application token, restart affected processes, update monitoring clients, and verify authorized access.
- **Redis password:** Change Redis and application credentials together, restart affected processes, and verify Redis-backed functions.
- **Administrator bootstrap values:** Remove `ADMIN_SEED_PASSWORD` and `ADMIN_SEED_EMAIL` after confirming that the initial administrator exists. Change an existing administrator's password through the account-management flow.

### Shibboleth internal secret

The secret exists only in the web-only environment overlay and the root-owned
nginx secret include. It is not a second SAML validator: it authenticates the
local header handoff after the SP has validated SAML. Possession plus Gunicorn-
socket access is therefore an arbitrary federated-impersonation capability.

The same startup reconciliation applies when the enabled flag, exact issuer
set, compiled MFA context, or code-owned policy version changes. Editing an
environment file alone does not change a running process: restart the web unit
and verify the federated-session revocation before treating the new policy as
active.

For a planned rotation:

1. Enter a maintenance window. Replace the Phase-2 callback with the Phase-1
   exact 404 block, run `nginx -t`, reload, and verify the callback returns 404.
2. Set `SHIBBOLETH_ENABLED=false` in
   `/etc/oralhistarchiv/shibboleth.env` and restart `oralhistarchiv`. The
   fingerprint change must revoke all Shibboleth sessions before startup
   completes; local sessions remain valid.
3. Generate a new independent value. Without placing it in shell history,
   update both `/etc/oralhistarchiv/shibboleth.env` and
   `/etc/nginx/snippets/oralhistarchiv-shibboleth-secret.conf`. Verify both are
   `root:root` mode `0600`. Do not capture complete `nginx -T` output because
   it expands the include and prints the credential.
4. Restart the web service while federation remains disabled. Restore the
   reviewed Phase-2 callback, run `nginx -t`, and reload nginx.
5. Repeat the deployment guide's issuer, persistent-subject, exact REFEDS-MFA,
   spoofed-header, socket-permission, and effective-nginx checks. Run the
   automated pending-enrollment contract tests while the production flag stays
   false.
6. Set `SHIBBOLETH_ENABLED=true` and restart only the web service as the final
   step. Complete a controlled real MFA login (and, when the change plan
   includes a disposable test identity, confirm its pending/no-session result).
   Restore the flag to false and the callback to 404 immediately on failure.

#### Suspected disclosure

Do **not** begin with the planned-rotation sequence when the internal secret may
have been disclosed. A holder who can also reach the Gunicorn socket bypasses
nginx, so closing the public callback first is not containment. Use this order:

1. Stop the web process immediately: `sudo systemctl stop oralhistarchiv`.
   Leave the scheduler running unless the wider incident requires otherwise.
2. Confirm `systemctl is-active oralhistarchiv` reports `inactive`, the Unix
   socket is absent or refuses connections, and no unauthorized TCP listener
   serves the application. Do not continue merely because the public callback
   is unreachable.
3. Replace the Phase-2 callback with the Phase-1 exact `return 404` location,
   run `nginx -t`, reload nginx, and verify the public callback returns 404.
4. While the web service remains stopped, set `SHIBBOLETH_ENABLED=false`,
   replace the compromised secret in both root-only files (or remove the
   Phase-2 secret include), and execute the manual revocation transaction below.
   This transaction is mandatory in the emergency path; do not wait for normal
   startup reconciliation to contain an attacker with direct socket access.
5. Preserve evidence outside the mutable database audit trail. Review all new
   or changed federated identities, sessions, tiers, and audit events against
   IdP/SP evidence, and invoke the incident-response process. A host or SP
   compromise is not repaired by rotating this credential.
6. Restart the current application code with federation still disabled. Verify
   startup reconciliation completes and that the query below returns zero.
   Keep both the callback at 404 and federation disabled until the investigation
   and the complete pre-flip checklist have passed.

A changed file alone has no effect. On restart, the application fingerprints
the flag, sorted issuer set, fixed MFA context, policy version, and callback
secret. An absent or changed fingerprint deletes every Shibboleth session and
records the new digest transactionally; local sessions are untouched. Confirm
the result explicitly:

```sql
SELECT count(*) AS federated_sessions
FROM sessions
JOIN users ON users.id = sessions.user_id
WHERE users.auth_method = 'shibboleth';
```

The expected count is zero. The emergency procedure requires this manual
fail-safe transaction while the web process is stopped; it is also the fallback
for any planned rotation whose startup reconciliation cannot run or does not
produce a zero count:

```sql
BEGIN;
UPDATE users
SET auth_revision = auth_revision + 1
WHERE auth_method = 'shibboleth';

DELETE FROM sessions
USING users
WHERE sessions.user_id = users.id
  AND users.auth_method = 'shibboleth';
COMMIT;
```

Record the operator action outside the mutable database audit trail. Review
new pending identities and recent federated email/profile changes against IdP
and application audit evidence. Keep affected accounts inactive until identity
is reconciled. If the host or SP was compromised, rotating this one secret is
not enough on its own.

## 9. Post-rotation checklist

- [ ] Every affected process started with the intended configuration, with no startup-validation or key-decryption errors.
- [ ] `/health` succeeds and `/health/detail` is accessible with the configured token.
- [ ] The verification for the changed secret passed, including a real end-to-end login or email flow where applicable.
- [ ] For a signing-key rotation, outstanding token-bearing messages were handled before delivery resumed; ordinary queued notices remain deliverable.
- [ ] For a disclosed Shibboleth internal secret, federation remains disabled,
      startup reconciliation was observed, the federated-session count is
      zero, and pending/profile-changed identities were reconciled. If the
      manual fallback was required, every federated `auth_revision` was also
      bumped in that transaction.
- [ ] For TOTP key retirement, both active and pending ciphertext were verified with the new key alone before old decryptors were removed.
- [ ] For outbox key retirement, all retained bodies were accounted for; an empty pending queue was not used as proof.
- [ ] Any decryption dependencies in backups were accounted for before destroying old key material.
- [ ] For a backup-recipient change, a new-recipient archive was copied off-host, decrypted, and restored in isolation before any old private identity was retired.
- [ ] Backup private identities remain separate from application environment files, database/VM snapshots, and archive-store access.
- [ ] The change was recorded without secret values: what changed, when, why, by whom, and the verification result.

## 10. Before retaining real user data

Before deployment:

- Configure the independent required outbox key ring and run its crypto, settings, startup-validation, and delivery regressions.
- Provision unique generated secrets through the documented environment source for both services and maintenance processes.
- Exercise the TOTP re-encryption and complete verification procedure against a disposable database populated with representative active and pending secrets.
- Confirm that an encrypted archive, the separately escrowed backup private identity, and the applicable historical application key rings can be restored together.
- Dry-run the signing-key procedure, including handling queued token-bearing messages.
- Record that outbox bulk re-encryption tooling remains deferred. Initial deployment uses one key; a future old-key retirement requires verified tooling or removal of every relevant ciphertext dependency under the retention policy.

This runbook describes operator actions. It does not claim that its database commands or production rotation procedures have already been executed.

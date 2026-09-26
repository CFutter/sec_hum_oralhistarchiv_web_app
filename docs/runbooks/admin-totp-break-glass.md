# Runbook — Sole-Administrator TOTP Break-Glass Recovery

**Applies to:** local administrator accounts in the Digital Oral History Archive

**Audience:** two operators with deployment-host sudo access; this procedure uses the web database role.

## When this runbook applies

Use only for an active, verified local administrator who lost their authenticator and cannot use normal recovery. Normal recovery needs another local administrator with a full session and working TOTP plus a usable code saved by the target. A code exhausted by three password attempts is unusable even if unused. The target must know their current password; otherwise complete the separately approved password-reset process first.

Record this database intervention as an incident/change: it bypasses the online two-person recovery policy and returns the account to initial TOTP enrollment.

## Why the application cannot self-reset today

`authorize_totp_recovery` rejects self-authorization; `finalize_local_login` refuses ordinary login while recovery is required. Changing seed-admin settings cannot repair an existing administrator: seeding stops when any administrator exists. This procedure creates no recovery session; it restores ordinary password login followed by initial TOTP enrollment.

## Preconditions and safety controls

1. Record the target ID/email, reason, approver, executor, and timestamps. A second operator must independently confirm identity and lack of a viable online recovery path. Record no passwords, seeds, recovery codes, or database credentials.
2. Verify a current backup. Stop every web instance, scheduler, and other database/mail writer. On the supplied host:

   ```console
   sudo systemctl stop oralhistarchiv.service oralhistarchiv-scheduler.service
   sudo systemctl is-active oralhistarchiv.service oralhistarchiv-scheduler.service
   ```

   Both must report `inactive`; confirm separate workers are also stopped.
3. With the peer mapping and stable lock inode from [Deployment](../../Deployment.md) installed, open an exclusive maintenance session:

   ```console
   sudo -u oralhistarchiv flock --exclusive --nonblock --no-fork /run/lock/oralhistarchiv-deploy.lock /usr/bin/psql -X --no-password --dbname=oralhistarchiv --username=oralhistarchiv_web --set=ON_ERROR_STOP=1
   ```

   A busy lock must fail: investigate, never replace the lock file. The web role has the required DML grants; do not use the migration owner interactively. Keep this session open until the intervention finishes, then `\q` before restarting services.
4. Replace every `123` and `'admin@example.org'` below with the independently reviewed literal values. Execute each SQL block separately and inspect its result before continuing. Any identity/count mismatch, SQL error, or concurrent writer requires `ROLLBACK` and investigation.

## 1. Read-only preflight

Run this before changing anything. Replace `123` and
`'admin@example.org'` with the reviewed target values.

```sql
SELECT id,
       email,
       auth_method,
       is_admin,
       is_active,
       email_verified,
       (totp_secret IS NOT NULL) AS totp_configured,
       totp_recovery_required,
       totp_recovery_code_generation,
       (SELECT COUNT(*)
          FROM totp_recovery_codes AS c
         WHERE c.user_id = u.id
           AND c.generation = u.totp_recovery_code_generation
           AND c.used_at IS NULL
           AND c.password_attempt_count < 3) AS usable_recovery_codes,
       (SELECT COUNT(*) FROM sessions AS s WHERE s.user_id = u.id) AS sessions,
       auth_revision
FROM users AS u
WHERE u.id = 123
  AND LOWER(u.email) = LOWER('admin@example.org');

SELECT id,
       email,
       auth_method,
       is_active,
       email_verified,
       totp_recovery_required,
       (totp_secret IS NOT NULL) AS totp_configured,
       EXISTS (
           SELECT 1
           FROM totp_recovery_codes AS c
           WHERE c.user_id = u.id
             AND c.generation = u.totp_recovery_code_generation
             AND c.used_at IS NULL
             AND c.password_attempt_count < 3
       ) AS has_usable_recovery_code
FROM users AS u
WHERE is_admin = true
  AND is_active = true
ORDER BY id;

SELECT id, message_type, status, created_at
FROM email_outbox
WHERE user_id = 123
  AND status IN ('pending', 'sending')
ORDER BY id;
```

The first query must return exactly the reviewed active, verified local administrator. Review the second for an eligible second administrator and confirm actual access to their authenticator and the target's saved codes; rows alone cannot establish possession. Review queued mail before cancellation. Stopping workers can leave `sending` rows: confirm no sender remains before cancelling their claims. Already-delivered mail cannot be recalled.

## 2. Reset the account in one transaction

Identity, password, tier, administrator/active flags, and email verification stay unchanged. Sessions (and their rotation challenges), pending action capabilities, recovery codes, and promotion requests are invalidated. First lock and recheck the target:

```sql
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

SELECT id, email, auth_method, is_admin, is_active, email_verified,
       (totp_secret IS NOT NULL) AS totp_configured,
       totp_recovery_required, auth_revision
FROM users
WHERE id = 123
  AND LOWER(email) = LOWER('admin@example.org')
  AND auth_method = 'local'
  AND is_admin = true
  AND is_active = true
  AND email_verified = true
FOR UPDATE;
```

Continue only after this returns exactly the reviewed row. Otherwise run `ROLLBACK` and stop. Keep the same session/transaction:

```sql
WITH deleted AS (
    DELETE FROM sessions
    WHERE user_id = 123
    RETURNING 1
)
SELECT COUNT(*) AS sessions_revoked FROM deleted;

-- Dead outbox rows require terminal_outcome and cleared delivery locks.
WITH cancelled AS (
    UPDATE email_outbox
       SET status = 'dead',
           failed_at = clock_timestamp(),
           sent_at = NULL,
           locked_at = NULL,
           lock_token = NULL,
           last_error = 'cancelled by operator TOTP break-glass recovery',
           terminal_outcome = 'cancelled'
     WHERE user_id = 123
       AND message_type IN (
           'password_reset',
           'email_verification',
           'email_change_verification'
       )
       AND status IN ('pending', 'sending')
     RETURNING 1
)
SELECT COUNT(*) AS action_messages_cancelled FROM cancelled;

DELETE FROM totp_recovery_codes
WHERE user_id = 123;

DELETE FROM admin_promotion_requests
WHERE user_id = 123;

UPDATE users
SET totp_secret = NULL,
    last_totp_step = NULL,
    pending_totp_secret = NULL,
    pending_totp_created_at = NULL,
    pending_email = NULL,
    pending_email_token_hash = NULL,
    pending_email_created_at = NULL,
    password_reset_token_hash = NULL,
    password_reset_created_at = NULL,
    email_verification_token_hash = NULL,
    email_verification_created_at = NULL,
    pending_totp_recovery_code_generation = NULL,
    totp_recovery_code_generation = 0,
    totp_recovery_required = false,
    totp_recovery_expires_at = NULL,
    totp_recovery_authorized_at = NULL,
    totp_recovery_auth_revision = NULL,
    failed_login_count = 0,
    locked_until = NULL,
    lockout_notice_enqueued_at = NULL,
    auth_revision = auth_revision + 1
WHERE id = 123
  AND LOWER(email) = LOWER('admin@example.org')
  AND auth_method = 'local'
  AND is_admin = true
  AND is_active = true
  AND email_verified = true
RETURNING id,
          email,
          auth_method,
          is_admin,
          is_active,
          email_verified,
          (totp_secret IS NOT NULL) AS totp_configured,
          totp_recovery_required,
          totp_recovery_code_generation,
          auth_revision;

```

The final update must return exactly the reviewed account, with no configured TOTP, recovery required false, generation zero, and revision incremented by one. Check deletion/cancellation counts against preflight. If any result differs, `ROLLBACK` and stop. Otherwise:

```sql
COMMIT;
\q
```

Exiting releases the deployment lock. Discard every saved copy of the old recovery codes: only the new enrollment set will work.

## 3. Restore access through normal enrollment

1. After leaving the maintenance session, start only the web service and verify startup:

   ```console
   sudo systemctl start oralhistarchiv.service
   sudo systemctl status oralhistarchiv.service --no-pager
   sudo journalctl -u oralhistarchiv.service -n 50 --no-pager
   ```

2. In a clean browser, submit email/password at `/login` with TOTP blank. Expect a restricted `totp_setup` session and redirect to `/setup-totp`, not a full session. Its lifetime uses `SESSION_MAX_AGE_SECONDS` (default eight hours).
3. Scan the new QR and save all ten recovery codes separately from the authenticator. Within the pending seed's ten-minute lifetime, submit a new TOTP code and one displayed recovery code. The confirmation code remains usable; refreshing or rerendering setup replaces the displayed recovery-code set. Completion upgrades this session to full access.
4. Explicitly log out, then log in with password and a fresh TOTP code; a just-used TOTP time step cannot be reused. Confirm `/admin` loads and run the verification below. Do not change another account to test recovery.
5. Restart remaining writers and check status/logs before reopening traffic:

   ```console
   sudo systemctl start oralhistarchiv-scheduler.service
   sudo systemctl status oralhistarchiv.service oralhistarchiv-scheduler.service --no-pager
   sudo journalctl -u oralhistarchiv-scheduler.service -n 50 --no-pager
   ```

Previously pending password-reset, email-verification, and email-change requests must be made again if still needed.

## Verification query

After fresh login, open a read-only verification session (no exclusive lock while services run):

```console
sudo -u oralhistarchiv /usr/bin/psql -X --no-password --dbname=oralhistarchiv --username=oralhistarchiv_web --set=ON_ERROR_STOP=1
```

Substitute the target ID and the timestamp recorded before intervention:

```sql
BEGIN READ ONLY;
SELECT u.id,
       u.email,
       u.is_admin,
       u.is_active,
       u.email_verified,
       (u.totp_secret IS NOT NULL) AS totp_configured,
       u.totp_recovery_required,
       u.totp_recovery_code_generation,
       (SELECT COUNT(*)
          FROM totp_recovery_codes AS c
         WHERE c.user_id = u.id
           AND c.generation = u.totp_recovery_code_generation
           AND c.used_at IS NULL
           AND c.password_attempt_count < 3) AS usable_recovery_codes,
       (SELECT COUNT(*) FROM sessions AS s WHERE s.user_id = u.id) AS session_count,
       (SELECT COUNT(*) FROM sessions AS s
         WHERE s.user_id = u.id
           AND s.created_at <= TIMESTAMPTZ '2026-01-01 00:00:00+00') AS old_sessions
FROM users AS u
WHERE u.id = 123;
COMMIT;
\q
```

Expect exactly the target active, verified administrator: TOTP configured, recovery required false, generation positive, ten usable codes, zero old sessions, and one session if only the verification browser logged in. Enrollment itself leaves a full session; explicit logout deletes it, and fresh login creates another.

## Failure and rollback rules

Before commit, roll back on any error or mismatch. After commit, do not restore an old seed, hand-edit sessions, clear the password, or grant account flags to bypass checks. Stop services and repeat the independently approved procedure if enrollment fails. Whole-database restoration can discard unrelated work and is not an account-recovery shortcut.


-- Use psql -X --set=ON_ERROR_STOP=1 under the exclusive deployment lock,
-- with all web/mail writers stopped. Require exit zero before restarting.
-- Revoke old-format/old-signer actions without resetting proof or mail budgets.
-- Keep setup hashes: NULL denotes a cancelled reservation that cannot resend.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

UPDATE public.users
SET password_reset_created_at = CURRENT_TIMESTAMP - INTERVAL '30 minutes'
WHERE password_reset_token_hash IS NOT NULL
  AND password_reset_created_at > CURRENT_TIMESTAMP - INTERVAL '30 minutes';

UPDATE public.users
SET email_verification_created_at = CURRENT_TIMESTAMP - INTERVAL '24 hours'
WHERE email_verification_token_hash IS NOT NULL
  AND email_verification_created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours';

UPDATE public.users
SET pending_email = NULL,
    pending_email_token_hash = NULL,
    pending_email_created_at = NULL
WHERE pending_email IS NOT NULL
   OR pending_email_token_hash IS NOT NULL
   OR pending_email_created_at IS NOT NULL;

UPDATE public.email_outbox
SET status = 'dead',
    terminal_outcome = 'cancelled',
    failed_at = CURRENT_TIMESTAMP,
    sent_at = NULL,
    locked_at = NULL,
    lock_token = NULL,
    last_error = 'Cancelled: action capability invalidated during maintenance'
WHERE status IN ('pending', 'sending')
  AND message_type IN (
      'password_reset', 'email_verification', 'email_change_verification'
  );

COMMIT;

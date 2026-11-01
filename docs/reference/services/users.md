# Users Service

Account state, local/federated authentication, TOTP, recovery, and administrator promotion. See [Authentication & Sessions](../../architecture/auth.md) for workflows.

## `app.services.users`

::: app.services.users

## `app.services.authentication`

::: app.services.authentication

## `app.services.federated_authentication`

::: app.services.federated_authentication

## `app.services.federated_review`

The review projection keeps assertion attributes out of session user snapshots.
Trusted login records the latest observation in its existing transaction;
`list_federated_reviews()` supplies the administrator view. Approval requires the
current revision and returns the locked proposed tier/rule alongside the
updated user so the route audits the reviewed result.

::: app.services.federated_review

## `app.services.totp`

::: app.services.totp

## `app.services.access_tiers`

::: app.services.access_tiers

## Registration, challenges, and recovery

::: app.services.resend_local_registration

## Mailbox-bound registration setup

`app.services` exports `RegistrationSetup`, `begin_local_registration()`,
`inspect_local_registration()` and `complete_local_registration()`.
The first operation admits shared mail issuance, then atomically creates an
inactive passwordless account and queues mailbox proof. Existing addresses and
limited requests are no-ops; no existing-account notice is sent. It hashes no
password. Callers render the same pending page without promising identical time.

Inspection checks signed and persisted capability state without consuming it.
Completion checks live state before password work, hashes without a database
connection, then locks/rechecks the current capability, expiry and revision
before atomically installing credentials, verifying, activating and revoking
sessions/pending state. It creates no session. An administrator-cleared pending
capability cannot be recreated by anonymous resend.

The registration routes use this boundary. Completion requires CSRF and form
content type in addition to the mailbox capability. Resend preserves a live
capability and its expiry, copying eligible retained mail without duplicating
pending/sending copies. Expired state may be replaced; cleared state cannot be
recreated. No password-first
creation or token-only activation API is supplied.

::: app.services.registration_setup

::: app.services.admin_promotion

::: app.services.credential_attempts

::: app.services.totp_recover

::: app.services.totp_recovery_codes

::: app.services.totp_maintenance

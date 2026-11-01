# Email-action links

**Status: WP I application acceptance complete; final source/check references and deployed cutover evidence open.**
This procedure covers registration verification, password reset and email-change
confirmation. New links contain only non-secret public identifiers; each email prints a
separate security code for manual entry in an ordinary HTML form. The flow
uses no JavaScript and retains signed, expiring, single-use POST authority.
It is not evidence that the deployed mail relay, browser estate, log collector
or historical records have been checked.

## Link and form contract

| Flow | Public landing path | Explicit action POST | Lifetime | CSRF |
|---|---|---|---|---|
| Registration setup | `/verify-email/{public_id}` | `/verify-email` | 24 hours | Required |
| Password reset | `/reset-password/{public_id}` | `/reset-password` | 30 minutes | Required |
| Email change | `/account/confirm-email/{public_id}` | `/account/confirm-email` | 1 hour | Exact reviewed capability exception; form content type remains required |

`SignedActionToken(salt, max_age)` shares issuance, signature/age validation and
signed issue-time metadata for all three purposes. Salts and lifetimes are
unchanged. Each issuance has a fresh random nonce; the account stores the
secret token's hash and timestamp. Database/state checks still enforce expiry,
replacement, cancellation, account eligibility, revision where applicable,
and single use. This transport change adds no schema revision or data reset.

A public ID is a 43-character unpadded base64url SHA-256 digest derived from the
token. It is unguessable for a fresh random capability but is deliberately
non-secret. It grants no action and cannot be used to retrieve the secret.
Every valid-shaped ID opens a generic form without resolving an action target.
Normal session middleware may still resolve a supplied browser cookie, and
navigation may show that already-signed-in browser's own identity. Unknown IDs
do not reveal whether an action request exists. An old signed token in a
GET path contains dots and is rejected with 404.

Generated messages provide a public link and a separate code (placeholders
below are not credentials):

```text
https://archive.example.org/reset-password/<public-id>

Security code:

<secret-code>
```

The generated URL has no secret, query or fragment. Open it, copy the security
code from the same email into the visible code field, complete the remaining
fields and submit the form. This is the normal flow for all three actions;
there is no JavaScript, automatic code transfer or automatic submission. The
public link or GET response cannot recover a lost code. Request a fresh
message through the normal flow when its code is unavailable or no longer valid.

The POST carries `public_id` and `token`. Their binding is checked before
signature/account processing; substituting an ID from another email is rejected.
A query string, path, generic GET response or empty/mismatched token field is
insufficient. Registration/reset retain CSRF and all three retain form-content
checks. Passwords are never repopulated after validation errors. A submitted
usable token can be retained in a POST error form; the public GET never
reconstructs it.

## Credential custody and limits

- Keep the email message and security code private. A holder of the code and
  its matching public ID has the capability until normal expiry or revocation.
  The new public URL alone is not a credential.
- Do not paste codes or message bodies into tickets, chat, analytics or
  screenshot evidence. Record a synthetic public ID, outcome and timestamp.
- Mailboxes, copied codes, browser extensions and records retained by clients
  are outside request-target protection. This change does not erase copies.
- Do not log POST bodies at nginx, application debug middleware or collectors.
  App validators log fixed failure descriptions without supplied signature text.
- Keep `Cache-Control: no-store`, `Referrer-Policy: strict-origin`, the existing
  strict CSP and the safe nginx access-log format in force.
- Existing path/query redaction is still defense in depth. nginx error logs can
  record arbitrary client targets before the application runs. A manually sent
  obsolete token URL can still leak there even though the app returns 404.
  Earlier log, mailbox and backup copies follow their separate retention and
  incident procedures. Complete legacy token-bearing URLs remain credentials.

## Deploying the link-format change

Coordinate the application and templates as one release. The generic form must
show an empty security-code field and work with JavaScript unavailable. The
release requires no Node, npm or browser-script test step.

1. Schedule a maintenance window. Stop web producers and every outbox delivery
   worker, including the scheduler and ad-hoc jobs. Let in-flight SMTP finish
   or account for a message already accepted by the relay.
2. Deploy the matching application and templates. Remove the previous draft's
   autofill asset and its test/CI step if that draft was installed. No database
   migration or reset is required; keep existing application data intact.
3. Before restarting writers, invalidate old capabilities and cancel their
   pending/sending mail in one transaction. Confirm the intended database and
   run the installed release's maintenance SQL with the web peer identity:

   ```console
   sudo -u oralhistarchiv /usr/bin/flock --exclusive --nonblock --no-fork \
     /run/lock/oralhistarchiv-deploy.lock \
     /usr/bin/psql -X --no-password \
     --host=/var/run/postgresql --dbname=oralhistarchiv \
     --username=oralhistarchiv_web --set=ON_ERROR_STOP=1 \
     --file=/opt/oralhistarchiv/deploy/invalidate-action-email-capabilities.sql
   ```

   Require exit zero. The SQL expires reset/setup timestamps, retains their
   hashes, clears pending email changes and cancels action mail. Keeping setup
   hashes permits a later admitted resend; clearing them disables that path.
   Expiry prevents requests from copying obsolete sent/delivery-failed bodies.
   Notices, retained sent/dead rows, proof counters and the issuance ledger stay
   unchanged. The script sends no mail, uses 5-second lock/30-second statement
   timeouts and rolls back every change on failure. Rerunning while writers
   remain stopped is safe; do not resume on a failed or uncertain result.
4. Record the cutover, then restart producers and workers. Users request fresh
   reset/setup mail through the normal flow; existing cooldown and mail budgets
   still apply, without waiting for the old capability's original expiry.
   Email changes require a new authenticated staging action. Never manually
   requeue old ciphertext.
5. Test the actual relay and manual form entry for all three flows with disposable
   accounts, including code entry, expired/replaced/replayed rejection,
   a legacy token-bearing GET returning 404, and public-ID-only failure.
6. Complete the edge/logging acceptance below and retain release/check records
   without the security code, message body or legacy secret-bearing URL.

Already-sent messages cannot be recalled. The maintenance SQL revokes their
stored capabilities, including older fragment-based messages; recipients need
replacement mail or a new authenticated email-change action. Treat historical
complete token-bearing URLs as private records, never test/support evidence.

This cutover changes no signing key and erases no historical URLs. Suspected
exposure still requires the [key-rotation procedure](key-rotation.md#3-rotating-secret_key)
and the incident response process.

## nginx and application logging acceptance

Retain the shipped nginx error-log level and `oralhistarchiv_safe` access format.
Construct a synthetic link using the application helper and a non-live canary
secret. The generated URL contains only its public ID. Exercise it with a
rate-limited request that produces 429, and submit the separate code only in
a form POST. Verify that:

- the 429 error-log record includes the public ID, proving rejection logging
  actually occurred;
- the canary secret is absent from access/error logs, the application journal
  and forwarded collector copies;
- GET, rejected form/CSRF/content-type/password submissions and static-asset
  requests do not put the secret into their request target or referrer; and
- no logging middleware or host setting captures the action POST body.

A native nginx test proves the shipped example's behavior, not the effective
host configuration or collector retention. Preserve effective configuration,
outcomes, timestamp and reviewer evidence separately. Never use a genuine
unexpired action token for log-canary testing.

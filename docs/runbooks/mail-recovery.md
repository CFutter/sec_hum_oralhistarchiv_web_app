# Recovery mail and protected sign-in

Anonymous password-recovery and registration requests have two independent
controls: the existing client-address request limits and shared mail-issuance
budgets. Changing client addresses does not create another mail allowance.

## Shared issuance policy

All web workers serialize anonymous issuance through a PostgreSQL transaction
lock. Contention returns the same generic response without waiting; later account
and outbox lock waits have a 250-ms bound. The same transaction checks a
short-lived issuance ledger, locks eligible account state, queues an admitted
message and appends its ledger entry. The current limits are:

| Scope | Limit |
| --- | --- |
| Normalized recipient | One message in five minutes |
| Normalized recipient | Five messages in one hour |
| All recipients | 500 messages in one hour |
| All recipients | 2,000 messages in one day |

The policy constants live in `app.services.mail_issuance`. Changes require
review of real delivery capacity and the regression tests. The limits count every actually queued password-reset or registration-
verification message, including a retained-message resend. Cancelling mail,
SMTP failure, outbox cleanup, account deletion and replacement of a pending
federated reservation do not refund an allowance.

`anonymous_mail_issuance` stores only a random event identifier, a domain-
separated keyed recipient digest, and issuance time. It has no account or outbox
foreign key. Unknown/ineligible addresses, existing-registration no-ops and
requests that reuse an already pending delivery create no ledger row. Recipient
normalization is shared across request paths; a plain email address is never
stored in this ledger.

Admission removes at most 100 entries older than one day before counting. With
the daily issuance cap, ordinary producer operations keep its state bounded;
no recipient keys can be added simply by requesting unknown addresses. A
ledger failure rolls back enqueue and capability changes. There is no
process-local or permissive fallback. Changing `SECRET_KEY` changes recipient
digests; coordinate that operation with delivery policy, while the global
allowance continues to include all retained entries.

Registering an existing address returns the normal pending response without
sending another notice or changing that account. An address that is unknown,
ineligible or temporarily limited receives the same request response. This is
a response-shape guarantee, not a claim that elapsed time is identical.

## Live codes and resend

An anonymous re-request never replaces an unexpired reset or verification
capability. Its hash, signed expiry and proof-attempt history remain unchanged.
The original email therefore stays usable after another person requests mail.

A pending or sending message continues through the ordinary delivery retry
path and is not duplicated. After the recipient cooldown, an admitted resend
can copy a retained delivered or delivery-failed message. The copy contains
the same encrypted body, capability hash and original expiry. It never extends
the lifetime or creates another code. Cancelled and unreadable messages cannot
be revived through resend. If no eligible retained copy exists, wait for expiry
before requesting a fresh code or contact support.

An expired capability can be replaced within the shared mail allowance.
Replacing a reset capability never resets the account's authenticator-proof
attempt budget. Administratively cancelled registration setup cannot be
restarted through the anonymous resend form.

## Sign in through a temporary login lock

Known-address login failures can still trigger the account-wide guessing
defence. The recovery email offers two paths for an established local account:
set a new password, or keep the current password and sign in. Both require the
live email security code and a fresh configured authenticator code.

The sign-in path is available while the username-triggered login lock is
active. On success, one transaction consumes the capability and authenticator
step, clears lockout, increments the authentication revision, revokes existing
sessions/pending capabilities, and creates a fresh full session. The password
and active authenticator remain unchanged. The browser receives the new cookie
only after commit. The two recovery paths share five proof attempts per
account in thirty minutes; anonymous re-requests cannot refund them.

An already authenticated full session has its own durable credential-proof
budget. New anonymous login failures do not disable that session's separately
bounded password/authenticator proof for protected account actions. Account
eligibility, session expiry, revision checks and proof replay protection still
apply.

An email code alone never bypasses the configured authenticator. If it is
unavailable, use the existing administrator-authorized account recovery
procedure. Ordinary password login remains intentionally subject to the
account-wide lock; the protected recovery path restores access without
weakening its distributed-guessing bound.

## Verification

Run the PostgreSQL mail/recovery regression tests with `REQUIRE_DB=1`.
Exercise concurrent requests through independent connections, retained-message
resends, expired replacement, global and recipient limits, deletion without
allowance refunds, bounded ledger cleanup, queue/ledger failures,
proof exhaustion and replay. Confirm that a locked owner can obtain a fresh
session without changing the password, while ordinary distributed login
failures still trigger their account-wide limit.

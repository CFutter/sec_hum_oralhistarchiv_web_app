# Account deletion

**Status: WP H application acceptance complete; final source/CI references remain open.**
This procedure covers immediate permanent deletion of an archive account and
its live user-owned database state. It supplies the deletion procedure referenced
by the [retention/DSAR supplement](retention-dsar-template.md) and the
[full DSAR template](../compliance/dsar-procedure.md). The
[processing register](../compliance/processing-register.md) supplies generic
inventory and retention decision records. Approved schedules, completed requests
and institutional adoption remain operator work. This procedure does not certify
an operational retention policy or erase an institutional identity.

## Local self-service

1. Sign in to the local account with a full session and open **Account**.
2. Choose **Delete account**. `GET /account/delete` displays the confirmation;
   opening the page makes no account change.
3. Read the scope, then submit your password, a fresh six-digit TOTP code and
   the explicit confirmation. `POST /account/delete` requires the normal form
   content type and CSRF protection. A TOTP step already used for login or
   another action cannot be reused.
4. Successful deletion clears this browser's application cookies. Every device's
   session has been removed, and outstanding account-action links fail closed.

There is no grace period or undo. Password/fresh-TOTP proof is required even
with a valid session. Attempts consume the shared session step-up allowance,
including successful submissions. Exhaustion expires that session. A
username-triggered login lock does not block the independent proof allowance
of an existing full session. Expired or revoked sessions still require the
normal protected sign-in or recovery procedure. Contact the operator if proof
cannot be completed; do not bypass it with an ad hoc database edit.

The final active administrator cannot delete their own account. Arrange another
eligible active administrator before retrying. Self-service is unavailable to
federated accounts; an archive administrator handles those requests.

## Administrator removal

1. Resolve and verify the request through the operator's approved identity and
   authorization process. Record the request reference separately from the
   application audit; avoid copying credentials or capability links.
2. Sign in as an eligible local administrator. Locate the exact user on the
   administrator page and open **Delete account**.
3. Review the target on `GET /admin/users/{user_id}/delete`, including its
   authentication method. This page does not delete anything.
4. Submit the administrator's own password, a fresh administrator TOTP code and
   the explicit target confirmation to `POST /admin/users/{user_id}/delete`.
   The target's credentials are neither required nor exposed.
5. Confirm success and retain the corresponding committed audit reference.

The service rechecks the current administrator and exact full session under
the shared administration lock; stale or revoked authority cannot authorize a
deletion. The administrator path rejects the acting administrator as its own
target. Use local self-service for that account, subject to last-active-admin
protection. Other local accounts and pending, approved or disabled federated
accounts can be removed through this guarded flow.

Deleting a federated archive row does not remove the IdP account or prevent a
future trusted assertion from creating a new pending row. New approval is
required. If continued institutional sign-in must be blocked, coordinate the
separate identity/provider policy with its owner; deletion is not a denylist.

## Transaction and cleanup boundary

The final transaction rechecks the off-connection password proof's credential
snapshot and revision, current local actor state, unexpired full session and
fresh TOTP. All deletion paths share the administration advisory lock with
membership mutations. The last-active-admin decision and deletion commit
atomically; concurrent deletions or role changes cannot remove every active
administrator.

| Live state | Committed deletion behavior |
|---|---|
| `users` | Removes the target profile, credentials, review data, lockout state and stored account-action capabilities |
| `sessions` | Cascades every target session, regardless of purpose or device |
| `pending_totp_rotations` | Cascades target challenges, including challenges tied to deleted sessions |
| `totp_recovery_codes` | Cascades every target generation and code |
| `admin_promotion_requests` | Cascades requests where the deleted user is target or requester |
| `email_outbox` | Cascades every user-linked row, including pending, claimed/sending and terminal rows |

A retained `users.federated_approved_by` integer on another account records a
historical approval actor. It is an audit marker, not a user-owned row or live
foreign-key association, and survives the approver's deletion. Deletion does
not remove unrelated users or their approval history.

Copied session cookies fail on their next request because session resolution
requires a live database row and account. An already-authorized in-flight
request may finish. Setup, password-reset and email-change signatures do not
authorize POST redemption after their user/capability state has gone. Their
public-ID GET pages remain generic even after deletion; rendering that form
reveals no account state and grants no action authority. A later account
with the same address has a new identity and cannot redeem the deleted
account's links.

Outbox deletion cannot recall email already delivered or a message whose SMTP
send has already begun using a worker's in-memory copy. Any embedded action
capability still fails after deletion. Account-unlinked notices, external mail
systems, historic audit logs and backup archives are outside this live cascade;
apply the separate retention procedure below.

## Audit and retention

After a successful commit, the route emits one `account_deleted` event for
self-service or `admin_account_deleted` for administrator removal. The
`email_hash` field is produced by `audit_email_hash` from the locked target
address. The event retains the relevant numeric actor/target identifiers and
normal request metadata without the plaintext address, password, TOTP,
institutional subject or raw assertion payload. A rejected or rolled-back
delete emits no successful deletion event.

The keyed address marker is pseudonymous, not anonymous. Protect access to
it and to existing audit records. Application logging follows the existing
post-commit audit convention; durable external shipping, retention and delivery
monitoring remain operational responsibilities. Do not report a database
transaction as atomically committed together with an external log sink.

Live account deletion does not rewrite historical logs or encrypted backups.
Use the [retention/DSAR template](retention-dsar-template.md) to record the
approved handling of those copies and of future restores. Do not restore an
entire database to undo one account deletion.
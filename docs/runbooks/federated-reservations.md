# Federated claims of unverified email reservations

This page describes replacement of an unverified local email reservation by a
new trusted federated identity. It does not approve federation activation or
close mailbox, identity-provider, deployment or governance acceptance.

## Replacement contract

Identity remains the exact `(issuer, subject)` pair. Matching email addresses
never merge accounts. Only the trusted federation login finalizer, after
assertion validation and the current database-backed federation-policy check,
may perform reservation replacement. Generic user-provisioning interfaces do
not gain that authority.

The finalizer first follows the ordinary identity path. When a new identity
collides on email, it checks that the exact federated identity does not already
exist, locks the case-insensitively matching local user row and rechecks its
state. Replacement requires all three conditions:

- `auth_method` is `local`.
- `email_verified` is false.
- `is_admin` is false.

A legacy unverified row may already contain credentials. Replacement deletes
that entire row and creates a fresh federated row; it never converts or reuses
the local account. The new account is public, inactive, unverified, nonadmin
and pending explicit administrator approval, with no session. No local
password, authenticator, recovery code, profile, access tier, approval or
capability is copied. User-linked state is removed through the existing
foreign-key cascades, including sessions and linked queued email. Already
delivered mail and historical records remain outside the live cascade.

Verified local users, administrator rows and other federated identities remain
collision refusals. Existing exact federated identities never remove local
reservations, including when an approved identity presents a changed email.
Advisory tier rules still supply review proposals only.

## Transactions and concurrent verification

The deletion and fresh federated insert share the trusted login transaction.
Any insert conflict or failed transaction restores the local reservation and
its linked state. A competing creation of the same exact federated identity
must not turn an existing-identity refresh into replacement authority.

Local setup completion and replacement lock the same local user row. If local
verification commits first, replacement observes the verified state after its
lock wait and refuses. If replacement commits first, setup observes no
matching retained account/capability and fails closed. Old public setup URLs
may still render their generic form, but no old security code can recreate or
verify the deleted local account. The race tests must observe the database
lock wait; scheduling sleeps alone are insufficient evidence.

Only a committed replacement emits `federated_email_reservation_claimed`, with
the removed local user ID, new federated user ID, client IP and the
`audit_email_hash`-derived `email_hash`. The event contains no plaintext email,
assertion, password or capability. Rejection and rollback emit no successful
claim event. As with other postcommit security events, reliable log collection
and retention remain operator responsibilities.

## Application acceptance record

The following criteria describe the accepted application scope. Retain exact
test IDs and result references in this acceptance record:

| Criterion | Required evidence |
|---|---|
| Fresh pending identity, without credential or authority transfer | Real PostgreSQL test of a passwordless reservation and a legacy credential-bearing reservation; inspect the new ID, defaults and user-linked state |
| Verified and ineligible collisions refuse | Tests for verified local, local administrator and other federated rows; unchanged account and no successful claim audit |
| Existing exact identity cannot delete a reservation | Pending/disabled identity and approved changed-email paths, preserving the local row |
| Concurrent local verification | Both commit orders with observed PostgreSQL row-lock waits; verified winner refuses claim, claim winner invalidates old setup completion |
| Concurrent exact identity or email claims | Transaction rollback preserves the reservation and linked state; no successful audit for a failed claim |
| Trust and policy boundary | Invalid/untrusted assertion and stale policy cannot delete a reservation |
| Committed audit | One pseudonymous event after successful commit, no plaintext address or assertion and no success event after rollback |
| Existing behavior retained | Registration, action links, federation proposal/review/approval, account deletion and ordinary provisioning regressions |

| Required reference | Record from the reviewed candidate |
|---|---|
| Source and artifact | Exact commit, artifact identity and independent provenance |
| Automated checks | Complete serial/randomized CI, measured collection/coverage, lint, typing, security audit, strict docs and repository scans |
| Focused behavior | Exact commands, runtime versions, results and unavailable checks |
| Deployment acceptance | Applicable source, identity, recovery and host evidence |

The new PostgreSQL module is
`src/tests/integration/test_federated_reservation_claim_db.py`. Its acceptance
nodes are:

- `test_claim_deletes_passwordless_signup_and_revokes_its_code`
- `test_legacy_credentials_and_cascading_children_are_deleted_never_transferred`
- `test_protected_collision_preserves_every_account` (verified, administrator, federated)
- `test_existing_exact_identity_does_not_delete_a_different_email_reservation` (pending, approved, disabled)
- `test_untrusted_or_stale_assertion_cannot_claim` (issuer, MFA, disabled, stale policy)
- `test_generic_provisioning_wrapper_has_no_claim_authority`
- `test_failure_after_claim_rolls_back_deleted_row_children_and_audit`
- `test_verification_claim_race_has_observed_locks_and_one_winner` (both commit orders)
- `test_concurrent_same_subject_creation_restores_losing_reservation`

The unit module `src/tests/unit/test_federated_reservation_claim.py` exercises
protected/absent reservations, existing identities, nonemail conflicts,
impossible missing locked rows, competing fresh inserts, post-delete uniqueness
failures and audit timing through the public finalizer. Preparation checks do
not replace the database acceptance nodes above.

This batch changes no database schema and requires no database reset or data
migration. Retain the existing initial-schema baseline. Run tests only against
explicitly disposable PostgreSQL/Redis services; an updater is not authorized
to alter application data or perform host activation.

## Deployment boundary

Deploy the accepted reservation behavior before enabling federation alongside
public registration. Keep the ordered SP installation, assertion, MFA,
approval, activation and rollback requirements in the
[federation acceptance procedure](federated-tier-acceptance.md). A successful
synthetic claim does not establish Gate F. Public registration independently
requires [Gate R](../configuration/deployment.md#registration-activation-gate-r).

The [account guide](../user-guide/accounts.md#registering-for-an-account)
explains the user-visible reservation rule. A legitimate verified-account
collision requires operator identity review; automatic email-based linking
is not available.

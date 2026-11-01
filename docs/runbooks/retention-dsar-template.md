# Retention and DSAR template

**Template only: the account-deletion slice of WP L.**
This page connects personal-data requests with the implemented
[account-deletion procedure](account-deletion.md). The operator must supply
approved owners, retention decisions, identity checks, response procedures and
restore handling. Use the [full DSAR procedure template](../compliance/dsar-procedure.md)
for intake, scope, authorized export/correction and response handling, and the
[processing register](../compliance/processing-register.md) for the systems and
retention inventory. This account-deletion supplement does not establish
institutional approval or completion of a request.

## Operator decision record

Complete this record before adopting the template as an operational procedure.
Keep request records in the approved restricted system; do not commit personal
identities or request evidence to this repository.

| Decision | Approved value/reference |
|---|---|
| Service owner and request contact | `<owner-and-contact>` |
| Request intake, identity verification and authorized approver | `<approved-procedure-reference>` |
| Request/response tracking, applicable deadlines and escalation | `<approved-procedure-reference>` |
| Grounds and review process for retaining specific records | `<approved-retention-decision-reference>` |
| Audit-log access, shipping, retention and expiry owner | `<owner-and-retention-reference>` |
| Backup retention, encrypted custody and expiry owner | `<owner-and-retention-reference>` |
| Deletion register access, retention and restore reconciliation owner | `<owner-and-retention-reference>` |
| External processors, mail and institutional identity coordination | `<processor-and-owner-register-reference>` |
| Review date and approval | `<date-and-approval-reference>` |

## Request handling record

Use a restricted record with the following fields. Record only what the request
process requires; never retain the user's password, authenticator code, recovery
codes, email-action security codes or legacy secret-bearing links as request
evidence.

- Request reference, receipt date, scope and verified requester authority.
- Systems covered, identity mapping and responsible owners, including external
  identity/email systems where applicable.
- Approved export, correction, deletion or retention decision for each system,
  with reviewer and decision reference.
- Live deletion completion and pseudonymous audit reference, or a precise
  explanation of an approved exception.
- Remaining retained copies, their approved expiry/handling and restore controls.
- Response date, recipient-verification record and escalation/review references.

A data export and account deletion are separate operations. Complete any approved
export before deletion using the authorized request process; the account-delete
form supplies no export or general DSAR workflow.

## Deletion procedure and retained copies

Use [Account deletion](account-deletion.md) for local self-service or confirmed
administrator removal. Local self-service requires password and fresh TOTP;
federated archive accounts require an administrator. Last-active-admin protection
still applies. Do not substitute unreviewed SQL or restore an entire database to
reverse a request.

| Data/copy | Procedure boundary and operator action |
|---|---|
| Live account and owned state | The application transaction removes the target and cascades sessions, factors, rotation challenges, target/requester promotion requests and user-linked outbox rows. Confirm the successful audit reference. |
| Other accounts' historical approval markers | Numeric `federated_approved_by` markers remain as approval history; review this explicit retained category in the approved schedule. |
| Successful deletion audit | Retains a keyed pseudonymous `email_hash`, actor/target IDs and normal request metadata. Restrict access and apply the approved audit schedule. |
| Earlier audit/application/edge logs | Account deletion does not rewrite them. Inventory their content, purpose, access, shipping and expiry under the approved schedule. |
| Encrypted backups and off-host copies | Account deletion does not edit archives. Record approved expiry and custody; reconcile completed deletions before a restored system is allowed to serve users or send mail. |
| Email already delivered or being sent | Database cleanup cannot recall a message already handed to SMTP or held in a worker's active send. Deleted-account action POST redemption fails closed; the public-ID GET remains a generic form without action authority. Apply the external mail system's approved handling. |
| Account-unlinked notices and other processors | Inventory separately; the user-ID cascade cannot find records lacking that association. Route any approved action to the responsible owner. |
| Institutional identity | Archive deletion does not delete the IdP account. Coordinate with its owner; a later trusted login may provision a new pending archive account. |
| Catalogue/source material | Account deletion does not withdraw catalogue descriptions or source-owned recordings. Apply the relevant source-owner/request procedure separately. |

A pseudonymous hash and numeric ID can still be personal data when they remain
linkable. Do not label them anonymous or promise that deleting an archive
account erases every copy everywhere.

## Restore reconciliation

Define a restricted deletion register or equivalent approved evidence process
that identifies completed deletions across retained backup dates without
embedding credentials. Assign an owner and access/retention rules. The application
does not supply that register or an automatic replay job.

Before exposing any restored database, reconcile approved deletions and other
post-backup identity/security changes against that record. Keep web login and
email delivery isolated until the approved reconciliation and security checks
pass. Record which backup was restored, the requests reconciled, the reviewer
and the release decision. The existing encrypted-backup restore runbook provides
the technical isolation steps; it does not decide the retention policy.

## Review and completion

Review the request record against every inventoried system, communicate the
approved result and any retained categories through the operator's verified
response process, and close only when the assigned owners have recorded their
actions. Repository templates are separate from operator adoption: approved
retention decisions, institutional request handling and recorded restore
reconciliation remain open until the responsible owners supply their evidence.

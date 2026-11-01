# Data-subject request procedure

**Template: complete and approve the marked fields before operational use.**
This maps request handling to implemented controls; it supplies no legal or
institutional decision or fulfillment evidence. Keep requests and personal
evidence in the approved restricted case system.

## Ownership and adopted procedure

| Decision | Approved value or restricted reference |
|---|---|
| Service/controller and accountable owner | `<service-and-owner-reference>` |
| Request intake and alternate accessible channel | `<approved-intake-channels>` |
| Privacy adviser and authorized decision maker | `<privacy-and-approval-roles>` |
| Applicable framework and rights assessment | `<approved-framework-reference>` |
| Identity and representative-authority checks | `<approved-verification-procedure>` |
| Response periods, clock rules and escalation | `<approved-deadline-and-escalation-rules>` |
| Secure response and recipient verification | `<approved-response-channel-procedure>` |
| Request/evidence retention and restricted access | `<case-retention-and-access-reference>` |
| Processor/source-owner coordination | `<processor-and-source-contact-register>` |
| Review date, approver and procedure version | `<date-approver-and-version>` |

Use the approved framework to determine which rights apply, when a response is
due, whether an extension or refusal is available, and who may approve it. The
application does not calculate legal deadlines or decide the request's merits.

## Open a controlled request record

| Record field | Case value or reference |
|---|---|
| Request identifier and receipt time, with timezone | `<request-id-and-receipt-time>` |
| Requested right, scope and original channel | `<request-type-scope-and-channel>` |
| Verification result, method and reviewer | `<verification-result-and-review-reference>` |
| Representative authority, if relevant | `<authority-decision-reference>` |
| Responsible owner and assigned system owners | `<case-owner-and-system-owners>` |
| Approved due date and escalation checkpoints | `<due-date-and-checkpoints>` |
| Decision and reasons for each requested action | `<per-action-decision-reference>` |
| Execution evidence and independent review | `<execution-and-review-references>` |
| Response recipient/channel, date and delivery result | `<verified-response-and-delivery-reference>` |
| Remaining retained copies and next review | `<retained-copy-and-follow-up-reference>` |
| Final approval and closure time | `<closure-approval-and-time>` |

Retain the minimum evidence required by the approved procedure. Reference the
verification result rather than duplicating identity documents. Never record
passwords, authenticator secrets or codes, recovery codes, session credentials,
email-action security codes, complete assertions or private message bodies as
request evidence. Restrict access to case identifiers that remain linkable.

## 1. Receive, verify and clarify

1. Record receipt promptly and assign the approved owner. Apply the adopted
   deadline rules and escalation checkpoints; track any permitted change with
   its decision reference.
2. Verify requester identity and, where relevant, representative authority using
   the approved proportional process. A claimed email address, public dataset
   identifier or forwarded action link alone is not verification.
3. Clarify the right and systems in scope without collecting unnecessary
   personal data. Distinguish an archive account from catalogue content about a
   person and from recordings held by an originating repository.
4. Decide whether there is an immediate disclosure/security issue. Use the
   [incident-response template](incident-response.md) and the existing
   [withdrawal procedure](../runbooks/emergency-dataset-withdrawal.md) when
   urgent containment is approved; keep the rights assessment active.
5. Record approved acknowledgements, assistance, escalation or refusal through
   the case procedure. Do not reveal account existence to an unverified third
   party while investigating.

## 2. Discover the relevant systems

Use the approved processing/asset register and assign an owner to every copy.
The [catalogue classification](data-classification.md) describes the public
`Dataset` fields; it is not a complete personal-data or storage inventory.

| System or copy | Review needed |
|---|---|
| Archive account and federation review | Profile, email changes, local/federated identity, review/approval history, roles and relevant security state |
| Sessions, factors and administration state | Live sessions/IP metadata, pending factor changes, recovery and promotion state; protect security credentials |
| Email outbox and delivery systems | Recipient/subject, encrypted bodies, delivery state, account-unlinked notices, relay/provider and recipient copies |
| Catalogue and ingestion state | Normalized fields, raw JSONB, derived search text/vectors, staging/quarantine/failure information and durable administrator restrictions |
| Application, audit and edge records | Identifiers/request metadata, transactional `security_audit_events` and `security_audit_receipts`, logs, collectors, forwarding, access controls and approved expiry |
| Backups, snapshots and off-host copies | Archive dates, custody, retention decisions, historical keys and restore reconciliation |
| Redis and other operational stores | Limiter/caching state and its operational retention; do not assume PostgreSQL deletion reaches it |
| External identities, sources and processors | IdP/SP, originating repository, source curator, mail/hosting/storage operators and responsible contacts |
| Request and incident records | Case evidence, correspondence and approved retention/access decisions |

Map identity using reviewed system identifiers. Federated archive identities
are keyed by issuer and subject; email is mutable and must not be used to merge
unrelated identities. A numeric ID or keyed email hash may remain personal data
when linkable. Do not label such records anonymous.

## 3. Decide and execute approved actions

Record the decision, reviewer, operator and expected result for each system.
Preserve evidence needed for an approved exception or retention hold through the
restricted process. A hold is a reviewed decision, not a reason to retain every
copy indefinitely or keep disclosure paths open.

### Access or export

The archive supplies no general DSAR/export endpoint. Arrange an authorized,
reviewed extraction through the responsible system owners. Limit the output to
the approved scope, review third-party and security-sensitive material, and
verify completeness against the inventory before sending it. Do not substitute
a database dump, an administrator screen capture or a mailbox export for that
review.

Search is not a complete export mechanism. Its
[pagination bookmarks](../runbooks/search-pagination.md) do not freeze a
multi-request snapshot or guarantee exactly-once enumeration. Request a stable,
reviewed extraction if the approved action requires that property.

### Correction, restriction or source material

Identify the authoritative owner before changing data. Archive account fields,
source-synchronized metadata, durable local restrictions and external recordings
have different owners. Coordinate correction or withdrawal with the source;
editing a serving cache alone can be overwritten by later ingestion.

For approved urgent catalogue containment, use
[Emergency Dataset Withdrawal](../runbooks/emergency-dataset-withdrawal.md).
Raising a metadata tier preserves public discovery; hiding removes the public
envelope as well. Hiding retains local metadata and other copies. Removing a
source from configuration is not a withdrawal or erasure operation.

Record source correction verification across normalized/raw metadata, derived
search fields and current catalogue surfaces, while preserving independently
approved durable restrictions. The originating repository controls its
recordings; the archive's resource redirect does not grant or revoke upstream
access. Assign external actions to that owner.

### Account deletion

Follow [Account deletion](../runbooks/account-deletion.md) and the existing
[retention/DSAR boundary](../runbooks/retention-dsar-template.md). Complete any
approved export before deletion. The delete form supplies no export or general
request workflow.

Local self-service requires password and fresh TOTP. Federated archive accounts
require administrator removal, and last-active-admin protection still applies.
Use the supported procedure; do not bypass it with unreviewed SQL or restore a
whole database to undo one deletion.

Confirm committed live cleanup and its pseudonymous audit reference. Sessions
fail on their next request, while already-authorized in-flight work may finish.
Historical approval markers on another account can remain. Already delivered
or in-flight SMTP cannot be recalled by outbox deletion; account-unlinked
notices, external systems, logs and backups need separate handling. Deleting an
archive account does not delete its IdP identity or prevent a later trusted
login from creating a new pending account.

## 4. Handle retention and later restores

Record each retained category, decision/hold reference, owner, access boundary,
expiry or review trigger, and any required notice. Live deletion does not edit
historical logs, archives, snapshots or processor copies. Apply the approved
retention schedule separately and verify the responsible owners' results.

Maintain the approved restricted deletion/reconciliation record without
credentials. The application supplies no automatic deletion-register replay.
Before a restored system serves users or sends mail, reconcile completed
requests and post-backup identity/security changes under the
[retention/DSAR restore procedure](../runbooks/retention-dsar-template.md#restore-reconciliation).
Use the existing isolated recovery controls; do not restore into a retained
database merely to investigate a request.

## 5. Review, respond and close

Have the authorized reviewer compare the decision with every inventory entry
and execution result. Resolve missing owners and unexplained retained copies.
Record any approved incomplete action, reason, next checkpoint and escalation;
do not report universal erasure when copies remain.

Verify the recipient and secure delivery channel before releasing the approved
response or export. Record the result, retained categories and any applicable
review/escalation route through the adopted procedure. Apply the case's own
retention/access rules after closure and update the register or technical
procedure when the investigation exposed a gap.

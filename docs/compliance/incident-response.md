# Incident-response procedure

**Template: adopt through the incident/privacy process, complete its fields and
exercise it in a disposable environment before use.** Completion establishes
neither notification approval nor deployed containment/recovery evidence.
Keep incident records and sensitive evidence in the approved restricted system.

## Ownership and decision rules

| Decision | Approved value or restricted reference |
|---|---|
| Incident intake and emergency contact route | `<approved-intake-and-emergency-route>` |
| Incident commander, deputy and authorized operators | `<incident-roles-and-delegation>` |
| Service, security, privacy and source owners | `<owner-and-contact-register>` |
| Severity, escalation and out-of-hours rules | `<approved-severity-and-escalation-rules>` |
| Emergency containment authority and review | `<containment-authority-and-review-rules>` |
| Evidence custody, access and retention | `<evidence-handling-and-retention-procedure>` |
| Applicable notification assessment and approver | `<notification-assessment-and-approval-procedure>` |
| Approved internal/external communication channels | `<communication-and-recipient-verification-procedure>` |
| Recovery/reopening authority and acceptance | `<recovery-approval-and-acceptance-rules>` |
| Version, review date and exercise record | `<version-review-and-exercise-reference>` |

Determine recipients, thresholds, notification periods and clock rules through
the approved applicable-framework assessment. Record the decision and reasons,
including a decision not to notify, without inventing a universal deadline.

## Controlled incident record

| Record field | Incident value or restricted reference |
|---|---|
| Incident identifier and reporting source | `<incident-id-and-report-source>` |
| Detection, report and estimated event times, with timezone | `<times-and-timezone>` |
| Known facts, uncertainties and last assessment time | `<facts-uncertainties-and-assessment-time>` |
| Affected service, release, environment and owners | `<service-release-environment-and-owners>` |
| Severity, scope and escalation decision | `<severity-scope-and-decision-reference>` |
| Containment decision, approver, operator and result | `<containment-decision-and-execution-reference>` |
| Evidence inventory, provenance and access history | `<controlled-evidence-register-reference>` |
| Personal-data impact and notification assessment | `<impact-and-notification-decision-reference>` |
| Communications and verified recipients | `<communication-record-reference>` |
| Recovery verification and reopening approval | `<verification-and-release-reference>` |
| Follow-up owners, due dates and closure approval | `<actions-deadlines-and-closure-reference>` |

Record observations separately from hypotheses. Preserve original timestamps
and note clock offsets or uncertain ordering; an application timestamp alone
does not establish causality across hosts or concurrent requests.

## 1. Triage and preserve evidence

1. Open the restricted record, assign the incident commander and apply the
   severity/escalation rules. Establish an approved communication route that
   remains usable if the application, host or normal identity system is suspect.
2. Identify confidentiality, integrity and availability impact. Review affected
   accounts, catalogue/source identities, processors and time windows without
   copying private content into a general ticket.
3. Preserve the minimum relevant evidence through approved custody controls.
   Record source, collector, collection time, method, integrity/provenance
   reference, access owner and retention decision. Preserve originals and record
   later transformations; a checksum by itself does not authenticate a producer.
4. Collect only authorized evidence from application/audit/edge logs, host and
   collector state, mail/IdP/SP systems and source operators. Refer to
   [Logging & Audit](../configuration/logging.md) for actual event fields and
   finite redaction boundaries. Do not enable unrestricted body/debug logging.
5. Protect credentials and private content. Never paste passwords, session or
   action credentials, TOTP/recovery material, complete assertion payloads,
   private keys or encrypted message bodies into incident evidence. Store any
   necessary sensitive acquisition under separately approved restricted custody.
6. Record audit gaps; absence does not prove no action. Account administration
   and deletion log after commit, leaving a crash gap. Dataset administration
   and ingestion persist security events with their mutations; local log copies
   follow commit. Verify delivery receipts, host delivery and retention separately.

Do not reset, migrate, truncate or restore a retained database to reproduce an
incident. Rehearsals and analysis copies need an explicitly approved isolated
environment, controlled data handling and no production mail or feed access.

## 2. Approve and apply containment

Choose the narrowest action that contains the observed exposure, with its
operational impact and verification recorded. Use the existing deployment and
technical runbooks rather than inventing emergency SQL or loosening grants.

| Incident concern | Existing procedure and verification boundary |
|---|---|
| Dataset must disappear from discovery | Use [Emergency Dataset Withdrawal](../runbooks/emergency-dataset-withdrawal.md); verify all viewer tiers, detail, search, recent cards, facets and counts. Raising a tier alone leaves public discovery visible. |
| Upstream metadata disclosure or incorrect classification | Contain affected `(source, uuid)` identities and coordinate authoritative correction with the source owner under the [Sensitive Source Contract](../architecture/source-b-ingestion-contract.md). Removing source configuration does not withdraw retained rows. |
| Account or session compromise | Apply the authorized account/session response through reviewed application/deployment procedures. Verify current authentication and privilege state; account deletion is not a substitute for preserving incident evidence. |
| Signing, session or encryption key exposure | Follow [Secret and Key Rotation](../runbooks/key-rotation.md), including the credential-specific maintenance and verification steps below. |
| Federation callback/internal-secret or host/SP exposure | Follow the key-rotation runbook's **Suspected disclosure** sequence. Stopping public callback access alone does not contain a holder who can reach the Gunicorn socket. Keep federation disabled until the investigation and pre-flip acceptance pass. |
| Mail capability or historical secret-bearing URL exposure | Use [Email-action links](../runbooks/action-links.md) and the applicable key/account procedure. A current public-ID GET is generic; test revoked authority by POST redemption, not by the appearance of that landing form. |
| Backup, snapshot or recovery-key exposure | Treat the complete archive and associated identities as in scope; follow [deployment backup controls](../configuration/deployment.md#encrypted-backups-under-a-separate-identity) and the key-rotation recipient procedure. Changing a recipient does not repair confidentiality of an already exposed archive. |
| Application/host integrity failure | Apply the approved service isolation and trusted recovery procedure. A single key rotation cannot establish that a compromised host or SP is trustworthy. |

Hiding retains local metadata, logs, archives and downstream copies. Its durable
restriction survives ingestion for the same source/UUID; a new UUID is a
different identity requiring review. Administrative status does not grant a
higher metadata tier. Record affected identities without copying their private
metadata into the incident record.

### Credential-specific impact

Record the credential category and version/reference, never its value. Confirm
which web, scheduler, maintenance and external processes use it before change.

- `SECRET_KEY` rotation invalidates signed email-action codes and encrypted
  [search bookmarks](../runbooks/search-pagination.md), changes keyed audit
  correlation and limiter-client identifiers, and requires fresh action emails
  and pagination entry where applicable. It does not rotate TOTP/outbox
  encryption or session signatures. Review queued token-bearing mail using the
  existing cancellation/reissue procedure; decryptability is not validity.
- `SESSION_SECRET` rotation invalidates existing signed session cookies and
  requires login/fresh CSRF state. It does not itself delete server-side session
  rows; follow the reviewed revocation/cleanup procedure where needed.
- TOTP and outbox encryption rings are independent. Retain decryptors while
  live or archived ciphertext still needs them. Verify active and pending TOTP
  state through the committed re-encryption/primary-key verification procedure.
  There is no supplied outbox bulk re-encryption tool.
- Backup recipient/private-identity custody is separate from application keys.
  Historical archives may need historical application decryptors as well as the
  matching archive identity. Do not remove required recovery material merely
  because the live database has been rotated.
- A changed `SHIBBOLETH_INTERNAL_SECRET` file revokes nothing until the required
  procedure and application restart/reconciliation complete. For suspected
  exposure, use the stopped-web emergency revocation sequence; confirm no
  federated sessions remain and keep the callback closed and federation disabled
  until approved recovery.

Restart every process that caches changed settings/keys as directed by the
runbook. Do not restore a compromised active signer/encryptor as a rollback.
Retaining a compromised decryptor temporarily preserves availability; it does
not undo the earlier confidentiality impact.

## 3. Assess impact and communications

Reconcile the known facts with the processing/asset register, source-owner
disclosure approvals and [catalogue classification](data-classification.md).
Include public record existence, enumeration, ordering/count channels, raw and
derived copies, accounts, mail, logs, retained archives and external systems in
the assessment. A high metadata tier does not hide the public envelope.

Have the authorized privacy/security decision maker assess affected people,
data categories, duration, protections, plausible consequences and remaining
uncertainty. Pseudonymous hashes and numeric identifiers can remain linkable
personal data. Record notification decisions, approved recipients, applicable
timing and follow-up reviews using the adopted rules; update the assessment as
facts change.

Use approved channels and verified recipients for communications. Share the
minimum approved information, preserve the decision and delivery record, and
coordinate with source, identity, mail and hosting/storage owners. Do not put
secrets or raw sensitive evidence into a public advisory.

## 4. Recover and verify before reopening

Repair the authoritative cause, review account/role/source/configuration state
and verify the exact affected boundary. A green repository test run supports
application behavior; it does not establish deployed custody, host integrity or
that private values were approved for public disclosure.

Use the [visibility/recovery acceptance record](../runbooks/visibility-recovery-acceptance.md)
and existing deployment restore procedure for reviewed isolated recovery.
Verify backup provenance, complete decryption, data/role policies and applicable
historical application keys. An archive table-of-contents listing alone is not
a restore or completeness test. Keep recovery work isolated from production
login, mail and feed side effects.

Before exposing restored state, reconcile completed deletions and later
identity/security changes using the
[retention/DSAR restore procedure](../runbooks/retention-dsar-template.md#restore-reconciliation).
Reapply approved durable hides/restrictions and verify current catalogue and
account/session behavior under actual restricted identities. Do not blindly
reintroduce a compromised credential, invalidated capability or withdrawn data.

Record the verification results, residual risks, monitoring plan and authorized
reopening decision. Reopen incrementally through the approved deployment
procedure and check real authentication, mail and disclosure boundaries where
they were affected. Keep failed checks isolated and escalate them.

## 5. Review and close

Hold a controlled review of cause, scope, detection/response gaps and the action
timeline. Assign a named role, due date and verification criterion to every
follow-up. Update templates, processing/asset records, access/retention controls
and technical runbooks where the incident revealed a gap.

Apply approved evidence retention/holds and expiry; do not retain copies
indefinitely by default. Close only after the authorized reviewer accepts the
recorded containment, recovery, communications and follow-up ownership. An
exercise or this completed template does not itself establish legal compliance
or real-host acceptance.

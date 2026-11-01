# Processing-register template

**Template: complete and approve the `<...>` fields before operational use.**
The responsible owner determines the framework, scope, grounds, approvals and
review process; this page records none of those institutional decisions.
Keep completed records, contacts, locations, contracts and evidence in
`<restricted-register-location>`. Publish only a reviewed version excluding
personal exports/narratives, secrets, private endpoints and request evidence.

## Register control record

| Field | Complete in the restricted record |
|---|---|
| Register reference, version and status | `<register-reference-version-and-status>` |
| Service scope and environments | `<service-scope-and-environment-inventory-reference>` |
| Responsible organization and role for each activity | `<organization-and-controller-processor-role-reference>` |
| Accountable owner and operational contact | `<owner-and-contact-reference>` |
| Privacy, security and request contacts | `<approved-contact-directory-reference>` |
| Applicable framework and jurisdiction review | `<framework-and-jurisdiction-decision-reference>` |
| Approval authority and approval record | `<approver-and-approval-reference>` |
| Last review, next review and change triggers | `<review-dates-and-change-trigger-reference>` |
| Restricted evidence and document access | `<evidence-location-access-and-retention-reference>` |

Describe relationships between the catalogue operator, source owners, hosting
providers, mail providers and identity providers for each activity. Do not
infer their legal roles from the software component they run.

## One record per processing activity

Copy this section for each activity. Separate activities when their purpose,
subjects, recipients, grounds, safeguards or retention differ. Account
administration, catalogue disclosure, ingestion, security monitoring, mail
delivery and recovery may need distinct records; the owner decides the scope.

| Field | Complete for this activity |
|---|---|
| Activity identity and accountable owner | `<activity-id-name-and-owner>` |
| Purpose and intended outcome | `<specific-purpose-and-outcome>` |
| Why the activity and each data category are necessary | `<necessity-and-minimization-assessment-reference>` |
| Applicable framework and grounds for this activity | `<framework-grounds-and-review-reference>` |
| Additional conditions for sensitive or otherwise specially regulated data | `<applicability-and-condition-decision-reference>` |
| Categories of people affected | `<subject-categories-and-vulnerability-assessment>` |
| Data categories, sources and collection method | `<data-categories-sources-and-collection-reference>` |
| Accuracy, correction and source-owner responsibilities | `<accuracy-and-correction-process-reference>` |
| Processing steps and approved data-flow map | `<steps-and-data-flow-reference>` |
| System and asset inventory entries | `<asset-ids-and-system-boundary-reference>` |
| Internal access groups and privileged access | `<role-access-approval-and-review-reference>` |
| External recipients and their roles | `<recipient-role-contract-and-purpose-reference>` |
| Storage, transit, access and recovery locations | `<location-and-remote-access-register-reference>` |
| Transfer assessment and safeguards where applicable | `<transfer-applicability-decision-and-safeguard-reference>` |
| Transparency, notices and communications | `<notice-version-delivery-and-contact-reference>` |
| Request handling, restrictions and exceptions | `<request-procedure-and-reviewed-exception-reference>` |
| Retention triggers, periods and approved exceptions | `<retention-schedule-and-exception-reference>` |
| Deletion, expiry, withdrawal and restore reconciliation | `<disposal-and-restore-control-reference>` |
| Technical and organizational safeguards | `<safeguard-implementation-and-evidence-reference>` |
| Risk assessment and DPIA screening | `<risk-and-dpia-decision-reference>` |
| Review decision, approver and next review | `<approval-and-next-review-reference>` |

Use the [DPIA questionnaire](dpia-questionnaire.md) to record screening and risk
decisions. Use the [DSAR procedure](dsar-procedure.md) for request coordination
and the [incident-response template](incident-response.md) for suspected harm or
unauthorized processing. These links provide templates, not an approved
institutional process.

## System and asset inventory

The rows below identify application boundaries to investigate. Complete each
row, split it when copies or owners differ, and add any deployed asset that is
missing. Record an approved non-applicability decision for an unused component.
This seed inventory is not an assertion that every deployment uses every
component or that it exhausts an institution's systems.

| Asset or boundary | Content and handling to verify | Restricted inventory record |
|---|---|---|
| Catalogue metadata and discovery/search projections | Source identifiers, descriptive metadata, raw stored JSON, generated search text/vectors and public discovery values; review combinations and upstream disclosure approval | `<catalogue-asset-owner-location-access-and-purpose-reference>` |
| Ingestion state and source connectivity | Source endpoints and credentials, transport/staged harvest data, cursors, quarantine and failure state; investigate retained errors and temporary copies | `<ingestion-asset-owner-location-access-and-purpose-reference>` |
| Dataset administration | Durable source/UUID hiding and tier restrictions, actor references and change evidence; these controls are distinct from catalogue deletion | `<dataset-administration-asset-reference>` |
| Account and federation profiles | Email, local account state, issuer/subject identity, federation attributes and approval history; upstream IdP accounts remain separate | `<account-and-federation-asset-reference>` |
| Authentication and recovery state | Password hashes, encrypted TOTP seeds/challenges, recovery-code digests, revisions, lockouts and account-action hashes; never include their values in this register | `<credential-and-recovery-asset-reference>` |
| Sessions and browser-held state | Server-side sessions, purpose, expiry, flash and step-up state; browser cookies and copied session identifiers need their own boundary review | `<session-and-browser-asset-reference>` |
| Transactional mail and development mailbox | Recipient/subject metadata, encrypted outbox bodies, retry/terminal state, worker-held sends and any development `.eml` files; delivered mail belongs to additional systems | `<outbox-mailbox-and-delivery-asset-reference>` |
| Redis and other deployed transient state | Rate-limit counters and any configured cache content, namespaces, logical databases, persistence, snapshots and administrative access | `<redis-and-cache-asset-reference>` |
| Application and audit logs | Request/account/resource event metadata, keyed address markers, IPs and identifiers; redaction is a safeguard rather than a guarantee that arbitrary content is safe | `<application-audit-and-collector-asset-reference>` |
| Transactional security audit | Database `security_audit_events` payloads and `security_audit_receipts`; mutation-linked restriction evidence and delivery state need retention, access and recovery review | `<transactional-security-audit-asset-reference>` |
| Edge and identity infrastructure | Reverse-proxy/SP/IdP logs and assertions, routing and access metadata, host/network telemetry and intermediate collectors | `<edge-identity-and-monitoring-asset-reference>` |
| Backups, replicas, exports and recovery copies | Encrypted archives, snapshots, off-host stores, copied dumps, restore workspaces and request exports; catalogue RLS does not restrict a complete backup | `<backup-export-and-recovery-asset-reference>` |
| Secrets, keys and configuration | Signing/session secrets, TOTP/outbox key rings, source credentials, SMTP/SP credentials and backup private identities; inventory custody references only | `<secret-configuration-and-key-custody-reference>` |
| Build, development and support systems | Source repositories, CI artifacts/logs, package/image registries, test fixtures, developer mailboxes and support/request records; synthetic fixtures do not authorize production-data copies | `<build-development-and-support-asset-reference>` |
| External source and material repositories | Source-owned recordings, transcripts, original records, landing pages and downstream copies; the catalogue's redirects do not control their access or retention | `<source-and-material-repository-asset-reference>` |
| Other processors and recipients | Hosting, mail, identity, monitoring, backup transfer/store and any additional service actually receiving data | `<processor-and-recipient-inventory-reference>` |

For each inventory entry, complete the following restricted record rather than
placing confidential operational detail in the table above.

| Inventory field | Complete for this asset or copy |
|---|---|
| Asset ID, version, environment and related activities | `<asset-identity-environment-and-activity-references>` |
| Owner, custodian, access approver and recovery custodian | `<ownership-access-and-custody-reference>` |
| Data/subject categories and approved classification | `<data-subject-and-classification-reference>` |
| Purpose, source and grounds decision | `<purpose-source-and-grounds-reference>` |
| Incoming/outgoing flows and recipients | `<data-flow-and-recipient-reference>` |
| Hosting, processing, remote-support and recovery locations | `<location-and-support-access-reference>` |
| Processor/subprocessor and contractual controls | `<processor-contract-and-review-reference>` |
| Access groups, service identities and review evidence | `<access-model-and-review-reference>` |
| Encryption, key separation and recovery dependencies | `<encryption-and-key-custody-reference>` |
| Retention trigger, period, legal hold/exception and expiry | `<approved-retention-and-exception-reference>` |
| Disposal, request execution and restore reconciliation | `<disposal-request-and-restore-control-reference>` |
| Safeguard verification and unresolved gaps | `<verification-result-and-gap-owner-reference>` |
| Approval, last review and next review | `<approval-review-and-next-review-reference>` |

## Catalogue disclosure and source-owned material

Use the code-checked [data-classification matrix](data-classification.md) for
the 22 public `Dataset` fields. A `public` code minimum is an additional floor,
not a source-owner disclosure approval. The effective protected-field boundary
combines code minima, configured source minima and the effective record tier,
including durable administrator restrictions. Hiding removes the identity from
catalogue discovery at every metadata tier.

The approved public discovery fields are `id`, `uuid`, `title`, `access_level`,
`version`, `source` and `visibility_tier`; public ungated text search uses
`title` and `access_level`. Record approval for each value and its combination
in `<source-public-disclosure-approval-reference>`. A title or identifier may
itself reveal information that a restricted description would conceal.

The catalogue does not store or serve recordings merely because it describes
them. [Resource redirects](../architecture/resource-access.md) recheck the
catalogue permission boundary; the external repository decides whether access
to the recording or other material is granted. Document those separate systems,
owners and request/incident handoffs in
`<source-material-responsibility-and-handoff-reference>`.

## Recipients, locations and transfers

For each actual data flow, record its purpose, minimum categories, recipient
role, contract, transit/storage locations, remote-support access and onward
recipients. Include SMTP delivery, SP/IdP assertions, external resource visits,
off-host log shipping, backup stores and request exports where used. A link to
an external resource can cause the browser to disclose network information to
that destination even when the catalogue does not fetch it.

| Flow record | Complete for the reviewed flow |
|---|---|
| Flow identity, source/destination and related activities | `<flow-id-source-destination-and-activity-reference>` |
| Purpose, categories, frequency and minimization | `<flow-purpose-categories-frequency-and-minimization>` |
| Sender/recipient roles, contract and onward handling | `<recipient-role-contract-and-onward-handling-reference>` |
| Storage, transit, access and support locations | `<flow-location-and-access-reference>` |
| Applicable transfer decision and safeguards | `<transfer-assessment-decision-and-safeguard-reference>` |
| Verification, approver and review date | `<flow-verification-approval-and-review-reference>` |

## Retention and request coordination

For every asset and copy, identify the event that starts retention, the approved
period, applicable exception/hold authority, disposal method, proof and owner.
Do not use a deployment default as an institutional retention decision.
Outbox cleanup settings apply to terminal rows; pending/sending rows, delivered
mail, logs and backups need separate review. See the
[mailbox/outbox settings](../configuration/settings.md#mailbox-and-outbox-retention).

Live [account deletion](../runbooks/account-deletion.md) does not rewrite
historical logs, another account's approval history, delivered mail, source
material or backups. Keyed hashes and numeric identifiers can remain linkable;
do not classify them as anonymous solely because the plaintext email is absent.
Use the [retention/DSAR supplement](../runbooks/retention-dsar-template.md) to
record retained categories and reconciliation before a restored system serves
users or sends mail. Reference any approved deletion register through
`<restricted-deletion-register-and-access-reference>`; do not publish its entries.

## Review and approval

1. Reconcile the activity records against actual deployed systems, data flows,
   processors, locations and retained copies. Record the result in
   `<inventory-and-flow-review-reference>`.
2. Resolve missing grounds, source-disclosure permissions, retention decisions,
   rights handling and safeguards with `<assigned-review-owner-reference>`.
3. Record screening, consultation and any required assessment through
   `<assessment-and-consultation-decision-reference>`.
4. Record outstanding actions, owners, target dates and any approved operating
   restriction in `<action-register-and-operating-decision-reference>`.
5. Have `<authorized-approver-reference>` approve the restricted register and
   schedule `<next-review-date-and-change-triggers>`.

Review changes to sources, field policy, account/federation attributes,
processors, destinations, retention, key custody and deployment architecture.
Repository tests establish technical contracts; they do not approve this
register or demonstrate how an institution operates it.

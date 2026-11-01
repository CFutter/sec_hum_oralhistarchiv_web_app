# External dependencies and operating decisions

Prepare external requests, controlled test identities and operating decisions
using the private [decision record](external-dependencies-record-template.md).
Keep completed records and deployment values outside Git; store secrets only
through the approved custody process and record restricted references.

Unknown details may remain pending during handoff preparation. Resolve each
activity's prerequisites before execution; preparation does not submit requests,
authorize data use or prove deployment. Handle retained targets through the
[inventory procedure](retained-staging-inventory.md) and record PoC scope in the
[handoff](before-staging-handoff.md).

## One record, separate milestones

For each request/decision record the environment, milestone, responsible person
and deputy, approving authority, restricted reference, status, next action,
needed-by date/review trigger and operating restriction while pending. Leave
unassigned entries explicit. Use these preparation states:

| State | Meaning |
|---|---|
| Pending | No completed decision or submitted request recorded |
| Requested | Submitted through an authorized channel; request reference and follow-up recorded |
| Approved | Authorized scope/conditions recorded; installation and execution still separate |
| Blocked | Dependency or decision prevents the stated activity; restriction remains in force |

Record installation and executed acceptance separately from requests/approvals.
Keep staging and production records distinct, with separate acceptance for core
service, registration (Gate R), federation (Gate F) and Source B. Assign responsible
operators and obtain activity-specific approvals before execution.

## Prepare integration requests

| Area | Information to obtain and track privately | Existing procedure and later proof |
|---|---|---|
| Federation, staging and production separately | SP entity/endpoint registrations; exact issuers; authoritative metadata/trust and renewal; persistent non-reassigned subject semantics; attribute aliases/release; exact MFA requirement; supported SP/nginx module build; canary identity and reviewer | [Federation decisions and ordered gates](federation-integration.md#decisions-before-installation); actual release, negative tests, canary login and rollback at Gate F |
| Mail, staging and production separately | Approved relay/provider and sender; access request; TLS/authentication custody; controlled recipient mailboxes; sandbox/relay delivery restrictions and every forwarding route; retained queued-mail handling | [Laptop staging](local-staging.md), [action-link cutover](action-links.md), [registration activation](../configuration/deployment.md#registration-activation-gate-r); real production relay/public-endpoint flow at Gate R |
| Source B access and disclosure | Source-owner contact/approval; approved actual feed/schema/configuration version; environment-specific access custody; authorized samples; public-envelope review; staging/backup/recovery data-use restrictions | [Source operational records](../sources/json-feed-acceptance.md#final-operational-record), [sensitive-source contract](../architecture/source-b-ingestion-contract.md); actual-feed and representative recovery acceptance at D2 |

Prepare the request's purpose, exact scope, environment, required claims/access,
controlled test window and return channel before submission. The authorized
requester submits it and records the returned reference, conditions and next
follow-up. Do not include credentials, private source rows or unrestricted
identity captures in request packets or application issues.

### Mail containment and closed registration

Set `LOCAL_REGISTRATION_ENABLED=false` until that environment's controlled
rehearsal or Gate R permits activation. The default is true in dev and false in
staging/production when omitted. Closure does not stop account-action or queued
mail. Keep federation closed pending its own activation procedure.

Hardened staging requires SMTP with TLS. Plan an approved sandbox or restrictive
relay boundary that satisfies that configuration and contains actual recipients;
`SMTP_ENABLED=false` is not a valid running-staging containment plan. The
application has no staging recipient rewrite/allowlist setting. Delivery uses
the supplied/outbox recipient, so new canary mailboxes alone do not contain
messages retained for other accounts.

Before starting the scheduler, review pending/sending outbox rows and any legacy
action messages through the approved BS4 preservation/action-link procedure.
Record the relay's containment and onward-forwarding behavior, recipient
custody, retained-mail disposition, provider data-use authorization and evidence
retention. Do not clear or rewrite retained rows ad hoc. On an isolated recovery
target, establish side-effect isolation before any service starts.

### Approve data use before access becomes ingestion

Assign the three source records separately: `source_owner_approval`,
`real_feed_acceptance` and `representative_encrypted_restore`. Access credentials
or a valid feed schema do not supply those approvals. Public-envelope review
includes existence, identifiers, labels, ordering, search/pagination/counts and
detail responses, including combinations of allowed fields. A restricted record
tier does not conceal that public envelope.

Approve sensitive use in staging, mail sandboxes, backups and isolated recovery
before copying or ingesting real data. Specify allowed samples/identities,
locations, recipients, retention/holds and disposal, plus any onward processors.
Use synthetic fixtures where real-data authorization is pending. Keep Source B
unselected in the reviewed private source configuration until its intended
environment and activity are approved; repository fixtures do not approve an
actual feed.
Source deselection stops ingestion; it does not withdraw retained catalogue
rows or their public discovery envelope. Before web startup, review any retained
Source B exposure and approve the data-use/access/withdrawal handling through
BS4 and the existing source/administrator procedures. Deselection alone is not
containment or withdrawal.

## Adopt the institutional and operating records

Assign restricted working copies of the existing documents rather than copying
their policies into this index:

| Record | Decision/completion responsibility |
|---|---|
| [Processing and asset register](../compliance/processing-register.md) | Actual processing/assets, locations, recipients, purposes, access/custody and retention owners |
| [DPIA screening](../compliance/dpia-questionnaire.md) | Applicable framework, screening assessment, review authority and resulting restrictions/actions |
| [DSAR procedure](../compliance/dsar-procedure.md) and [retention supplement](retention-dsar-template.md) | Intake, identity verification, authorized scope/timing, retention/holds, deletion and restore reconciliation |
| [Incident response](../compliance/incident-response.md) | Triage/containment, assessment/communications, evidence custody, escalation, recovery and reopening authority |
| [Monitoring](monitoring.md) | Approved thresholds, monitor identity, recipients/deputy, out-of-hours escalation, independent backup/off-host checks, monitor failure and response rehearsal |
| [Recovery acceptance](visibility-recovery-acceptance.md), [key custody](key-rotation.md) and [PITR](point-in-time-recovery.md) | Recovery objectives/scenarios, archive provenance/custody, backup versus restore identities, required historical decryptors and isolated proof |

Agree RPO (acceptable loss boundary), RTO (recovery-time objective), covered
failure scenarios and how measurements begin/end. Record recovery/cutover and
reopening authority. A local backup marker does not establish achieved RPO,
off-host custody or recovery capability. Identify separate archive and
application-key custody, deputies, emergency retrieval, authenticated receipt,
retention/holds and secure disposal. Keep key values out of the record.

Make the PITR decision explicit: **required and proved before production**, or
**outside the accepted initial recovery capability**, with the accepted scope,
limitations and adoption owner recorded. If required, select and rehearse the
physical-base/WAL/history pipeline under the existing PITR procedure. The logical
dump unit is not that pipeline. A recorded exclusion cannot make an inadequate
initial capability satisfy the approved recovery objectives.

Approve log retention per stream/copy: application/audit, edge/SP, local journal,
off-host collector, support and incident evidence. Record purpose, access,
retention trigger/period, holds and expiry in the institutional records and
[logging configuration](../configuration/logging.md). Example journal capacity
and age values are not institutional approval or guaranteed retention. Monitoring
must include forwarding/queue failure and its own loss of service, not only a
successful liveness response.

## Own dependency and advisory response

Weekly Dependabot updates cover uv and GitHub Actions. CI runs
`scripts/audit_dependencies.py` on push/PR/manual jobs; the separate
`.github/workflows/dependency-advisories.yml` runs it Mondays at 05:41 UTC and
on manual dispatch. It audits runtime, development, documentation and actual
build dependencies and retains evidence for 30 days. These are configured jobs,
not proof that a particular run succeeded.

Assign an owner/deputy to review findings and missed runs, triage severity,
authorize dispositions and deploy tested fixes. Follow `CONTRIBUTING.md`; retain
locked inputs, pinned Action provenance and the deployed artifact identity.
Bot PRs and successful audits do not establish timely review or deployment.

## Handoff

Record submitted requests, approved mail/data arrangements, institutional-record
owners, recovery/custody/logging/monitoring decisions, PITR scope and advisory
responsibility. Mark the precise blocked activity for each pending requirement.

Keep host installation, retained-state recovery, Gate R, Gate F and actual-feed
acceptance pending until observed. A prepared handoff or synthetic PoC supplies
none of those results.

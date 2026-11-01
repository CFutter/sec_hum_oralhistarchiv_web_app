# Restricted external-dependency and decision record

Copy this blank template into the private evidence system, outside Git. Use the
[BS5 preparation runbook](external-dependencies-and-decisions.md) and link to
restricted working copies of the existing procedures. Do not insert credentials,
keys, private payloads, account lists or raw identity/configuration captures.
Unknowns are **Pending**. No request, approval or host result is supplied here.

For the mock-data PoC, mark unknown assignments/service details **Deferred to
deployment** and resolve them before the affected action. Placeholders permit
[candidate preparation](before-staging-handoff.md), not verified acceptance.
Keep public copies blank and role-based.

## Scope and tracking

| Field | Value/reference |
|---|---|
| Record/version and restricted location | Pending |
| Environments and candidate/configuration references | Pending |
| Intended D1 core scope and separately staged Gate R/Gate F/D2 milestones | Pending |
| Coordinator/reviewer/deputy and review trigger | Pending |
| BS4 retained-state inventory/preservation/recovery reference | Pending |
| Repository checks and actual candidate identity | Pending |

For each row below add: **environment/milestone; responsible person/deputy;
approving authority; Pending/Requested/Approved/Blocked status; restricted
request/decision reference; next action and needed-by date/review trigger;
operating restriction while pending; separate installation/execution result**.
Keep staging and production entries distinct even when the same provider serves
both. Request submission and approval are not executed acceptance.

## External request and preparation register

| Request/decision | Required scope and restricted references | Tracking fields |
|---|---|---|
| Staging federation | SP registration/endpoints, exact issuer, metadata trust/renewal, persistent non-reassigned subject/aliases, attributes, MFA, supported edge build, canary/reviewer | Pending |
| Production federation | Separate registration/release scope, issuer/subject semantics and production Gate F authority/window/rollback | Pending |
| Staging mail | Sandbox/relay approval, sender/access/TLS custody, controlled recipients, restrictions and every forwarding route, provider data-use/retention | Pending |
| Retained queued mail | Pending/sending and legacy actions reviewed before scheduler startup; BS4 preservation and approved disposition/containment procedure | Pending |
| Production mail | Intended relay/sender access, controlled canary mailbox, production public-endpoint Gate R window and reviewer | Pending |
| Source B feed access | Actual schema/configuration version, approved samples, environment-specific credentials custody and feed-contact/request reference | Pending |
| Source-owner public envelope | Existence/identifiers/labels, combinations, search/ordering/pagination/counts/detail disclosure and explicit source/version approval | Pending |
| Actual-feed acceptance | Full/incremental chains, correction/withdrawal/quarantine/resumption evidence owner and intended rehearsal | Pending |
| Representative encrypted recovery | Source/configuration scope, approved sensitive recovery use, archive/key custody and isolated target/evidence owner | Pending |

### Controls before any staging/recovery service startup

- [ ] Private registration/federation activation state explicitly reviewed;
      production remains closed until its own gate permits activation.
- [ ] Staging SMTP/TLS configuration and relay/sandbox recipient containment
      approved; actual queued recipients and all forwarding paths accounted for.
- [ ] Retained-mail preservation/disposition reviewed without ad-hoc row changes.
- [ ] Test accounts/mailboxes have controlled custody and approved data use.
- [ ] Source selection and permitted samples/locations/retention/disposal approved.
- [ ] Retained Source B exposure/access/withdrawal approved before web startup;
      source deselection alone does not withdraw existing catalogue rows.
- [ ] Isolated recovery target cannot cause uncontrolled mail/feed/login effects.

## Institutional working-copy index

| Existing record | Restricted copy/reference, responsible person, approval/review and remaining actions |
|---|---|
| Processing register and asset/recipient/location inventory | Pending |
| DPIA screening and resulting assessment/actions | Pending |
| DSAR intake/verification/scope/timing and retention/holds | Pending |
| Deletion register and restore reconciliation | Pending |
| Incident triage/containment/assessment/communications/evidence/reopening | Pending |

The responsible authority determines the applicable framework and timing. This
worksheet establishes neither legal roles nor universal response deadlines.

## Operational decisions

| Decision | Approved value, scope, authority, review trigger and restricted proof |
|---|---|
| RPO/RTO, covered scenarios, loss boundary and measurement start/end | Pending |
| Recovery/cutover/reopening authority and independent review | Pending |
| Backup/restore OS/DB identities, peer mappings and isolated target | Pending |
| Off-host archive provenance, receipt, retention/holds and disposal | Pending |
| Separate archive/application-key versions, custodians/deputies and emergency retrieval | Pending; references only |
| Monitoring identity/credential custody, checks, thresholds and polling/retry budgets | Pending |
| Alert recipients/deputy, out-of-hours escalation and monitor/forwarding failure | Pending |
| Per-copy application/audit/edge/SP/journal/collector/support/incident retention and access | Pending |
| Response/recovery rehearsal scope, frequency and failed-drill handling | Pending |

PITR decision — select and approve one:

- [ ] **Required before production:** approved toolchain/owner, physical base,
      complete off-host WAL/history chain and keys, lag/capacity controls and
      successful isolated target replay must be recorded before relying on it.
- [ ] **Outside accepted initial capability:** approved logical-recovery scope,
      objective compatibility, limitations and explicit adoption owner/review
      trigger recorded. This choice does not establish PITR.

Decision reference/approver/date and remaining evidence: **Pending**.
Actual restore, measured objectives and host verification: **Pending**.

## Dependency/advisory operating process

| Field | Approved process/reference |
|---|---|
| Weekly uv/Actions bot review owner and deputy | Pending; existing Dependabot retained |
| Recurring advisory/audit cadence, intake and missed-check handling | Pending |
| Severity/response policy, triage/escalation and disposition authority | Pending |
| Direct/transitive dependency and Action review; locked remediation/checks | Pending |
| Tested release/deployment responsibility and deployed-version tracking | Pending |

CI and the Monday 05:41 UTC/manual dependency-advisories workflow audit runtime,
development, documentation and build dependencies. Record actual run review and
missed-run handling separately; bot updates do not establish incident response.
This form authorizes no audit exception or automatic merge.

## Handoff and acceptance

This checklist records eventual BS5 adoption. It can remain unchecked/deferred
while the placeholder handoff is prepared; record the controlled PoC's selected
scope and execution prerequisites in its private candidate record.

- [ ] External requests submitted by authorized requesters and tracked separately
      from approvals and eventual execution.
- [ ] Controlled staging mail/data arrangements approved before affected use.
- [ ] Institutional records assigned; prerequisites/restrictions explicit.
- [ ] Recovery/custody/log-retention/monitoring/response decisions agreed.
- [ ] PITR choice approved and compatible with initial recovery objectives.
- [ ] Dependency review and recurring advisory response assigned.
- [ ] BS4 prerequisites and BS6 configuration/scope handoff references recorded.
- [ ] Remaining staging, Gate R, Gate F and D2 execution evidence stays pending
      until observed in the intended environment.

Preparation reviewer/date and unresolved restrictions: **Pending**.
Record institutional adoption and deployed acceptance separately.

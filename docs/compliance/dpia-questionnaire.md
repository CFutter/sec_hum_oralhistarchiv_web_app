# DPIA questionnaire skeleton

**Template: complete the `<...>` fields in `<restricted-assessment-location>`.**
Record the activity, effects on people and review decisions. The responsible
owner determines the framework, assessment requirement and approval.
Public summaries may contain only reviewed references and minimized synthetic
examples, excluding personal data, secrets, private endpoints, vulnerability
details and consultation records.

## Assessment and screening record

| Field | Complete in the restricted record |
|---|---|
| Assessment identity, version and status | `<assessment-id-version-and-status>` |
| Proposed activity/change and related register entries | `<proposal-change-and-processing-register-references>` |
| Accountable owner, assessment lead and review participants | `<owner-lead-and-reviewer-references>` |
| Applicable framework and assessment criteria | `<framework-and-screening-criteria-reference>` |
| Screening result and reasoned assessment decision | `<required-not-required-or-further-review-decision-and-reasons>` |
| Who may decide and what evidence supports that decision | `<decision-authority-and-evidence-reference>` |
| Decision date, review date and change triggers | `<decision-and-review-dates-and-change-triggers>` |
| Planned operational scope and decision dependencies | `<scope-operating-restrictions-and-dependency-reference>` |
| Restricted record access and retention | `<record-access-owner-and-retention-reference>` |

Consider the actual scale, duration, data sensitivity, linking across systems,
affected people, vulnerability, public disclosure, monitoring, new uses and
consequences of error. Record how the chosen criteria apply in
`<screening-analysis-reference>`. If a full assessment is not required, retain
the reason, responsible decision and review triggers rather than leaving the
remaining questions silently unanswered.

## 1. Describe the activity and its boundaries

Use the [processing-register template](processing-register.md) and
[classification matrix](data-classification.md) as inputs. Describe each
environment and each copy; a diagram of the web application alone will omit
upstream repositories, identity/mail providers, collectors and recovery systems.

| Question | Answer/evidence |
|---|---|
| What purpose and measurable outcome does this activity serve? | `<purpose-and-intended-outcome>` |
| Which activities, environments and changes are included or excluded, and why? | `<scope-boundaries-and-exclusion-reasons>` |
| Which groups of people are affected, including people described in source material? | `<subject-groups-and-vulnerability-assessment>` |
| Which categories may reveal sensitive information through their values or combination? | `<data-category-sensitivity-and-inference-assessment>` |
| Who supplies the data, and what authority/approval supports its use and disclosure? | `<source-collection-and-disclosure-approval-reference>` |
| How much data is processed, for how long and how often? | `<scale-duration-frequency-and-growth-assessment>` |
| Which operations create, enrich, match, search, disclose, export or delete data? | `<processing-step-and-data-flow-reference>` |
| Which parties decide purposes or means and which provide services? | `<party-role-and-responsibility-assessment>` |
| Where can data be stored, transmitted, accessed or restored? | `<location-transfer-and-support-access-reference>` |
| Which external processors, recipients and onward recipients are involved? | `<processor-recipient-and-contract-reference>` |
| What copies survive deletion, withdrawal, expiry or a service shutdown? | `<retained-copy-and-disposal-assessment>` |

Trace catalogue/raw/staged/quarantine data; account/federation attributes;
credentials/recovery/action state; sessions/cookies; queued, in-flight and
delivered mail; Redis/persistence; application/audit/proxy/SP/IdP logs;
transactional security events/receipts; backups/exports/recovery workspaces;
keys/configuration; and build/development/support copies. Record approved
exclusions in `<boundary-applicability-and-evidence-reference>`.

## 2. Necessity, proportionality and alternatives

| Question | Answer/evidence |
|---|---|
| What applicable grounds and additional conditions support each activity and category? | `<framework-grounds-and-condition-review-reference>` |
| Why is each field, identifier, association and copy necessary for the stated purpose? | `<field-and-copy-necessity-assessment>` |
| Can the purpose be met with fewer fields, less precision, shorter retention or fewer recipients? | `<minimization-options-and-decision-reference>` |
| Could a less intrusive design achieve the outcome, and why was it chosen or rejected? | `<alternatives-comparison-and-decision-reference>` |
| How will unrelated reuse, inference and linking be prevented or reviewed? | `<purpose-limitation-and-linkage-control-reference>` |
| Are notices understandable and aligned with the actual processing and source relationship? | `<transparency-and-notice-review-reference>` |
| How are inaccuracies challenged and corrected without overwriting source responsibilities? | `<accuracy-and-correction-procedure-reference>` |
| How can people exercise applicable rights and obtain an accessible response? | `<rights-intake-authority-and-response-procedure-reference>` |
| How are retention, holds/exceptions, disposal and restore reconciliation justified? | `<retention-and-restore-reconciliation-decision-reference>` |
| How are processor, recipient, location and transfer choices justified and checked? | `<recipient-location-and-transfer-assessment-reference>` |

Use the [DSAR procedure](dsar-procedure.md) and
[retention/DSAR supplement](../runbooks/retention-dsar-template.md) for the
request and retained-copy questions. The software's account-delete form is not
a general request workflow or an export function.

## 3. Catalogue and identity disclosure questions

- Does `<source-public-disclosure-review-reference>` approve the seven public
  discovery values (`id`, `uuid`, `title`, `access_level`, `version`, `source`,
  `visibility_tier`) and what their combination can reveal? A restricted
  description does not make a revealing public title safe.
- Does `<field-policy-review-reference>` show that code/source field minima,
  effective record tiers and durable administrator restrictions match the
  intended disclosure? The code's `public` minimum is not approval to publish.
- Does `<search-and-inference-review-reference>` examine public `title` and
  `access_level` search, field-gated matches, filters/facets/counts, result order
  and the consequences of changes or withdrawal?
- Does `<resource-boundary-review-reference>` explain that catalogue permission
  and an audited redirect do not grant access to source-owned recordings? Who
  handles requests and incidents at the external repository?
- Does `<identity-linkage-review-reference>` assess email, institutional subject,
  affiliation/entitlement, approval history and account/security events together?
  Federation proposals require explicit review; they are not automatic grants.
- Does `<privileged-access-review-reference>` distinguish metadata viewer tiers
  from application administration, raw database/scheduler access and backup
  access? An administrator account does not bypass metadata policy.

See [field visibility](../architecture/field-visibility.md),
[resource access](../architecture/resource-access.md) and
[federated proposals](../architecture/federated-tier-rules.md) for the technical
contracts to verify against the deployed configuration.

## 4. Risks to people

Define the assessment's likelihood and impact scales, uncertainty treatment,
acceptance authority and escalation criteria in
`<risk-method-scales-and-escalation-reference>`. Assess harm to people rather
than treating service downtime or reputational cost as its only proxy.
Consider confidentiality, loss of control, misidentification, exclusion,
unwanted inference, discrimination and physical/social/economic consequences
where relevant. The reviewer determines applicable scenarios and significance.

The scenarios below are prompts, not a completed assessment or exhaustive
inventory. Record an evidence-based applicability decision for every prompt and
add risks specific to `<activity-and-context-specific-risk-reference>`.

| Scenario prompt | Risk record |
|---|---|
| Public metadata or a combination of identifiers exposes a person or sensitive subject | `<public-disclosure-risk-record>` |
| Search, counts, filters, ordering or copied output reveals restricted content or permits inference | `<search-and-inference-risk-record>` |
| Raw/staged/quarantined data, logs, exports or backups bypass presentation controls | `<secondary-copy-and-privileged-access-risk-record>` |
| Incorrect metadata, source mappings or administrative restrictions harm a subject | `<accuracy-misidentification-and-restriction-risk-record>` |
| Local/federated identity linking or review mistakes grant access or deny legitimate use | `<identity-linkage-and-eligibility-risk-record>` |
| Credential, session, authenticator or recovery compromise enables unauthorized access | `<credential-session-and-recovery-risk-record>` |
| Mail delivery, support handling or processor access discloses identifiers or action authority | `<mail-support-and-processor-risk-record>` |
| Retention, request handling or restoration reintroduces erased or corrected state | `<retention-request-and-restore-risk-record>` |
| Encryption keys and encrypted data are compromised together or old dependencies are lost | `<key-custody-and-recoverability-risk-record>` |
| Source-owned recordings or downstream recipients are handled outside agreed boundaries | `<external-material-and-recipient-risk-record>` |
| Monitoring, incident containment or security evidence creates an additional disclosure | `<monitoring-and-incident-evidence-risk-record>` |
| Service failure or inaccessible request handling has harmful consequences for people | `<availability-and-accessibility-risk-record>` |

Copy the following record for each identified risk. Do not fill ratings by
assuming a repository test proves the deployed safeguard works.

| Risk field | Complete for this risk |
|---|---|
| Risk identity, owner and related activity/assets | `<risk-id-owner-and-activity-asset-references>` |
| Threat/event, affected people and potential harm | `<event-subjects-and-harm-description>` |
| Preconditions, actors, exposure and uncertainty | `<conditions-actors-exposure-and-uncertainty>` |
| Initial likelihood, impact, rating and reasons | `<initial-likelihood-impact-rating-and-reasons>` |
| Existing safeguards and verified evidence | `<existing-safeguards-and-verification-reference>` |
| Proposed change, alternative and responsible owner | `<mitigation-alternative-and-owner>` |
| Completion target and evidence required before use | `<mitigation-target-and-pre-use-evidence>` |
| Residual likelihood, impact, rating and reasons | `<residual-likelihood-impact-rating-and-reasons>` |
| Remaining uncertainty, dependency and review trigger | `<remaining-uncertainty-dependency-and-review-trigger>` |
| Acceptance/escalation decision and authorized approver | `<decision-approver-date-and-reference>` |

## 5. Safeguards and verification plan

| Control area | Assessment and evidence to complete |
|---|---|
| Collection, disclosure and source authority | `<minimization-and-source-disclosure-approval-evidence>` |
| Tier/field policy, hiding, search and resource actions | `<deployed-authorization-and-negative-test-evidence>` |
| Local/federated identity, review, sessions and request security | `<identity-session-csrf-and-rate-control-evidence>` |
| Least privilege and privileged operator access | `<service-role-and-operator-access-review-evidence>` |
| TOTP/outbox/archive encryption and separated key custody | `<key-custody-rotation-and-recovery-evidence>` |
| Logs, monitoring, processors and edge infrastructure | `<collection-redaction-access-retention-and-transfer-evidence>` |
| Retention, rights handling, withdrawal and restored copies | `<request-disposal-withdrawal-and-restore-reconciliation-evidence>` |
| Build, development, support and non-production copies | `<fixture-data-copy-and-artifact-control-evidence>` |
| Incident management and safe recovery | `<incident-rehearsal-and-recovery-release-evidence>` |

Distinguish design documents, passing application tests, configuration review
and observed deployment evidence. [Key rotation](../runbooks/key-rotation.md)
and [visibility/recovery acceptance](../runbooks/visibility-recovery-acceptance.md)
describe dependencies that cannot be established by a field matrix alone.
Track unresolved controls and operating restrictions through
`<safeguard-action-and-restriction-register-reference>`.

## 6. Consultation and decision

| Decision or consultation | Complete in the restricted record |
|---|---|
| Privacy, security, service-owner and source-owner advice | `<advice-participants-dates-and-outcome-reference>` |
| Consultation with affected people or representatives, or reasons for another approach | `<subject-consultation-decision-and-outcome-reference>` |
| Processor/recipient and external repository coordination | `<external-coordination-and-responsibility-reference>` |
| Need for further authority consultation or review under the applicable framework | `<further-consultation-applicability-and-decision-reference>` |
| Unresolved disagreement and escalation outcome | `<disagreement-and-escalation-record-reference>` |
| Required safeguards completed and residual risks reviewed | `<control-completion-and-residual-risk-review-reference>` |
| Operating decision, conditions, scope and restrictions | `<proceed-restrict-revise-or-stop-decision-and-conditions>` |
| Authorized decision maker, date and evidence | `<authorized-signoff-date-and-evidence-reference>` |
| Communications/public-summary decision and safe publication review | `<communication-and-publication-review-reference>` |
| Next review and triggering events | `<next-review-and-change-trigger-reference>` |

Record the applicable response/consultation timescales and their source in
`<approved-timescale-and-authority-reference>`; this template supplies no fixed
legal deadlines. Do not treat a blank cell, an untested mitigation or the mere
existence of this questionnaire as approval to proceed.

## 7. Review after change or incident

Reassess when purposes, data/categories, source disclosures, scale, field/tier
policy, identity rules, processors, locations, retention, key custody or recovery
design change; also review relevant incidents and newly identified risks.
Use the [incident-response template](incident-response.md) when an event needs
containment or escalation, and record any resulting assessment revision in
`<post-change-or-incident-review-reference>`.

The completed record should identify who verifies each condition, who accepts
residual risk and who can suspend processing. Repository template completion
is separate from that institutional decision and its operating evidence.

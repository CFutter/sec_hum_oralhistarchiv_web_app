# Before-staging handoff and controlled PoC

The first deployment on the intended production host is a controlled synthetic-data
PoC. Use the private [candidate record](staging-candidate-record-template.md) for
scope and retries. Resolve each action's prerequisites before execution; wider
unknown operating decisions may remain pending during preparation.

Keep actual people, contacts, site values, registrations and completed evidence
outside Git. Store credentials/keys through secret custody and record restricted
references only. Public records may retain non-sensitive reference IDs/status.

## Remaining work and timing

| Work | Can be prepared now | Complete privately when available |
|---|---|---|
| BS4.2 retained starting state | Collector, preservation worksheet and review criteria already supplied | Inventory the retained target; review the actual contract, applicable forward changes and recovery before modifying that target |
| BS5.2 operating decisions | Role placeholders, request fields, planned PoC scope and deferred-decision list | Identify the executing operator and resolve the details needed for each deployment action; complete wider institutional/recovery/advisory adoption for its accepted operational scope |
| BS6 candidate qualification | Source/check/artifact/configuration fields, release procedure and acceptance checklist | Select the actual commit, run required checks, build/verify an immutable artifact, record private configuration and results |

Repository handoff preparation, a qualified artifact and accepted deployment are
separate states. Unresolved fields are **Deferred to deployment** or **Pending
verification**, never a pass. Wider BS5 decisions do not block this draft handoff.
At execution, resolve prerequisites for the selected PoC activity before that
activity. Gate R, Gate F, Source B D2 and later full production acceptance remain
separate; mock catalogue data and green repository checks do not close them.

## Classify the target before selecting a procedure

Choose and record the actual target, configuration mode and data boundary:

- **New disposable PoC:** use additional, explicitly disposable infrastructure
  with synthetic records and controlled accounts. Record the permitted reseed,
  retry and cleanup boundary. This is a fresh-install proof, not retained-upgrade
  acceptance. Keep required access/configuration/key recovery separately scoped.
- **Existing retained staging:** follow the [BS4 inventory procedure](retained-staging-inventory.md).
  Preserve its catalogue/accounts, durable controls and source progress. Prepare
  the compatible upgrade and pre-change recovery point before changing it.
- **Retained production:** freeze the baseline; subsequent schema changes need
  reviewed Alembic revisions and rehearsed upgrades. Do not classify a database
  disposable solely because its catalogue currently contains mock records.

No generic reset, stamp, downgrade or recreate command is supplied here. The
existing staging target remains retained unless its approved disposition says
otherwise. One source/configuration choice does not clear old records or withdraw
their public discovery. See the [source/data decisions](external-dependencies-and-decisions.md#approve-data-use-before-access-becomes-ingestion).

## Qualify the artifact using the existing release path

Follow the [deployment overview](../configuration/deployment.md) and the root
`Deployment.md` release/install/maintenance procedures. The existing manual path
is GitHub Actions → CI → Run workflow on `main`. Its release job depends on the
required checks and builds the exact `GITHUB_SHA`. A source archive or a local
Git inventory used for scans does not supply that remote provenance.

Record the tested source commit, required check/run references, dependency
dispositions, collection/coverage measurements, source and lock identity, package
version, artifact ZIP identity/digest and independent approval reference. Build
and promote that artifact. A later executable/dependency/schema/packaging change
creates a new candidate requiring the applicable checks again.

Record release label, wheel version and source SHA separately. The workflow has
no version/tag input; a label does not change wheel metadata. Review/test metadata
changes before building the candidate.

The release manifest covers generic payload/dependency inputs, not the private
runtime configuration. Keep an independent restricted configuration/version
inventory for web, scheduler, migration, backup, source selection and edge units.
Record both identities together for each attempt.
Record the Actions artifact ZIP digest separately from the inner release-tarball
digest in `ARTIFACT.txt`. A workflow rerun has a new artifact identity to verify;
neither digest is replaced by the source SHA.

The existing installer verifies package hashes/manifest consistency; establish
approved CI provenance and the independent ZIP digest before invoking it. It
needs the documented root/Python 3.11/lock/stopped-unit prerequisites and package
source access for the pinned runtime dependencies; this bundle is not an offline
wheelhouse. It refuses replacement of an active same-SHA release. Follow the
reviewed installer rather than treating another invocation as a clean reset.

## Resolve PoC execution details at deployment

These values may remain placeholders during repository preparation. Fill and
verify them privately before the affected services/actions run; this handoff
does not weaken the existing startup or deployment checks.

| Execution boundary | Private decision/result needed at that point |
|---|---|
| Operator and custody | Executing deployment role, approved contact/escalation route and custody for supplied secrets/configuration; personal assignments stay private |
| Environment and ingress | Deliberate `ENV_STATE=staging` or `production`, HTTPS origin/allowed hosts, secure cookies, controlled ingress and separate test-service resources |
| Secrets and identities | Deployment-specific application/health keys; separate web/scheduler/migration/backup OS/DB authority, peer/grant/socket boundaries and dedicated limiter Redis |
| Fixture selection | Same reviewed protected `SOURCES_CONFIG_FILE` for web and scheduler; synthetic sources selected explicitly; scheduler performs ingestion |
| Production-mode fixtures | If the chosen production-mode source uses fixtures/static JSON, explicitly review `ALLOW_FIXTURE_SOURCE=true` for this PoC; it permits fixtures but does not select, seed, reset or approve any real source |
| Closed features | Explicit `LOCAL_REGISTRATION_ENABLED=false` initially; federation closed until its controlled procedure permits activation; no real Source B activation inferred |
| SMTP and retained mail | Hardened modes require enabled SMTP with TLS and valid host/from/authentication settings; approved sandbox/relay containment, forwarding and pending/sending outbox handling before scheduler startup |
| Data/recovery boundary | New disposable versus retained target, controlled identities/logs, authorized preservation/reseed and retry scope, isolation of mail/feed/login side effects and recovery needed before any retained change |

An SMTP provider or Shibboleth registration can be unknown now. Registration
closure does not suppress existing queued or account-action mail, and the app
does not rewrite recipients for staging. Resolve containment when enabling the
relevant delivery/service path. If federation remains closed, no live Gate F
claim is made; request/registration and later canary acceptance stay private.

The larger institutional records, recovery objectives/PITR adoption, monitoring
and advisory responsibilities remain in the [BS5 decision record](external-dependencies-record-template.md).
Their detailed completion can accompany deployment as authorized by the
maintainer. Record the PoC's accepted limits and revisit them before extending
access, introducing real source data or claiming the wider operational capability.
Do not claim verified backups/PITR, achieved recovery objectives or completed
incident arrangements on the strength of a blank template.

## Run, observe and repeat with a record

Use the existing installation/maintenance procedures and the root `Deployment.md`
section 16 checklist. Record applicable native-service/role/peer/socket/TLS/Redis,
source freshness, browser and logging results. Carry existing admission-policy
or other unresolved checklist items forward; green repository tests do not
resolve a deployed checklist exception. Use synthetic identities/captures.

Record each attempt separately: artifact/configuration/data-state identities,
target classification, planned action, observations, failures, correction and
next decision. Reusing an artifact with a changed private configuration is a
different observed attempt. Code/schema/dependency changes return through
candidate checks/build; a retry does not authorize discarding retained state.

Use the [BS4 record](retained-staging-record-template.md) for retained-state
comparisons, [visibility/recovery acceptance](visibility-recovery-acceptance.md)
for controlled recovery, [action-link acceptance](action-links.md) for mail and
[federation integration](federation-integration.md) for any later SP activation.
Keep the completed results private and publish only generic corrections to the
application repository.

## Acceptance states

- **Prepared:** generic handoff/templates and applicable repository checks ready;
  deployment placeholders may remain unresolved.
- **Candidate qualified:** actual tested source/artifact identified and verified,
  with private configuration scope and prerequisites recorded for the intended
  action. A placeholder digest or unknown retained-start upgrade is not executable
  qualification for that action.
- **PoC observed:** the recorded synthetic scope was executed with its results
  and limits; retries/issues remain visible.
- **Operationally accepted:** the applicable retained-state, real-service/data,
  institutional, recovery and live integration evidence is accepted separately.

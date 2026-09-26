# Project Roadmap — Digital Oral History Archive

This roadmap lists remaining work. Implementation is not evidence that deployment acceptance has passed; follow test_plan.md and Deployment.md.


## Current implementation

Source A ingestion, tier-filtered metadata, local authentication, TOTP recovery,
federation application policy, transactional email and deployment tooling are
implemented. See README.md for features, docs/architecture/ for contracts, and
Deployment.md for installation. Source B is not implemented.

Release acceptance remains environment-specific. Collect tests with
`pytest --collect-only -q`; run the service-backed suite on disposable databases
and Redis. REQUIRE_DB=1 and REQUIRE_REDIS=1 make unavailable required services
fail. Test-function counts are not collected-case counts.

## Phase 2 — Sensitive Data, Federation & Production Operations

**Status: ⬜ Planned**

Phase 2 takes the prototype to a system that can hold sensitive Source B data, authenticate federated users, and run with production-grade operations and compliance.

### Source B integration

| Item | Status | Notes |
|------|--------|-------|
| Source B client module | ⬜ Planned | Dedicated authenticated parser/adapter enforcing the [mandatory tier contract](docs/architecture/source-b-ingestion-contract.md), then shared low-level persistence; distinct `source` tag |
| Source B branches in `run_sync()` / `run_full_rebuild()` | ⬜ Planned | Future `_sync_source_b()` / `_full_rebuild_source_b()` orchestration boundary is marked in comments; no stub implementation exists today |
| Source B data-sharing agreement | ⬜ Planned | DPIA precondition |
| Ethics board approval (if applicable) | ⬜ Planned | Depends on Source B data |
| Download-link provisioning + per-access logging for Source B | ⬜ Planned | Builds on the existing download/audit hooks |

### Federated authentication (Shibboleth deployment)

| Item | Status | Notes |
|------|--------|-------|
| nginx Shibboleth SP deployment (shibd + FastCGI via the nginx-http-shibboleth module) | ⬜ Planned | Application callback already implemented; this is the edge plumbing |
| SWITCH AAI / eduGAIN registration | ⬜ Planned | Federation metadata, attribute release |
| Attribute-based tier assignment | ⬜ Planned | Map affiliation/entitlement to `access_tier` |
| REFEDS MFA deployment | ⬜ Planned | The application already requires the fixed MFA context; verify the SP/IdP assertion and edge mapping |

### Account and security follow-ups

| Item | Status | Notes |
|------|--------|-------|
| Unverified email reservation and federation | ⬜ Planned | Let a legitimate federated identity claim an address reserved by an unverified local signup; do not transfer attacker-selected credentials or merge verified accounts by email alone |
| Registration verification safety | ⬜ Planned | Prove mailbox ownership before password setup so following a verification link cannot activate an attacker-selected password |
| Account deletion | ⬜ Planned | Add authenticated self-service deletion and audited administrator removal; revoke sessions, factors and tokens and honor the retention policy |
| Capability tokens in edge error logs | ⬜ Planned | Keep reset, verification and email-change tokens out of URL paths that can be logged by the app or nginx |
| Flash message for totp reset | ⬜ Planned | Small change: Flash message for totp reset should be green on success|

**Release gate:** Do not expose local registration to untrusted users until the registration verification change is complete, even before federation deployment. Record the implementation and acceptance tests before opening registration.

### Field-level visibility & RLS

| Item | Status | Notes |
|------|--------|-------|
| Per-field visibility matrix | ⬜ Planned | Replace all-or-nothing `filter_for_tier` with per-field minimum tiers |
| PostgreSQL Row-Level Security | ⬜ Planned | Defense-in-depth so direct SQL cannot bypass tier rules |
| Admin dataset visibility controls | ⬜ Planned | Add an admin UI to set public, registered, or vetted, no less restrictive than the source classification and policy, and to hide or restore an entire dataset. Hidden records must expose no metadata, titles, identifiers, listings, search results, facets, counts, or direct detail pages to any viewer tier; retain admin-only management. Audit changes and preserve classification and hiding decisions across incremental harvests, full rebuilds, and removal/reintroduction of the same source UUID. |

### Compliance (FADP / GDPR)

| Item | Status | Notes |
|------|--------|-------|
| Data processing register | ⬜ Planned | |
| DPIA review with the Data Protection Advisor | ⬜ Planned | |
| Data classification matrix + asset inventory | ⬜ Planned | |
| Incident response procedure | ⬜ Planned | |
| Data subject access request procedures | ⬜ Planned | |
| Immutable audit trail via external log shipping | ⬜ Planned | rsyslog agent over RELP/TLS (deploy/rsyslog-…conf.example); host-level, not in-app |

> The compliance documents are not yet written. Earlier drafts and an ISO 27001 / LeoMed questionnaire mapping were produced for a previous prototype iteration and are **not** part of this repository.

### Operational hardening

| Item | Status | Notes |
|------|--------|-------|
| CI quality gates | ✅ | `.github/workflows/ci.yml` — `ruff`, `mypy`, `bandit`, `pip-audit` (locked deps), `pytest` vs PostgreSQL + Redis service containers with `REQUIRE_DB=1`/`REQUIRE_REDIS=1` and a coverage gate. See Deployment.md §15 |
| Automated deployment (push-to-deploy) | ⬜ Planned | Deployment is deliberately manual — see Deployment.md §15 for why (avoids passwordless sudo for a deploy user) |
| Log monitoring and alerting | ⬜ Planned | Alert on health-check failure and recorded sync errors |
| Encrypted logical-backup tooling | ✅ | Dedicated read-only identity, root-owned systemd timer, direct `pg_dump`→`age` streaming, atomic encrypted publication, format verifier, and explicit isolated-restore procedure; host custody/monitoring/restore evidence remain deployment acceptance checks |
| Point-in-time recovery | ⬜ Planned | Define WAL archiving, its independently encrypted off-host retention, recovery-point objective and tested replay procedure; this is separate from the shipped logical-backup path |

### Performance & scalability

| Item | Status | Notes |
|------|--------|-------|
| Full-text search (`tsvector`) | ⬜ Planned | Replace ILIKE substring matching; not urgent at current scale |
| Cursor-based pagination | ⬜ Planned | Replace OFFSET; only matters at scale |
| Robust `access_level` classification | ⬜ Planned | Replace the license-string `startswith` heuristic with an explicit mapping |

### Dependency maintenance

Run the locked dependency audit in CI and review findings against the deployed
lockfile. This roadmap is not a current advisory database.

### Secret custody

Production already uses passwordless PostgreSQL peer mappings and separate
common, web, scheduler and migration environment files. TOTP and outbox rings
are independent of SECRET_KEY; see docs/runbooks/key-rotation.md for effects.

Potential work: introduce a reviewed credential-provider integration for
signing/encryption keys and SMTP credentials. Settings currently reads environment
values, not systemd credential files. Separating files does not protect secrets
from code execution in a process authorized to read them.

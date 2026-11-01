# Project roadmap

Current behavior is documented in [README](README.md) and the
[architecture](docs/architecture/overview.md). This page lists remaining work;
application implementation does not establish deployed acceptance.

| Work | Required outcome |
|---|---|
| Real sensitive sources | Owner approval of public discovery, actual-feed acceptance and representative encrypted restore; [source contract](docs/architecture/source-b-ingestion-contract.md) |
| Federation | Installed SP/IdP, trusted attribute/MFA release, socket isolation, controlled activation and rollback; [integration](docs/runbooks/federation-integration.md) |
| Public registration | Real relay/mailbox acceptance before enabling sign-ups; [Gate R](docs/configuration/deployment.md#registration-activation-gate-r) |
| Retained deployment | Inventory, reviewed compatible transition, preserved state and verified recovery; [inventory](docs/runbooks/retained-staging-inventory.md) |
| Metadata controls | Browser/operator rehearsal of dataset hide/restore; [withdrawal](docs/runbooks/emergency-dataset-withdrawal.md) |
| Search | Representative workload, query-plan and concurrency measurements; [search](docs/runbooks/search-fulltext.md) |
| Operations | Activate monitoring, independent log/event delivery, custody and restore checks; adopt a separately reviewed physical-backup/WAL pipeline if PITR is required |
| Governance | Complete and approve restricted processing, risk, request, retention and incident records; [register](docs/compliance/processing-register.md) |
| Release evidence | Exact reviewed source/artifact, required CI/docs/scan results and remaining interface evidence; [candidate record](docs/runbooks/staging-candidate-record-template.md) |
| Static JSON proof | Complete the deferred isolated baseline/candidate diff proof |
| Publication | Resolve legal/metadata/configuration and defect dispositions, then curate the public release |

Run the locked dependency advisory checks and review findings against the deployed
lock. Do not use historical test counts or advisory results as current evidence.

Potential extensions are automatic opt-in federation approval and a reviewed
credential-provider integration. Current rules only propose tiers, and Settings
reads environment values rather than systemd credential files. File separation
does not protect secrets from code executing as an authorized reader.

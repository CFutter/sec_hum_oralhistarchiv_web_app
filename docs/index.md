# Oral History Archive Documentation

User, developer, and operator documentation for the Digital Oral History Archive.

## Start here

| Task | Documentation |
|---|---|
| Review accepted work and remaining deployment gates | [Project status](project-status.md) |
| Browse datasets and manage an account | [User Guide](user-guide/overview.md) |
| Extend the application | [Architecture](architecture/overview.md), [Code Reference](reference/main.md) |
| Understand resource links and their audit evidence | [Resource access and audit](architecture/resource-access.md) |
| Configure and deploy | [Settings](configuration/settings.md), [Deployment](configuration/deployment.md) |
| Operate the service | [Logging & Audit](configuration/logging.md), [Key Rotation](runbooks/key-rotation.md) |

## Project scope

The application ingests explicitly configured OAI-PMH/CMDI, authenticated JSON
feeds, fixtures or static JSON proof sources into PostgreSQL and serves Jinja2
pages with tier-based metadata redaction.

The authenticated [JSON-feed adapter](sources/json-feed-adapter.md) is implemented
and selectable at runtime. [Feed Contract v1](sources/feed-contract-v1.md),
[configuration](sources/json-feed-configuration.md),
[transport](sources/json-feed-transport.md), [page validation](sources/json-feed-pages.md)
and [record validation](sources/json-feed-records.md) define its bounded signed-input
contract. Persistence, auditing, catalogue behavior and synthetic encrypted
recovery have application acceptance coverage in the
[feed evidence record](sources/json-feed-acceptance.md).


# Oral History Archive Documentation

User, developer, and operator documentation for the Digital Oral History Archive.

## Start here

| Task | Documentation |
|---|---|
| Browse datasets and manage an account | [User Guide](user-guide/overview.md) |
| Extend the application | [Architecture](architecture/overview.md), [Code Reference](reference/main.md) |
| Configure and deploy | [Settings](configuration/settings.md), [Deployment](configuration/deployment.md) |
| Operate the service | [Logging & Audit](configuration/logging.md), [Key Rotation](runbooks/key-rotation.md) |



## Project scope

The application harvests SWISSUbase OAI-PMH metadata into PostgreSQL and serves Jinja2 pages with tier-based metadata redaction. Source B ingestion is unimplemented; its [acceptance contract](architecture/source-b-ingestion-contract.md) defines the additional requirements for sensitive sources.

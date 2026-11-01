# Data classification

This table classifies every public `Dataset` field against `FIELD_VISIBILITY`.
The [processing register](processing-register.md),
[DPIA questionnaire](dpia-questionnaire.md), [request procedure](dsar-procedure.md)
and [incident procedure](incident-response.md) are templates requiring
institutional completion and approval; none authorizes disclosure.

## How to read the classification

A `public` code minimum is an additional floor, not authorization to disclose a
field. For a protected field, access requires the strictest of its code minimum,
configured source field minimum and effective record tier. The effective record
tier includes durable administrator restrictions; source configuration can only
tighten field minima. A hidden identity disappears from catalogue discovery at
every metadata tier. The separately guarded administrator identity/state view
does not grant access to its metadata.

The seven approved public discovery fields remain exempt from the record floor.
Only `title` and `access_level` contribute to ungated public search. Source owners
must approve public values and their combination; a structural field table does
not certify that approval.

The three resource-target fields can represent the same destination and must
share their merged minimum. Their classification does not authorize a download:
resource actions still require full-record permission, safe stored targets and
the existing audited redirect policy. The originating repository controls access
to its recordings and other materials.

## Catalogue field classification

The code contract is the source of truth. Update this table with any change to
the model, minima or field groups; the documentation contract test rejects
missing, duplicated, unknown or differently classified rows.

<!-- DATASET_FIELD_CLASSIFICATION_START -->
| Field | Code minimum | Public discovery | Public search | Resource target group |
|---|---|---|---|---|
| `id` | `public` | Yes | No | No |
| `uuid` | `public` | Yes | No | No |
| `title` | `public` | Yes | Yes | No |
| `project_title` | `public` | No | No | No |
| `description` | `public` | No | No | No |
| `resource_description` | `public` | No | No | No |
| `languages` | `public` | No | No | No |
| `project_description` | `public` | No | No | No |
| `authors` | `public` | No | No | No |
| `keywords` | `public` | No | No | No |
| `resource_proxies` | `public` | No | No | Yes |
| `resource_access_url` | `public` | No | No | Yes |
| `landing_page_url` | `public` | No | No | Yes |
| `license_val` | `public` | No | No | No |
| `license_url` | `public` | No | No | No |
| `access_level` | `public` | Yes | Yes | No |
| `version` | `public` | Yes | No | No |
| `doi` | `public` | No | No | No |
| `resource_type` | `public` | No | No | No |
| `bibliographical_citation` | `public` | No | No | No |
| `source` | `public` | Yes | No | No |
| `visibility_tier` | `public` | Yes | No | No |
<!-- DATASET_FIELD_CLASSIFICATION_END -->

See [Field visibility](../architecture/field-visibility.md) for effective minima,
source scope and rendering, [Access control and visibility](../architecture/access-control.md)
for authorization boundaries, and the
[Sensitive Source Contract](../architecture/source-b-ingestion-contract.md) for
source-owner disclosure responsibilities. Operational identity, custody and
representative restore evidence remain in the
[visibility/recovery acceptance record](../runbooks/visibility-recovery-acceptance.md).

# Page Routes

`GET /`, `/search` and `/dataset/{dataset_id}` pass the viewer tier and catalogue policy to dataset services and render redacted results. `GET /about` shows configured sources and public synchronization badges. Nonpublic detail views emit `dataset_access`, including redacted views. Numbered search pages run from 1 to 100; opaque cursors continue beyond them. Filters persist through navigation.

Dataset details resolve `SourceDisplay` from the web process's retained
configured sources. Full metadata includes the configured source label.
Resource and landing actions use that source's display labels, with the
resource URL taking precedence.

Retained records whose source is no longer configured use their persistent
source identity and generic action labels. Their stored visibility tier still
controls metadata access. Labels are HTML-escaped, and external URLs retain
the `safe_url` filter.

For the visibility filtering logic see [Architecture → Access Control & Visibility](../../architecture/access-control.md).

About preserves configuration order and excludes unconfigured stored identities.
Its public projection contains only source identity, display label, sensitivity
description and a finite status. Active requires both successful-operation
timestamps to be no older than twice their respective configured intervals,
with no recorded error. Clean incomplete history is Awaiting sync; an error
or stale completed operation is Needs attention. Status describes recorded
synchronization history rather than current upstream reachability. Diagnostic
messages remain in authorized health diagnostics. Database failures use the
existing application error handling, including controlled 503 responses for
pool capacity failures.

`GET /dataset/{dataset_id}/resource/{proxy_index}` re-reads the current
catalogue record and redirects with `303` only when the viewer can see its full
metadata and the original stored proxy index selects a safe Resource or
LandingPage URL. Missing, hidden, below-tier or invalid targets receive a
cloaked `404` without a resource-access event. Successful redirects emit one
`resource_access` event; administrator status does not raise metadata tier.
For sources with `log_resource_access=true`, detail actions expose internal
links without the raw resource/landing target. Unknown or unselected retained
sources use the same conservative behavior. See
[Resource access and audit](../../architecture/resource-access.md).

::: app.routes.pages

# JSON-feed configuration

Feed descriptions are strict and nonsecret. Prepare credentials explicitly
before constructing the [adapter](json-feed-adapter.md).

The runnable registry contains `oai_pmh_cmdi`, `fixture`, `static_json` and
`json_feed`. Scheduler feed construction requires prepared credentials; scheduler startup
validates all selected feed secrets before any adapter factory. This structural
example is not a real-source activation decision. The shipped development TOML
continues to select only its existing fixture.

## Describe a feed

The flat TOML format uses ordinary nonsecret source fields plus environment
references. Never put credential values in TOML, URLs, labels or diagnostics.

```toml
[[sources]]
name = "history_feed"
adapter = "json_feed"
label = "Reviewed history catalogue"
resource_link_label = "Open resource"
landing_link_label = "View source record"
sensitivity_badge = "Restricted metadata"
endpoint = "https://feed.example.org/v1/catalogue"
credential_env = "HISTORY_FEED_BEARER"
signing_key_env = "HISTORY_FEED_SIGNING_KEY"
max_visibility = "registered"
requires_record_tier = true
max_project_title_chars = 4096
incremental_interval_seconds = 3600
rebuild_interval_seconds = 86400
write_timeout_seconds = 120
max_page_bytes = 1048576
max_total_bytes = 8388608
max_record_bytes = 65536
max_records = 10000
max_pages = 100
max_result_bytes = 16777216
fetch_deadline_seconds = 120
```

`JsonFeedConfig` is frozen and strict: unknown fields, coercible strings and
boolean values for integer budgets are rejected. All seven budgets must be
positive and cannot exceed the [v1 profile caps](feed-contract-v1.md#resource-budgets)
shown above; omitted budgets use those caps. `requires_record_tier=false` is
refused. The ordinary source name, display, schedule and visibility rules apply.
These checks validate configuration. [B3 transport](json-feed-transport.md)
enforces page, aggregate-byte, page-count and deadline budgets. B4 also enforces
original record-byte and record/withdrawal-count limits. B5 enforces the actual
serialized-result limit. B6 runs complete source fetching/validation/serialization
inside one terminating worker; bounded parent reconstruction checks that deadline.

`max_project_title_chars` defaults to 4,096 and accepts integers from 1 to 16,384.
Increase it only for a reviewed source requirement. Identifiable records above
the selected character cap are quarantined as `record_metadata`; valid neighbours
continue. Byte budgets still apply. This is an interpretation setting, so changing
it changes the source fingerprint and requires authoritative rebuild.

HTTPS is required in every environment. The endpoint is fixed, absolute and
credential-free, without query, fragment, whitespace or backslashes. Validation
performs no DNS lookup. Preparation additionally rejects placeholder hosts in
staging and production; this example's `example.org` host is therefore unsuitable
there. It does not follow redirects, connect to the endpoint or validate a feed.

## Prepare an explicit secret snapshot

Import the public API from `app.sources`. Parsing creates descriptions without
constructing adapters, reading files, accessing process environment variables or
importing global application settings. Preparation uses only its supplied mapping:

```python
from app.sources import (
    JsonFeedConfig,
    parse_source_configs_from_toml,
    prepare_json_feed_startup,
)

descriptions = parse_source_configs_from_toml(toml_text)
feeds = tuple(item for item in descriptions if isinstance(item, JsonFeedConfig))
credentials = prepare_json_feed_startup(
    feeds,
    environment="dev",
    environ={
        "HISTORY_FEED_BEARER": bearer_from_secret_store,
        "HISTORY_FEED_SIGNING_KEY": signing_key_from_secret_store,
    },
)
```

`toml_text` and the two secret values above are caller-supplied strings.
Preparation revalidates every description and reference before reading secrets.
It returns ordered, immutable `JsonFeedCredentials` snapshots with `source_name`,
`bearer_token` (`SecretStr`) and decoded `signing_key` (`SecretBytes`). Secret fields
are excluded from the snapshot representation. Missing or invalid credentials
produce fixed messages without their values. Do not unwrap secrets for logging.
Changing the supplied mapping later does not change an existing snapshot; prepare
a new snapshot when rotating credentials. No automatic `.env` lookup occurs.

Environment references use 1–128 uppercase ASCII letters, digits or underscores,
with a letter or underscore first. Bearer and signing roles require separate
references. A bearer is 43–256 characters in RFC 6750 bearer-token syntax and must
pass the shared secret-strength checks. A signing key is the canonical unpadded
base64url encoding of exactly 32 random bytes: precisely 43 characters, with
round-trip validation and the same strength checks. Generate independent values
with a cryptographically secure generator; passing checks does not prove randomness.

Signing-key references and decoded keys must be distinct for every feed. A key
cannot reuse bearer material, including base64 padding or alphabet aliases, or
use a reference used by any feed's bearer. Bearers may be shared where the same
upstream account authorizes multiple feeds. Use separate keys per environment.

Preparation alone does not activate a source or replace the hardened source-file
gate. Pass its snapshots explicitly to construction, or supply `environ` to the
[B6 runtime loader](json-feed-adapter.md); omitted `environ` means an empty mapping.
Scheduler runtime loading deliberately passes `os.environ`. Web startup uses
`load_runtime_catalogue_sources()` instead: it validates the same nonsecret TOML,
file ownership, endpoints and credential-reference separation, then constructs
only immutable catalogue metadata and pure policy. It resolves no secret and
retains no fetch adapter. The catalogue policy fingerprint is identical for the
same source descriptions in either process.

Supply feed bearer and signing-key values only to the scheduler environment
(`scheduler.env` in the reference deployment). Remove those names from
`common.env`, `web.env` and inherited web-service overrides; the web refuses to
start if any selected feed credential variable is present, including an empty
one. Both processes still read the same nonsecret source TOML. Restart both after
changing that description; value-only credential rotation requires restarting
the scheduler.

Credential-reference
names enter the interpretation fingerprint, while resolved values do not:
same-reference value rotation needs restart without rebuild; changing a reference
requires authoritative rebuild. The [wire schema](feed-contract-v1.schema.json)
and synthetic examples are unchanged. Real-source activation still needs the
[Sensitive Source Contract](../architecture/source-b-ingestion-contract.md) evidence.

# Health Endpoints

`GET /health` returns `200 {"status": "alive"}` without querying dependencies. It is exempt from the application rate limiter; the supplied nginx deployment applies a separate probe limit.

`GET /health/detail` requires an exact `Bearer HEALTH_DETAIL_TOKEN` unless `FASTAPI_DEBUG` is true. Missing/invalid/unconfigured credentials return 404 in every non-debug environment. Restrict the endpoint at nginx if desired; see the supplied configuration.

| Status | HTTP | Meaning |
|---|---|---|
| `healthy` | 200 | Database reachable; successful harvest/rebuild within twice their configured intervals; no recorded errors or outbox degradation |
| `degraded` | 200 | Database reachable, but missing/stale/failed sync/rebuild state or degraded/unavailable outbox diagnostics |
| `unhealthy` | 503 | Database/pool connection failure, including failure after the initial probe |

Statement cancellation/diagnostic SQL failure after a successful probe is degraded rather than unhealthy. Inspect the JSON `status` and `checks`, not HTTP alone. No connection-pool internals are returned.

Source diagnostics are grouped under `checks.sources.<name>`, in configuration
order. Each source reports its own `status`, numeric `harvest_age_seconds` and
`rebuild_age_seconds` (null when unavailable), and the applicable harvest,
rebuild, staleness and error fields. Staleness uses twice that source's own
configured interval. Missing or unreadable state degrades the affected source;
with the database reachable, any degraded source degrades the overall response.

Only configured source identities are queried. Database and outbox diagnostics
remain global under `checks.database` and `checks.outbox`. Source-specific
fields previously at the root of `checks` now belong to their source object.

Outbox diagnostics include live pending/sending ages, overdue retention, and recent terminal delivery/body-decryption failures. `counts_capped_at=1000` means a count of 1,000 is a lower bound; ages remain exact. The 24-hour failure window is an alert window, not proof older failures were repaired. Ordinary cancellation/supersession/unused-token expiry is not delivery failure; expiry after a failed delivery attempt is.

::: app.routes.health


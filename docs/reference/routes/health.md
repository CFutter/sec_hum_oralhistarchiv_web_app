# Health Endpoints

Two endpoints with very different audiences.

`GET /health` is public, rate-limit exempt, and safe to expose externally. It is a pure **liveness** probe: it always returns `200` with `{"status": "alive"}` and performs **no dependency checks** — no database query, nothing that could turn a database hiccup into a flapping load balancer. It answers exactly one question: is the process up and serving requests? It is what an external uptime monitor or load balancer should poll. For dependency health, use the detail endpoint.

`GET /health/detail` is for internal diagnostics. It returns a `checks` object with database connectivity and the sync status read from the `sync_status` table (the last harvest timestamp, plus the most recent sync error and its timestamp if one is set). It does not expose connection-pool internals or scheduler state. The overall `status` is one of three values: `healthy` (everything fine), `degraded` (database reachable, but a sync error is recorded or the sync check itself failed — still HTTP `200`, since the web app is serving), or `unhealthy` (database unreachable — HTTP `503`). The 503 is reserved for the database case because that is the only condition under which the web application itself cannot do its job.

In production it requires a `Bearer` token matching `HEALTH_DETAIL_TOKEN`, compared in constant time. On any failed authorization — missing token, wrong token, or no token configured — the endpoint returns 404, a fail-secure default that also avoids revealing the endpoint exists. In debug mode it is open without a token.

Restricting `/health/detail` to internal IP ranges at the nginx layer is a sensible extra hardening on top of the bearer-token check — a commented snippet ships in `deploy/nginx.conf.example`; uncomment it and set your monitoring ranges if your network layout allows.

::: app.routes.health

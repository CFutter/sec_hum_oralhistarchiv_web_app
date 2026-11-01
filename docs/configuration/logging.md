# Logging & Audit

Application and audit loggers write to stdout. Audit events support request and security review; their completeness and retention depend on application coverage and host configuration.

Both streams go to stdout, captured by systemd-journald in production. journald handles rotation and retention.

Text application output escapes line breaks, terminal escapes and Unicode
control/direction characters after formatting the complete event, including
exception and stack output. Each event therefore occupies one physical line.
JSON remains the default, and the audit channel always uses JSON.

Dataset restriction mutations also append durable evidence in their database
transaction. This is separate from the local log stream: see the
[security event delivery runbook](../runbooks/security-event-delivery.md) for
independently acknowledged HTTPS export, retries, access control and retention.

## The two streams

| | Application | Audit |
|---|---|---|
| Logger | Module name | `audit` |
| Format | `LOG_FORMAT=json` selects JSON; other values select text | Always JSON |
| Minimum level | `LOG_LEVEL` | INFO |
| Content | Operational events | Audited requests and explicit security events |
| Destination | stdout | stdout, without root propagation |

`setup_logging()` replaces existing root/audit handlers. Both channels redact configured secret values and recognized runtime-secret shapes. Application output redacts email-pattern matches; audit filtering first converts matching address values to keyed markers, or redacts them before a hasher is registered. Matching is heuristic; never intentionally log credentials or private content. Host forwarding can include both streams.

The deployed `SafeUvicornWorker` routes Gunicorn/Uvicorn error records through
the same root pipeline. Before application import, a settings-independent JSON
formatter reports exception type and bounded file/function/line frames, omitting
messages, arguments and source text. Configuration/worker failures are replaced
with a categorical error because Gunicorn also prints their text directly to
stderr. Lifespan failure messages are categorical; the original exception is
recorded separately through the safe formatter. No server error records are
dropped. Bootstrap diagnostics use stderr; normal application diagnostics use
stdout. The Gunicorn master retains its normal lifecycle logger.

## Why stdout instead of files?

The application leaves collection, rotation, retention, and forwarding to systemd-journald and the host agent. It does not coordinate shared file rotation. Python StreamHandler has no cross-process atomic-write guarantee; verify collected records under the deployed worker configuration.

## OAI worker logging

OAI harvesting runs in a spawned child that explicitly initializes its handlers
from the parent's `LOG_LEVEL` and `LOG_FORMAT`. Its application records include
the configured source identity as `source` and the child process ID as
`worker_pid`. JSON carries these as structured fields; text includes both before
the message. Audit output stays JSON at INFO and carries the same context.
The source identity is a validated lowercase source name, never an endpoint or
credential. Parent handlers are not modified by worker initialization.

## Audit log fields

Per-request records include UTC timestamp, logger/level/message, source module/function/line, `request_id`, `event_type`, client IP, method, safe path, scrubbed query structure, status, elapsed milliseconds, and resolved user ID or null. The 16-hex request ID is attached to request state and returned responses as `X-Request-ID`; requests rejected before this middleware may have neither.

Status below 400 logs INFO, 4xx WARNING, and 5xx ERROR. Exact `/health` and `/static/` paths skip statuses below 400, including redirects; `/health/detail` and errors remain audited. Escaping Exceptions log `request_error` with status 500 and are re-raised. Elapsed time ends when downstream returns a response, before streaming completes.

CSRF origin refusals additionally emit `CSRF origin validation failed` through
`app.middleware.csrf`, with the same `request_id`, a safe route path and a fixed
`reason`: `missing_origin`, `ambiguous_origin_headers` or `origin_mismatch`.
This distinguishes an origin refusal from a missing or mismatched token while
keeping the browser-facing 403 generic. Raw Origin/Referer headers, form bodies,
cookie values and token values are not included in these diagnostics.

Client IP uses the trusted-proxy policy in `request_utils.py`; safe deployment of Unix-socket attribution requires the filesystem boundary in [Deployment](../configuration/deployment.md). The legacy `dataset_access` event remains for nonpublic detail views. Bounded `metadata_disclosure` events additionally describe protected fields rendered by home/search cards, detail views and resource responses, including public-tier records with stricter field minima. They contain record identities, field names and outcomes, without field values or search text. Facet suggestions retain viewer-specific permissions and emit contributor identity/field events for the protected options actually rendered; option values are omitted. Read events describe the server response and remain best-effort local records; they cannot prove that a browser displayed it.

## Rotation and retention

Configure journald on the host, for example in `/etc/systemd/journald.conf.d/oralhistarchiv.conf`:

```ini
[Journal]
SystemMaxUse=2G
SystemMaxFileSize=128M
MaxRetentionSec=30day
```

Apply with `sudo systemctl restart systemd-journald`. Application and audit events share the journal quota; 30 days is an upper retention limit, not a guarantee when storage pressure removes older entries. Use the shipped rsyslog forwarding example and a separately managed collector policy when longer retention is required. Separately schedule the durable-event exporter and monitor pending-event count and age as described in its runbook.

## Remote stream identity

The web, scheduler, backup, and migration systemd units set the stable journal
identifiers `oralhistarchiv`, `oralhistarchiv-scheduler`,
`oralhistarchiv-backup`, and `oralhistarchiv-migrate`.
The rsyslog forwarding rule does not trust those process-visible strings as
its selector: it selects the trusted journald `_SYSTEMD_UNIT` values
`oralhistarchiv.service`, `oralhistarchiv-scheduler.service`,
`oralhistarchiv-backup.service`, and `oralhistarchiv-migrate.service`. The
identifiers remain useful as stable collector fields. Remote shipping is not
an active security control until a
real event from every unit—not a synthetic `logger -t` event—has been observed
at the collector and action suspension/queue growth are monitored.

## Sensitive data redaction

`app/request_utils.py` supplies `safe_request_path` and `scrub_sensitive_query`.
After routing, paths use the route template. Before routing, logging uses the
internally generated admission label when available: the matched route template,
`/<unmatched>` for unmatched paths/methods, or `/<unresolved>` if resolution failed.
This also applies to early 429/503 diagnostics and the request audit event. The
label comes from server-owned request state, never a request header or query.
Without either a routed template or an admission label, known action-token path
segments are scrubbed; other concrete paths can still contain client-chosen text.
Query logging retains at most 20 components: known `q`, `page`, `keyword`,
`language`, and `access_level` names become `name=<present>`; other names/values
become generic markers. No query values are preserved.

`SensitiveDataFilter` recursively redacts messages/extras using actual Settings values whose annotations contain `SecretStr` or whose metadata marks them sensitive. Rules also match known Fernet tokens, image data URIs, TOTP seeds, displayed recovery codes, action-token paths, and Bearer tokens. Values shorter than eight characters warn and are skipped. Patterns are built lazily and cached; changing settings requires restart. Unmatched secrets, alternate encodings, and address forms can remain, so filters do not make arbitrary object logging safe.

Audit email filtering hashes matching message/extra values before formatting; callers should still use `audit_email_hash` explicitly. Dictionary keys are not hashed by that filter, although final formatting applies application redaction.

Formatters omit exception messages/arguments and cached exception text. Diagnostic trees allow at most 16 nodes, depth four and 25 frames per node, with exception type, integer errno and valid SQLSTATE. Frames contain file/function names and line numbers, without source text or locals; redaction still applies.

## Resource-access events

Each successful `GET /dataset/{dataset_id}/resource/{proxy_index}` emits one
`resource_access` event with `dataset_id`, `source`, `user_id`, `user_tier` and
`proxy_index`, plus the audit helper's `request_id` and `client_ip`. Guests have
a null user ID. Target URLs, titles, UUIDs and proxy payloads are excluded.
Refusals emit no resource-access event; ordinary request audit still applies.
The route rechecks current catalogue visibility, so a previously obtained link
can be refused after a hide or tier change. This event records an attempted
visit, not an upstream download or authorization. See
[Resource access and audit](../architecture/resource-access.md) for source
configuration, link selection and application evidence.

## Dataset administrator events

`admin_dataset_tier_raised`, `admin_dataset_hidden` and `admin_dataset_restored`
identify committed durable changes. Each carries `actor_admin_id`, `dataset_id`,
`dataset_source`, `dataset_uuid`, `request_id`, `client_ip`, and `before`/`after`
objects containing stored tier, administrator floor, effective tier and hide
timestamp. Metadata values, source endpoints and session credentials are absent.
No-ops, rejections and rollbacks produce no successful-change event. The
service appends durable evidence in the restriction transaction, then emits an
additional local log after commit. Independent delivery uses the
[security event exporter](../runbooks/security-event-delivery.md).

## Operator queries

Inspect or follow web logs:

```bash
sudo journalctl -u oralhistarchiv -n 100
sudo journalctl -u oralhistarchiv -f
```

Parse JSON lines while ignoring application text and host messages:

```bash
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.logger == "audit")'
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.event_type == "dataset_access" and .user_id == 42)'
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.logger == "audit" and .event_type == "resource_access")'
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.request_id == "a1b2c3d4e5f6a7b8")'
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.path == "/login" and .status_code == 401)'
```

`event_type` also appears on operational application events, so use `logger == "audit"` to select the audit stream. Add the scheduler or other unit with `-u` when investigating those processes. These commands require host journal access and `jq`.

## Email-action request targets

Generated reset, registration-verification and email-change links put a
non-secret public ID in the path, with no query, fragment or secret. The same
email prints a separate security code. The landing GET is generic and never
returns a credential or target account data from that ID. The user copies the
code into the HTML form; only explicit POST sends it to the application. No
JavaScript is used. Action-token validation logs fixed failures without
embedding supplied signature bytes.

The native nginx throttling canary exercises a 429 while retaining the shipped
error-log settings: the logged request target contains the public ID, not the
separately emailed code. Access logs still require `oralhistarchiv_safe`. nginx error logs
may retain arbitrary request targets, including an obsolete token URL sent
manually; app-side 404 and redaction cannot prevent logging before the app.
Do not record POST bodies, email message bodies or entered codes at proxies,
debug middleware, collectors or support systems. Complete legacy token-bearing
URLs also remain secret. Existing redaction
patterns remain defense in depth. [Cutover and canary procedure](../runbooks/action-links.md)
covers queued messages and already-issued links.

## Logging boundaries

Request audit middleware does not capture bodies or cookies. This is not a blanket guarantee for every application or dependency log call: fields explicitly logged elsewhere pass through finite redaction patterns. Never log passwords, session/action tokens, factor secrets, recovery codes, private metadata, or complete request/response objects. Debug level does not disable redaction or authorize collecting those values.

# Logging & Audit

Application and audit loggers write to stdout. Audit events support request and security review; their completeness and retention depend on application coverage and host configuration.

Both streams go to stdout, captured by systemd-journald in production. journald handles rotation and retention.

## The two streams

| | Application | Audit |
|---|---|---|
| Logger | Module name | `audit` |
| Format | `LOG_FORMAT=json` selects JSON; other values select text | Always JSON |
| Minimum level | `LOG_LEVEL` | INFO |
| Content | Operational events | Audited requests and explicit security events |
| Destination | stdout | stdout, without root propagation |

`setup_logging()` replaces existing root/audit handlers. Both channels redact configured secret values and recognized runtime-secret shapes. Application output redacts email-pattern matches; audit filtering first converts matching address values to keyed markers, or redacts them before a hasher is registered. Matching is heuristic; never intentionally log credentials or private content. Host forwarding can include both streams.

## Why stdout instead of files?

The application leaves collection, rotation, retention, and forwarding to systemd-journald and the host agent. It does not coordinate shared file rotation. Python StreamHandler has no cross-process atomic-write guarantee; verify collected records under the deployed worker configuration.

## Audit log fields

Per-request records include UTC timestamp, logger/level/message, source module/function/line, `request_id`, `event_type`, client IP, method, safe path, scrubbed query structure, status, elapsed milliseconds, and resolved user ID or null. The 16-hex request ID is attached to request state and returned responses as `X-Request-ID`; requests rejected before this middleware may have neither.

Status below 400 logs INFO, 4xx WARNING, and 5xx ERROR. Exact `/health` and `/static/` paths skip statuses below 400, including redirects; `/health/detail` and errors remain audited. Escaping Exceptions log `request_error` with status 500 and are re-raised. Elapsed time ends when downstream returns a response, before streaming completes.

Client IP uses the trusted-proxy policy in `request_utils.py`; safe deployment of Unix-socket attribution requires the filesystem boundary in [Deployment](../configuration/deployment.md). `dataset_access` is emitted for non-public-tier dataset detail rendering and includes IDs, user/dataset tiers, and `access_granted`; it records metadata access, not upstream downloads.

## Rotation and retention

Configure journald on the host, for example in `/etc/systemd/journald.conf.d/oralhistarchiv.conf`:

```ini
[Journal]
SystemMaxUse=2G
SystemMaxFileSize=128M
MaxRetentionSec=30day
```

Apply with `sudo systemctl restart systemd-journald`. Application and audit events share the journal quota; 30 days is an upper retention limit, not a guarantee when storage pressure removes older entries. Use the shipped rsyslog forwarding example and a separately managed collector policy when longer retention is required. No periodic export job is supplied.

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

`app/request_utils.py` supplies `safe_request_path` and `scrub_sensitive_query`. After routing, paths use the route template; otherwise known action-token path segments are scrubbed. Unmatched concrete paths can still contain attacker-chosen text. Query logging retains at most 20 components: known `q`, `page`, `keyword`, `language`, and `access_level` names become `name=<present>`; other names/values become generic markers. No query values are preserved.

`SensitiveDataFilter` recursively redacts messages/extras using actual Settings values whose annotations contain `SecretStr` or whose metadata marks them sensitive. Rules also match known Fernet tokens, image data URIs, TOTP seeds, displayed recovery codes, action-token paths, and Bearer tokens. Values shorter than eight characters warn and are skipped. Patterns are built lazily and cached; changing settings requires restart. Unmatched secrets, alternate encodings, and address forms can remain, so filters do not make arbitrary object logging safe.

Audit email filtering hashes matching message/extra values before formatting; callers should still use `audit_email_hash` explicitly. Dictionary keys are not hashed by that filter, although final formatting applies application redaction.

Formatters omit exception messages/arguments and render bounded diagnostic trees: at most 16 nodes, truncation at depth four, and 25 frames per node, with exception type, integer errno, and valid SQLSTATE. Frames include filenames and source lines and are redacted afterward. Cached exception text is omitted. Do not place secrets in source literals or log message arguments.

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
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.request_id == "a1b2c3d4e5f6a7b8")'
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.path == "/login" and .status_code == 401)'
```

`event_type` also appears on operational application events, so use `logger == "audit"` to select the audit stream. Add the scheduler or other unit with `-u` when investigating those processes. These commands require host journal access and `jq`.

## Logging boundaries

Request audit middleware does not capture bodies or cookies. This is not a blanket guarantee for every application or dependency log call: fields explicitly logged elsewhere pass through finite redaction patterns. Never log passwords, session/action tokens, factor secrets, recovery codes, private metadata, or complete request/response objects. Debug level does not disable redaction or authorize collecting those values.
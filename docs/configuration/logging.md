# Logging & Audit

The application produces two distinct streams of log output: an **application log** for ordinary operational visibility, and an **audit log** for compliance-grade request tracking. They share infrastructure but have different purposes and consumers.

Both streams go to stdout, captured by systemd-journald in production. journald handles rotation and retention.

## The two streams

| | Application log | Audit log |
|---|---|---|
| **Logger name** | module-scoped (`app.routes.pages`, etc.) | `audit` |
| **What goes in** | Anything `logger.info()`/`warning()`/`error()` from application code | One structured record per HTTP request, plus per-event records |
| **Format** | JSON (production) / text (development) | Same formatter as the application log |
| **Destination** | stdout → systemd-journald | stdout → systemd-journald |
| **Retention** | Managed by journald (`MaxRetentionSec` in journald.conf) | Same |
| **Consumer** | Operators, developers debugging incidents | Compliance, security review, incident response |
| **Remote shipping** | No | Optional, via a host-level rsyslog agent reading journald (see `deploy/rsyslog-oralhistarchiv.conf.example` and Deployment.md §12) — not an application setting |

Both streams pass through a `SensitiveDataFilter` that replaces any configured secret value with a `[REDACTED:<field_name>]` marker (details below). One deliberate difference: the **application** log's filter additionally auto-redacts anything matching an email-address pattern; the **audit** channel's filter does not, because audit events never carry raw addresses in the first place — where an email must be correlated, the code logs the keyed, truncated `audit_email_hash(...)` instead (an HMAC under a `SECRET_KEY`-derived key, so log holders cannot precompute a lookup table).

## Why stdout instead of files?

Earlier versions used `TimedRotatingFileHandler` for both streams. This is **not** multi-process safe — when gunicorn workers rotate at midnight simultaneously, log entries can be corrupted or lost. The Python stdlib documentation explicitly warns against using rotating file handlers across multiple processes.

systemd-journald is designed for multi-process log collection. It handles rotation, retention, and indexing reliably across all workers.

## Audit log fields

Every per-request audit log line carries a consistent set of fields:

| Field | Description |
|---|---|
| `timestamp` | ISO 8601 UTC |
| `level` | `INFO` for successful requests, `WARNING` for 4xx, `ERROR` for 5xx |
| `request_id` | 16-character hex, also exposed on `request.state.request_id` and in the `X-Request-ID` response header; used as a correlation key across application logs |
| `event_type` | `request`, `request_error`, `dataset_access`, `login_success`, etc. |
| `client_ip` | Real client IP (`X-Real-IP` / `X-Forwarded-For` are honoured only when `RATE_LIMIT_TRUST_PROXY=true` and the request arrived through a trusted upstream — an allowlisted TCP peer or the Unix socket) |
| `method` | HTTP method |
| `path` | URL path (scrubbed for token segments — see *Sensitive data redaction* below) |
| `query_string` | Query string (scrubbed for non-allowlisted parameters) |
| `status_code` | HTTP status code |
| `duration_ms` | Wall-clock duration of the request |
| `user_id` | Authenticated user's database ID, or `null` for guests |

A handful of route handlers emit additional structured `event_type` records on top of the per-request line. The most important is `dataset_access`, emitted whenever a restricted-tier dataset detail page is rendered (whether or not access was granted). It carries `dataset_id`, `dataset_uuid`, `dataset_visibility_tier`, `user_id`, `user_tier`, and `access_granted`. This is the record you would consult during a privacy investigation: who looked at which restricted dataset, when, and whether they were authorised at the time.

## Rotation and retention

Rotation is handled by journald. Configure in `/etc/systemd/journald.conf.d/oralhistarchiv.conf`:

```ini
[Journal]
SystemMaxUse=2G
SystemMaxFileSize=128M
MaxRetentionSec=30day
```

Apply with `sudo systemctl restart systemd-journald`.

**Retention shift from earlier versions:** the previous file-based setup retained audit logs for 365 days. Under journald, both application and audit logs share the same retention pool (30 days by default in the shipped config). Options for longer audit retention:

1. Increase `MaxRetentionSec` and `SystemMaxUse` in journald.conf
2. Ship audit records off-host with the rsyslog agent (`deploy/rsyslog-oralhistarchiv.conf.example`) and apply the collector's retention policy
3. Periodic export-to-disk via cron (Phase 2)

## Sensitive data redaction

Three layers of redaction operate before logs are written:

**Path token scrubbing.** Sensitive route prefixes have their token segments replaced before logging: `/reset-password/abc123...`, `/verify-email/abc123...`, and `/account/confirm-email/abc123...` all become `/<prefix>/<token>`. See `_scrub_path` and `_TOKEN_PATH_REGEX` in `app/middleware/audit_logging.py`. If you add new token-bearing routes, update the regex.

**Query parameter scrubbing.** Query parameters use an allowlist — only the known-safe categorical parameters `page`, `keyword`, `language`, and `access_level` appear verbatim. Anything else is logged as `<key>=<redacted>`, so free-text search queries (`q=`), email addresses, and tokens never reach the logs. See `_scrub_query` and `_SAFE_QUERY_PARAMS` in `app/middleware/audit_logging.py`. If you add new safe parameters, update the allowlist.

**SecretStr field redaction.** The `SensitiveDataFilter` (in `config/logging.py`) collects, from `Settings.model_fields`, every field that is a `SecretStr` or marked `json_schema_extra={"sensitive": True}`. For each such field, the filter compiles a regex from the actual current value and applies it to the message and to every non-standard extra field of every log record, replacing matches with `[REDACTED:<field_name>]`. A static pattern also strips `Bearer <token>` values, and the application-log instance adds the email pattern. This means a developer can `logger.info("Got %s", some_object)` without remembering whether `some_object` happens to contain a secret — if it does, the secret is redacted before it hits the log. (The pattern set is built lazily on first use, after settings are loaded.)

Two limitations to know about:

- **Values shorter than 8 characters cannot be reliably redacted** (the substring is too likely to appear in unrelated text). The filter emits a warning for any such sensitive field and skips it.
- **Redaction is value-based, not field-based.** If two settings happen to share the same value, both occurrences are redacted, which is the right behaviour.

Each of the two stdout handlers (application and audit) carries its own filter instance, so redaction is formatter-independent and applies to both streams — including any rsyslog-forwarded copy, which reads the already-redacted journald output.

## Operator queries

A few common things to do with the logs.

**Recent application logs:**

```bash
sudo journalctl -u oralhistarchiv -n 100
sudo journalctl -u oralhistarchiv -f
sudo journalctl -u oralhistarchiv --since "1 hour ago"
```

**Audit events only (filter for the `event_type` field):**

```bash
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.event_type)'
```

**Specific event type:**

```bash
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.event_type == "login_success")'
```

**Every restricted-dataset access by user 42:**

```bash
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.event_type == "dataset_access" and .user_id == 42)'
```

**Trace a specific request across all logs:**

```bash
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.request_id == "a1b2c3d4e5f6a7b8")'
```

The request ID is the same key used in both streams and is also exposed in the response via the `X-Request-ID` header.

**Failed login attempts:**

```bash
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.path == "/login" and .status_code == 401)'
```

## What is *not* in the logs

To keep the audit story clean and the privacy story defensible, the following are deliberately absent:

- Request bodies. Form fields are never logged, so passwords, TOTP codes, and reset tokens cannot leak via logs.
- Response bodies. The HTML rendered to the user is not captured.
- Cookie values. The session ID is never logged in raw form (only the 8-character prefix for correlation).
- Raw email addresses in the audit channel — where correlation is needed, the keyed `audit_email_hash` appears instead.
- The values of any `SecretStr` setting, ever, even in tracebacks (see redaction above).

If you need any of these for debugging, the right path is to reproduce the issue in development with `LOG_LEVEL=DEBUG`, not to capture it in production logs.

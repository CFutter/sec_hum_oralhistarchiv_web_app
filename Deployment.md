# Deployment Guide

**Oral History Archive — University of Zurich**

This guide covers deploying the application on a single Ubuntu VM
behind nginx with SSL, Shibboleth, PostgreSQL, and Redis.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [VM Setup & Hardening](#2-vm-setup--hardening)
3. [PostgreSQL](#3-postgresql)
4. [Redis](#4-redis)
5. [Application Installation](#5-application-installation)
6. [Environment Configuration](#6-environment-configuration)
7. [Gunicorn, Scheduler & Systemd](#7-gunicorn-scheduler--systemd)
8. [Nginx & SSL](#8-nginx--ssl)
9. [Shibboleth SP](#9-shibboleth-sp)
10. [Firewall](#10-firewall)
11. [Backups](#11-backups)
12. [Log Management](#12-log-management)
13. [Monitoring](#13-monitoring)
14. [Memory Tuning](#14-memory-tuning)
15. [CI/CD](#15-cicd)
16. [Post-Deployment Checklist](#16-post-deployment-checklist)
17. [Maintenance](#17-maintenance)

---

## 1. Prerequisites

- Ubuntu 22.04 or 24.04 LTS
- Root or sudo access
- Domain name pointing to the VM's IP (e.g., `archive.example.uzh.ch`)
- PostgreSQL 15+ (same VM)
- Redis 6+ (same VM, used for rate limiting, scheduler coordination, and
  facet cache invalidation across workers)
- Python 3.11+
- SSL certificate (institutional or Let's Encrypt)

---

## 2. VM Setup & Hardening

### System updates

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Install ssh server (check)

```bash
sudo apt install openssh-server
```

### Create application user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin oralhistarchiv
```

### SSH hardening

Edit `/etc/ssh/sshd_config`:

```
PermitRootLogin no
PasswordAuthentication no
AllowUsers your_admin_user
MaxAuthTries 3
```

```bash
sudo systemctl restart sshd
```

### Install fail2ban

```bash
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
```

Create `/etc/fail2ban/jail.local`:

```ini
[sshd]
enabled = true
maxretry = 3
bantime = 3600
findtime = 600
```

```bash
sudo systemctl restart fail2ban
```

---

## 3. PostgreSQL

### Install

```bash
sudo apt install -y postgresql postgresql-contrib
```

### Create database and user

```bash
sudo -u postgres psql
```

```sql
CREATE USER oralhistarchiv WITH PASSWORD 'GENERATE_A_STRONG_PASSWORD';
CREATE DATABASE oralhistarchiv OWNER oralhistarchiv;
\q
```

### Configure authentication

Edit `/etc/postgresql/*/main/pg_hba.conf` — add before broader existing rules:

```
# App connects over TCP (DATABASE_URL uses @localhost) — configure that path
# explicitly instead of relying on the distribution's default host rule:
host    oralhistarchiv   oralhistarchiv   127.0.0.1/32   scram-sha-256
host    oralhistarchiv   oralhistarchiv   ::1/128        scram-sha-256

# Unix-socket clients (the §11 backup cron, manual psql as the service user)
# authenticate by OS identity — no password on disk:
local   oralhistarchiv   oralhistarchiv                  peer
```

The split matters: the application never uses the `local` (socket) line — it
connects over TCP with the database password, matched by the two `host`
lines. The socket line exists for the non-interactive backup job; do **not**
put `scram-sha-256` on it, or the cron fails with `fe_sendauth: no password
supplied` (see §11).

```bash
sudo systemctl restart postgresql
```

### Test connection

```bash
sudo -u oralhistarchiv psql -d oralhistarchiv -c "SELECT 1"
```

---

## 4. Redis

Redis is used for three things in this deployment:

- **Rate limiting** — unified across all gunicorn workers (slowapi backend)
- **Facet cache invalidation** — pub/sub so all workers see sync updates
- **Scheduler coordination** — not currently needed because the scheduler
  runs in a dedicated systemd unit, but the client is initialized anyway

### Install

```bash
sudo apt install -y redis-server
sudo systemctl enable redis-server
```

### Configure

Edit `/etc/redis/redis.conf`:

```
# Bind to loopback only — Redis should never be reachable from outside the VM
bind 127.0.0.1 ::1

# Disable persistence (not need it — all data is ephemeral coordination state)
save ""
appendonly no

# Limit memory as a safety net
maxmemory 128mb
maxmemory-policy allkeys-lru
```

```bash
sudo systemctl restart redis-server
```

### Test

```bash
redis-cli ping
# Should return: PONG
```

### Verify it's not exposed

```bash
# From another machine (should fail or time out)
redis-cli -h <VM_IP> ping
```

---

## 5. Application Installation

### Install system dependencies

```bash
sudo apt install -y python3.11 python3.11-venv python3-pip git jq
```

`jq` is used for filtering structured JSON logs from journald.

### Clone and set up

```bash
sudo mkdir -p /opt/oralhistarchiv
sudo chown oralhistarchiv:oralhistarchiv /opt/oralhistarchiv

# Clone as your admin user, then transfer ownership
git clone https://github.com/YOUR_REPO.git /opt/oralhistarchiv
sudo chown -R oralhistarchiv:oralhistarchiv /opt/oralhistarchiv
```

### Create virtual environment

```bash
cd /opt/oralhistarchiv
sudo -u oralhistarchiv python3.11 -m venv .venv
sudo -u oralhistarchiv .venv/bin/pip install -e ".[dev]"
# (gunicorn and uvicorn are part of the project dependencies — no separate install needed)
```

### Directories

The application keeps no on-disk state of its own: logs go to
systemd-journald and the facet cache is in memory (coordinated via Redis
when enabled). **One directory must exist anyway:** both systemd units
mount `/opt/oralhistarchiv/data` read-write under `ProtectSystem=strict`
(`ReadWritePaths=`, no `-` prefix), and a missing path makes the mount
namespace fail — the unit dies with `status=226/NAMESPACE` before the app
even starts. The directory is in `.gitignore`, so a fresh clone does not
have it. Create it:

```bash
sudo install -d -o oralhistarchiv -g oralhistarchiv /opt/oralhistarchiv/data
```

No log directory is needed.

---

## 6. Environment Configuration

Create `/opt/oralhistarchiv/.env`:

```bash
# Environment
ENV_STATE=production
PUBLIC_BASE_URL=https://archive.example.uzh.ch
ALLOWED_HOSTS=["archive.example.uzh.ch"]

# Database
DATABASE_URL=postgresql://oralhistarchiv:YOUR_DB_PASSWORD@localhost/oralhistarchiv

# Redis — unified backend for rate limiting and cache invalidation
REDIS_ENABLED=true
REDIS_URL=redis://localhost:6379/0

# FastAPI
FASTAPI_HOST=127.0.0.1
FASTAPI_PORT=5000
FASTAPI_DEBUG=false
PAGINATION_SIZE=20

# Security — GENERATE ALL, DO NOT COPY
# python -c "import secrets; print(secrets.token_urlsafe(64))"
SECRET_KEY=GENERATE_ME
SESSION_SECRET=GENERATE_ME

# JSON list; MultiFernet — the first key encrypts, all keys decrypt.
# Rotation has a re-encryption procedure: see docs/runbooks/key-rotation.md
TOTP_ENCRYPTION_KEYS=["GENERATE_ME"]

# python -c "import secrets; print(secrets.token_urlsafe(32))"
HEALTH_DETAIL_TOKEN=GENERATE_ME
SHIBBOLETH_INTERNAL_SECRET=GENERATE_ME

# Sessions
SESSION_MAX_AGE_SECONDS=28800
SESSION_COOKIE_NAME=oha_session

# Authentication
LOCAL_AUTH_ENABLED=true
TOTP_ISSUER_NAME=Oral History Archive UZH

# Shibboleth — enable after the SP layer (shibd + nginx module, §9) is configured
SHIBBOLETH_ENABLED=false
# NOTE: currently not read by the app — the callback trusts the Unix socket
# + X-Internal-Auth only; reserved for a future split-host deployment.
SHIBBOLETH_TRUSTED_PROXY_IP=127.0.0.1

# Logging — all logs go to systemd-journald via stdout
LOG_LEVEL=INFO
LOG_FORMAT=json

# Rate limiting — backed by Redis, so limits are global across workers
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_PER_HOUR=1000
RATE_LIMIT_PER_DAY=10000
RATE_LIMIT_TRUST_PROXY=true

# OAI-PMH
OAI_INSTITUTION_FILTER=YOUR_INSTITUTION_NAME
SWISSUBASE_OAI_PMH_URL=https://www.swissubase.ch/oai-pmh/v1/oai
# Visibility ceiling for harvested records ("public" for the open catalogue;
# the code default is the most restrictive, "vetted")
SWISSUBASE_MAX_VISIBILITY=public
SYNC_INTERVAL_SECONDS=3600
FULL_REBUILD_INTERVAL_SECONDS=86400

# Email (SMTP) — required for password reset and email verification
SMTP_ENABLED=true
SMTP_HOST=smtp.example.ethz.ch
SMTP_PORT=587
SMTP_USER=your-smtp-user
SMTP_PASSWORD=your-smtp-password
SMTP_FROM_ADDRESS=noreply@example.uzh.ch
SMTP_FROM_NAME=Oral History Archive
SMTP_USE_TLS=true

# Admin seed — remove after first startup
ADMIN_SEED_EMAIL=your-admin@uzh.ch
ADMIN_SEED_PASSWORD=GENERATE_A_STRONG_INITIAL_PASSWORD

# Contact
CONTACT_EMAIL=archive@example.uzh.ch
```

**Secure the file:**

```bash
sudo chown oralhistarchiv:oralhistarchiv /opt/oralhistarchiv/.env
sudo chmod 600 /opt/oralhistarchiv/.env
```

**Note on secrets:** `SECRET_KEY`, `SESSION_SECRET`, `HEALTH_DETAIL_TOKEN`,
`SHIBBOLETH_INTERNAL_SECRET`, and every entry of `TOTP_ENCRYPTION_KEYS` must
all be unique, high-entropy values. Never reuse between environments. Never
commit them to git. Before rotating any of them, read
`docs/runbooks/key-rotation.md` — the TOTP keys in particular require a
re-encryption procedure, and each secret has a different blast radius.

---

## 7. Gunicorn, Scheduler & Systemd

The application runs as two systemd units:

- **oralhistarchiv.service** — gunicorn web workers, handles HTTP requests
- **oralhistarchiv-scheduler.service** — APScheduler, runs OAI-PMH syncs
  and session cleanup in a dedicated process

Running the scheduler separately prevents sync jobs from running once per
gunicorn worker (4× per interval), which would rate-limit SWISSUbase and
produce inconsistent state.

### Install both units

```bash
sudo cp /opt/oralhistarchiv/oralhistarchiv.service \
    /etc/systemd/system/
sudo cp /opt/oralhistarchiv/oralhistarchiv-scheduler.service \
    /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable oralhistarchiv oralhistarchiv-scheduler
```

(The two unit files ship at the repository root. The nginx and journald
examples under `deploy/` are copied in their respective sections below.)

### Start and verify

```bash
sudo systemctl start oralhistarchiv oralhistarchiv-scheduler
sudo systemctl status oralhistarchiv
sudo systemctl status oralhistarchiv-scheduler

# Check the web socket was created
ls -la /run/oralhistarchiv/gunicorn.sock

# Check logs for both
sudo journalctl -u oralhistarchiv -f
sudo journalctl -u oralhistarchiv-scheduler -f
```

The scheduler should log `"Scheduler started"` and then an initial sync
attempt within a few seconds.

### Test the web service directly (before nginx)

```bash
curl --unix-socket /run/oralhistarchiv/gunicorn.sock http://localhost/health
# Should return: {"status": "alive"}   (liveness only — no dependency checks)
```

> **Note:** the scheduler unit lists `/run/oralhistarchiv` in its
> `ReadWritePaths=` but has no `RuntimeDirectory=` of its own — that
> directory is created by the **web** unit. Start (or restart) the
> scheduler only while the web service is active; a standalone scheduler
> start while the web unit is down fails with `status=226/NAMESPACE`.
> (Unit-file fix — giving the scheduler its own `RuntimeDirectory=` — is
> tracked in the open questions.)

### Verify the scheduler isn't running in web workers

```bash
# The web journal should NOT contain "Scheduler started" or OAI-PMH sync messages
sudo journalctl -u oralhistarchiv | grep -i "scheduler\|oai-pmh"
# Should produce no output
```

### Verify per-process database identity

After both services are running, check pg_stat_activity to confirm the
web and scheduler processes identify themselves correctly:

```bash
sudo -u postgres psql -d oralhistarchiv -c \
    "SELECT pid, application_name, state FROM pg_stat_activity WHERE datname = 'oralhistarchiv'"
```

Should show entries with `application_name` set to `oralhistarchiv-web`
and `oralhistarchiv-scheduler`. If you see `psycopg` instead, the
scheduler's pool isn't being created with the right identifier.

---

## 8. Nginx & SSL

### Install nginx

```bash
sudo apt install -y nginx
```

### SSL certificate

**Option A — Let's Encrypt** (if the VM is publicly accessible):

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d archive.example.uzh.ch
```

**Option B — Institutional certificate:**

```bash
sudo cp your-cert.crt /etc/ssl/certs/oralhistarchiv.crt
sudo cp your-cert.key /etc/ssl/private/oralhistarchiv.key
sudo chmod 600 /etc/ssl/private/oralhistarchiv.key
```

### Install nginx config

```bash
sudo cp /opt/oralhistarchiv/deploy/nginx.conf.example \
    /etc/nginx/sites-available/oralhistarchiv

sudo nano /etc/nginx/sites-available/oralhistarchiv
```

**Required edits in the config:**

- `server_name` — your domain
- `ssl_certificate` and `ssl_certificate_key` paths
- `X-Internal-Auth` value in the `/auth/shibboleth/callback` location —
  must match `SHIBBOLETH_INTERNAL_SECRET` in `.env` exactly
- Static file alias path if your deployment path differs

The Shibboleth `$shib_*` attribute lines in the example ship **commented
out**: they require the Phase-2 SP layer (§9), and active without it they
make `nginx -t` fail with `unknown "shib_remote_user" variable`. Leave them
commented for a Phase-1 deployment — the `nginx -t` step below must pass
before you continue (and before attempting §9).

**Critical security notes on the nginx config:**

1. The `location = /auth/shibboleth/callback` block is kept above the
   generic `location /` block for readability — correctness does not depend
   on file order, because the exact-match `=` prefix has priority over
   prefix locations wherever it appears. What is load-bearing is the header
   hygiene: the callback is the only location that may set `X-Internal-Auth`
   and the attribute headers, and `location /` must keep clearing them.

2. The main `location /` block must explicitly clear any client-supplied
   `X-Internal-Auth` header with `proxy_set_header X-Internal-Auth "";`.
   Without this, a client could send the header to any path, bypassing
   the callback-specific injection.

3. The same principle applies to the Shibboleth attribute headers
   (`REMOTE_USER`, `mail`, `displayName`, `affiliation`, and the configured country header — the names must match the app's `SHIBBOLETH_HEADER_*` settings; note the code default for the country header is `schacHomeOrganizationCountry`, while `.env.example` overrides it to `country`). 
   Clear them on the main location, inject them only on the Shibboleth callback.

### Enable the site

```bash
sudo ln -s /etc/nginx/sites-available/oralhistarchiv \
    /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

### Verify

```bash
# From the VM itself
curl -k https://localhost/health

# From your machine
curl https://archive.example.uzh.ch/health
```

### Verify client IP propagation

After nginx is in place, verify that audit logs show real client IPs
rather than nginx's loopback IP:

```bash
# Hit the app from an external machine, then check the audit log entry
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.event_type == "request") | .client_ip' | tail -5
```

Should show the external client IP. If you see `127.0.0.1` for requests
from external hosts, the three-way IP trust contract is broken — verify
nginx sets `X-Real-IP`, gunicorn has `forwarded_allow_ips = ""`, and the
app's `RATE_LIMIT_TRUST_PROXY=true` with the right `TRUSTED_PROXY_IPS`.

---

## 9. Shibboleth SP

> **Phase 2 — design notes.** This section has not been validated
> end-to-end; the SP deployment is a Phase-2 task (see `roadmap.md`).
> Treat it as a design sketch to finalise with UZH IT — nothing in a
> Phase-1 deployment depends on it, and §8's `nginx -t` must already pass
> before you start here.

### Install the Shibboleth SP (nginx variant)

```bash
sudo apt install -y shibboleth-sp-utils   # shibd + FastCGI shibauthorizer/shibresponder
sudo systemctl enable shibd
```

Do **not** install `libapache2-mod-shib` — that is the Apache module and
pulls Apache (`apache2-bin`) onto the nginx VM. There is no "mod_shib" for
nginx: nginx integrates with `shibd` via the two FastCGI applications above
plus the third-party **nginx-http-shibboleth** module, which provides the
`shib_request*` directives and the `$shib_*` variables the callback config
uses. That module is not in Ubuntu's nginx packages — provision it as a
dynamic module or custom build (coordinate with UZH IT / LeoMed). The
FastCGI apps also do not start themselves: run `shibauthorizer` and
`shibresponder` as services (systemd units or supervisor) listening on
Unix sockets.

### nginx wiring (handler + attribute variables)

Add to the site config (socket paths and variable mapping illustrative —
align with how the FastCGI services are actually run):

```nginx
# SP protocol handler — makes /Shibboleth.sso/Metadata etc. reachable
location /Shibboleth.sso/ {
    include fastcgi_params;
    fastcgi_pass unix:/run/shibboleth/shibresponder.sock;
}

location = /shibauthorizer {
    internal;
    include fastcgi_params;
    fastcgi_pass unix:/run/shibboleth/shibauthorizer.sock;
}

location = /auth/shibboleth/callback {
    shib_request /shibauthorizer;
    # one shib_request_set per attribute the app expects, e.g.:
    #   shib_request_set $shib_remote_user $upstream_http_variable_remote_user;
    # …then uncomment the proxy_set_header $shib_* lines in
    # deploy/nginx.conf.example so the attributes reach the app.
}
```

### Configure SP

Edit `/etc/shibboleth/shibboleth2.xml`:

```xml
<ApplicationDefaults entityID="https://archive.example.uzh.ch/shibboleth"
                     REMOTE_USER="eppn"
                     signing="true"
                     encryption="true">

    <Sessions lifetime="28800" timeout="3600"
              checkAddress="false"
              handlerSSL="true"
              cookieProps="https">

        <SSO entityID="https://aai.switchaai.ch/idp/shibboleth">
            SAML2
        </SSO>

        <Handler type="MetadataGenerator" Location="/Metadata"
                 signing="true"/>
    </Sessions>

    <AttributeExtractor type="XML" validate="true"
                        path="attribute-map.xml"/>
</ApplicationDefaults>
```

### Register with SWITCH AAI

1. Generate SP metadata: `https://archive.example.uzh.ch/Shibboleth.sso/Metadata`
2. Submit to SWITCH AAI resource registry: https://rr.aai.switch.ch/
3. Request attributes: `mail`, `displayName`, `affiliation`, `schacHomeOrganizationCountry`
4. Wait for approval (typically 1-2 business days)

### Enable in application

Once registration is confirmed:

```bash
# Edit .env
SHIBBOLETH_ENABLED=true

# Restart the web service (scheduler doesn't need a restart)
sudo systemctl restart oralhistarchiv
```

### Test Shibboleth flow

1. Visit `https://archive.example.uzh.ch/login`
2. Click "Login with SWITCH edu-ID"
3. Authenticate at your IdP
4. Should redirect back to the app with a session

If the callback is rejected, check the application log for
`"Shibboleth callback rejected"` — common causes are a missing
`X-Internal-Auth` header (nginx config) or a mismatch between the
nginx header value and `SHIBBOLETH_INTERNAL_SECRET` in `.env`.

---

## 10. Firewall

```bash
sudo apt install -y ufw

sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

sudo ufw enable
sudo ufw status verbose
```

**Verify Gunicorn and Redis are not directly accessible:**

```bash
# These should all fail
curl http://YOUR_VM_IP:5000
redis-cli -h YOUR_VM_IP ping
```

---

## 11. Backups

### PostgreSQL automated backup

Create `/opt/oralhistarchiv/scripts/backup.sh`:

```bash
#!/bin/bash
# Daily PostgreSQL backup
# Critical tables: users, sessions
# Rebuildable tables: oral_history_datasets (from OAI-PMH), sync_status

BACKUP_DIR="/opt/oralhistarchiv/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

pg_dump -U oralhistarchiv -Fc oralhistarchiv \
    > "$BACKUP_DIR/oralhistarchiv_${TIMESTAMP}.dump"

find "$BACKUP_DIR" -name "*.dump" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: oralhistarchiv_${TIMESTAMP}.dump"
```

```bash
sudo chmod +x /opt/oralhistarchiv/scripts/backup.sh
sudo chown oralhistarchiv:oralhistarchiv /opt/oralhistarchiv/scripts/backup.sh
```

**Authentication (why the cron works without a password):** the job runs
non-interactively as the `oralhistarchiv` OS user and connects over the
Unix socket, so §3's `peer` rule authenticates it by OS identity — no
password on disk. If you used `scram-sha-256` on that `local` line instead,
every nightly run fails with `fe_sendauth: no password supplied` — while a
by-hand test, which can prompt, appears to work. In that case give the
service user a credentials file:

```bash
sudo -u oralhistarchiv install -m 600 /dev/null ~oralhistarchiv/.pgpass
echo "localhost:5432:oralhistarchiv:oralhistarchiv:YOUR_DB_PASSWORD" | \
    sudo -u oralhistarchiv tee -a ~oralhistarchiv/.pgpass
```

**Redis is deliberately not backed up** — it holds only ephemeral
coordination state (rate limit counters, cache invalidation signals).
Losing it on restart is fine; everything regenerates on the next cycle.

### Schedule with cron

```bash
sudo crontab -u oralhistarchiv -e
```

```
0 2 * * * /opt/oralhistarchiv/scripts/backup.sh 2>&1 | logger -t oralhistarchiv-backup
```

The `logger -t oralhistarchiv-backup` pipe sends the script output to
systemd-journald with a `SYSLOG_IDENTIFIER=oralhistarchiv-backup` tag.
Query backup logs with:

```bash
sudo journalctl -t oralhistarchiv-backup --since "1 week ago"
```

### Restore

```bash
# Stop both services first — --clean against live connections fails or
# leaves a half-restored state
sudo systemctl stop oralhistarchiv oralhistarchiv-scheduler

sudo -u oralhistarchiv pg_restore -d oralhistarchiv --clean --if-exists \
    /path/to/backup.dump

sudo systemctl start oralhistarchiv oralhistarchiv-scheduler
```

---

## 12. Log Management

### Initial setup

Install the journald retention configuration:

```bash
sudo cp /opt/oralhistarchiv/deploy/journald-oralhistarchiv.conf \
    /etc/systemd/journald.conf.d/oralhistarchiv.conf

sudo systemctl restart systemd-journald
```

This caps journal disk usage and sets retention policy.

### Application logs via systemd-journald

All application and audit logs go to stdout. systemd-journald captures both
streams and handles rotation/retention. This is multi-process safe — unlike
Python's TimedRotatingFileHandler, which can corrupt logs when gunicorn
workers rotate concurrently.

### Retention configuration

The journald config file (`/etc/systemd/journald.conf.d/oralhistarchiv.conf`)
contains:

```ini
[Journal]
# Cap total journal disk usage. Adjust based on /var/log volume size.
SystemMaxUse=2G

# Per-file cap forces rotation more frequently than the 128M default.
SystemMaxFileSize=128M

# Time-based retention.
MaxRetentionSec=30day
```

**Note:** journald retention (30 days) is shorter than the previous file-based
audit retention (365 days). If compliance requires longer retention, options:
increase `MaxRetentionSec` and `SystemMaxUse` accordingly or set up a periodic 
export-to-disk cron job.

### Off-host audit log shipping (optional)

The application does not ship logs itself — it writes to journald. To
forward audit logs to a central collector for long-term, tamper-evident
retention, use a host-level rsyslog agent over RELP+TLS:

    sudo apt install -y rsyslog-relp   # provides the omrelp module (not in base rsyslog)
    sudo cp /opt/oralhistarchiv/deploy/rsyslog-oralhistarchiv.conf.example \
        /etc/rsyslog.d/30-oralhistarchiv.conf
    sudo nano /etc/rsyslog.d/30-oralhistarchiv.conf   # fill in <...> placeholders
    # place collector CA + client cert/key under /etc/rsyslog.d/tls/ (perms 0640)
    sudo rsyslogd -N1            # validate config
    sudo systemctl restart rsyslog

Collector endpoint, transport (RELP vs RFC 5425 TLS-syslog), CA, and client
certificate enrollment are provided by Central IT — confirm these in the
onboarding consultation.

**PRE-FLIGHT — do NOT enable shipping until all are true:**
[ ] Audit email logging uses the keyed HMAC hash, not raw addresses
[ ] The audit-hash key lives on this host and is NOT in the shipped stream
[ ] The email redaction net in config/logging.py is active
[ ] rsyslog queue.maxDiskSpace is bounded (a collector outage must not fill disk)
[ ] A test record reaches the collector (verify end-to-end before relying on it)

### Sensitive data scrubbing

Audit logs scrub:
- Password reset and email verification tokens from URL paths
  (see `_scrub_path` in `middleware/audit_logging.py`)
- Free-text query parameters not in the safe-list
  (see `_scrub_query` and `_SAFE_QUERY_PARAMS` in `middleware/audit_logging.py`)
- All values matching SecretStr settings fields
  (see `SensitiveDataFilter` in `config/logging.py`)

If you add new token-bearing routes or query parameters, update the
respective scrubbing patterns.

### Nginx logs

Standard nginx logrotate at `/etc/logrotate.d/nginx` (pre-configured).

### Systemd journal

Both gunicorn and scheduler services log to the journal:

```bash
# Web service
sudo journalctl -u oralhistarchiv --since "1 hour ago"
sudo journalctl -u oralhistarchiv -f

# Scheduler
sudo journalctl -u oralhistarchiv-scheduler --since "1 hour ago"
sudo journalctl -u oralhistarchiv-scheduler -f

# Backup script (via logger tag)
sudo journalctl -t oralhistarchiv-backup --since "1 week ago"
```

### Querying audit events

The app emits structured JSON logs. Filter with `jq`:

```bash
# All audit events
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.event_type)'

# Specific event type
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.event_type == "login_success")'

# Trace a specific request by request_id
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.request_id == "abc12345")'

# Failed login attempts
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.path == "/login" and .status_code == 401)'

# All restricted dataset accesses by a specific user
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.event_type == "dataset_access" and .user_id == 42)'
```

---

## 13. Monitoring

### Health check script

Create `/opt/oralhistarchiv/scripts/health_check.sh`:

```bash
#!/bin/bash
HEALTH_URL="https://archive.example.uzh.ch/health"
ALERT_EMAIL="admin@example.uzh.ch"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$HEALTH_URL")

if [ "$HTTP_CODE" != "200" ]; then
    echo "ALERT: Oral History Archive health check failed (HTTP $HTTP_CODE)" | \
        mail -s "OHA Health Check FAILED" "$ALERT_EMAIL"
fi
```

```bash
sudo chmod +x /opt/oralhistarchiv/scripts/health_check.sh
```

Schedule:

```bash
sudo crontab -e
```

```
*/5 * * * * /opt/oralhistarchiv/scripts/health_check.sh
```

### Detailed health check (internal)

```bash
curl -H "Authorization: Bearer YOUR_HEALTH_DETAIL_TOKEN" \
    https://archive.example.uzh.ch/health/detail
```

### Scheduler liveness

The scheduler service has no HTTP health endpoint. Monitor it via:

```bash
# Is it running?
systemctl is-active oralhistarchiv-scheduler

# When was the last sync?
psql -U oralhistarchiv -d oralhistarchiv -c \
    "SELECT last_harvest_date, last_sync_error, last_sync_error_at FROM sync_status WHERE id = 1"
```

A stale `last_harvest_date` more than 2× `SYNC_INTERVAL_SECONDS` old
means the scheduler is stuck or crashed.

---

## 14. Memory Tuning

Both systemd units set `MemoryMax` as a safety net. Initial values:

- **oralhistarchiv.service** — 1024M (up to 4 gunicorn workers)
- **oralhistarchiv-scheduler.service** — 256M (1 scheduler process)

Tune these after observing real usage. To check current memory:

```bash
systemctl show oralhistarchiv --property=MemoryCurrent
systemctl show oralhistarchiv-scheduler --property=MemoryCurrent
```

**Signs you need to raise the limit:**

- `journalctl -u oralhistarchiv | grep -i "oom\|killed"`
- Requests timing out during OAI-PMH full rebuilds
- Scheduler service restarting unexpectedly

**Signs you can lower the limit:**

- `MemoryCurrent` stays well below the cap for weeks under load
- VM is memory-constrained overall

To adjust:

```bash
sudo nano /etc/systemd/system/oralhistarchiv.service
# Change MemoryMax=1024M to desired value
sudo systemctl daemon-reload
sudo systemctl restart oralhistarchiv
```

If the VM itself is memory-tight, an alternative to raising
`MemoryMax` is reducing the worker count in `gunicorn.conf.py`
from 4 to 2. For this app's scale, 2 workers are usually sufficient.

---

## 15. CI/CD

If using GitHub Actions, create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          pip install uv
          uv pip install -e ".[dev]" --system

      - name: Lint (ruff)
        run: ruff check src/

      - name: Security scan (bandit)
        run: bandit -r src/app src/config -c pyproject.toml

      - name: Dependency audit
        run: pip-audit

      # TODO(tests-rework): update this section once the new test suite lands
      - name: Run tests
        env:
          ENV_STATE: dev
          SECRET_KEY: test-ci-secret-key-do-not-use-in-production-1234567890
          SESSION_SECRET: test-ci-session-secret-do-not-use-in-production-1234
          OAI_INSTITUTION_FILTER: "Test University"
          REDIS_ENABLED: "false"
        run: |
          cd src && python -m pytest tests/ -v --tb=short

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
      - name: Deploy to production
        run: |
          ssh -o StrictHostKeyChecking=no ${{ secrets.DEPLOY_USER }}@${{ secrets.DEPLOY_HOST }} << 'EOF'
            cd /opt/oralhistarchiv
            git pull origin main
            .venv/bin/pip install -e ".[dev]"
            cd src && ../.venv/bin/alembic upgrade head
            sudo systemctl restart oralhistarchiv oralhistarchiv-scheduler
          EOF
```

---

## 16. Post-Deployment Checklist

```
Configuration
[ ] .env has production SECRET_KEY, SESSION_SECRET, TOTP_ENCRYPTION_KEYS,
    HEALTH_DETAIL_TOKEN, and SHIBBOLETH_INTERNAL_SECRET (all generated,
    not defaults)
[ ] PUBLIC_BASE_URL is the public https:// URL; ALLOWED_HOSTS lists the
    public hostname
[ ] .env file permissions are 600
[ ] FASTAPI_DEBUG=false
[ ] REDIS_ENABLED=true
[ ] RATE_LIMIT_TRUST_PROXY=true
[ ] journald retention config installed at
    /etc/systemd/journald.conf.d/oralhistarchiv.conf

Services
[ ] postgresql.service is running
[ ] redis-server.service is running
[ ] oralhistarchiv.service is running
[ ] oralhistarchiv-scheduler.service is running
[ ] Scheduler log shows "Scheduler started" and at least one sync
[ ] Web service log does NOT contain scheduler messages
[ ] Redis only accepts connections from 127.0.0.1
[ ] pg_stat_activity shows oralhistarchiv-web and oralhistarchiv-scheduler
    (sudo -u postgres psql -d oralhistarchiv -c
     "SELECT pid, application_name FROM pg_stat_activity")

Endpoints
[ ] SSL certificate is valid and HTTPS works
[ ] HTTP → HTTPS redirect works
[ ] /health returns {"status": "alive"}
[ ] /health/detail returns 404 without token
[ ] /health/detail returns data with correct Bearer token
[ ] /docs and /redoc return 404 (disabled in production)
[ ] Static files load from nginx (not gunicorn)

Authentication flows
[ ] Admin user can log in
[ ] Admin is email_verified by default (no verification email required)
[ ] Registration sends verification email via SMTP
[ ] Clicking the verification link marks the user verified
[ ] Unverified users cannot reach /setup-totp (see "check your email" page)
[ ] TOTP enrollment works after verification
[ ] Password reset email sends via SMTP
[ ] Password reset link can only be used once
[ ] CSRF protection works (form submissions succeed, forged ones rejected)
[ ] Rate limiting active and global across workers (test with curl
    from different simulated IPs)

Shibboleth (if enabled)
[ ] Shibboleth login works end-to-end
[ ] Shibboleth callback rejected when X-Internal-Auth header is missing
    (simulate by curling gunicorn directly without the header)
[ ] Shibboleth users auto-provisioned as email_verified=true

Security
[ ] Security headers present (curl -I https://...)
[ ] Firewall blocks direct gunicorn access (curl to port 5000 fails)
[ ] Firewall blocks direct Redis access (redis-cli -h VM_IP ping fails)
[ ] Gunicorn only listens on Unix socket, not TCP
[ ] Audit logs show real external client IPs (not 127.0.0.1)
    when accessing via nginx (sudo journalctl -u oralhistarchiv -o cat |
    jq 'select(.event_type == "request") | .client_ip')

Operations
[ ] Backup script runs **from cron** (non-interactive — check the
    journald tag), not only by hand, and produces dump files
[ ] Backup script output appears in journald
    (sudo journalctl -t oralhistarchiv-backup)
[ ] Health check cron is running
[ ] Both systemd units restart on failure
[ ] Remove ADMIN_SEED_EMAIL and ADMIN_SEED_PASSWORD from .env after
    first successful admin login
```

---

## 17. Maintenance

### Updating the application

```bash
cd /opt/oralhistarchiv
sudo -u oralhistarchiv git pull origin main
sudo -u oralhistarchiv .venv/bin/pip install -e ".[dev]"

# Run migrations (if any)
cd src && sudo -u oralhistarchiv ../.venv/bin/alembic upgrade head

# Restart both services
sudo systemctl restart oralhistarchiv oralhistarchiv-scheduler
```

### Database migrations only

```bash
cd /opt/oralhistarchiv/src
sudo -u oralhistarchiv ../.venv/bin/alembic upgrade head
sudo systemctl restart oralhistarchiv oralhistarchiv-scheduler
```

### Viewing logs

All application and audit logs go through systemd-journald.

```bash
# All web service logs (live)
sudo journalctl -u oralhistarchiv -f

# Audit events only (filter for event_type field)
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.event_type)'

# Specific audit event types
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.event_type == "login_success")'

# Trace a specific request across all logs
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.request_id == "abc12345")'

# Scheduler journal (live)
sudo journalctl -u oralhistarchiv-scheduler -f

# Backup script output
sudo journalctl -t oralhistarchiv-backup --since "1 week ago"

# Nginx access
sudo tail -f /var/log/nginx/oralhistarchiv_access.log
```

### Memory check

```bash
systemctl show oralhistarchiv --property=MemoryCurrent
systemctl show oralhistarchiv-scheduler --property=MemoryCurrent
```

### Maintenance mode (planned downtime)

For a destructive migration, a restore, or anything needing more than a
restart blip:

```bash
# 1. Stop the workers (nginx keeps answering)
sudo systemctl stop oralhistarchiv-scheduler oralhistarchiv

# 2. Have nginx answer 503 while the app is down — add temporarily to the
#    HTTPS server block, then reload:
#      location / { return 503; }
sudo nginx -t && sudo systemctl reload nginx

# 3. Do the work (alembic upgrade/downgrade, pg_restore, ...)

# 4. Remove the override, reload nginx, start both services
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl start oralhistarchiv oralhistarchiv-scheduler
```

### Rotating secrets

The step-by-step operator procedure for every secret — including the
delicate `TOTP_ENCRYPTION_KEYS` re-encryption — lives in
**`docs/runbooks/key-rotation.md`**. Read it before rotating anything.
The short version:

- **`SECRET_KEY`** — invalidates all outstanding password-reset,
  email-verification, and email-change links (they are short-lived; users
  simply request new ones) and breaks audit-email-hash correlation across
  the rotation boundary. It does **not** affect TOTP secrets (those are
  encrypted under `TOTP_ENCRYPTION_KEYS`) and does **not** log anyone out.
- **`SESSION_SECRET`** — invalidates all signed session cookies (every
  user must log in again). CSRF cookies regenerate automatically on the
  next GET.
- **`TOTP_ENCRYPTION_KEYS`** — the careful one: **prepend** the new key,
  re-encrypt every stored TOTP secret, verify, and only then retire the
  old key. Dropping the old key before re-encryption completes locks
  every enrolled user out of 2FA. Follow the runbook — do not improvise
  this one.

Procedure (for the two signing secrets; TOTP keys follow the runbook):

1. Generate new key(s): `python -c "import secrets; print(secrets.token_urlsafe(64))"`
2. Update `.env`
3. Restart: `sudo systemctl restart oralhistarchiv oralhistarchiv-scheduler`
4. Run the rotated secret's verification step from the runbook

### Rotating SHIBBOLETH_INTERNAL_SECRET

1. Generate new secret
2. Update `.env` with the new value
3. Update the `proxy_set_header X-Internal-Auth` line in the nginx config
   with the same new value
4. `sudo nginx -t && sudo systemctl reload nginx`
5. `sudo systemctl restart oralhistarchiv`
6. Test a Shibboleth login

Both values must match exactly. If they don't, Shibboleth callbacks are
rejected with a log warning.

### Emergency procedures

**Application won't start:**

```bash
sudo journalctl -u oralhistarchiv -n 50 --no-pager
sudo journalctl -u oralhistarchiv-scheduler -n 50 --no-pager
```

**Scheduler stopped syncing:**

```bash
# Check if the process is running
sudo systemctl status oralhistarchiv-scheduler

# Check last sync status in the DB
psql -U oralhistarchiv -d oralhistarchiv -c \
    "SELECT last_harvest_date, last_sync_error FROM sync_status WHERE id = 1"

# Restart it
sudo systemctl restart oralhistarchiv-scheduler
```

**Database connection failed:**

```bash
sudo systemctl status postgresql
sudo -u oralhistarchiv psql -d oralhistarchiv -c "SELECT 1"
```

**Database pool exhausted:**

```bash
# Check for pool exhaustion warnings in the journal
sudo journalctl -u oralhistarchiv -o cat | jq 'select(.message | contains("DB pool exhausted"))'

# Check active connections in postgres
sudo -u postgres psql -d oralhistarchiv -c \
    "SELECT pid, application_name, state, query_start, state_change FROM pg_stat_activity WHERE datname = 'oralhistarchiv'"

# If connections are stuck, consider increasing DATABASE_POOL_SIZE in .env
```

**Redis connection failed:**

```bash
sudo systemctl status redis-server
redis-cli ping
# Rate limiting and cache invalidation will degrade gracefully if Redis
# is unreachable, but the app will log warnings. Web requests will still
# be served.
```

**Restore from backup:**

```bash
sudo systemctl stop oralhistarchiv oralhistarchiv-scheduler
pg_restore -U oralhistarchiv -d oralhistarchiv --clean /path/to/backup.dump
sudo systemctl start oralhistarchiv oralhistarchiv-scheduler
```

**Force restart everything:**

```bash
sudo systemctl restart postgresql redis-server
sudo systemctl restart oralhistarchiv oralhistarchiv-scheduler
sudo systemctl restart nginx
```
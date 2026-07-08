# Runbook — Secret & Key Rotation

**Applies to:** Digital Oral History Archive (`oralhistarchiv`)
**Audience:** Operators / on-call. Assumes shell access to the host and to wherever production secrets are provisioned.
**Status:** Living document — update when secrets are added or the deployment changes.

> **Golden rules (read before doing anything):**
> 1. **Never** set `TOTP_ENCRYPTION_KEYS` to an empty list (the app refuses to start; `min_length=1` enforces this).
> 2. During a TOTP-key rotation, **never remove the old key until every stored secret has been re-encrypted under the new one.** Removing it early locks every affected user out of 2FA (`decrypt` → `InvalidToken` → `get_totp_secret` returns `None`).
> 3. After changing **any** secret, **restart both** the web service and the scheduler — the encryption/HMAC keys are module-level globals cached at import, so a running process keeps the old value until restarted.
> 4. Keep the **old** secret value available until the rotation is verified complete. Don't destroy it prematurely.
> 5. Production secrets are **not** in `.env`. The `.env` file is only loaded when `ENV_STATE=dev`. In staging/production, secrets come from the process environment (the systemd unit's `EnvironmentFile` or your secrets store).

---

## 0. Secret inventory

| Secret | Type | Protects | Rotation cost | Blast radius of rotation |
|---|---|---|---|---|
| `TOTP_ENCRYPTION_KEYS` | Encryption (Fernet/`MultiFernet`) | TOTP secrets at rest | **High** — needs re-encryption | None if done correctly; **2FA lockout** if old key dropped early |
| `SECRET_KEY` | Signing + keyed hash | Password-reset / e-mail-verification / e-mail-change token signatures; audit e-mail-hash | Low | In-flight links die; audit-hash correlation breaks at the boundary |
| `SESSION_SECRET` | Signing + HMAC | Session cookie signatures; CSRF token HMAC | Low | **All users logged out**; CSRF self-heals on next GET |
| `DATABASE_URL` (password) | Credential | DB access | Medium | App can't reach DB until both sides match |
| `SMTP_PASSWORD` | Credential | Outbound mail auth | Low | Mail send fails until updated (caught by `verify_smtp_tls` / `security_email_failed`) |
| `SHIBBOLETH_INTERNAL_SECRET` | Shared secret | nginx→app callback authenticity | Medium | SSO login breaks until nginx **and** app match |
| `HEALTH_DETAIL_TOKEN` | Bearer token | `/health/detail` access | Low | Monitoring loses detail until clients updated |
| `REDIS_URL` (password) | Credential | Rate-limit / cache backend | Low | Falls back to single-worker / local cache until updated |
| `ADMIN_SEED_PASSWORD` | Bootstrap | First admin creation only | n/a | Inert once an admin exists — just remove it |

**Cryptographic domain separation (for reference — do not change casually):** `SECRET_KEY` feeds two HKDF contexts, `oralhistarchiv-totp-encryption-v1` *(historical — moved to `TOTP_ENCRYPTION_KEYS`)* and `oralhistarchiv-audit-email-hash-v1`; `SESSION_SECRET` feeds the cookie signer (salt `session-cookie-v1`) and the CSRF HMAC (prefix `csrf-hmac-v1|`). Bumping a context/version string is itself a form of rotation (it changes the derived key) and has the same blast radius as rotating the underlying secret.

---

## 1. When to rotate

Rotate **immediately** on:
- Confirmed or suspected exposure of a secret (committed to git, leaked in logs/screenshare, copied off-host).
- Host or secrets-store compromise.

Rotate **promptly** on:
- Offboarding of anyone who had access to production secrets.
- Post-incident hygiene after any security event.

Rotate **on a schedule** per org policy (suggested baseline: signing keys yearly; credentials per the upstream system's policy). Encryption-key rotation is heavier — do it on a schedule only if your compliance posture requires it, otherwise rotate on cause.

---

## 2. Generating new secrets

```bash
# SECRET_KEY, SESSION_SECRET, and each TOTP_ENCRYPTION_KEYS entry:
python -c "import secrets; print(secrets.token_urlsafe(64))"

# HEALTH_DETAIL_TOKEN, SHIBBOLETH_INTERNAL_SECRET:
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Each new value must clear `validate_security_settings` (length ≥ 43 — exactly the length `token_urlsafe(32)` produces, i.e. 256 bits — sufficient entropy, not a blocklisted/placeholder string). A weak or placeholder value will **block production startup** by design — generate a real one.

**Where to set them:**
- **Dev:** edit `.env`.
- **Staging/production:** edit the production environment source (the systemd unit's `EnvironmentFile`, e.g. `/etc/oralhistarchiv/oha.env`, or your secrets manager — see `Deployment.md` for the exact mechanism). A value placed in a production `.env` is **ignored**.

**Applying a change** (env vars are read at process start, so a reload is not enough):
```bash
sudo systemctl restart oralhistarchiv.service
sudo systemctl restart oralhistarchiv-scheduler.service
# confirm clean startup (validate_security_settings passed, no key errors):
journalctl -u oralhistarchiv.service -n 50 --no-pager
```
> A restart causes a brief blip. For this low-traffic deployment that's acceptable; schedule a short maintenance window if you prefer.

---

## 3. Rotating `SECRET_KEY` (signing + audit hash)

**Effect:** Outstanding signed links become invalid (bad signature). Audit e-mail-hash values produced under the old key no longer correlate with new ones (old log lines keep their old hashes; that's fine). **TOTP secrets are unaffected** — they moved to `TOTP_ENCRYPTION_KEYS` in the SEC-012 change (TOTP encryption re-keyed from SECRET_KEY-derived Fernet onto the independent `TOTP_ENCRYPTION_KEYS`), and that split is the whole point.

Token lifetimes you're invalidating:
- Password reset: **30 min** (`RESET_TOKEN_MAX_AGE_SECONDS`)
- E-mail change: **1 h** (`EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS`)
- E-mail verification: **24 h** (`VERIFICATION_TOKEN_MAX_AGE_SECONDS`)

**Procedure**
1. Generate a new `SECRET_KEY` (§2).
2. Replace the value in the environment source.
3. Restart both services (§2) and confirm clean startup.
4. Verify: request a fresh password-reset e-mail and confirm the new link works; confirm an *old* outstanding link now shows the "invalid or expired" page.

**Notes**
- For a routine (non-compromise) rotation where you want to minimise user friction, you may announce a maintenance window or simply accept that the small number of users mid-flow must re-request their link. For a **compromise**, rotate now and accept the breakage.
- Do **not** revert to the old value after a compromise rotation (it would re-validate attacker-usable tokens).

---

## 4. Rotating `SESSION_SECRET` (sessions + CSRF)

**Effect:** Every session cookie fails signature validation → **all users are logged out** and must log in again. CSRF cookies stop matching and are **regenerated automatically on the next GET**, so no user action is needed there. Server-side session rows are orphaned (unreachable) and expire naturally via `cleanup_expired_sessions`.

**Procedure**
1. Generate a new `SESSION_SECRET` (§2).
2. Replace the value; restart both services; confirm clean startup.
3. Verify: confirm you are logged out, log back in, and submit any form (e.g. change display name) to confirm CSRF works end-to-end.

Use this for a session-token compromise, or as a deliberate "force everyone to re-authenticate" action.

---

## 5. Rotating `TOTP_ENCRYPTION_KEYS` (the careful one)

This is the only rotation with a data-migration step. `_get_fernet()` builds a `MultiFernet` over the list: **the first key encrypts; all keys decrypt.** Rotation = add the new key to the front, re-encrypt everything under it, then drop the old key.

> ⚠️ **Re-read Golden Rule #2.** The old key must stay in the list until 100% of stored secrets are re-encrypted under the new key.

### Phase A — introduce the new key
1. Generate a new key (§2).
2. **Prepend** it so the list is `[new, old]`:
   ```properties
   # dev .env  (prod: same value in the systemd EnvironmentFile / secrets store)
   TOTP_ENCRYPTION_KEYS=["<new-token-urlsafe-64>", "<old-token-urlsafe-64>"]
   ```
3. Restart both services; confirm clean startup. State now:
   - New enrollments and re-encryptions use **new**.
   - Existing secrets (encrypted under **old**) still decrypt because **old** is still present.

### Phase B — re-encrypt existing secrets under the new key
Choose **one** path.

**B1 — Lazy (only if the login re-encryption hook is implemented):** each user's secret is re-encrypted on their next successful TOTP login. Monitor coverage; set a deadline by which any not-yet-rotated users will be handled by B2.

**B2 — Eager / break-glass (one-off script).** Run it in the **rotation-state environment** (so the app's `MultiFernet` is `[new, old]`). It uses `MultiFernet.rotate()`, which decrypts under any key and re-encrypts under the front (new) key — consistent with the app's HKDF stretching because it reuses the app's instance. (The pool and cursor helpers are async, hence the `asyncio` wrapper; `dict_row` gives the by-name row access the script relies on.)

```python
# scripts/reencrypt_totp.py  — run with the SAME env as the app (TOTP_ENCRYPTION_KEYS=[new, old])
import asyncio

from psycopg.rows import dict_row

from app.services.crypto import _fernet_instance      # MultiFernet over [new, old]
from app.services.db import create_pool, get_db_cursor


async def main() -> None:
    pool = create_pool("oralhistarchiv-reencrypt")
    await pool.open()
    try:
        async with get_db_cursor(pool, row_factory=dict_row) as cur:
            # both columns hold Fernet ciphertext; pending is short-lived but rotate it too for safety
            await cur.execute(
                "SELECT id, totp_secret, pending_totp_secret FROM users "
                "WHERE totp_secret IS NOT NULL OR pending_totp_secret IS NOT NULL"
            )
            rows = await cur.fetchall()

            n = 0
            for row in rows:
                updates, params = [], []
                for col in ("totp_secret", "pending_totp_secret"):
                    ct = row[col]
                    if ct:
                        rotated = _fernet_instance.rotate(ct.encode()).decode()  # -> encrypted under NEW
                        updates.append(f"{col} = %s"); params.append(rotated)
                if updates:
                    params.append(row["id"])
                    await cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = %s", params)
                    n += 1
    finally:
        await pool.close()
    print(f"re-encrypted secrets for {n} user(s)")


asyncio.run(main())
```

### Phase C — verify, then retire the old key
1. **Verify** every secret now decrypts under **new alone** before removing **old**. Quick check:
   ```python
   # run with TOTP_ENCRYPTION_KEYS=["<new-only>"]  (simulate the post-removal state)
   import asyncio

   from psycopg.rows import dict_row

   from app.services.crypto import decrypt_value
   from app.services.db import create_pool, get_db_cursor


   async def main() -> None:
       pool = create_pool("oralhistarchiv-verify")
       await pool.open()
       try:
           async with get_db_cursor(pool, row_factory=dict_row) as cur:
               await cur.execute("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL")
               rows = await cur.fetchall()
       finally:
           await pool.close()
       bad = [r["id"] for r in rows if decrypt_value(r["totp_secret"]) is None]
       print("FAIL — still encrypted under old key:", bad) if bad else print("OK — all decrypt under new key")


   asyncio.run(main())
   ```
   If `bad` is non-empty, **do not proceed** — re-run Phase B for those rows (or keep `[new, old]` and let the lazy hook finish).
2. Remove **old** from the list → `["<new>"]`. Restart both services; confirm clean startup.
3. Verify a real TOTP login succeeds end-to-end.

**Pending secrets caveat:** `pending_totp_secret` has a 10-minute TTL. If an enrollment is mid-flight under the old key when you drop it, that one enrollment fails to decrypt and the user simply restarts setup — negligible impact. The script above re-encrypts pending secrets anyway.

**Rollback:** while `old` is still in the list, you can revert the front key by removing `new` and restarting — old ciphertext is unaffected. Once `old` is dropped and secrets are re-encrypted under `new`, that's the committed state.

---

## 6. Operational credentials (brief)

These rotate independently; the principle is "change both ends, then restart, so they never drift."

- **`DATABASE_URL` password:** `ALTER ROLE <user> PASSWORD '<new>';` in Postgres → update the secret → restart both services. (Schedule a window: there's a moment where old connections still use the old password until workers recycle.)
- **`SMTP_PASSWORD`:** rotate at the provider → update → restart. Confirm via a test reset e-mail; `verify_smtp_tls` and the `security_email_failed` audit event will surface a mismatch.
- **`SHIBBOLETH_INTERNAL_SECRET`:** must equal the value nginx injects as `X-Internal-Auth`. Update **nginx** and the **app secret** to the same new value, then `nginx -s reload` **and** restart the app. A mismatch causes the callback to reject (SSO login fails) — do them together.
- **`HEALTH_DETAIL_TOKEN`:** generate new → update → restart → update monitoring clients' bearer token.
- **`REDIS_URL` password:** rotate at Redis → update → restart.
- **`ADMIN_SEED_PASSWORD` / `ADMIN_SEED_EMAIL`:** inert once any admin exists. Remove them from the environment after initial setup (their presence is a standing risk if the secret store leaks).

---

## 7. Post-rotation checklist

- [ ] App started cleanly on both services (`journalctl` shows `validate_security_settings` passed, no decrypt/key errors).
- [ ] `/health` returns `{"status": "alive"}`; `/health/detail` reachable with the (possibly new) token.
- [ ] The rotated secret's specific verification (per §3–§6) passed.
- [ ] For `TOTP_ENCRYPTION_KEYS`: Phase C verification clean **before** the old key was dropped.
- [ ] Old secret value retained until the above is green, then securely destroyed.
- [ ] Change recorded (what, when, why, by whom) in your ops log.

---

## 8. Pre-production note

Several rotation conveniences are currently deferred on the basis that the database can be wiped during development. **That ceases to be true at the first real user enrolment.** Before production go-live, confirm: the lazy re-encryption hook (§5/B1) is implemented *or* the eager script (§5/B2) is tested; this runbook has been dry-run once in staging; and production secrets are provisioned outside `.env`. After that point, "nuke and re-seed" is no longer an available recovery path for TOTP data.

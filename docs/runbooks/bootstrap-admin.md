# Initial administrator bootstrap

The first local administrator is created by a one-shot terminal command.
Neither the web service nor scheduler accepts `ADMIN_SEED_EMAIL` or
`ADMIN_SEED_PASSWORD`. Remove those legacy assignments before starting a new
release. Service restarts never create an administrator automatically.

Keep public access closed until initial enrollment is complete. Choose a fresh
email address and a newly generated password; documentation examples are
explicitly rejected. The command refuses to promote an account that already
uses the address. Concurrent invocations serialize and do not create additional
administrators after one exists.

On the reference systemd deployment, run the installed command using the web
profile and an interactive terminal:

```sh
sudo systemd-run --pty --wait --collect \
  --property=User=oralhistarchiv \
  --property=Group=oralhistarchiv-proxy \
  --property=SupplementaryGroups=oralhistarchiv-deploy-lock \
  --property=WorkingDirectory=/opt/oralhistarchiv \
  --property=EnvironmentFile=/etc/oralhistarchiv/common.env \
  --property=EnvironmentFile=/etc/oralhistarchiv/web.env \
  /usr/bin/flock --shared --timeout 60 --no-fork \
  /run/lock/oralhistarchiv-deploy.lock \
  /opt/oralhistarchiv/.venv/bin/python -I \
  /opt/oralhistarchiv/scripts/bootstrap_admin.py --email operator@example.org
```

The protected profiles must supply an explicit `ENV_STATE` and the normal web
database and authentication configuration. Do not add bootstrap credentials to
them. The password is requested twice without terminal echo and is never a
command-line argument. Piped input is rejected. The command exits after its
guarded database transaction and closes its pool.

Start the web service behind an operator-only network boundary, log in and
complete authenticator enrollment. Keep the password and newly issued recovery
codes in their approved separate custody. Verify a fresh MFA login before
opening ordinary access. A password copied before enrollment remains a threat;
the restricted enrollment window is part of bootstrap, not a substitute for
MFA.

For development, explicitly export `ENV_STATE=dev` before running the same
command from the project root. Only that explicit selection allows development
dotenv settings to load.

# Browser security cookies and request origins

Staging and production use host-prefixed security cookies with `Secure`,
`HttpOnly`, `Path=/`, no `Domain` and `SameSite=Strict`. The default names are
`__Host-oha_session`, `__Host-oha_pre_session` and `__Host-oha_csrf`. A custom
session name must retain the host prefix and remain distinct from the two
fixed names. Deletion responses use the same secure attributes.

Old unprefixed names are not accepted under the hardened policy. Plan for users
to sign in again at this cutover. Duplicate active security-cookie names are
rejected before account lookup, rather than selecting whichever value a cookie
parser happened to keep.

Ordinary browser mutations require an `Origin` matching `PUBLIC_BASE_URL`.
When `Origin` is absent, a same-origin `Referer` is accepted. Missing both
headers, ambiguous repeated headers, `Origin: null` and sibling origins are
rejected in staging and production. Existing token-bound capability exceptions
remain limited to their exact route contract. HMAC-bound form protection remains
required on the ordinary mutation routes.

# Explicit environment and registration policy

Application runtimes and source-policy commands require the exact uppercase OS variable `ENV_STATE`, with the
value `dev`, `staging` or `production`. Alternate spellings and case collisions
fail before settings are loaded. A dotenv file cannot choose or change this
mode, and is used only after explicit `ENV_STATE=dev` selection.

New local registration is disabled by default in staging and production. Set
`LOCAL_REGISTRATION_ENABLED=true` explicitly when it is intended. Development
keeps its existing enabled default. Disabling new registration does not disable
existing local login, recovery or eligible pending setup completion.
`LOCAL_AUTH_ENABLED` is obsolete and is rejected with replacement guidance.

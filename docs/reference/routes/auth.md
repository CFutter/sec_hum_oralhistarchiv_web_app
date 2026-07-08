# Auth Routes

The authentication subsystem is split across eight route modules under `app.routes.auth`, plus a small `helpers` module. Each module owns one cohesive slice of the auth flow.

For the conceptual model — sessions, TOTP enforcement, email verification, password-reset enumeration protection, CSRF wiring — see [Architecture → Authentication & Sessions](../../architecture/auth.md).

## Module map

| Module | Routes | Purpose |
|---|---|---|
| `login` | `GET/POST /login`, `POST /logout`, `GET /auth/shibboleth/callback` | Local login, logout, Shibboleth callback |
| `register` | `GET/POST /register`, `GET/POST /send_verification` | Local account creation and verification-email resend |
| `verify_email` | `GET /verify-email/{token}`, `POST /verify-email` | Confirm an email address: the GET is safe (shows a confirm page without consuming the token); the POST consumes it |
| `totp` | `GET/POST /setup-totp`, `GET/POST /account/reset-totp` | TOTP enrollment and authenticator change |
| `password_reset` | `GET/POST /forgot-password`, `GET/POST /reset-password/{token}` | Password reset flow |
| `account` | `GET /account`, `POST /account/change-name` | Account page and self-service display-name change |
| `email_change` | `GET/POST /account/change-email`, `GET /account/confirm-email/{token}`, `POST /account/confirm-email` | Self-service email change (same safe-GET / consuming-POST pattern as verification) |
| `admin` | `GET /admin`, `POST /admin/users/{id}/...` | Admin dashboard and user management |
| `helpers` | — | Shared helpers (`safe_redirect_url`, `generate_totp_qr`, `require_local_auth`) |

The individual routers are combined in `app.routes.auth.__init__` into a single `auth_router` that is mounted on the application in `main.py`. (`logout` is a POST so it is CSRF-protected; the Shibboleth callback is a GET on `/auth/shibboleth/callback` that the nginx SP layer targets. The two token-consuming confirm POSTs — `/verify-email` and `/account/confirm-email` — deliberately skip `verify_csrf`, because the signed single-use token itself is the capability and the click may come from a device with no app cookies; see the source comments.)

## `app.routes.auth.login`

::: app.routes.auth.login

## `app.routes.auth.register`

::: app.routes.auth.register

## `app.routes.auth.verify_email`

::: app.routes.auth.verify_email

## `app.routes.auth.totp`

::: app.routes.auth.totp

## `app.routes.auth.password_reset`

::: app.routes.auth.password_reset

## `app.routes.auth.account`

::: app.routes.auth.account

## `app.routes.auth.email_change`

::: app.routes.auth.email_change

## `app.routes.auth.admin`

::: app.routes.auth.admin

## `app.routes.auth.helpers`

::: app.routes.auth.helpers

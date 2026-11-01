# Auth Routes

Authentication routes and shared helpers live under `app.routes.auth`.

For the conceptual model — sessions, TOTP enforcement, email verification, password-reset enumeration protection, CSRF wiring — see [Architecture → Authentication & Sessions](../../architecture/auth.md).

## Module map

| Module | Routes |
|---|---|
| `login` | `GET/POST /login`, `POST /logout`, `GET /auth/shibboleth/callback` |
| `register` | `GET/POST /register`, `GET/POST /send_verification` |
| `verify_email` | `GET /verify-email/{public_id}`, `POST /verify-email` |
| `totp` | `GET/POST /setup-totp`, `GET/POST /account/reset-totp`, `POST /account/reset-totp/confirm` |
| `totp_recover` | `GET/POST /recover-totp` |
| `password_reset` | `GET/POST /forgot-password`, `GET /reset-password/{public_id}`, `POST /reset-password`, `POST /unlock-account` |
| `password_change` | `GET/POST /account/change-password` |
| `account` | `GET /account`, `POST /account/change-name` |
| `account_deletion` | `GET/POST /account/delete`; `GET/POST /admin/users/{user_id}/delete` |
| `admin_promotion` | `GET /account/admin-promotion`; `POST /account/admin-promotion/prepare`, `/accept`, `/decline` |
| `email_change` | `GET/POST /account/change-email`, `GET /account/confirm-email/{public_id}`, `POST /account/confirm-email` |
| `admin` | `GET /admin`; `GET/POST /admin/users/{user_id}/totp-recovery`; `POST /admin/users/{user_id}/approve-federated`, `/set-active`, `/set-tier`, `/set-admin`, `/cancel-admin-promotion`, `/change-email` |
| `helpers` | No routes; redirect validation and QR generation |
| `datasets` | `GET /admin/datasets`, `GET /admin/datasets/{dataset_id}`, `POST /admin/datasets/{dataset_id}/state` |

`SecureAPIRouter` supplies exact-route access policies and mutation defaults. `app.routes.auth.routers` feeds the validated application collection. Only `POST /account/confirm-email` omits CSRF; form-content validation remains. Email-action GETs validate only public-ID shape and render generic forms without account lookups or credentials. Their POSTs require the bound public ID and secret token; registration/reset retain CSRF. See [Authentication & Sessions](../../architecture/auth.md) for federation and credential-state contracts.

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

## `app.routes.auth.password_change`

::: app.routes.auth.password_change

## `app.routes.auth.account`

::: app.routes.auth.account

## `app.routes.auth.account_deletion`

::: app.routes.auth.account_deletion

## `app.routes.auth.email_change`

::: app.routes.auth.email_change

## `app.routes.auth.admin`

::: app.routes.auth.admin

## `app.routes.auth.helpers`

::: app.routes.auth.helpers

## `app.routes.auth.admin_promotion`

::: app.routes.auth.admin_promotion

## `app.routes.auth.totp_recover`

::: app.routes.auth.totp_recover

## `app.routes.auth.datasets`

::: app.routes.auth.datasets
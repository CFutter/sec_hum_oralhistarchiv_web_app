# Application Entry

Application construction and shared helpers. See [Architecture](../architecture/overview.md) for startup and [Request Lifecycle](../architecture/request-lifecycle.md) for request ordering.

## `app.main`

::: app.main

## `app.paths`

::: app.paths

## `app.template_setup`

::: app.template_setup

## `app.jinja_helpers`

::: app.jinja_helpers

## `app.url_safety`

Absolute HTTP(S) URL validation for external metadata links. Post-login redirect validation is separate and accepts same-site paths in `app.routes.auth.helpers`.

::: app.url_safety

## `app.request_utils`

::: app.request_utils
## Runtime and shared contracts

::: app

::: app.cookie_contract

::: app.credentials

::: app.doi

::: app.exceptions

::: app.federation_contract

::: app.migrate

::: app.runtime_preflight

::: app.thread_work

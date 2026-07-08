# Application Entry

The top-level FastAPI application object, the `lifespan` context manager that owns startup and shutdown, the middleware wiring, and the global exception handlers.

For a narrative walkthrough of what happens during startup and how a request flows through the middleware stack, see [Architecture → Request Lifecycle](../architecture/request-lifecycle.md).

## `app.main`

::: app.main

## `app.paths`

Centralized path constants used throughout the application — template directory, static directory, project root.

::: app.paths

## `app.template_setup`

Shared Jinja2 environment configuration and global registrations. All routes import `templates` from this module rather than constructing their own environment, so template globals (CSRF token, `url_for_query`, etc.) are consistent across the application.

::: app.template_setup

## `app.jinja_helpers`

Template helper functions registered on the Jinja2 environment. The most important is `url_for_query`, which preserves existing query parameters when generating links — used by the search pagination and facet filters to keep state across navigation.

::: app.jinja_helpers

## `app.url_safety`

The shared `http(s)`-scheme allowlist check. It is the single definition consumed by the OAI client (validating upstream URLs at parse time), by the `safe_url` Jinja filter (the last line of defense before a URL is rendered into an `href`), and by the redirect validation in the auth helpers — so a `javascript:` or `data:` URL is rejected identically at every layer.

::: app.url_safety

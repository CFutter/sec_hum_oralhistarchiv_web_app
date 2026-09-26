# HTML Templates

Templates are under `src/app/templates`; all page templates extend `base.html`. Routes supply `request` and page context. `base.html` reads `request.state.user` and flash state; do not treat a hidden navigation control as authorization.

`app.template_setup` registers globals `csrf_token`, `get_flash`, `path_for`, `url_for_query`, `can_view_full`, `contact_email`, `is_production`, `shibboleth_enabled`, `local_registration_enabled`, `facet_label_max_chars`, and `required_shibboleth_authn_context`. Filters are `safe_url` (validated HTTP(S) URL or empty string), `doi_url` (safe DOI link), and `utc_datetime` (UTC display or em dash). HTML autoescaping is enabled; URL attributes still require URL validation. Keep POST form actions synchronized with named routes and include CSRF except for the two central capability exceptions.

## Layout chrome

| Template | Context and behavior |
|---|---|
| `base.html` | Shared head/navigation/footer, optional active_page, flash display, title/meta_description/content blocks; logout is a CSRF-protected POST |
| `error.html` | Optional error_title/error_message, with not-found defaults; routes and exception handlers choose status and text |

Templates escape supplied messages; callers must still avoid passing sensitive internal details.

## Public pages

| Template | Context and behavior |
|---|---|
| `home.html` | total_datasets, total_languages, total_keywords, last_full_rebuild, recent, user_tier; global dataset count, tier-scoped metadata counts, recent redacted cards |
| `search.html` | results/query, active filters, all_access_levels/all_keywords/all_languages, result_count/current_page/total_pages/result_window_limited, user_tier; exact filter suggestions and query-preserving pagination |
| `detail.html` | dataset, user_tier; full metadata or required-tier notice; SWISSUbase resource/landing link only when present and visible |
| `about.html` | Static project/source/contact copy using shared globals |

Home/search cards retain public title/access-level and a generic restricted notice. The exact required tier appears on the detail page. Services redact before rendering; templates additionally choose presentation with `can_view_full`.

## Account and authentication pages

These include public forms, signed-link capabilities, and authenticated pages; authorization belongs to route policies.

| Template | Context and behavior |
|---|---|
| `login.html` | Optional email/error; local password/TOTP form and configured institutional-login link |
| `register.html` | Optional error/email/display_name/affiliation/country; password plus confirmation are never echoed |
| `send_verification.html` | email and optional success; resend form or generic registration/resend result |
| `verify_email_pending.html` | email; setup route's unverified-email guidance, not the registration result |
| `confirm_verify_email.html` | token/email; POST confirmation without CSRF; GET does not consume token |
| `setup_totp.html` | totp_secret/totp_qr_data/recovery_codes/recovery_code_max_chars/error; confirms TOTP and one code; refresh/error rendering replaces staged recovery codes |
| `account.html` | user/admin_promotion; profile/tier/invitation; edits and authenticator controls only for local accounts |
| `change_email.html` | user/error and optional new_email; requires current password, then queues confirmation/notice |
| `confirm_email.html` | token/new_email/is_admin_initiated; capability POST commits address and revokes target sessions |
| `reset_totp.html` | error/password_max_chars; current password and current TOTP proof, no replacement seed |
| `reset_totp_confirm.html` | new_totp_secret/totp_qr_data/error; initial response shows replacement seed, retries show only the new-code form |
| `totp_recover.html` | email/error/recovery_code_max_chars/recovery_authorization_lifetime_minutes; password plus owner-retained code |
| `forgot_password.html` | error/success; request form or generic success result |
| `reset_password.html` | error/token/email; route validates capability; password_form macro renders new password/confirmation when token remains |
| `admin.html` | users/total_users/current_page/total_pages/page_size/page_size_options/admin_promotion_states; guarded account-management forms |
| `admin_totp_recovery.html` | target/error/current_page/page_size/admin_return_url/recovery_authorization_lifetime_minutes; consent plus actor TOTP, no target code disclosure |
| `admin_promotion.html` | promotion/error/recovery_code_max_chars; prepare, confirm already-staged codes, or decline |
| `admin_promotion_codes.html` | prepared/recovery_code_max_chars; one response containing plaintext codes and acceptance deadlines |
| `admin_totp_recovery_code.html` | Unused legacy template; references authorization.recovery_code, which the current authorization result does not provide; no route renders it |

Initial TOTP enrollment upgrades the existing session; recovery completion and rotation require login again. Email-link GETs do not complete changes: their POST buttons do. Rendering itself performs no authorization, token consumption, or password validation.

## Extending templates

Add or update a named route, its access policy, context contract, and form CSRF/content-type coverage together. Use `path_for` for route links, URL filters for external destinations, and redacted service results for datasets. Keep TOTP seeds and recovery codes out of URLs, logs, and hidden fields; setup/rotation services retain encrypted server-side state.


# HTML Templates

Templates are under `src/app/templates`; all page templates extend `base.html`. Routes supply `request` and page context. `base.html` reads `request.state.user` and flash state; do not treat a hidden navigation control as authorization.

`app.template_setup` registers globals `csrf_token`, `get_flash`, `path_for`, `url_for_query`, `access_tiers`, `can_view_full`, `site_name`, `institution_name`, `about_summary`, `federated_login_label`, `contact_email`, `is_production`, `shibboleth_enabled`, `local_registration_enabled`, `facet_label_max_chars`, `required_shibboleth_authn_context`, `can_view_field`, `field_required_tier`, `full_required_tier`, `local_email_max_chars`, `local_password_max_chars`, `local_password_min_chars`, `totp_code_raw_max_chars`, `action_token_max_chars`, and `local_display_name_max_chars`. Filters are `safe_url` (validated HTTP(S) URL or empty string), `doi_url` (safe DOI link), and `utc_datetime` (UTC display or em dash). HTML autoescaping is enabled; URL attributes still require URL validation. Keep POST form actions synchronized with named routes and include CSRF except for the exact central email-change capability exception.

`access_tiers` is the ordered tuple of metadata-tier names derived from `app.sources.AccessTier`: `public`, `registered`, and `vetted`. Both administrator tier selectors use this global. Account access tiers and dataset `visibility_tier` control metadata disclosure; dataset `access_level` labels describe upstream material restrictions and do not grant access to recordings. The About and Account pages describe the current dataset-level metadata rules, including the public discovery information visible below tier.

Shared styles include visually hidden labels (`sr-only`), vetted-tier badges, inactive-status badges, wrapping recovery-code lists, and administrator page-size controls. Visually hidden labels remain available to assistive technology; do not hide them with `display: none` or `aria-hidden`.

## Layout chrome

| Template | Context and behavior |
|---|---|
| `base.html` | Shared head/navigation/footer, optional active_page, flash display, title/meta_description/content blocks; logout is a CSRF-protected POST. `show_auth_navigation=false` omits account controls when identity has not been resolved. |
| `error.html` | Optional error_title/error_message, with not-found defaults; routes and exception handlers choose status and text. `error_return_route` and `error_return_label` select a named-route button; defaults return home. |

Templates escape supplied messages; callers must still avoid passing sensitive internal details.

## Public pages

| Template | Context and behavior |
|---|---|
| `home.html` | total_datasets, last_full_rebuild, recent, user_tier; live nonhidden dataset count, cached rebuild freshness, at most three recent redacted cards |
| `search.html` | results/query, filters/facets, current_page, cursor_pagination, next_page_url/previous_page_url and notice flags; result_count/total_pages are None; lookahead navigation without exact totals |
| `detail.html` | dataset, user_tier, configured_sources, source_display, resource_href/resource_kind; fields render independently; full permission gates Resource/LandingPage actions, preserving the original proxy index |
| `about.html` | source_statuses; configured source labels, optional sensitivity descriptions and finite synchronization badges, plus project/contact copy using shared globals |

About receives public `SourceStatus` projections rather than source configurations
or raw synchronization rows. Labels and sensitivity descriptions are escaped.
An absent sensitivity description displays “Not specified”; access policy does
not supply this description.

Home/search cards retain public title/access level and show field/full-record
requirements. Services redact first; templates use `can_view_field` with the
same `configured_sources` policy for each field.

## Account and authentication pages

These include public forms, signed-link capabilities, and authenticated pages; authorization belongs to route policies.

| Template | Context and behavior |
|---|---|
| `login.html` | Optional email/error/notice; fixed error or success feedback, local password/TOTP form, and configured institutional-login link |
| `register.html` | Optional error/email and email_max_chars; email-only request with CSRF |
| `send_verification.html` | email and optional success; resend form or generic registration/resend result |
| `verify_email_pending.html` | email; setup route's unverified-email guidance, not the registration result |
| `confirm_verify_email.html` | Public ID and generic setup fields on GET; token/email/profile values only after submitted proof; password/profile setup retains CSRF and never repopulates passwords |
| `setup_totp.html` | totp_secret/totp_qr_data/recovery_codes/recovery_code_max_chars/error; confirms TOTP and one code; refresh/error rendering replaces staged recovery codes |
| `account.html` | user/admin_promotion; profile/tier/invitation; edits and authenticator controls only for local accounts |
| `change_email.html` | user/error and optional new_email; current password plus fresh TOTP, then queues confirmation/notice |
| `confirm_email.html` | Public ID and generic confirmation on GET; public ID plus secret token in POST commit the address change and revoke target sessions |
| `reset_totp.html` | error/password_max_chars; current password and current TOTP proof, no replacement seed |
| `reset_totp_confirm.html` | new_totp_secret/totp_qr_data/error; initial response shows replacement seed, retries show only the new-code form |
| `totp_recover.html` | email/error/recovery_code_max_chars/recovery_authorization_lifetime_minutes; password plus owner-retained code |
| `forgot_password.html` | error/success; request form or generic success result |
| `reset_password.html` | Public ID, token/error/email; password-reset and unlock forms both require fresh TOTP; passwords are never repopulated |
| `admin.html` | users/total_users/current_page/total_pages/page_size/page_size_options/admin_promotion_states; guarded account-management forms |
| `admin_totp_recovery.html` | target/error/current_page/page_size/admin_return_url/recovery_authorization_lifetime_minutes; consent plus actor TOTP, no target code disclosure |
| `admin_promotion.html` | promotion/error/recovery_code_max_chars; prepare, confirm already-staged codes, or decline |
| `admin_promotion_codes.html` | prepared/recovery_code_max_chars; one response containing plaintext codes and acceptance deadlines |
| `change_password.html` | Optional error; current/new password, confirmation and fresh TOTP; passwords are never repopulated |
| `account_deletion.html` | target/admin_action/error; actor password/TOTP and explicit confirmation for self/admin deletion |
| `admin_datasets.html` | records, page_size, newer/older URLs, source/uuid and source_labels; bounded identity/state controls |
| `admin_dataset_detail.html` | record/source_label/error/notice; durable raise/hide/restore controls and independent quarantine guidance |

Login feedback uses fixed server-side mappings: `?error=` selects an error message and `?notice=` selects a success message. Recognized errors take precedence. Unknown codes are ignored, and failed login submissions never show query-supplied success notices. Error messages use `role="alert"`; success messages use `role="status"`. Query parameters are presentation hints and never establish account state or grant access. The existing `resubmit=1` guidance and safe `next` handling remain independent.

Initial TOTP enrollment, recovery completion and rotation end account sessions
and require login again. Email-action GETs render generic forms without
resolving the action target or exposing its PII or secret. Existing session
middleware and navigation may still reflect the signed-in browser itself. The
public URL contains no token, query or fragment. The user copies the separate
security code from the email into the visible HTML form field and submits it.
No JavaScript or automatic request/submission is involved. Every action POST
carries the public ID and secret token;
registration/reset also carry CSRF. Rendering itself performs no token
consumption or password validation. See [Action links](runbooks/action-links.md).

`action_token_fields.html` is the shared form partial. It renders the hidden
public ID and an initially visible manual-code input; a POST retry with a
usable token can keep that token hidden. The initial GET always leaves the
code field empty and visible. The action templates load no script, and their
security-code entry works under the existing CSP without JavaScript.

## Extending templates

Add or update a named route, its access policy, context contract, and form CSRF/content-type coverage together. Use `path_for` for route links, URL filters for external destinations, and redacted service results for datasets. Keep TOTP seeds and recovery codes out of URLs, logs, and hidden fields; setup/rotation services retain encrypted server-side state.


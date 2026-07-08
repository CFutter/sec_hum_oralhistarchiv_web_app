"""Admin routes at the client tier — the DB-less tier's admin coverage.

Before this file the unit/client tier had ZERO admin coverage (TEST-041: the
admin_client fixture existed but was used by no test), so a developer running
`pytest -m "not integration"` stayed green after regressing require_admin —
the only admin authz tests lived in the integration tier, which can be
skipped. These tests pin the 404 cloak, the CSRF rejection on the
highest-privilege mutation (TEST-018), the framework-level 422 for a garbage
tier value (TEST-026), and the not-found flash for stale admin forms on all
four mutation routes (TEST-025) — none of which need a database.
"""
from contextlib import ExitStack
from unittest.mock import patch

import pytest


def _patch(name, **kw):
    return patch(f"app.routes.auth.admin.{name}", autospec=True, **kw)


# ---------------------------------------------------------------------------
# require_admin — 404 cloak both directions (TEST-041)
# ---------------------------------------------------------------------------

def test_admin_dashboard_404_for_guest_and_non_admin(
    guest_client, authenticated_client
):
    """Both a guest and an ordinary authenticated user get a 404 (NEVER a
    403 — the cloak must not confirm the endpoint exists)."""
    for client in (guest_client, authenticated_client):
        resp = client.get("/admin", follow_redirects=False)
        assert resp.status_code == 404
        assert "Page not found" in resp.text


def test_admin_dashboard_renders_for_admin(admin_client):
    """Positive control (and the admin_client fixture's first consumer): an
    is_admin session gets the real dashboard, with the user list fetched."""
    with _patch("get_all_users", return_value=[]) as users:
        resp = admin_client.get("/admin")
    assert resp.status_code == 200
    users.assert_awaited_once()


def test_admin_mutation_404_for_non_admin_post(authenticated_client):
    """The cloak holds on POST too: a non-admin with a VALID CSRF pair gets
    404 from set-admin and the service is never reached."""
    with _patch("set_user_admin") as set_admin:
        resp = authenticated_client.post(
            "/admin/users/7/set-admin",
            data={"is_admin": "true",
                  "csrf_token": authenticated_client.csrf_token},
            follow_redirects=False,
        )
    assert resp.status_code == 404
    set_admin.assert_not_awaited()


# ---------------------------------------------------------------------------
# TEST-018 — CSRF on the highest-privilege mutation (behavioural companion
# to the structural canary in unit/test_route_guards.py)
# ---------------------------------------------------------------------------

def test_set_admin_without_csrf_token_is_403_and_writes_nothing(admin_client):
    """POST /admin/users/{id}/set-admin with NO csrf_token → 403 before the
    handler runs: no user lookup, no privilege write."""
    with _patch("get_user_by_id") as lookup, _patch("set_user_admin") as write:
        resp = admin_client.post(
            "/admin/users/7/set-admin",
            data={"is_admin": "true"},
            follow_redirects=False,
        )
    assert resp.status_code == 403
    lookup.assert_not_awaited()
    write.assert_not_awaited()


def test_set_admin_with_forged_csrf_token_is_403(admin_client):
    """A well-formed but non-HMAC-matching token fails the recompute → 403,
    no write."""
    with _patch("set_user_admin") as write:
        resp = admin_client.post(
            "/admin/users/7/set-admin",
            data={"is_admin": "true", "csrf_token": "deadbeef" * 8},
            follow_redirects=False,
        )
    assert resp.status_code == 403
    write.assert_not_awaited()


# ---------------------------------------------------------------------------
# TEST-026 — a garbage tier value is a 422, not a 500 (typed AccessTier Form)
# ---------------------------------------------------------------------------

def test_set_tier_with_unknown_tier_value_is_422_before_any_db_work(admin_client):
    """access_tier is typed as the AccessTier Literal, so 'root' must die in
    framework validation (422 branded page) before any user lookup or UPDATE.
    Loosening the annotation to str would turn this into an uncaught CHECK-
    constraint 500 on every mistyped submission."""
    with _patch("get_user_by_id") as lookup, _patch("update_access_tier") as write:
        resp = admin_client.post(
            "/admin/users/7/set-tier",
            data={"access_tier": "root",
                  "csrf_token": admin_client.csrf_token},
            follow_redirects=False,
        )
    assert resp.status_code == 422
    assert "Invalid request" in resp.text  # branded 422, not JSON
    lookup.assert_not_awaited()
    write.assert_not_awaited()


# ---------------------------------------------------------------------------
# TEST-025 — nonexistent user id: 303 + "User not found." on all 4 mutations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("path", "form", "service"),
    [
        ("/admin/users/999999/set-active", {"is_active": "false"}, "set_user_active"),
        ("/admin/users/999999/set-tier", {"access_tier": "vetted"}, "update_access_tier"),
        ("/admin/users/999999/set-admin", {"is_admin": "true"}, "set_user_admin"),
        ("/admin/users/999999/change-email", {"new_email": "x@uzh.ch"}, None),
    ],
)
def test_mutation_on_nonexistent_user_flashes_not_found(
    admin_client, path, form, service
):
    """A stale admin form (user deleted between page load and submit) must
    land back on /admin with the 'User not found.' flash — never a 500 from
    an unguarded service ValueError, and never a write."""
    with ExitStack() as stack:
        stack.enter_context(_patch("get_user_by_id", return_value=None))
        flash = stack.enter_context(_patch("set_flash"))
        writer = stack.enter_context(_patch(service)) if service else None

        resp = admin_client.post(
            path,
            data={**form, "csrf_token": admin_client.csrf_token},
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin"
    flash.assert_awaited_once()
    assert flash.await_args.args[2] == "User not found."
    assert flash.await_args.args[3] == "error"
    if writer is not None:
        writer.assert_not_awaited()

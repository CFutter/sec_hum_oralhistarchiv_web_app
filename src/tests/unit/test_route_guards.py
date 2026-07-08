"""Structural canaries over the live route table (TEST-005, TEST-017).

These iterate app.routes at import-cost-only and pin two app-wide invariants
that per-route behavioural tests cannot: *every* state-changing POST carries
Depends(verify_csrf), and *every* /admin path carries Depends(require_admin).
The failure mode they close is the FUTURE one — a new route added without the
guard ships a live CSRF hole / access-control hole while every existing test
stays green. ~15 lines each, they catch that class permanently.

The CSRF-exempt set is asserted EXACTLY (not just "no offenders") so a new
exempt POST cannot slip in silently: exemption must be a reviewed edit here.
"""
from fastapi.routing import APIRoute

from app.main import app
from app.middleware.content_type import validate_form_content_type
from app.middleware.csrf import verify_csrf
from app.middleware.session import require_admin

# Token-capability POSTs, deliberately CSRF-exempt BY DESIGN (documented in
# their route docstrings): the signed single-use token in the body is the
# capability; the click may come from a mail client with no app session.
CSRF_EXEMPT_POSTS = {
    "/verify-email",
    "/account/confirm-email",
}


def _api_routes():
    return [r for r in app.routes if isinstance(r, APIRoute)]


def _post_routes():
    return [r for r in _api_routes() if "POST" in r.methods]


def _dependency_calls(route):
    return {d.call for d in route.dependant.dependencies}


def test_route_table_is_populated():
    """Anti-vacuity control for this module: if app.main stops registering
    routers, the canaries below would pass over an empty list. Pin the
    known-surface floor instead (14 CSRF-wired POSTs + 2 exempt = 16)."""
    posts = _post_routes()
    assert len(posts) >= 16, f"only {len(posts)} POST routes collected"
    admin = [r for r in _api_routes() if r.path.startswith("/admin")]
    assert len(admin) >= 5, f"only {len(admin)} /admin routes collected"


def test_every_state_changing_post_enforces_csrf():
    """TEST-005: the design is dependency-per-route; the exempt set must
    match EXACTLY. A POST route missing verify_csrf (or a new 'exempt' one
    nobody reviewed) fails immediately."""
    unprotected = {
        r.path for r in _post_routes()
        if verify_csrf not in _dependency_calls(r)
    }
    assert unprotected == CSRF_EXEMPT_POSTS, (
        f"POST routes without verify_csrf: {sorted(unprotected - CSRF_EXEMPT_POSTS)}"
        f" / documented-exempt routes that vanished: "
        f"{sorted(CSRF_EXEMPT_POSTS - unprotected)}"
    )


def test_every_csrf_protected_post_validates_content_type():
    """Companion invariant: every CSRF-protected POST also carries
    validate_form_content_type (the 415 gate) — the documented dependency
    convention in middleware/__init__.py. A form route accepting arbitrary
    content types re-opens content-type-confusion CSRF vectors."""
    offenders = [
        r.path for r in _post_routes()
        if verify_csrf in _dependency_calls(r)
        and validate_form_content_type not in _dependency_calls(r)
    ]
    assert not offenders, (
        f"CSRF-protected POSTs missing validate_form_content_type: {offenders}"
    )


def test_every_admin_path_requires_admin():
    """TEST-017: today require_admin is router-level on the one admin router;
    this pins the INVARIANT (any route whose path lives under /admin carries
    it) so an admin endpoint added to a different router without the guard —
    an export/report route, say — fails a unit test instead of shipping an
    access-control hole."""
    offenders = [
        r.path for r in _api_routes()
        if (r.path == "/admin" or r.path.startswith("/admin/"))
        and require_admin not in _dependency_calls(r)
    ]
    assert not offenders, f"/admin routes missing require_admin: {offenders}"

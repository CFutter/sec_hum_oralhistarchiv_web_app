"""E2E page-route tests — real PostgreSQL, real CatalogueStatsCache, real middleware.

Covers home & search rendering through the REAL async CatalogueStatsCache
(the requests that would hand a template a coroutine if the cache were called
through run_in_threadpool), plus tier redaction on the detail page, the search
presence-oracle gating in search_datasets, ILIKE wildcard escaping, the
empty-page pagination redirect, and the full login/logout cookie roundtrip.
"""

import logging

from config import settings
from tests.integration.conftest import login_with_totp as _login_with_totp


def _audit_records(caplog, event_type):
    """All records on the 'audit' channel with the given event_type."""
    return [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == event_type
    ]


# ---------------------------------------------------------------------------
# Home & search render through the real async CatalogueStatsCache
# ---------------------------------------------------------------------------


def test_home_and_search_render_for_guest_and_authenticated(
    e2e_client, user_factory, dataset_factory
):
    """GET / and GET /search return 200 for a guest AND for an
    authenticated user (a second tier — the cache holds one entry per tier).

    The routes must await the async get_cached_facets directly: calling it
    through run_in_threadpool hands the template a coroutine —
    "'coroutine' object has no attribute 'get'" → 500 on every page load.
    """
    for _ in range(3):
        dataset_factory()

    # Guest (public tier) — first request populates the 'public' cache entry.
    home = e2e_client.get("/")
    assert home.status_code == 200
    # The datasets count is rendered from real DB data, not a coroutine.
    assert '<span class="stat-number">3</span>' in home.text

    search = e2e_client.get("/search")
    assert search.status_code == 200
    assert "3 datasets found" in search.text

    # Authenticated at a different tier — a second, lazily-built cache entry.
    _login_with_totp(e2e_client, user_factory, access_tier="registered")

    home2 = e2e_client.get("/")
    assert home2.status_code == 200
    assert '<span class="stat-number">3</span>' in home2.text

    search2 = e2e_client.get("/search")
    assert search2.status_code == 200
    assert "3 datasets found" in search2.text


# ---------------------------------------------------------------------------
# Detail page — tier redaction + audit trail
# ---------------------------------------------------------------------------


def test_detail_redacts_below_tier_and_audits_access(
    e2e_client, user_factory, dataset_factory, caplog
):
    """SB-DISC-002/003: a vetted-tier detail page deliberately shows its
    public discovery title/access level to a guest but not its full description.
    A vetted user sees the description; each non-public access emits an audit
    event with the correct access_granted flag.
    """
    ds_id = dataset_factory(
        visibility_tier="vetted",
        description="SENSITIVE-DETAIL-TEXT",
        title="Public Title",
        keywords=["sec-kw"],
        languages=["German"],
        authors=["A. Author"],
    )

    with caplog.at_level(logging.INFO, logger="audit"):
        # Guest: 200 with the redacted view — title yes, description no.
        guest_view = e2e_client.get(f"/dataset/{ds_id}")
        assert guest_view.status_code == 200
        assert "Public Title" in guest_view.text
        assert "SENSITIVE-DETAIL-TEXT" not in guest_view.text
        assert "Restricted Dataset" in guest_view.text

        denied = _audit_records(caplog, "dataset_access")
        assert len(denied) == 1
        assert denied[0].access_granted is False
        assert denied[0].user_tier == "public"
        assert denied[0].user_id is None
        caplog.clear()

        # Vetted user: full metadata visible, access audited as granted.
        vetted = _login_with_totp(e2e_client, user_factory, access_tier="vetted")
        full_view = e2e_client.get(f"/dataset/{ds_id}")
        assert full_view.status_code == 200
        assert "SENSITIVE-DETAIL-TEXT" in full_view.text

        granted = _audit_records(caplog, "dataset_access")
        assert len(granted) == 1
        assert granted[0].access_granted is True
        assert granted[0].user_tier == "vetted"
        assert granted[0].user_id == vetted.id


def test_detail_unknown_id_renders_branded_404(e2e_client):
    """/dataset/999999 renders the branded error.html with 404 — not a bare
    JSON error (pages.detail's not-found branch)."""
    resp = e2e_client.get("/dataset/999999")
    assert resp.status_code == 404
    assert "Dataset not found" in resp.text
    # Jinja autoescaping turns the apostrophe in "doesn't" into &#39;.
    assert "exist or has been removed" in resp.text


# ---------------------------------------------------------------------------
# Search — full-blob gating (the presence oracle)
# ---------------------------------------------------------------------------


def test_search_full_blob_matches_only_visible_rows(e2e_client, user_factory, dataset_factory):
    """SB-DISC-003/006: a guest querying a full-only DESCRIPTION gets zero
    results, while the curated TITLE still matches via the public-discovery
    search subset. A vetted user matches the description."""
    dataset_factory(
        visibility_tier="vetted",
        description="SENSITIVE-DETAIL-TEXT",
        title="Public Title",
    )

    # Guest probing the redacted description: nothing leaks.
    resp = e2e_client.get("/search", params={"q": "SENSITIVE-DETAIL-TEXT"})
    assert resp.status_code == 200
    assert "0 datasets found" in resp.text
    assert "Public Title" not in resp.text

    # Guest searching the title: public discovery search matches everywhere.
    resp = e2e_client.get("/search", params={"q": "Public Title"})
    assert resp.status_code == 200
    assert "1 dataset found" in resp.text
    assert "Public Title" in resp.text

    # Vetted user: the full blob (description) matches.
    _login_with_totp(e2e_client, user_factory, access_tier="vetted")
    resp = e2e_client.get("/search", params={"q": "SENSITIVE-DETAIL-TEXT"})
    assert resp.status_code == 200
    assert "1 dataset found" in resp.text
    assert "Public Title" in resp.text


def test_keyword_filter_is_tier_gated(e2e_client, user_factory, dataset_factory):
    """The ?keyword filter matches ONLY rows the user may fully see: a guest
    cannot confirm a hidden dataset carries a guessed keyword (0 results),
    while a vetted user filters normally (search_datasets keyword gate)."""
    dataset_factory(
        visibility_tier="vetted",
        title="Public Title",
        keywords=["sec-kw"],
    )

    resp = e2e_client.get("/search", params={"keyword": "sec-kw"})
    assert resp.status_code == 200
    assert "0 datasets found" in resp.text

    _login_with_totp(e2e_client, user_factory, access_tier="vetted")
    resp = e2e_client.get("/search", params={"keyword": "sec-kw"})
    assert resp.status_code == 200
    assert "1 dataset found" in resp.text
    assert "Public Title" in resp.text


def test_access_level_filter_is_deliberately_not_gated(e2e_client, dataset_factory):
    """The ?access_level filter is NOT tier-gated: access_level stays visible
    on redacted rows (it's in PUBLIC_DISCOVERY_FIELDS), so filtering on it
    reveals nothing new. A guest filtering access_level=restricted gets the
    redacted vetted-tier row back — title visible, per the explicit comment
    in search_datasets ("access_level is visible on redacted rows")."""
    dataset_factory(title="Open Dataset", access_level="public")
    dataset_factory(
        visibility_tier="vetted",
        title="Hidden But Listed",
        access_level="restricted",
        description="SENSITIVE-DETAIL-TEXT",
    )

    # Baseline: the ungated filter works for plainly visible rows.
    resp = e2e_client.get("/search", params={"access_level": "public"})
    assert resp.status_code == 200
    assert "1 dataset found" in resp.text
    assert "Open Dataset" in resp.text

    # The vetted-tier row IS returned to a guest — redacted, but listed.
    resp = e2e_client.get("/search", params={"access_level": "restricted"})
    assert resp.status_code == 200
    assert "1 dataset found" in resp.text
    assert "Hidden But Listed" in resp.text
    assert "SENSITIVE-DETAIL-TEXT" not in resp.text


# ---------------------------------------------------------------------------
# The middle tier — a 'registered' dataset AND a 'registered' logged-in actor
# ---------------------------------------------------------------------------


def test_registered_dataset_hidden_from_guest_visible_to_registered(
    e2e_client, user_factory, dataset_factory
):
    """A visibility_tier='registered' dataset must be invisible to a guest on
    BOTH gated search channels (full-text description match and ?keyword
    filter), and visible to a logged-in registered user on both. Flipping a
    single CASE copy's `WHEN 'registered' THEN 1` to `THEN 0` leaks
    middle-tier metadata to guests — this is the test that turns that
    mutation red."""
    dataset_factory(
        visibility_tier="registered",
        title="Reg DS",
        description="REG-SENSITIVE-TEXT",
        keywords=["reg-kw"],
    )

    # Guest (rank 0): neither channel may confirm the dataset's contents.
    resp = e2e_client.get("/search", params={"q": "REG-SENSITIVE-TEXT"})
    assert "0 datasets found" in resp.text
    resp = e2e_client.get("/search", params={"keyword": "reg-kw"})
    assert "0 datasets found" in resp.text

    # Positive control: the registered actor sees it through both channels.
    _login_with_totp(e2e_client, user_factory, access_tier="registered")
    resp = e2e_client.get("/search", params={"q": "REG-SENSITIVE-TEXT"})
    assert "1 dataset found" in resp.text
    assert "Reg DS" in resp.text
    resp = e2e_client.get("/search", params={"keyword": "reg-kw"})
    assert "1 dataset found" in resp.text


def test_registered_actor_is_below_vetted_tier(e2e_client, user_factory, dataset_factory):
    """The authenticated-but-below-tier direction (no actor ever tested it
    before): a REGISTERED user probing a VETTED dataset's description gets 0
    results and a redacted detail page — 'any authenticated user → full
    access' mapping bugs in _get_user_tier ship green without this."""
    ds_id = dataset_factory(
        visibility_tier="vetted",
        title="Vetted Title",
        description="VETTED-ONLY-TEXT",
    )

    _login_with_totp(e2e_client, user_factory, access_tier="registered")

    resp = e2e_client.get("/search", params={"q": "VETTED-ONLY-TEXT"})
    assert "0 datasets found" in resp.text

    detail = e2e_client.get(f"/dataset/{ds_id}")
    assert detail.status_code == 200
    assert "Vetted Title" in detail.text  # visible field
    assert "VETTED-ONLY-TEXT" not in detail.text  # redacted for the middle tier
    assert "Restricted Dataset" in detail.text


def test_registered_detail_page_shows_middle_tier_content(
    e2e_client, user_factory, dataset_factory
):
    """Detail-redaction channel for the middle tier, both directions: guest
    gets the redacted view of a registered dataset; the registered owner-tier
    actor gets the full metadata."""
    ds_id = dataset_factory(
        visibility_tier="registered",
        title="Reg Title",
        description="REG-DETAIL-TEXT",
    )

    guest_view = e2e_client.get(f"/dataset/{ds_id}")
    assert guest_view.status_code == 200
    assert "Reg Title" in guest_view.text
    assert "REG-DETAIL-TEXT" not in guest_view.text

    _login_with_totp(e2e_client, user_factory, access_tier="registered")
    full_view = e2e_client.get(f"/dataset/{ds_id}")
    assert full_view.status_code == 200
    assert "REG-DETAIL-TEXT" in full_view.text


# ---------------------------------------------------------------------------
# Download link rendering — both directions, first proxy fixture
# ---------------------------------------------------------------------------


def test_resource_access_link_shown_only_at_sufficient_metadata_tier(
    e2e_client, user_factory, dataset_factory
):
    """detail.html renders the Download button only inside {% if can_view %},
    and filter_for_tier nulls resource_access_url below tier. Before this test no
    dataset ever HAD a resource proxy, so the positive direction ('Download
    Dataset' actually renders for an authorized user) was never exercised and
    the template gate itself was unpinned."""
    ds_id = dataset_factory(
        visibility_tier="vetted",
        title="Proxied DS",
        resource_proxies=[
            {"type": "Resource", "ref": "https://example.org/dl/proxied-ds"},
        ],
    )

    # Guest: no download URL anywhere in the page (service nulled it AND the
    # template gate hides the block).
    guest_view = e2e_client.get(f"/dataset/{ds_id}")
    assert guest_view.status_code == 200
    assert "https://example.org/dl/proxied-ds" not in guest_view.text
    assert "Access dataset on SWISSUbase" not in guest_view.text

    # Vetted user: the real download link renders.
    _login_with_totp(e2e_client, user_factory, access_tier="vetted")
    full_view = e2e_client.get(f"/dataset/{ds_id}")
    assert full_view.status_code == 200
    assert "Access dataset on SWISSUbase" in full_view.text
    assert "Download Dataset" not in full_view.text
    assert "https://example.org/dl/proxied-ds" in full_view.text


def test_restricted_swissubase_resource_is_rendered_as_upstream_access_action(
    e2e_client, dataset_factory
):
    """A restricted SWISSUbase Resource proxy remains an upstream access link.

    SWISSUbase—not this application—authorizes access to the underlying
    resource. The application must therefore retain the link but must not
    represent it as a guaranteed direct download.
    """
    access_url = "https://example.org/access/restricted-dataset"
    ds_id = dataset_factory(
        source="swissubase",
        visibility_tier="public",
        access_level="restricted",
        license_val="Restricted access — request permission from depositor",
        title="Restricted SWISSUbase Dataset",
        resource_proxies=[
            {
                "type": "Resource",
                "ref": access_url,
            },
        ],
    )

    response = e2e_client.get(f"/dataset/{ds_id}")

    assert response.status_code == 200

    # Positive controls: this is the intended restricted record.
    assert "Restricted SWISSUbase Dataset" in response.text
    assert '<span class="card-access restricted">restricted</span>' in response.text

    # The upstream action remains available despite access_level=restricted.
    assert f'href="{access_url}"' in response.text
    assert "Access dataset on SWISSUbase" in response.text

    # The application must not promise that following the link directly
    # downloads data or replace SWISSUbase's request-access workflow.
    assert "Download Dataset" not in response.text
    assert "Available to vetted researchers only." not in response.text


# ---------------------------------------------------------------------------
# Facet sidebar (HTTP channel) — the leak as a user would see it
# ---------------------------------------------------------------------------


def test_search_sidebar_facets_are_tier_scoped_end_to_end(
    e2e_client, user_factory, dataset_factory
):
    """The service-level facet pins live in test_access_tiers_db.py; this is
    the same property driven through GET /search → CatalogueStatsCache → get_facets →
    sidebar template, per tier — the channel probe P12 actually leaked
    through. Keywords need two sharers (HAVING >= 2)."""
    dataset_factory(visibility_tier="public", keywords=["pub-kw"])
    dataset_factory(visibility_tier="public", keywords=["pub-kw"])
    dataset_factory(visibility_tier="vetted", keywords=["secret-kw"], languages=["Rumantsch"])
    dataset_factory(visibility_tier="vetted", keywords=["secret-kw"])

    guest_page = e2e_client.get("/search")
    assert guest_page.status_code == 200
    assert "pub-kw" in guest_page.text  # positive control
    assert "secret-kw" not in guest_page.text  # the sidebar leak
    assert "Rumantsch" not in guest_page.text

    _login_with_totp(e2e_client, user_factory, access_tier="vetted")
    vetted_page = e2e_client.get("/search")
    assert "secret-kw" in vetted_page.text  # positive control
    assert "Rumantsch" in vetted_page.text


def _set_visibility_tier(sync_conn, dataset_ids, tier):
    """Change stored records' visibility tier without any application call,
    so nothing can publish a cache-invalidation signal along the way."""
    sync_conn.execute(
        "UPDATE oral_history_datasets SET visibility_tier = %s WHERE id = ANY(%s)",
        (tier, list(dataset_ids)),
    )
    sync_conn.commit()


def test_a_direct_tier_change_is_reflected_in_the_next_visitor_s_facets(
    e2e_client, dataset_factory, sync_conn
):
    """A record's visibility tier can become stricter at any time — a later
    harvest, a withdrawal, a corrected source assertion. The keyword and
    language suggestions in the search sidebar are derived from the same
    records, so a restriction that has landed in the database must not keep
    being advertised to visitors below the new tier while some cached copy
    lives out its lifetime.

    Nothing here calls the application to announce the change, and Redis is
    switched off in this environment, so there is no invalidation channel to
    rescue a stale copy. The suggestions have to come from the same live,
    tier-scoped query the results do.
    """
    assert settings.redis_enabled is False, (
        "this test relies on there being no invalidation channel"
    )

    restricted = [
        dataset_factory(
            visibility_tier="public", keywords=["field-recordings"], languages=["Sursilvan"]
        ),
        dataset_factory(
            visibility_tier="public", keywords=["field-recordings"], languages=["Sursilvan"]
        ),
    ]

    offered = e2e_client.get("/search")
    assert offered.status_code == 200
    assert "field-recordings" in offered.text
    assert "Sursilvan" in offered.text

    _set_visibility_tier(sync_conn, restricted, "vetted")

    withheld = e2e_client.get("/search")
    assert withheld.status_code == 200
    assert "field-recordings" not in withheld.text, (
        "a restricted record's keyword was still offered to an anonymous visitor"
    )
    assert "Sursilvan" not in withheld.text

    _set_visibility_tier(sync_conn, restricted, "public")

    released = e2e_client.get("/search")
    assert "field-recordings" in released.text
    assert "Sursilvan" in released.text


# ---------------------------------------------------------------------------
# Search — ILIKE wildcard escaping
# ---------------------------------------------------------------------------


def test_search_percent_is_literal_not_wildcard(e2e_client, dataset_factory):
    """search_datasets escapes '%' before building the ILIKE pattern: a query
    for '100%' matches only the title literally containing '100%', not every
    title starting with '100' (the .replace escaping of '%' makes it literal)."""
    dataset_factory(title="Zurich 100% oral")
    dataset_factory(title="Zurich 100x oral")

    # httpx encodes the params dict, so the wire query is q=100%25.
    resp = e2e_client.get("/search", params={"q": "100%"})
    assert resp.status_code == 200
    assert "1 dataset found" in resp.text
    assert "Zurich 100% oral" in resp.text
    assert "Zurich 100x oral" not in resp.text


def test_search_underscore_is_literal_not_wildcard(e2e_client, dataset_factory):
    """'_' is escaped too: q=100_ matches NEITHER 'Zurich 100% oral' nor
    'Zurich 100x oral'. An unescaped '_' would be a single-char wildcard and
    match both — the second dataset proves the escape is load-bearing."""
    dataset_factory(title="Zurich 100% oral")
    dataset_factory(title="Zurich 100x oral")

    resp = e2e_client.get("/search", params={"q": "100_"})
    assert resp.status_code == 200
    assert "0 datasets found" in resp.text
    assert "Zurich 100" not in resp.text


def test_search_backslash_is_a_literal(e2e_client, dataset_factory):
    """The escaping does the backslash FIRST
    (.replace('\\\\','\\\\\\\\')) so a query containing a backslash (e.g. a
    Windows path 'C:\\data') matches the literal backslash rather than
    corrupting the following escape sequence. Dropping the backslash escape
    would make the ILIKE pattern's own escape char leak into match semantics.
    A dataset whose title has a literal backslash matches; a sibling without
    one does not."""
    dataset_factory(title=r"Archive C:\data set")
    dataset_factory(title="Archive C data set")

    resp = e2e_client.get("/search", params={"q": r"C:\data"})
    assert resp.status_code == 200
    assert "1 dataset found" in resp.text
    assert r"Archive C:\data set" in resp.text
    assert "Archive C data set" not in resp.text


# ---------------------------------------------------------------------------
# Search — empty-page fallback redirect
# ---------------------------------------------------------------------------


def test_search_past_last_page_redirects_to_last_page(e2e_client, dataset_factory):
    """GET /search?page=99 with only one dataset (one page) 303-redirects to
    the real last page instead of rendering an empty page (search_page's
    empty-results + page>1 fallback recomputes the total and redirects)."""
    dataset_factory(title="Solo Dataset")

    resp = e2e_client.get("/search", params={"page": "99"}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/search?page=1"

    # Following the redirect lands on a populated page.
    followed = e2e_client.get("/search", params={"page": "99"})
    assert followed.status_code == 200
    assert "Solo Dataset" in followed.text


# ---------------------------------------------------------------------------
# Cookie roundtrip — login, authenticated page, server-side logout
# ---------------------------------------------------------------------------


def test_login_account_logout_roundtrip(e2e_client, user_factory, sync_conn):
    """Full cookie lifecycle: TOTP login sets a working session cookie
    (GET /account renders the email), POST /logout with the session-bound
    CSRF token 303s, and the session row is DELETED server-side — a replayed
    cookie is dead, so GET /account bounces to /login."""
    user = _login_with_totp(e2e_client, user_factory)

    # The session cookie is set and honoured end-to-end.
    assert e2e_client.cookies.get(settings.session_cookie_name)
    account = e2e_client.get("/account")
    assert account.status_code == 200
    assert user.email in account.text

    # That GET also refreshed the CSRF cookie, HMAC-bound to the session id.
    csrf = e2e_client.cookies.get("csrf_token")
    logout = e2e_client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert logout.status_code == 303
    assert logout.headers["location"] == "/"

    # Server-side deletion, not just a cleared cookie: the table is empty.
    row = sync_conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
    assert row[0] == 0

    # And the app treats the browser as a guest again.
    bounced = e2e_client.get("/account", follow_redirects=False)
    assert bounced.status_code == 303
    assert bounced.headers["location"].startswith("/login")


# ---------------------------------------------------------------------------
# (HTTP channel) — the leak as a visitor would see it
# ---------------------------------------------------------------------------


def test_home_recent_list_is_tier_redacted(e2e_client, user_factory, dataset_factory):
    """SB-DISC-002/003 through GET /: title and existence are deliberately
    public, while description, authors, languages, and keywords remain
    redacted. The service-level pin lives in test_access_tiers_db.py."""
    dataset_factory(
        visibility_tier="vetted",
        title="Vetted Title",
        description="SECRET-DESC",
        keywords=["secret-kw"],
        languages=["Rumantsch"],
        authors=["Secret Author"],
    )

    guest = e2e_client.get("/")
    assert guest.status_code == 200
    assert "Vetted Title" in guest.text  # positive control: it IS listed
    assert "SECRET-DESC" not in guest.text  # THE leak
    assert "secret-kw" not in guest.text
    assert "Secret Author" not in guest.text
    assert "Rumantsch" not in guest.text

    # POSITIVE CONTROL: the vetted actor's home page shows the real content.
    _login_with_totp(e2e_client, user_factory, access_tier="vetted")
    full = e2e_client.get("/")
    assert full.status_code == 200
    assert "SECRET-DESC" in full.text
    assert "secret-kw" in full.text

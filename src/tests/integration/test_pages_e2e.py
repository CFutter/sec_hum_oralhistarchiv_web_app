"""E2E page-route tests — real PostgreSQL, real CatalogueStatsCache, real middleware."""

import logging
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from lxml import html

from app.paths import PROJECT_ROOT
from app.services import ensure_source_status_rows
from app.services.scheduler import sync_and_invalidate
from app.sources import (
    FixtureAdapter,
    FixtureConfig,
    OaiPmhCmdiConfig,
    SourceDisplay,
    configure_sources,
)
from config import settings
from tests.integration.conftest import login_with_totp as _login_with_totp
from tests.integration.sync_doubles import FETCH


def _assert_search_rows(response, expected):
    """Pin the bounded rendered rows without requesting an exact catalogue count."""
    assert response.context["result_count"] is None
    assert response.context["total_pages"] is None
    assert len(response.context["results"]) == expected
    assert ("No datasets found." in response.text) is (expected == 0)


def _audit_records(caplog, event_type):
    """All records on the 'audit' channel with the given event_type."""
    return [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == event_type
    ]


# Home & search render through the real async CatalogueStatsCache


def test_home_and_search_render_for_guest_and_authenticated(
    e2e_client, user_factory, dataset_factory
):
    """Verify home and search render for guest and authenticated."""
    for _ in range(3):
        dataset_factory()

    # Guest (public tier) — first request populates the 'public' cache entry.
    home = e2e_client.get("/")
    assert home.status_code == 200
    # The datasets count is rendered from real DB data, not a coroutine.
    assert '<span class="stat-number">3</span>' in home.text

    search = e2e_client.get("/search")
    assert search.status_code == 200
    _assert_search_rows(search, 3)

    # Authenticated at a different tier — a second, lazily-built cache entry.
    _login_with_totp(e2e_client, user_factory, access_tier="registered")

    home2 = e2e_client.get("/")
    assert home2.status_code == 200
    assert '<span class="stat-number">3</span>' in home2.text

    search2 = e2e_client.get("/search")
    assert search2.status_code == 200
    _assert_search_rows(search2, 3)


# Detail page — tier redaction + audit trail


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


# Search — full-blob gating (the presence oracle)


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
    _assert_search_rows(resp, 0)
    assert "Public Title" not in resp.text

    # Guest searching the title: public discovery search matches everywhere.
    resp = e2e_client.get("/search", params={"q": "Public Title"})
    assert resp.status_code == 200
    _assert_search_rows(resp, 1)
    assert "Public Title" in resp.text

    # Vetted user: the full blob (description) matches.
    _login_with_totp(e2e_client, user_factory, access_tier="vetted")
    resp = e2e_client.get("/search", params={"q": "SENSITIVE-DETAIL-TEXT"})
    assert resp.status_code == 200
    _assert_search_rows(resp, 1)
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
    _assert_search_rows(resp, 0)

    _login_with_totp(e2e_client, user_factory, access_tier="vetted")
    resp = e2e_client.get("/search", params={"keyword": "sec-kw"})
    assert resp.status_code == 200
    _assert_search_rows(resp, 1)
    assert "Public Title" in resp.text


def test_access_level_filter_is_deliberately_not_gated(e2e_client, dataset_factory):
    """Verify access level filter is deliberately not gated."""
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
    _assert_search_rows(resp, 1)
    assert "Open Dataset" in resp.text

    # The vetted-tier row IS returned to a guest — redacted, but listed.
    resp = e2e_client.get("/search", params={"access_level": "restricted"})
    assert resp.status_code == 200
    _assert_search_rows(resp, 1)
    assert "Hidden But Listed" in resp.text
    assert "SENSITIVE-DETAIL-TEXT" not in resp.text


# The middle tier — a 'registered' dataset AND a 'registered' logged-in actor


def test_registered_dataset_hidden_from_guest_visible_to_registered(
    e2e_client, user_factory, dataset_factory
):
    """Verify registered dataset hidden from guest visible to registered."""
    dataset_factory(
        visibility_tier="registered",
        title="Reg DS",
        description="REG-SENSITIVE-TEXT",
        keywords=["reg-kw"],
    )

    # Guest (rank 0): neither channel may confirm the dataset's contents.
    resp = e2e_client.get("/search", params={"q": "REG-SENSITIVE-TEXT"})
    _assert_search_rows(resp, 0)
    resp = e2e_client.get("/search", params={"keyword": "reg-kw"})
    _assert_search_rows(resp, 0)

    # Positive control: the registered actor sees it through both channels.
    _login_with_totp(e2e_client, user_factory, access_tier="registered")
    resp = e2e_client.get("/search", params={"q": "REG-SENSITIVE-TEXT"})
    _assert_search_rows(resp, 1)
    assert "Reg DS" in resp.text
    resp = e2e_client.get("/search", params={"keyword": "reg-kw"})
    _assert_search_rows(resp, 1)


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
    _assert_search_rows(resp, 0)

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


# Download link rendering — both directions, first proxy fixture


def test_resource_access_link_shown_only_at_sufficient_metadata_tier(
    e2e_client, user_factory, dataset_factory
):
    """detail.html renders the Download button only inside {% if can_view %},
    and filter_for_tier nulls resource_access_url below tier. A real proxy
    fixture proves both denial below tier and a rendered download link for
    the authorized user."""
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


# Facet sidebar (HTTP channel) — the leak as a user would see it


def test_search_sidebar_facets_are_tier_scoped_end_to_end(
    e2e_client, user_factory, dataset_factory
):
    """The service-level facet pins live in test_access_tiers_db.py; this is
    the same property driven through GET /search → CatalogueStatsCache → get_facets →
    sidebar template, per tier — a facet channel previously leaked through
    the sidebar. Keywords need two sharers (HAVING >= 2)."""
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
        "UPDATE oral_history_datasets SET visibility_tier = %s, "
        "data = jsonb_set(COALESCE(data, '{}'::jsonb), '{visibility_tier}', to_jsonb(%s::text)) "
        "WHERE id = ANY(%s)",
        (tier, tier, list(dataset_ids)),
    )
    sync_conn.commit()


def test_a_direct_tier_change_is_reflected_in_the_next_visitor_s_facets(
    e2e_client, dataset_factory, sync_conn
):
    """Verify a direct tier change is reflected in the next visitor s facets."""
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


# Search — ILIKE wildcard escaping


def test_search_percent_is_literal_not_wildcard(e2e_client, dataset_factory):
    """search_datasets escapes '%' before building the ILIKE pattern: a query
    for '100%' matches only the title literally containing '100%', not every
    title starting with '100' (the .replace escaping of '%' makes it literal)."""
    dataset_factory(title="Zurich 100% oral")
    dataset_factory(title="Zurich 100x oral")

    # httpx encodes the params dict, so the wire query is q=100%25.
    resp = e2e_client.get("/search", params={"q": "100%"})
    assert resp.status_code == 200
    _assert_search_rows(resp, 1)
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
    _assert_search_rows(resp, 0)
    assert "Zurich 100" not in resp.text


def test_search_backslash_is_a_literal(e2e_client, dataset_factory):
    """Verify search backslash is a literal."""
    dataset_factory(title=r"Archive C:\data set")
    dataset_factory(title="Archive C data set")

    resp = e2e_client.get("/search", params={"q": r"C:\data"})
    assert resp.status_code == 200
    _assert_search_rows(resp, 1)
    assert r"Archive C:\data set" in resp.text
    assert "Archive C data set" not in resp.text


# Search — empty-page fallback redirect


def test_search_past_last_page_restarts_at_page_one(e2e_client, dataset_factory):
    """Empty numbered pages restart at page one without computing a total."""
    dataset_factory(title="Solo Dataset")

    resp = e2e_client.get("/search", params={"page": "99"}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/search?page=1&pagination=empty"

    # Following the redirect lands on a populated page.
    followed = e2e_client.get("/search", params={"page": "99"})
    assert followed.status_code == 200
    assert "Solo Dataset" in followed.text
    assert "That search page is empty. Showing page 1." in followed.text


# Cookie roundtrip — login, authenticated page, server-side logout


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


def test_logout_retry_is_inert_and_an_old_form_cannot_revoke_a_new_login(
    e2e_client, user_factory, sync_conn
):
    """Replay an actual logout form across anonymous and newly logged-in states."""
    _login_with_totp(e2e_client, user_factory)
    assert e2e_client.get("/account").status_code == 200
    old_form = {"csrf_token": e2e_client.cookies[settings.csrf_cookie_name]}
    first = e2e_client.post("/logout", data=old_form, follow_redirects=False)
    assert first.status_code == 303
    assert settings.session_cookie_name not in e2e_client.cookies
    assert settings.csrf_cookie_name not in e2e_client.cookies
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0

    retry = e2e_client.post("/logout", data=old_form, follow_redirects=False)
    assert retry.status_code == 303
    assert retry.headers["location"] == "/"
    assert retry.headers.get_list("set-cookie") == []
    assert retry.headers["cache-control"] == "no-store"
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0

    new_user = _login_with_totp(e2e_client, user_factory)
    assert e2e_client.get("/account").status_code == 200
    assert e2e_client.cookies[settings.csrf_cookie_name] != old_form["csrf_token"]
    before = dict(e2e_client.cookies)
    # Apply a late anonymous response after the newer login's cookies arrive.
    e2e_client.cookies.extract_cookies(retry)
    assert dict(e2e_client.cookies) == before
    rejected = e2e_client.post("/logout", data=old_form, follow_redirects=False)
    assert rejected.status_code == 403
    assert rejected.headers.get_list("set-cookie") == []
    assert dict(e2e_client.cookies) == before
    assert sync_conn.execute("SELECT user_id FROM sessions").fetchall() == [(new_user.id,)]
    account = e2e_client.get("/account")
    assert account.status_code == 200
    assert new_user.email in account.text


# (HTTP channel) — the leak as a visitor would see it


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


def test_about_sources_follow_persisted_state_without_public_diagnostics(
    replace_bound_catalogue_sources, e2e_client, sync_conn, monkeypatch
):
    """About renders configured sources and changes only the affected badge."""
    sources = configure_sources(
        (
            OaiPmhCmdiConfig(
                name="online_archive",
                display=SourceDisplay(
                    label="Recorded archive", sensitivity_badge="Public catalogue"
                ),
                endpoint="https://endpoint-canary.example.edu/oai",
                institution_filter="Configured archive",
            ),
            FixtureConfig(
                name="offline_archive",
                display=SourceDisplay(label="Offline archive", sensitivity_badge="Mixed access"),
            ),
        )
    )
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, sources)
    now = datetime.now(UTC)
    for source in sources:
        sync_conn.execute(
            """INSERT INTO sync_status (source, last_harvest_date, last_full_rebuild_date)
               VALUES (%s, %s, %s)""",
            (source.name, now, now),
        )
    # Unselected stored identities do not belong in the public table.
    sync_conn.execute(
        "INSERT INTO sync_status (source, last_sync_error) VALUES (%s, %s)",
        ("unselected_archive", "UNSELECTED-DIAGNOSTIC-CANARY"),
    )
    sync_conn.commit()

    response = e2e_client.get("/about")
    assert response.status_code == 200
    rendered_pages = [response.text]
    document = html.fromstring(response.text)
    rows = document.xpath("//table[contains(@class, 'about-table')]/tbody/tr")
    assert [row.xpath("string(td[1])").strip() for row in rows] == [
        source.display.label for source in sources
    ]
    assert [row.xpath("string(td[2])").strip() for row in rows] == [
        "Public catalogue",
        "Mixed access",
    ]
    assert [row.xpath("string(td[3])").strip() for row in rows] == ["Active", "Active"]

    sync_conn.execute(
        "UPDATE sync_status SET last_rebuild_error = %s WHERE source = %s",
        ("PRIVATE-UPSTREAM-DIAGNOSTIC-CANARY", sources[1].name),
    )
    sync_conn.commit()
    response = e2e_client.get("/about")
    assert response.status_code == 200
    rendered_pages.append(response.text)
    document = html.fromstring(response.text)
    rows = document.xpath("//table[contains(@class, 'about-table')]/tbody/tr")
    assert [row.xpath("string(td[3])").strip() for row in rows] == ["Active", "Needs attention"]

    sync_conn.execute("DELETE FROM sync_status WHERE source = %s", (sources[1].name,))
    sync_conn.commit()
    response = e2e_client.get("/about")
    assert response.status_code == 200
    rendered_pages.append(response.text)
    document = html.fromstring(response.text)
    rows = document.xpath("//table[contains(@class, 'about-table')]/tbody/tr")
    assert [row.xpath("string(td[3])").strip() for row in rows] == ["Active", "Awaiting sync"]

    for canary in (
        "endpoint-canary.example.edu",
        "PRIVATE-UPSTREAM-DIAGNOSTIC-CANARY",
        "UNSELECTED-DIAGNOSTIC-CANARY",
        "unselected_archive",
    ):
        assert all(canary not in page for page in rendered_pages)


def test_web_startup_loads_the_selected_source_file_without_harvesting(
    tmp_path, monkeypatch, e2e_client_from_address, sync_conn
):
    """Real web startup reads the file and exposes its pending configured sources."""
    path = tmp_path / "sources.toml"
    path.write_text(
        """[[sources]]
name = "file_archive_one"
adapter = "fixture"
label = "First file archive"
sensitivity_badge = "Synthetic examples"

[[sources]]
name = "file_archive_two"
adapter = "fixture"
label = "Second file archive"
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "sources_config_file", str(path))
    monkeypatch.setattr(settings, "allow_fixture_source", False)
    with patch.object(FixtureAdapter, "fetch", autospec=True) as fetch:
        client = e2e_client_from_address("127.0.0.51")
        sources = client.app.state.configured_sources
        assert tuple(source.name for source in sources) == (
            "file_archive_one",
            "file_archive_two",
        )
        response = client.get("/about")

    assert response.status_code == 200
    rows = html.fromstring(response.text).xpath("//table[@class='about-table']/tbody/tr")
    assert [row.xpath("string(td[1])").strip() for row in rows] == [
        "First file archive",
        "Second file archive",
    ]
    assert [row.xpath("string(td[3])").strip() for row in rows] == [
        "Awaiting sync",
        "Awaiting sync",
    ]
    fetch.assert_not_called()
    assert (
        sync_conn.execute(
            "SELECT source FROM sync_status WHERE source = ANY(%s::text[])",
            ([source.name for source in sources],),
        ).fetchall()
        == []
    )


@pytest.mark.parametrize("viewer_tier", ["public", "registered", "vetted"])
async def test_ingested_fixture_metadata_respects_the_viewer_tier(
    db_pool, sync_conn, e2e_client_from_address, user_factory, monkeypatch, viewer_tier
):
    """Verify ingested fixture metadata respects the viewer tier."""
    monkeypatch.setattr(settings, "env_state", "dev")
    monkeypatch.setattr(
        settings,
        "sources_config_file",
        str(PROJECT_ROOT / "deploy/environment/sources.dev.toml"),
    )
    monkeypatch.setattr(settings, "allow_fixture_source", False)
    client = e2e_client_from_address("127.0.0.53")
    sources = client.app.state.configured_sources
    assert tuple(source.name for source in sources) == ("fixture_demo",)
    assert not hasattr(sources[0], "adapter")
    source = configure_sources(tuple(item.config for item in sources))[0]
    assert isinstance(source.adapter, FixtureAdapter)
    await ensure_source_status_rows(db_pool, (source.name,))
    with patch(
        FETCH, autospec=True, side_effect=AssertionError("Fixture ingestion used OAI")
    ) as oai:
        outcome = await sync_and_invalidate(db_pool, client.app.state.catalogue_stats_cache, source)
    oai.assert_not_called()
    assert (outcome.status, outcome.affected_count) == ("success", 3)
    rows = sync_conn.execute(
        "SELECT id, visibility_tier, title FROM oral_history_datasets "
        "WHERE source = %s ORDER BY uuid",
        (source.name,),
    ).fetchall()
    assert [row[1] for row in rows] == ["public", "registered", "vetted"]
    if viewer_tier != "public":
        _login_with_totp(client, user_factory, access_tier=viewer_tier)
    ranks = {"public": 0, "registered": 1, "vetted": 2}
    description = "Synthetic example; no real interview or participant."
    for dataset_id, required_tier, title in rows:
        permitted = ranks[viewer_tier] >= ranks[required_tier]
        detail = client.get(f"/dataset/{dataset_id}")
        assert detail.status_code == 200
        document = html.fromstring(detail.text)
        assert document.xpath("string(//h1)") == title
        assert (description in detail.text) is permitted
        keywords = document.xpath("//div[@class='card-topics']/a/text()")
        assert sorted(keywords) == (sorted(["sample", required_tier]) if permitted else [])
        resource_url = f"https://archive.example.org/resources/{required_tier}"
        resource_path = f"/dataset/{dataset_id}/resource/0"
        assert source.log_resource_access is True
        assert (resource_path in document.xpath("//a/@href")) is permitted
        assert resource_url not in detail.text

        resource = client.get(resource_path, follow_redirects=False)
        assert resource.status_code == (303 if permitted else 404)
        if permitted:
            assert resource.headers["location"] == resource_url
        else:
            assert "location" not in resource.headers

        search = client.get("/search", params={"keyword": required_tier})
        assert search.status_code == 200
        _assert_search_rows(search, int(permitted))
        assert (title in search.text) is permitted

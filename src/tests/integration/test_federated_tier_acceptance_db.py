"""Integrated proposal review through real HTTP, middleware, audit and PostgreSQL."""

import logging
from html.parser import HTMLParser

import pyotp
import pytest
from psycopg.rows import dict_row
from pydantic import SecretStr

from app.federated_tier_rules import FederatedTierRule
from app.federation_contract import (
    SHIBBOLETH_AFFILIATION_HEADER,
    SHIBBOLETH_AUTHN_CONTEXT_HEADER,
    SHIBBOLETH_ENTITLEMENT_HEADER,
    SHIBBOLETH_INTERNAL_AUTH_HEADER,
    SHIBBOLETH_ISSUER_HEADER,
    SHIBBOLETH_MAIL_HEADER,
    SHIBBOLETH_SUBJECT_HEADER,
)
from app.services.federated_session_policy import (
    REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    reconcile_federated_session_policy,
)
from app.services.totp_crypto import encrypt_value
from config import settings

ISSUER = "https://idp.test.example/idp/shibboleth"
SUBJECT = "urn:test:subject:integrated-tier-acceptance"
EMAIL = "federated-acceptance@example.org"
SECRET = "hK8cJ4qM7bP2vY9zR6wF1aN5eX3dL0sT8uG4mV7oQ2iC9rB6"
PREFIX = "urn:archive:"
AFFILIATION = "<script>alert(7)</script> & archival researchers"
RULE = {"index": 1, "match": {"entitlement": {"prefix": PREFIX}}, "tier": "registered"}
AUTHORITY_FIELDS = (
    "access_tier",
    "is_active",
    "is_admin",
    "email_verified",
    "federated_status",
    "federated_approved_at",
    "federated_approved_by",
    "auth_revision",
    "federated_approved_proposal",
)


class ReviewPage(HTMLParser):
    """Read actual forms and review-cell content without executing markup."""

    def __init__(self):
        """Initialize HTML parser state for forms and federated-review cells."""
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, str]] = []
        self.current_form: dict[str, str] | None = None
        self.current_select: str | None = None
        self.in_review = False
        self.review_text: list[str] = []
        self.review_tags: list[str] = []

    def handle_starttag(self, tag, attrs):
        """Collect review markup and named form inputs from opening tags."""
        attributes = dict(attrs)
        if tag == "td" and attributes.get("class") == "federated-tier-review":
            self.in_review = True
        if self.in_review:
            self.review_tags.append(tag)
        if tag == "form":
            self.current_form = {"@action": attributes.get("action") or ""}
        elif self.current_form is not None:
            if tag == "input" and attributes.get("name"):
                self.current_form[attributes["name"]] = attributes.get("value") or ""
            elif tag == "select":
                self.current_select = attributes.get("name")
            elif tag == "option" and self.current_select and "selected" in attributes:
                self.current_form[self.current_select] = attributes.get("value") or ""

    def handle_endtag(self, tag):
        """Finish review-cell, form and select tracking at closing tags."""
        if tag == "td":
            self.in_review = False
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None
        if tag == "select":
            self.current_select = None

    def handle_data(self, data):
        """Record text encountered inside the federated-review cell."""
        if self.in_review:
            self.review_text.append(data)


@pytest.fixture(autouse=True)
async def trusted_federation(monkeypatch, clean_db, db_pool):
    """Install this test's trusted issuers and tier rules, then reconcile durable federation
    policy.
    """
    del clean_db
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER])
    monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET))
    monkeypatch.setattr(
        settings,
        "federated_tier_rules",
        (FederatedTierRule.model_validate({"match": RULE["match"], "tier": RULE["tier"]}),),
    )
    await reconcile_federated_session_policy(db_pool)


@pytest.fixture
def approval_audit(caplog):
    """Capture audit records even after another test installed logging handlers."""
    audit = logging.getLogger("audit")
    handlers, propagate = audit.handlers[:], audit.propagate
    audit.addHandler(caplog.handler)
    audit.propagate = False
    caplog.set_level(logging.INFO, logger="audit")
    try:
        yield caplog
    finally:
        audit.handlers[:] = handlers
        audit.propagate = propagate


def assertion_headers(entitlement, *, affiliation=AFFILIATION):
    """Build trusted internal federation headers for the requested affiliation and entitlement."""
    return {
        SHIBBOLETH_INTERNAL_AUTH_HEADER: SECRET,
        SHIBBOLETH_ISSUER_HEADER: ISSUER,
        SHIBBOLETH_SUBJECT_HEADER: SUBJECT,
        SHIBBOLETH_MAIL_HEADER: EMAIL,
        SHIBBOLETH_AUTHN_CONTEXT_HEADER: REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
        SHIBBOLETH_AFFILIATION_HEADER: affiliation,
        SHIBBOLETH_ENTITLEMENT_HEADER: entitlement,
    }


def callback(client, entitlement, *, affiliation=AFFILIATION):
    """Invoke the federation callback with this test's trusted assertion headers."""
    return client.get(
        "/auth/shibboleth/callback",
        headers=assertion_headers(entitlement, affiliation=affiliation),
        follow_redirects=False,
    )


def identity_state(conn):
    """Read the test federated identity and require it to exist."""
    with conn.cursor(row_factory=dict_row) as cur:
        row = cur.execute(
            """SELECT id, access_tier, is_active, is_admin, email_verified,
                      federated_status, federated_approved_at, federated_approved_by,
                      auth_revision, federated_approved_proposal,
                      federated_review, federated_review_revision, last_login,
                      email, affiliation
                 FROM users
                WHERE shibboleth_issuer = %s AND shibboleth_subject_id = %s""",
            (ISSUER, SUBJECT),
        ).fetchone()
    assert row is not None
    return row


def authority(row):
    """Copy only the authority fields from an identity-state row."""
    return {name: row[name] for name in AUTHORITY_FIELDS}


def session_count(conn, user_id):
    """Count stored sessions for the user, including expired rows."""
    return conn.execute("SELECT count(*) FROM sessions WHERE user_id = %s", (user_id,)).fetchone()[
        0
    ]


def admin_login(client, user_factory):
    """Use password, a fresh TOTP and the real anonymous CSRF form."""
    secret = pyotp.random_base32()
    admin = user_factory(is_admin=True, totp_secret=encrypt_value(secret))
    client.get("/login")
    response = client.post(
        "/login",
        data={
            "email": admin.email,
            "password": admin.password,
            "totp_code": pyotp.TOTP(secret).now(),
            "csrf_token": client.cookies.get("csrf_token"),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert settings.session_cookie_name in client.cookies
    return admin


def review_page(client):
    """Fetch the admin page, require success and return its parsed review forms."""
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 200, response.text
    parsed = ReviewPage()
    parsed.feed(response.text)
    return response, parsed


def approval_form(page, user_id):
    """Require exactly one approval form for this user and return its fields."""
    forms = [
        form
        for form in page.forms
        if form["@action"] == f"/admin/users/{user_id}/approve-federated"
    ]
    assert len(forms) == 1
    return {name: value for name, value in forms[0].items() if name != "@action"}


def restore_browser(client, cookies):
    """Replace the client's entire cookie jar with the saved cookies."""
    client.cookies.clear()
    client.cookies.update(cookies)


def approval_events(caplog):
    """Select captured administrator approval audit events."""
    return [
        event
        for event in caplog.records
        if event.name == "audit"
        and getattr(event, "event_type", None) == "admin_federated_user_approved"
    ]


def pending_assertion(client, conn, entitlement, proposal):
    """Invoke a pending federated assertion and check it grants no session or authority."""
    pending_response = callback(client, entitlement)
    assert pending_response.status_code == 401, pending_response.text
    assert settings.session_cookie_name not in client.cookies
    pending = identity_state(conn)
    assert pending["access_tier"] == "public"
    assert pending["federated_status"] == "pending"
    assert not pending["is_active"] and not pending["is_admin"] and not pending["email_verified"]
    assert pending["last_login"] is None
    assert pending["federated_review_revision"] == 1
    assert pending["federated_review"]["proposal"] == proposal
    assert session_count(conn, pending["id"]) == 0
    anonymous_account = client.get("/account", follow_redirects=False)
    assert anonymous_account.status_code == 303
    assert anonymous_account.headers["location"].startswith("/login?")
    return pending


def submit_reviewed_approval(
    client, conn, *, form, pending, admin_id, reviewed_proposal, entitlement, caplog
):
    """Submit the reviewed approval and check stored authority follows the operator's selected
    tier.
    """
    form.update(
        access_tier="vetted",
        proposed_tier="public",
        proposed_rule="posted-untrusted-proposal-marker",
    )
    approved_response = client.post(
        f"/admin/users/{pending['id']}/approve-federated", data=form, follow_redirects=False
    )
    assert approved_response.status_code == 303, approved_response.text
    approved = identity_state(conn)
    assert approved["access_tier"] == "vetted"
    assert approved["is_active"] and not approved["is_admin"] and not approved["email_verified"]
    assert approved["federated_status"] == "approved"
    assert approved["federated_approved_at"] is not None
    assert approved["federated_approved_by"] == admin_id
    assert approved["auth_revision"] == pending["auth_revision"] + 1
    assert approved["federated_approved_proposal"] == {"proposal": reviewed_proposal}
    assert session_count(conn, pending["id"]) == 0
    events = approval_events(caplog)
    assert len(events) == 1
    event = events[0]
    assert event.actor_admin_id == admin_id
    assert event.target_user_id == pending["id"]
    assert event.proposed_tier == ("registered" if reviewed_proposal is not None else None)
    assert event.proposed_rule == reviewed_proposal
    assert event.access_tier == "vetted"
    assert event.request_id and event.created > 0
    event_values = repr(vars(event))
    for observed_value in (SUBJECT, AFFILIATION, entitlement, SECRET):
        assert observed_value not in event_values
    assert "posted-untrusted-proposal-marker" not in event_values
    return approved


@pytest.mark.parametrize("matched", [True, False], ids=["matched-proposal", "reviewed-no-match"])
def test_http_assertion_review_approval_and_changed_proposal_keep_authority_manual(
    e2e_unix_client, user_factory, sync_conn, approval_audit, matched
):
    """Verify HTTP assertion review approval and changed proposal keep authority manual."""
    client = e2e_unix_client
    initial_entitlement = f"{PREFIX}member:observed-raw-value" if matched else "urn:unknown:member"
    reviewed_proposal = RULE if matched else None

    pending = pending_assertion(client, sync_conn, initial_entitlement, reviewed_proposal)

    admin = admin_login(client, user_factory)
    response, page = review_page(client)
    form = approval_form(page, pending["id"])
    assert form["expected_issuer"] == ISSUER
    assert form["expected_subject_id"] == SUBJECT
    assert form["expected_review_revision"] == "1"
    assert form["access_tier"] == "public"
    assert initial_entitlement in "".join(page.review_text)
    assert AFFILIATION in "".join(page.review_text)
    assert "script" not in page.review_tags and "a" not in page.review_tags
    assert "&lt;script&gt;" in response.text
    if matched:
        assert "No matching rule" not in response.text
        assert '"prefix": "urn:archive:"' in "".join(page.review_text)
    else:
        assert "No matching rule" in response.text

    approved = submit_reviewed_approval(
        client,
        sync_conn,
        form=form,
        pending=pending,
        admin_id=admin.id,
        reviewed_proposal=reviewed_proposal,
        entitlement=initial_entitlement,
        caplog=approval_audit,
    )
    admin_browser = dict(client.cookies)

    client.cookies.clear()
    first_login = callback(client, initial_entitlement)
    assert first_login.status_code == 303, first_login.text
    assert settings.session_cookie_name in client.cookies
    first_browser = dict(client.cookies)
    account = client.get("/account")
    assert account.status_code == 200, account.text
    assert account.context["user"].id == pending["id"]
    assert account.context["user"].access_tier == "vetted"
    assert initial_entitlement not in account.text
    assert session_count(sync_conn, pending["id"]) == 1
    assert authority(identity_state(sync_conn)) == authority(approved)
    restore_browser(client, admin_browser)
    _, unchanged_page = review_page(client)
    assert "Proposal changed since approval." not in "".join(unchanged_page.review_text)

    # A second browser supplies the later assertion. Normal same-browser login
    # replacement is independent of advisory observations and is not exercised.
    client.cookies.clear()
    changed_entitlement = "urn:unknown:changed" if matched else f"{PREFIX}newly-matched"
    changed_login = callback(client, changed_entitlement, affiliation="later group")
    assert changed_login.status_code == 303, changed_login.text
    changed = identity_state(sync_conn)
    assert changed["federated_review_revision"] == 2
    assert changed["federated_review"]["proposal"] == (None if matched else RULE)
    assert authority(changed) == authority(approved)
    assert session_count(sync_conn, pending["id"]) == 2
    restore_browser(client, first_browser)
    preserved_account = client.get("/account", follow_redirects=False)
    assert preserved_account.status_code == 200, preserved_account.text
    assert preserved_account.context["user"].access_tier == "vetted"
    restore_browser(client, admin_browser)
    _, changed_page = review_page(client)
    changed_text = "".join(changed_page.review_text)
    assert "Proposal changed since approval." in changed_text
    assert "Assigned tier remains vetted." in changed_text
    assert not any(
        form["@action"] == f"/admin/users/{pending['id']}/approve-federated"
        for form in changed_page.forms
    )
    assert len(approval_events(approval_audit)) == 1


def test_http_changed_attributes_with_the_same_proposal_reject_a_stale_approval_form(
    e2e_unix_client, user_factory, sync_conn, approval_audit
):
    """Verify HTTP changed attributes with the same proposal reject a stale approval form."""
    client = e2e_unix_client
    assert callback(client, f"{PREFIX}first-observation").status_code == 401
    pending = identity_state(sync_conn)
    admin_login(client, user_factory)
    _, page = review_page(client)
    old_form = approval_form(page, pending["id"])
    assert old_form["expected_review_revision"] == "1"
    admin_browser = dict(client.cookies)

    client.cookies.clear()
    changed_response = callback(
        client, f"{PREFIX}second-observation", affiliation="changed same-rule attributes"
    )
    assert changed_response.status_code == 401, changed_response.text
    latest = identity_state(sync_conn)
    assert latest["federated_review_revision"] == 2
    assert latest["federated_review"]["proposal"] == pending["federated_review"]["proposal"] == RULE
    assert authority(latest) == authority(pending)
    assert session_count(sync_conn, pending["id"]) == 0

    restore_browser(client, admin_browser)
    old_form["access_tier"] = "vetted"
    rejected = client.post(
        f"/admin/users/{pending['id']}/approve-federated", data=old_form, follow_redirects=False
    )
    assert rejected.status_code == 303, rejected.text
    after = identity_state(sync_conn)
    assert authority(after) == authority(pending)
    assert after["federated_review_revision"] == 2
    assert session_count(sync_conn, pending["id"]) == 0
    response, fresh_page = review_page(client)
    assert "review changed" in response.text
    assert approval_form(fresh_page, pending["id"])["expected_review_revision"] == "2"
    assert approval_events(approval_audit) == []

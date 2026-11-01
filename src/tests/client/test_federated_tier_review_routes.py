"""Administrator proposal review, escaping and stale-form behavior through HTTP."""

from unittest.mock import patch

import pytest
from lxml import html

from app.services.federated_review import FederatedReview
from app.services.users import AdminActionRejected, FederatedApproval
from tests.fixtures import make_sample_user

ISSUER = "https://idp.example.org/idp/shibboleth"
SUBJECT = "review-subject-7"
RULE = {"index": 2, "match": {"affiliation": "member"}, "tier": "vetted"}


def _patch(name, **kwargs):
    """Patch the route collaborator with its real signature."""
    return patch(f"app.routes.auth.admin.{name}", autospec=True, **kwargs)


def _review(**overrides):
    """Build a registered-tier federated proposal with caller field overrides."""
    values = {
        "revision": 4,
        "issuer": ISSUER,
        "affiliation": "member",
        "entitlement": "urn:example:archive:researcher",
        "proposed_tier": "vetted",
        "proposed_rule": RULE,
        "mismatch": False,
    }
    values.update(overrides)
    return FederatedReview(**values)


def _pending_target(**overrides):
    """Build an inactive pending federated user with caller field overrides."""
    values = {
        "id": 7,
        "auth_method": "shibboleth",
        "is_active": False,
        "federated_status": "pending",
        "shibboleth_issuer": ISSUER,
        "shibboleth_subject_id": SUBJECT,
    }
    values.update(overrides)
    return make_sample_user(**values)


def _dashboard(client, target, review):
    """Render the mocked admin dashboard and return its successful response."""
    with (
        _patch("list_users", return_value=([target], 1)),
        _patch("list_admin_promotion_states", return_value={}),
        _patch("list_federated_reviews", return_value={7: review} if review else {}) as lookup,
    ):
        response = client.get("/admin")
    assert response.status_code == 200
    lookup.assert_awaited_once_with(client.mock_pool, user_ids=[target.id])
    return response


def _approval_form(client, **overrides):
    """Build the valid form with caller overrides and the current CSRF token."""
    values = {
        "expected_issuer": ISSUER,
        "expected_subject_id": SUBJECT,
        "expected_review_revision": "4",
        "access_tier": "public",
        "csrf_token": client.csrf_token,
    }
    values.update(overrides)
    return values


def test_pending_identity_without_observation_requires_a_fresh_assertion(admin_client):
    """Check pending identity without observation requires a fresh assertion."""
    response = _dashboard(admin_client, _pending_target(), None)
    document = html.fromstring(response.text)
    assert "A fresh trusted assertion is required before approval." in response.text
    assert document.xpath('//form[@action="/admin/users/7/approve-federated"]') == []
    assert document.xpath('//form[@action="/admin/users/7/set-active"]') == []


@pytest.mark.parametrize(
    ("proposal", "rule", "label"),
    [(None, None, "No matching rule"), ("public", {**RULE, "tier": "public"}, "public")],
    ids=("no-match", "explicit-public"),
)
def test_no_match_and_public_are_distinct_manual_review_states(admin_client, proposal, rule, label):
    """Check no match and public are distinct manual review states."""
    response = _dashboard(
        admin_client, _pending_target(), _review(proposed_tier=proposal, proposed_rule=rule)
    )
    document = html.fromstring(response.text)
    cell = document.xpath('//td[@class="federated-tier-review"]')[0]
    assert cell.xpath("string(./strong)") == label
    form = document.xpath('//form[@action="/admin/users/7/approve-federated"]')[0]
    assert form.xpath('string(.//input[@name="expected_review_revision"]/@value)') == "4"
    assert form.xpath("string(.//option[@selected]/@value)") == "public"
    assert "Proposals never change assigned access automatically." in cell.text_content()


def test_proposed_tier_does_not_preselect_a_grant_and_assertion_values_are_text(admin_client):
    """Check proposed tier does not preselect a grant and assertion values are text."""
    markup = '<img src=x onerror="alert(1)"> & <script>alert(2)</script>'
    review = _review(
        issuer=f"{ISSUER}?q={markup}",
        affiliation=markup,
        entitlement=f"https://example.org/{markup}",
        proposed_rule={**RULE, "match": {"affiliation": markup}},
    )
    response = _dashboard(admin_client, _pending_target(), review)
    document = html.fromstring(response.text)
    cell = document.xpath('//td[@class="federated-tier-review"]')[0]
    assert cell.xpath(".//script|.//img|.//a") == []
    codes = [element.text_content() for element in cell.xpath("./code")]
    assert codes[1:] == [review.issuer, markup, review.entitlement]
    assert '"index": 2' in codes[0]
    assert "\\u003cimg" in codes[0]
    form = document.xpath('//form[@action="/admin/users/7/approve-federated"]')[0]
    assert form.xpath("string(.//option[@selected]/@value)") == "public"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


@pytest.mark.parametrize("status", ["approved", "disabled"])
def test_changed_proposal_is_visible_without_another_approval_action(admin_client, status):
    """Check changed proposal is visible without another approval action."""
    target = _pending_target(
        federated_status=status, is_active=status == "approved", access_tier="registered"
    )
    response = _dashboard(admin_client, target, _review(mismatch=True))
    document = html.fromstring(response.text)
    cell = document.xpath('//td[@class="federated-tier-review"]')[0]
    assert "Proposal changed since approval." in cell.text_content()
    assert "Assigned tier remains registered." in cell.text_content()
    assert document.xpath('//form[@action="/admin/users/7/approve-federated"]') == []
    assert document.xpath('string(//select[@name="access_tier"]/option[@selected]/@value)') == (
        "registered"
    )


def test_intentionally_different_chosen_tier_does_not_create_a_display_mismatch(admin_client):
    """Check intentionally different chosen tier does not create a display mismatch."""
    target = _pending_target(federated_status="approved", is_active=True, access_tier="registered")
    response = _dashboard(admin_client, target, _review(mismatch=False))
    document = html.fromstring(response.text)
    cell = document.xpath('//td[@class="federated-tier-review"]')[0]
    assert cell.xpath("string(./strong)") == "vetted"
    assert "Proposal changed since approval." not in cell.text_content()


@pytest.mark.parametrize("revision", [None, "0", "-1", "not-an-integer", "1.5", str(2**63)])
def test_approval_requires_a_bounded_positive_review_revision(admin_client, revision):
    """Check approval requires a bounded positive review revision (HTTP 422)."""
    form = _approval_form(admin_client, expected_review_revision=revision)
    if revision is None:
        form.pop("expected_review_revision")
    with _patch("approve_federated_user") as approve, _patch("audit_admin_action") as audit:
        response = admin_client.post(
            "/admin/users/7/approve-federated", data=form, follow_redirects=False
        )
    assert response.status_code == 422
    approve.assert_not_awaited()
    audit.assert_not_called()


def test_stale_review_rejection_has_feedback_without_success_audit(admin_client):
    """Check stale review rejection has feedback without success audit (HTTP 303)."""
    message = "The reviewed assertion changed. Reload the review before approving."
    with (
        _patch("approve_federated_user", side_effect=AdminActionRejected(message)) as approve,
        _patch("set_flash_if_exists") as flash,
        _patch("audit_admin_action") as audit,
    ):
        response = admin_client.post(
            "/admin/users/7/approve-federated",
            data=_approval_form(admin_client, page="2", page_size="10"),
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/admin?page=2&page_size=10"
    assert approve.await_args.kwargs["expected_review_revision"] == 4
    assert flash.await_args.args[2:] == (message, "error")
    audit.assert_not_called()


def test_no_proposal_approval_audits_explicit_null_and_committed_chosen_tier(admin_client):
    """Check no proposal approval audits explicit null and committed chosen tier (HTTP 303)."""
    approved = _pending_target(
        federated_status="approved", is_active=True, access_tier="registered"
    )
    with (
        _patch(
            "approve_federated_user",
            return_value=FederatedApproval(approved, proposed_tier=None, proposed_rule=None),
        ),
        _patch("set_flash_if_exists"),
        _patch("audit_admin_action") as audit,
    ):
        response = admin_client.post(
            "/admin/users/7/approve-federated",
            data=_approval_form(admin_client, access_tier="public"),
            follow_redirects=False,
        )
    assert response.status_code == 303
    fields = audit.call_args.kwargs
    assert fields["access_tier"] == "registered"
    assert fields["proposed_tier"] is None
    assert fields["proposed_rule"] is None
    assert "entitlement" not in fields
    assert "affiliation" not in fields
    assert "subject" not in " ".join(fields)
    assert ISSUER not in repr(audit.call_args)
    assert SUBJECT not in repr(audit.call_args)

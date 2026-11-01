"""Configured site identity reaches pages and authenticator labels safely."""

import pytest
from fastapi import Request
from lxml import html
from markupsafe import escape
from pydantic import ValidationError

from app.main import app as application
from app.template_setup import templates
from config import settings
from tests.fixtures import make_sample_user
from tests.unit.settings_builders import base_kwargs, make_settings

IDENTITY_FIELDS = (
    "site_name",
    "institution_name",
    "about_summary",
    "federated_login_label",
)


@pytest.fixture(autouse=True)
def isolate_identity_environment(monkeypatch):
    """_env_file=None does not suppress a developer's OS environment."""
    for name in (*IDENTITY_FIELDS, "totp_issuer_name", "contact_email"):
        monkeypatch.delenv(name.upper(), raising=False)


def test_generic_defaults_include_an_authenticator_issuer():
    """Check generic defaults include an authenticator issuer."""
    configured = make_settings(**base_kwargs())

    assert configured.site_name == "Oral History Archive"
    assert configured.institution_name == "Your institution"
    assert configured.about_summary == (
        "Search and explore interview metadata from oral history research collections."
    )
    assert configured.federated_login_label == "Institutional login"
    assert configured.totp_issuer_name == configured.site_name
    assert configured.contact_email == "archive@example.org"


def test_environment_configures_and_trims_the_site_identity(monkeypatch):
    """Check environment configures and trims the site identity."""
    expected = {
        "site_name": "Community Voices",
        "institution_name": "Example Research Centre",
        "about_summary": "Interviews from our community.",
        "federated_login_label": "Example institutional login",
    }
    for name, value in expected.items():
        monkeypatch.setenv(name.upper(), f"  {value}  ")

    configured = make_settings(**base_kwargs())

    for name, value in expected.items():
        assert getattr(configured, name) == value
    assert configured.totp_issuer_name == expected["site_name"]


@pytest.mark.parametrize("issuer", [None, "", "   "], ids=["unset", "empty", "spaces"])
def test_missing_or_blank_issuer_uses_the_configured_site_name(issuer):
    """Check missing or blank issuer uses the configured site name."""
    kwargs = base_kwargs(site_name="  Community Voices  ")
    if issuer is not None:
        kwargs["totp_issuer_name"] = issuer

    configured = make_settings(**kwargs)

    assert configured.totp_issuer_name == "Community Voices"


def test_explicit_authenticator_issuer_survives_site_renaming(monkeypatch):
    """Check explicit authenticator issuer survives site renaming."""
    monkeypatch.setenv("TOTP_ISSUER_NAME", "  Existing Authenticator Label  ")

    configured = make_settings(**base_kwargs(site_name="Renamed Archive"))

    assert configured.totp_issuer_name == "Existing Authenticator Label"


@pytest.mark.parametrize("name", IDENTITY_FIELDS)
def test_identity_fields_refuse_blank_values(name):
    """Check identity fields refuse blank values (ValidationError)."""
    with pytest.raises(ValidationError, match=name):
        make_settings(**base_kwargs(**{name: "   "}))


@pytest.mark.parametrize("name", IDENTITY_FIELDS)
def test_identity_fields_refuse_control_characters(name):
    """Check identity fields refuse control characters (ValidationError)."""
    with pytest.raises(ValidationError, match=name):
        make_settings(**base_kwargs(**{name: "Example\x00Archive"}))


def test_explicit_authenticator_issuer_refuses_control_characters():
    """Check explicit authenticator issuer refuses control characters (ValidationError)."""
    with pytest.raises(ValidationError, match=r"(?i)totp_issuer_name"):
        make_settings(**base_kwargs(totp_issuer_name="Example\nArchive"))


def test_configured_identity_is_registered_with_jinja():
    """Check configured identity is registered with jinja."""
    for name in IDENTITY_FIELDS:
        assert templates.env.globals[name] == getattr(settings, name)


@pytest.mark.parametrize(
    "template_name",
    ["base.html", "home.html", "about.html", "login.html", "error.html", "account.html"],
)
def test_custom_identity_is_rendered_as_text_across_pages(monkeypatch, template_name):
    """Check custom identity is rendered as text across pages."""
    identity = {
        "site_name": "Archive <script>site</script> & Voices",
        "institution_name": "Institute <script>institution</script>",
        "about_summary": "Stories <script>summary</script> & memories.",
        "federated_login_label": "Login <script>federation</script>",
    }
    for name, value in identity.items():
        monkeypatch.setitem(templates.env.globals, name, value)
    monkeypatch.setitem(templates.env.globals, "shibboleth_enabled", True)
    monkeypatch.setitem(templates.env.globals, "contact_email", "archive@example.org")

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [],
            "app": application,
        }
    )
    user = (
        make_sample_user(
            auth_method="shibboleth",
            email="reader@example.org",
            display_name="Example Reader",
            affiliation="Example Research Centre",
        )
        if template_name == "account.html"
        else None
    )
    request.state.user = user
    rendered = templates.get_template(template_name).render(
        request=request,
        user=user,
        user_tier="public",
        recent=[],
        total_datasets=0,
        last_full_rebuild=None,
        error_title="Unavailable",
        source_statuses=(),
    )
    document = html.fromstring(rendered)

    assert identity["site_name"] in document.xpath("string(//title)")
    assert identity["institution_name"] in document.text_content()
    assert document.xpath("//meta[@name='description']/@content") == [identity["about_summary"]]
    assert not document.xpath("//script")
    for name in ("site_name", "institution_name", "about_summary"):
        assert str(escape(identity[name])) in rendered
    if template_name in {"home.html", "about.html"}:
        assert identity["about_summary"] in document.text_content()
    if template_name in {"login.html", "account.html"}:
        assert identity["federated_login_label"] in document.text_content()
        assert str(escape(identity["federated_login_label"])) in rendered
    assert "Oral History Archive" not in rendered

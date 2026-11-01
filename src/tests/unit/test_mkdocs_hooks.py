"""The generated operator guide fixes site links without changing source commands."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _load_hooks():
    """Load and execute the selected repository script in an isolated module."""
    spec = importlib.util.spec_from_file_location(
        "mkdocs_hooks_under_test", _PROJECT_ROOT / "scripts/mkdocs_hooks.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hooks = _load_hooks()


@pytest.mark.parametrize(
    "source_uri",
    [
        "architecture/auth.md",
        "configuration/deployment.md",
        "configuration/settings.md",
        "runbooks/admin-totp-break-glass.md",
        "runbooks/local-staging.md",
    ],
)
def test_existing_one_level_pages_link_to_the_virtual_root_guide(source_uri):
    """Check existing one level pages link to the virtual root guide."""
    for original in ("../../Deployment.md", "../Deployment.md"):
        markdown = f"Follow [Deployment]({original}#16-post-deployment-checklist).\n"

        assert hooks.render_markdown(markdown, source_uri=source_uri) == (
            "Follow [Deployment](../Deployment.md#16-post-deployment-checklist).\n"
        )


@pytest.mark.parametrize(
    ("old", "current"),
    [
        ("2-vm-setup--hardening", "2-vm-setup-hardening"),
        ("7-gunicorn-scheduler--systemd", "7-gunicorn-scheduler-systemd"),
        ("8-nginx--ssl", "8-nginx-ssl"),
    ],
)
def test_known_heading_aliases_work_inside_the_guide_and_from_existing_pages(old, current):
    """Check known heading aliases work inside the guide and from existing pages."""
    assert hooks.render_markdown(f"[Jump](#{old})", source_uri="Deployment.md") == (
        f"[Jump](#{current})"
    )
    assert (
        hooks.render_markdown(
            f"[Jump](../../Deployment.md#{old})", source_uri="runbooks/local-staging.md"
        )
        == f"[Jump](../Deployment.md#{current})"
    )


def test_generated_guide_rebases_the_reviewed_docs_links():
    """Check generated guide rebases the reviewed docs links."""
    destinations = (
        "runbooks/retained-staging-inventory.md",
        "configuration/settings.md",
        "runbooks/federation-integration.md",
        "runbooks/key-rotation.md",
        "runbooks/search-fulltext.md",
        "runbooks/bootstrap-admin.md",
        "runbooks/deployment-boundaries.md",
        "runbooks/security-event-delivery.md",
        "runbooks/mail-recovery.md",
        "runbooks/source-rebinding.md",
        "runbooks/dependency-advisories.md",
    )
    original = "\n".join(f"[Reference](docs/{target}#details)" for target in destinations)
    expected = "\n".join(f"[Reference]({target}#details)" for target in destinations)

    assert hooks.render_markdown(original, source_uri="Deployment.md") == expected


def test_unrelated_destinations_and_pages_are_left_unchanged():
    """Check unrelated destinations and pages are left unchanged."""
    markdown = (
        "[External](https://example.org/docs/runbooks/key-rotation.md)\n"
        "[External guide](https://example.org/../../Deployment.md#8-nginx--ssl)\n"
        "[Sibling](key-rotation.md#8-nginx--ssl)\n"
        "[Unknown root link](docs/runbooks/future-procedure.md)\n"
        "[Unknown anchor](#future--heading)\n"
        "Raw paths: docs/runbooks/key-rotation.md and ../../Deployment.md\n"
    )

    assert hooks.render_markdown(markdown, source_uri="Deployment.md") == markdown
    other_page = "[Deployment](../../Deployment.md#7-gunicorn-scheduler--systemd)"
    assert hooks.render_markdown(other_page, source_uri="reference/routes/auth.md") == other_page


@pytest.mark.parametrize("fence", ["````", "~~~"])
def test_fenced_operator_examples_are_preserved_while_adjacent_links_change(fence):
    """Check fenced operator examples are preserved while adjacent links change."""
    example = (
        f"{fence}sh\n"
        "printf '[Deployment](../../Deployment.md#7-gunicorn-scheduler--systemd)'\n"
        "```\n"
        "[Key rotation](docs/runbooks/key-rotation.md)\n"
        f"{fence}\n"
    )
    original = example + "See [Deployment](../../Deployment.md).\n"

    assert hooks.render_markdown(original, source_uri="runbooks/local-staging.md") == (
        example + "See [Deployment](../Deployment.md).\n"
    )


def test_inline_code_uses_matching_backtick_spans_and_preserves_literal_commands():
    """Check inline code uses matching backtick spans and preserves literal commands."""
    literals = (
        "`[Deployment](../../Deployment.md)` and ``printf '`[Deployment](../../Deployment.md)`'``"
    )
    original = literals + " then [Deployment](../../Deployment.md)."

    assert hooks.render_markdown(original, source_uri="architecture/auth.md") == (
        literals + " then [Deployment](../Deployment.md)."
    )
    command = "`[Key rotation](docs/runbooks/key-rotation.md)`"
    assert hooks.render_markdown(command, source_uri="Deployment.md") == command


def test_link_rebasing_preserves_labels_angle_destinations_and_titles():
    """Check link rebasing preserves labels angle destinations and titles."""
    original = '[Read the guide](<../../Deployment.md#8-nginx--ssl> "Operator procedure")'

    assert hooks.render_markdown(original, source_uri="configuration/deployment.md") == (
        '[Read the guide](<../Deployment.md#8-nginx-ssl> "Operator procedure")'
    )


def test_files_event_generates_in_memory_and_refuses_a_conflicting_page(tmp_path):
    """Check files event generates in memory and refuses a conflicting page (ValueError)."""
    project = tmp_path / "project"
    project.mkdir()
    configuration = project / "mkdocs.yaml"
    configuration.write_text("site_name: Test documentation\n", encoding="utf-8")
    canonical = project / "Deployment.md"
    canonical_text = "See [Settings](docs/configuration/settings.md).\n"
    canonical.write_text(canonical_text, encoding="utf-8")
    original = "Follow [Deployment](../../Deployment.md).\n"
    existing_path = project / "docs/runbooks/local-staging.md"
    existing_path.parent.mkdir(parents=True)
    existing_path.write_text(original, encoding="utf-8")
    existing = SimpleNamespace(src_uri="runbooks/local-staging.md", content_string=original)
    other = SimpleNamespace(src_uri="index.md", content_string="Unrelated home page\n")
    config = SimpleNamespace(config_file_path=str(configuration))

    class Files(list):
        """Provide the path lookup expected by the MkDocs files event."""

        def get_file_from_path(self, source_uri):
            """Return the first file with the selected source URI, or None."""
            return next((file for file in self if file.src_uri == source_uri), None)

    def generated(factory_config, source_uri, *, content):
        """Require the original MkDocs config and return an in-memory generated file."""
        assert factory_config is config
        return SimpleNamespace(src_uri=source_uri, content_string=content)

    files = Files([existing, other])
    file_module = SimpleNamespace(File=SimpleNamespace(generated=generated))
    with patch.object(
        hooks.importlib, "import_module", autospec=True, return_value=file_module
    ) as optional_import:
        hooks.on_files(files, config=config)

        optional_import.assert_called_once_with("mkdocs.structure.files")
        assert files.get_file_from_path("Deployment.md").content_string == (
            "See [Settings](configuration/settings.md).\n"
        )
        assert existing.content_string == "Follow [Deployment](../Deployment.md).\n"
        assert other.content_string == "Unrelated home page\n"
        assert canonical.read_text(encoding="utf-8") == canonical_text
        assert existing_path.read_text(encoding="utf-8") == original

        # An actual docs-tree page must never be silently replaced by the
        # generated canonical guide, nor should the factory run twice.
        conflict = project / "docs/Deployment.md"
        conflict.write_text("Existing documentation\n", encoding="utf-8")
        conflicting_files = Files(
            [SimpleNamespace(src_uri="Deployment.md", content_string="Existing documentation\n")]
        )
        with pytest.raises(ValueError, match="conflicts"):
            hooks.on_files(conflicting_files, config=config)
        assert conflict.read_text(encoding="utf-8") == "Existing documentation\n"
        optional_import.assert_called_once()

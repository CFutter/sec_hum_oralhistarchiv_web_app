"""Startup source files combine construction, filesystem trust and source policy."""

import errno
import os
from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest

import app.sources.startup_file as startup_file_module
from app.sources import (
    FixtureAdapter,
    OaiPmhCmdiAdapter,
    load_sources_for_startup,
    validate_source_startup,
)

_DOCUMENT = """[[sources]]
name = "online_archive"
adapter = "oai_pmh_cmdi"
label = "Online café"
endpoint = "https://archive.example.edu/oai"
institution_filter = "Configured archive"

[[sources]]
name = "offline_archive"
adapter = "fixture"
label = "Offline archive"
"""


def _write_sources(tmp_path: Path, document: str = _DOCUMENT) -> Path:
    """Write the selected UTF-8 source document to sources.toml and return its path."""
    path = tmp_path / "sources.toml"
    path.write_text(document, encoding="utf-8")
    return path


def _trusted_metadata(
    monkeypatch,
    *,
    changed_path: Path | None = None,
    uid: int = 0,
    permissions: int = 0,
) -> None:
    """Exercise real descriptor traversal without root-owned test directories."""
    original_fstat = os.fstat
    changed_identity = None
    if changed_path is not None:
        value = changed_path.stat()
        changed_identity = (value.st_dev, value.st_ino)

    def fstat(descriptor: int) -> os.stat_result:
        """Simulate root-owned trusted metadata except for the selected file identity."""
        value = original_fstat(descriptor)
        values = list(value)
        mode = value.st_mode & ~0o022
        values[0] = mode
        values[4] = 0
        if (value.st_dev, value.st_ino) == changed_identity:
            values[0] = mode | permissions
            values[4] = uid
        return os.stat_result(values)

    monkeypatch.setattr(os, "fstat", fstat)


def test_development_reads_utf8_in_order_without_fetching_or_resolving_hosts(
    tmp_path: Path, monkeypatch
) -> None:
    """Check development reads utf8 in order without fetching or resolving hosts."""
    _write_sources(tmp_path)
    monkeypatch.chdir(tmp_path)
    with (
        patch.object(OaiPmhCmdiAdapter, "fetch", autospec=True) as oai_fetch,
        patch.object(FixtureAdapter, "fetch", autospec=True) as fixture_fetch,
        patch("socket.getaddrinfo", autospec=True) as resolve,
        patch.object(
            startup_file_module,
            "validate_source_startup",
            new=create_autospec(
                validate_source_startup,
                side_effect=validate_source_startup,
            ),
        ) as source_gate,
    ):
        sources = load_sources_for_startup("sources.toml", environment="dev")

    assert tuple(source.name for source in sources) == ("online_archive", "offline_archive")
    assert sources[0].display.label == "Online café"
    assert isinstance(sources[0].adapter, OaiPmhCmdiAdapter)
    assert isinstance(sources[1].adapter, FixtureAdapter)
    source_gate.assert_called_once_with(sources, environment="dev", allow_fixture=False)
    assert source_gate.call_args.args[0] is sources
    oai_fetch.assert_not_called()
    fixture_fetch.assert_not_called()
    resolve.assert_not_called()


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_hardened_startup_accepts_a_trusted_file(
    tmp_path: Path, monkeypatch, environment: str
) -> None:
    """Check hardened startup accepts a trusted file."""
    path = _write_sources(tmp_path)
    _trusted_metadata(monkeypatch)

    sources = load_sources_for_startup(path, environment=environment, allow_fixture=True)

    assert tuple(source.name for source in sources) == ("online_archive", "offline_archive")


@pytest.mark.parametrize(
    ("target", "uid", "permissions"),
    [
        ("file", 1000, 0),
        ("file", 0, 0o020),
        ("file", 0, 0o002),
        ("parent", 1000, 0),
        ("parent", 0, 0o020),
        ("parent", 0, 0o002),
    ],
    ids=[
        "file-owner",
        "file-group-write",
        "file-world-write",
        "parent-owner",
        "parent-group-write",
        "parent-world-write",
    ],
)
def test_hardened_startup_refuses_untrusted_metadata_and_closes_descriptors(
    tmp_path: Path, monkeypatch, target: str, uid: int, permissions: int
) -> None:
    """Check hardened startup refuses untrusted metadata and closes descriptors."""
    path = _write_sources(tmp_path)
    real_fstat = os.fstat
    real_open = os.open
    descriptors: list[int] = []

    def open_file(*args, **kwargs) -> int:
        """Open a real descriptor and retain it for the closure assertions."""
        descriptor = real_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    _trusted_metadata(
        monkeypatch,
        changed_path=path if target == "file" else path.parent,
        uid=uid,
        permissions=permissions,
    )
    monkeypatch.setattr(os, "open", open_file)
    with pytest.raises(ValueError):
        load_sources_for_startup(path, environment="staging")

    assert descriptors
    for descriptor in set(descriptors):
        with pytest.raises(OSError) as closed:
            real_fstat(descriptor)
        assert closed.value.errno == errno.EBADF


@pytest.mark.parametrize("part", ["file", "parent"])
def test_hardened_startup_refuses_symlink_components(
    tmp_path: Path, monkeypatch, part: str
) -> None:
    """Check hardened startup refuses symlink components (OSError)."""
    directory = tmp_path / "direct"
    directory.mkdir()
    path = _write_sources(directory)
    if part == "file":
        link = directory / "linked.toml"
        link.symlink_to(path)
        selected = link
    else:
        link = tmp_path / "linked-directory"
        link.symlink_to(directory, target_is_directory=True)
        selected = link / path.name
    _trusted_metadata(monkeypatch)

    with pytest.raises(OSError):
        load_sources_for_startup(selected, environment="staging")


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_hardened_startup_refuses_nonregular_files_without_blocking(
    tmp_path: Path, monkeypatch, kind: str
) -> None:
    """Check hardened startup refuses nonregular files without blocking (ValueError)."""
    path = tmp_path / "sources.toml"
    if kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    _trusted_metadata(monkeypatch)
    real_open = os.open

    def open_file(selected_path, flags, *args, **kwargs) -> int:
        """Require nonblocking open for the selected special file, then delegate to os.open."""
        if selected_path == path.name:
            assert flags & os.O_NONBLOCK
        return real_open(selected_path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_file)
    with pytest.raises(ValueError, match="regular"):
        load_sources_for_startup(path, environment="staging")


@pytest.mark.parametrize("relative", [True, False], ids=["relative", "parent-traversal"])
def test_hardened_startup_refuses_ambiguous_paths_before_opening(
    tmp_path: Path, monkeypatch, relative: bool
) -> None:
    """Check hardened startup refuses ambiguous paths before opening (ValueError)."""
    _write_sources(tmp_path)
    monkeypatch.chdir(tmp_path)
    path = "sources.toml" if relative else str(tmp_path / ".." / tmp_path.name / "sources.toml")
    with (
        patch.object(os, "open", autospec=True) as open_file,
        pytest.raises(ValueError),
    ):
        load_sources_for_startup(path, environment="staging")

    open_file.assert_not_called()


@pytest.mark.parametrize(
    ("environment", "allow_fixture", "error"),
    [("unknown", False, ValueError), ("dev", "false", TypeError)],
    ids=["unknown-environment", "nonboolean-fixture-override"],
)
def test_invalid_startup_options_fail_before_opening(
    tmp_path: Path, environment: str, allow_fixture: object, error: type[Exception]
) -> None:
    """Check invalid startup options fail before opening (error)."""
    with (
        patch.object(os, "open", autospec=True) as open_file,
        patch.object(Path, "read_text", autospec=True) as read_text,
        pytest.raises(error),
    ):
        load_sources_for_startup(
            tmp_path / "missing.toml",
            environment=environment,
            allow_fixture=allow_fixture,  # type: ignore[arg-type]
        )

    open_file.assert_not_called()
    read_text.assert_not_called()


@pytest.mark.parametrize(
    "document",
    ["", _DOCUMENT.replace('adapter = "fixture"', 'adapter = "unknown"')],
    ids=["empty", "unknown-adapter"],
)
def test_startup_rejects_invalid_source_documents(tmp_path: Path, document: str) -> None:
    """Check startup rejects invalid source documents (ValueError)."""
    path = _write_sources(tmp_path, document)
    with pytest.raises(ValueError):
        load_sources_for_startup(path, environment="dev")


@pytest.mark.parametrize(
    ("contents", "error"),
    [(None, FileNotFoundError), (b"\xff", UnicodeDecodeError)],
    ids=["missing-file", "invalid-utf8"],
)
def test_file_errors_propagate(
    tmp_path: Path, contents: bytes | None, error: type[Exception]
) -> None:
    """Check file errors propagate."""
    path = tmp_path / "sources.toml"
    if contents is not None:
        path.write_bytes(contents)
    with pytest.raises(error):
        load_sources_for_startup(path, environment="dev")


def test_production_fixture_permission_is_applied_after_loading(
    tmp_path: Path, monkeypatch
) -> None:
    """Check production fixture permission is applied after loading (ValueError)."""
    path = _write_sources(tmp_path)
    _trusted_metadata(monkeypatch)
    with pytest.raises(ValueError, match="production fixture permission"):
        load_sources_for_startup(path, environment="production")

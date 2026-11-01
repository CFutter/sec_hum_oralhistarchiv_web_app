"""Local completion evidence is bounded, conservative and independent of file mtime."""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from app.backup_status import read_backup_status
from app.paths import PROJECT_ROOT

_NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
_UNKNOWN = {"status": "unknown", "age_seconds": None}


def _write_marker(path, *, completed_at=None):
    """Write a mode-0640 marker using _NOW for an omitted timestamp; return its path."""
    completed_at = int(_NOW.timestamp()) if completed_at is None else completed_at
    path.write_bytes(f"OHA_BACKUP_SUCCESS_V1 {completed_at}\n".encode("ascii"))
    path.chmod(0o640)
    return str(path)


@pytest.mark.parametrize("age_seconds", [0, 1, 3600, 30 * 86400])
def test_valid_completion_marker_returns_nonnegative_integer_age(tmp_path, age_seconds):
    """Valid completion marker returns nonnegative integer age."""
    marker = _write_marker(
        tmp_path / "last-success", completed_at=int(_NOW.timestamp()) - age_seconds
    )

    assert read_backup_status(marker, now=_NOW) == {"status": "ok", "age_seconds": age_seconds}


def test_disabled_marker_is_unknown_without_opening_a_file():
    """Disabled marker is unknown without opening a file."""
    with patch("os.open") as opened:
        assert read_backup_status(None, now=_NOW) == _UNKNOWN

    opened.assert_not_called()


@pytest.mark.parametrize("name", ["", "relative-marker", "../marker"])
def test_relative_marker_paths_are_unknown_without_opening_them(name):
    """Relative marker paths are unknown without opening them."""
    with patch("os.open") as opened:
        assert read_backup_status(name, now=_NOW) == _UNKNOWN

    opened.assert_not_called()


def test_missing_marker_is_unknown_and_does_not_create_it(tmp_path):
    """Missing marker is unknown and does not create it."""
    marker = tmp_path / "missing"

    assert read_backup_status(str(marker), now=_NOW) == _UNKNOWN
    assert not marker.exists()


def test_invalid_nul_path_is_unknown_without_exposing_the_path():
    """Invalid NUL path is unknown without exposing the path."""
    assert read_backup_status("/private/invalid\x00marker", now=_NOW) == _UNKNOWN


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"OHA_BACKUP_SUCCESS_V1 0\n",
        b"OHA_BACKUP_SUCCESS_V1 01\n",
        b"OHA_BACKUP_SUCCESS_V1 -1\n",
        b"OHA_BACKUP_SUCCESS_V1 +1\n",
        b"OHA_BACKUP_SUCCESS_V1 1.0\n",
        b"OHA_BACKUP_SUCCESS_V1 1e9\n",
        b"OHA_BACKUP_SUCCESS_V1 1000000000000\n",
        b"OHA_BACKUP_SUCCESS_V1 1",
        b"OHA_BACKUP_SUCCESS_V1 1\r\n",
        b"OHA_BACKUP_SUCCESS_V1  1\n",
        b"OHA_BACKUP_SUCCESS_V1\t1\n",
        b" OHA_BACKUP_SUCCESS_V1 1\n",
        b"OHA_BACKUP_SUCCESS_V1 1 \n",
        b"OHA_BACKUP_SUCCESS_V1 1\n\n",
        b"OHA_BACKUP_SUCCESS_V1 1\nprivate-archive-name\n",
        b"OHA_BACKUP_SUCCESS_V2 1\n",
        b"OHA_BACKUP_SUCCESS_V1 \xff\n",
        b"1761048000\n",
        b'{"completed_at": 1761048000}\n',
    ],
)
def test_noncanonical_or_malformed_content_is_unknown(tmp_path, content):
    """Noncanonical or malformed content is unknown."""
    marker = tmp_path / "last-success"
    marker.write_bytes(content)

    result = read_backup_status(str(marker), now=_NOW)

    assert result == _UNKNOWN
    assert set(result) == {"status", "age_seconds"}
    assert str(marker) not in json.dumps(result)


def test_twelve_digit_supported_timestamp_is_parsed_without_float_rounding(tmp_path):
    """Twelve digit supported timestamp is parsed without float rounding."""
    now = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)
    marker = _write_marker(tmp_path / "last-success", completed_at=int(now.timestamp()) - 1)

    assert read_backup_status(marker, now=now) == {"status": "ok", "age_seconds": 1}


@pytest.mark.parametrize("future_seconds", [1, 60, 86400])
def test_future_completion_is_unknown_instead_of_a_negative_age(tmp_path, future_seconds):
    """Future completion is unknown instead of a negative age."""
    marker = _write_marker(
        tmp_path / "last-success", completed_at=int(_NOW.timestamp()) + future_seconds
    )

    assert read_backup_status(marker, now=_NOW) == _UNKNOWN


def test_age_uses_completion_content_even_if_the_marker_is_touched(tmp_path):
    """Age uses completion content even if the marker is touched."""
    completed_at = int(_NOW.timestamp()) - 86400
    marker = _write_marker(tmp_path / "last-success", completed_at=completed_at)
    os.utime(marker, (int(_NOW.timestamp()), int(_NOW.timestamp())))

    assert read_backup_status(marker, now=_NOW) == {"status": "ok", "age_seconds": 86400}


def test_old_mtime_does_not_age_a_fresh_completion(tmp_path):
    """Old mtime does not age a fresh completion."""
    marker = _write_marker(tmp_path / "last-success", completed_at=int(_NOW.timestamp()) - 1)
    os.utime(marker, (1, 1))

    assert read_backup_status(marker, now=_NOW) == {"status": "ok", "age_seconds": 1}


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o444])
def test_readable_non_group_or_world_writable_files_are_accepted(tmp_path, mode):
    """Readable non group or world writable files are accepted."""
    path = tmp_path / "last-success"
    _write_marker(path)
    path.chmod(mode)

    assert read_backup_status(str(path), now=_NOW) == {"status": "ok", "age_seconds": 0}


@pytest.mark.parametrize("mode", [0o660, 0o602, 0o666])
def test_group_or_world_writable_completion_evidence_is_unknown(tmp_path, mode):
    """Group or world writable completion evidence is unknown."""
    path = tmp_path / "last-success"
    _write_marker(path)
    path.chmod(mode)

    assert read_backup_status(str(path), now=_NOW) == _UNKNOWN


def test_symbolic_link_is_never_followed_even_to_a_valid_marker(tmp_path):
    """Symbolic link is never followed even to a valid marker."""
    target = tmp_path / "private-target"
    _write_marker(target)
    link = tmp_path / "last-success"
    link.symlink_to(target)

    assert read_backup_status(str(link), now=_NOW) == _UNKNOWN
    assert read_backup_status(str(target), now=_NOW) == {"status": "ok", "age_seconds": 0}


def test_hard_linked_marker_is_unknown_under_both_names(tmp_path):
    """Hard linked marker is unknown under both names."""
    target = tmp_path / "last-success"
    _write_marker(target)
    alias = tmp_path / "alias"
    os.link(target, alias)

    assert read_backup_status(str(target), now=_NOW) == _UNKNOWN
    assert read_backup_status(str(alias), now=_NOW) == _UNKNOWN


def test_directory_marker_is_unknown(tmp_path):
    """Directory marker is unknown."""
    assert read_backup_status(str(tmp_path), now=_NOW) == _UNKNOWN


def test_fifo_marker_returns_unknown_without_waiting_for_a_writer(tmp_path):
    """FIFO marker returns unknown without waiting for a writer."""
    fifo = tmp_path / "last-success"
    os.mkfifo(fifo, 0o600)
    source = (
        "import sys\n"
        f"sys.path.insert(0, {str(PROJECT_ROOT / 'src')!r})\n"
        "from app.backup_status import read_backup_status\n"
        f"assert read_backup_status({str(fifo)!r}) == {_UNKNOWN!r}\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", source], capture_output=True, text=True, check=False, timeout=10
    )

    assert completed.returncode == 0, completed.stderr


def test_oversized_file_is_rejected_before_reading_its_body(tmp_path):
    """Oversized file is rejected before reading its body."""
    marker = tmp_path / "last-success"
    marker.write_bytes(b"OHA_BACKUP_SUCCESS_V1 1\n" + b"private-content" * 100)
    with patch("os.read") as read:
        assert read_backup_status(str(marker), now=_NOW) == _UNKNOWN

    read.assert_not_called()


@pytest.mark.parametrize("error", [PermissionError("denied"), OSError("unavailable")])
def test_open_errors_are_unknown_without_error_details(tmp_path, error):
    """Open errors are unknown without error details."""
    marker = _write_marker(tmp_path / "last-success")
    with patch("os.open", side_effect=error):
        assert read_backup_status(marker, now=_NOW) == _UNKNOWN


def test_read_error_closes_the_descriptor_and_returns_unknown(tmp_path):
    """Read error closes the descriptor and returns unknown."""
    marker = _write_marker(tmp_path / "last-success")
    with (
        patch("os.read", side_effect=OSError("read failed")),
        patch("os.close", wraps=os.close) as close,
    ):
        assert read_backup_status(marker, now=_NOW) == _UNKNOWN

    close.assert_called_once()


def test_changed_content_length_during_a_read_is_unknown(tmp_path):
    """Changed content length during a read is unknown."""
    marker = _write_marker(tmp_path / "last-success")
    with patch("os.read", return_value=b"OHA_BACKUP_SUCCESS_V1 1\n"):
        assert read_backup_status(marker, now=_NOW) == _UNKNOWN


def test_naive_clock_is_unknown_instead_of_assuming_the_host_timezone(tmp_path):
    """Naive clock is unknown instead of assuming the host timezone."""
    marker = _write_marker(tmp_path / "last-success")

    assert read_backup_status(marker, now=_NOW.replace(tzinfo=None)) == _UNKNOWN


def test_aware_non_utc_clock_represents_the_same_instant(tmp_path):
    """Aware non UTC clock represents the same instant."""
    marker = _write_marker(tmp_path / "last-success", completed_at=int(_NOW.timestamp()) - 10)
    shifted = datetime.fromisoformat("2026-10-21T13:00:00+01:00")

    assert read_backup_status(marker, now=shifted) == {"status": "ok", "age_seconds": 10}

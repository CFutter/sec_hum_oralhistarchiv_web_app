"""Read the optional local logical-backup completion marker without archive access."""

import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypedDict

__all__ = ["BackupStatus", "read_backup_status"]

_MAX_MARKER_BYTES = 64
_MARKER = re.compile(rb"OHA_BACKUP_SUCCESS_V1 ([1-9][0-9]{0,11})\n")


class BackupStatus(TypedDict):
    """Informational age of local logical-backup completion, not recovery assurance."""

    status: Literal["ok", "unknown"]
    age_seconds: int | None


def read_backup_status(path: str | None, *, now: datetime | None = None) -> BackupStatus:
    """Return the marker's age in seconds, or unknown for absent/unsafe/invalid data.

    Require an absolute path under trusted directories and an aware ``now``
    (default: current UTC). Read at most 65 bytes without following a final
    symlink; reject nonregular, hard-linked, group/world-writable, oversized or
    future markers. The marker is ``OHA_BACKUP_SUCCESS_V1 <Unix seconds>\n``.
    No archive, off-host copy or restore is checked.
    """
    unknown = BackupStatus(status="unknown", age_seconds=None)
    if path is None or not Path(path).is_absolute():
        return unknown
    checked_at = datetime.now(UTC) if now is None else now
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        return unknown
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 0 < metadata.st_size <= _MAX_MARKER_BYTES
            ):
                return unknown
            content = os.read(descriptor, _MAX_MARKER_BYTES + 1)
        finally:
            os.close(descriptor)
        match = _MARKER.fullmatch(content)
        if match is None or len(content) != metadata.st_size:
            return unknown
        completed_at = int(match[1])
        current_time = int(checked_at.timestamp())
        if completed_at > current_time:
            return unknown
        return BackupStatus(status="ok", age_seconds=current_time - completed_at)
    except (OSError, ValueError, OverflowError):
        return unknown

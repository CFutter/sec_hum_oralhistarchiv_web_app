"""Fail-closed checks of the effective kernel boundary before accepting a job."""

import errno
import os
import socket
import struct
import sys
from pathlib import Path

_DENIED = {errno.EACCES, errno.EPERM}


def _require_network_denial(family: int, address: str) -> None:
    """Probe a live loopback TCP listener and require connect denial; tolerate unavailable IPv6.

    Explicit refusal checks raise RuntimeError; socket setup OSErrors propagate.
    """
    try:
        listener = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        if family == socket.AF_INET6 and error.errno == errno.EAFNOSUPPORT:
            return
        raise RuntimeError("Parser network sandbox is unavailable") from None
    with listener:
        listener.bind((address, 0))
        listener.listen(1)
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            try:
                connection.connect(listener.getsockname())
            except TimeoutError:
                # cgroup SKB filters may discard SYN packets, rather than
                # reporting EPERM. Our own live listener removes the ordinary
                # closed-port ambiguity from this denial check.
                return
            except OSError as error:
                if error.errno in _DENIED:
                    return
            raise RuntimeError("Parser loopback network denial is unavailable")


def validate_effective_sandbox(connection: socket.socket) -> None:
    """Check the Linux service sandbox before releasing the parser identity hello.

    Inspect peer/own UIDs, process environment, /proc, protected paths and privilege
    flags; probe Unix-socket creation and live IPv4/IPv6 loopback connection denial.
    Require a separate unprivileged UID and minimal bootstrap environment. Explicit
    policy failures raise RuntimeError; unexpected socket/filesystem errors propagate.
    """
    pid, uid, _gid = struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    if os.getuid() in {0, uid} or os.getuid() != os.geteuid():
        raise RuntimeError("Parser identity separation is unavailable")
    if "config" in sys.modules or set(os.environ) - {"LANG", "PATH", "HOME"}:
        raise RuntimeError("Parser bootstrap environment is not minimal")
    try:
        Path(f"/proc/{pid}/environ").read_bytes()
    except (PermissionError, FileNotFoundError):
        pass
    else:
        raise RuntimeError("Parser can access its client's process environment")
    for path in ("/etc/oralhistarchiv", "/run/postgresql"):
        try:
            tuple(Path(path).iterdir())
        except (PermissionError, FileNotFoundError):
            continue
        raise RuntimeError("Parser service paths are not isolated")
    try:
        database_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno not in _DENIED | {errno.EAFNOSUPPORT}:
            raise RuntimeError("Parser Unix socket denial is unavailable") from None
    else:
        database_socket.close()
        raise RuntimeError("Parser can open peer-authenticated database sockets")
    _require_network_denial(socket.AF_INET, "127.0.0.1")
    _require_network_denial(socket.AF_INET6, "::1")
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines()
        if ":" in line
    )
    if status.get("NoNewPrivs", "").strip() != "1" or int(status.get("CapEff", "1"), 16):
        raise RuntimeError("Parser privilege restrictions are unavailable")

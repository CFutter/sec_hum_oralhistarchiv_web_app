"""Explicit cross-identity proof for deployment-lock permissions.

Run this file explicitly with RUN_DEPLOYMENT_LOCK_TESTS=1 as root on a
disposable Linux host. It uses temporary files and unused numeric identities;
it neither creates OS accounts nor changes the installed deployment lock.
"""

import fcntl
import grp
import os
import pwd
import subprocess
import sys
import tempfile
from pathlib import Path

_CHILD = r"""
import fcntl
import os
import sys

path, uid, gid, lock_group, participant = sys.argv[1:]
os.setgroups([int(lock_group)] if participant == 'yes' else [])
os.setgid(int(gid))
os.setuid(int(uid))
assert os.getuid() == int(uid) and os.geteuid() == int(uid)
try:
    handle = open(path, 'rb')
except PermissionError:
    raise SystemExit(77)
with handle:
    try:
        fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit(75)
"""


def test_deployment_lock_group_excludes_unrelated_kernel_identities():
    """Real nonroot credentials can lock only with the provisioned group."""
    assert os.environ.get("RUN_DEPLOYMENT_LOCK_TESTS") == "1", "explicit host proof required"
    assert os.geteuid() == 0, "host proof needs root to select distinct numeric identities"
    used_ids = {entry.pw_uid for entry in pwd.getpwall()} | {
        entry.gr_gid for entry in grp.getgrall()
    }
    identities = [value for value in range(50_000, 60_000) if value not in used_ids][:6]
    assert len(identities) == 6
    lock_group, unrelated_group, *participant_ids = identities
    with tempfile.TemporaryDirectory(prefix="oralhistarchiv-lock-proof-", dir="/tmp") as name:
        directory = Path(name)
        directory.chmod(0o755)
        lock_path = directory / "deployment.lock"
        lock_path.touch(mode=0o640)
        lock_path.chmod(0o640)
        os.chown(lock_path, 0, lock_group)

        def invoke(uid: int, *, participant: bool) -> subprocess.CompletedProcess[bytes]:
            """Run the lock probe under selected numeric credentials and capture its exit status."""
            return subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    _CHILD,
                    str(lock_path),
                    str(uid),
                    str(unrelated_group),
                    str(lock_group),
                    "yes" if participant else "no",
                ],
                capture_output=True,
                timeout=5,
                check=False,
            )

        for uid in participant_ids:
            result = invoke(uid, participant=True)
            assert result.returncode == 0, result.stderr.decode(errors="replace")
        result = invoke(participant_ids[0], participant=False)
        assert result.returncode == 77, result.stderr.decode(errors="replace")
        with lock_path.open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = invoke(participant_ids[0], participant=True)
            assert result.returncode == 75, result.stderr.decode(errors="replace")
        result = invoke(participant_ids[0], participant=True)
        assert result.returncode == 0, result.stderr.decode(errors="replace")

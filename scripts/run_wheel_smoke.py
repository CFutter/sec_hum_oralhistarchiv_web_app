"""Build and smoke-test the CI commit using the production release builder."""

import os
import subprocess  # nosec B404 - fixed interpreter and repository script
import sys
import tempfile
from pathlib import Path


def main() -> None:
    """Build GITHUB_SHA in temporary storage and discard the artifact after validation.

    Requires a clean checkout, Python 3.11 and the builder dependencies. Raises
    RuntimeError if GITHUB_SHA is absent; subprocess failures and the 1800-second
    timeout propagate.
    """
    root = Path(__file__).resolve().parents[1]
    commit = os.environ.get("GITHUB_SHA", "")
    if not commit:
        raise RuntimeError("GITHUB_SHA is required for the release-artifact smoke test")

    with tempfile.TemporaryDirectory(prefix="oha-release-smoke-") as temporary:
        output = Path(temporary) / "release"
        subprocess.run(  # nosec B603 - arguments are fixed except trusted CI SHA/path
            [
                sys.executable,
                str(root / "scripts/build_release.py"),
                "--commit-sha",
                commit,
                "--output-dir",
                str(output),
            ],
            cwd=root,
            check=True,
            timeout=1800,
        )


if __name__ == "__main__":
    main()

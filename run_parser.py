"""Socket-activated parser entrypoint: discard ambient settings before imports."""

import os

# systemd supplies no application EnvironmentFile. Clearing before importing
# application packages is defense in depth and also covers manual invocation.
os.environ.clear()
os.environ.update({"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})

from app.sources import run_parser_service

if __name__ == "__main__":
    run_parser_service()

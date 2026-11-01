"""Small spawn targets for source-fetch cancellation tests.

Keep this module independent of test fixtures and application startup: a spawned
child imports its target's module before it can publish the phase marker.
"""

import os
import signal
import struct
import threading
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from app.ingestion_contracts import HarvestResult, harvest_result_to_json


def _blocked_worker(connection, endpoint):
    """Make cancellation prove SIGKILL escalation, not only cooperative cleanup."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    marker = Path(urlsplit(endpoint).path)
    if marker.name == "partial":
        os.write(connection.fileno(), struct.pack("!i", 1024) + b"unfinished")
    elif marker.name == "complete":
        result = HarvestResult(source_cursor=datetime(2026, 10, 26, tzinfo=UTC))
        connection.send_bytes(b"S" + harvest_result_to_json(result))
    marker.touch()
    threading.Event().wait()
    connection.close()


def blocked_oai_worker(connection, endpoint, _since, _institution, _max_pages, **_logging):
    """Run the SIGTERM-ignoring worker using the endpoint as its marker path."""
    _blocked_worker(connection, endpoint)


def blocked_feed_worker(connection, config, _credentials, _since, _deadline):
    """Run the SIGTERM-ignoring worker using the configured endpoint as its marker path."""
    _blocked_worker(connection, config.endpoint)

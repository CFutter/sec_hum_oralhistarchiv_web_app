"""Exercise pinned server logging, including paths outside logging's exception API."""

import asyncio
import json
import logging
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from types import SimpleNamespace

import h11
import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from gunicorn.config import Config as GunicornConfig
from gunicorn.glogging import Logger
from uvicorn.config import Config as UvicornConfig
from uvicorn.lifespan.on import LifespanOn
from uvicorn.protocols.http.flow_control import FlowControl
from uvicorn.protocols.http.h11_impl import RequestResponseCycle

from app.bootstrap_logging import setup_bootstrap_logging
from app.paths import PROJECT_ROOT
from app.server_worker import SafeUvicornWorker
from config import setup_logging

_SENTINEL = "private-server-error-value-812938"


class _Transport(asyncio.Transport):
    """Capture protocol response bytes and track closure without actual transport I/O."""

    def __init__(self):
        """Initialize the response byte buffer and open transport state."""
        self.data = bytearray()
        self.closed = False

    def is_closing(self):
        """Return whether the transport has been closed."""
        return self.closed

    def write(self, data):
        """Append outgoing bytes to the captured response buffer."""
        self.data.extend(data)

    def close(self):
        """Mark the fake transport closed."""
        self.closed = True

    def pause_reading(self):
        """Accept the transport flow-control callback without changing state."""
        pass

    def resume_reading(self):
        """Accept the transport flow-control callback without changing state."""
        pass


@pytest.fixture
def worker(tmp_path, restore_logging):
    """Use the real pinned constructors: Uvicorn aliases Gunicorn's plain handler list."""
    del restore_logging
    config = GunicornConfig()
    config.set("worker_tmp_dir", str(tmp_path))
    instance = SafeUvicornWorker(1, os.getpid(), [], None, 30, config, Logger(config))
    try:
        yield instance
    finally:
        instance.tmp.close()


def _worker_app(worker, app):
    """Install an application on the worker, load it, and return its WSGI application."""
    worker.app = SimpleNamespace(wsgi=lambda: app)
    worker.load_wsgi()
    return worker.wsgi


@pytest.mark.parametrize("parent_handler", [False, True], ids=["gunicorn", "uvicorn-parent"])
async def test_actual_uvicorn_error_path_uses_application_formatter(worker, capsys, parent_handler):
    """A real HTTP cycle retains the 500 and server diagnostic without exception values."""
    app = FastAPI()

    @app.exception_handler(Exception)
    async def handle_failure(_request, error):
        """Log the original exception with structured traceback data and return a generic 500."""
        logging.getLogger("app.main").error(
            "Unhandled exception", exc_info=(type(error), error, error.__traceback__)
        )
        return PlainTextResponse("generic 500", status_code=500)

    @app.get("/boom")
    async def boom():
        """Raise the sentinel RuntimeError from a real endpoint."""
        raise RuntimeError(_SENTINEL)

    if parent_handler:
        parent = logging.getLogger("uvicorn")
        parent.handlers = [logging.StreamHandler(sys.stderr)]
        parent.propagate = False
    setup_logging(log_format="json")
    conn = h11.Connection(h11.SERVER)
    conn.receive_data(b"GET /boom HTTP/1.1\r\nHost: localhost\r\n\r\n")
    conn.next_event()
    conn.next_event()
    transport = _Transport()
    event = asyncio.Event()
    event.set()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/boom",
        "raw_path": b"/boom",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 1234),
        "server": ("localhost", 80),
    }
    cycle = RequestResponseCycle(
        scope,
        conn,
        transport,
        FlowControl(transport),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("uvicorn.access"),
        False,
        [],
        event,
        lambda: None,
    )
    cycle.more_body = False
    await cycle.run_asgi(_worker_app(worker, app))

    captured = capsys.readouterr()
    assert _SENTINEL not in captured.out + captured.err
    assert bytes(transport.data).startswith(b"HTTP/1.1 500")
    records = [json.loads(line) for line in captured.out.splitlines()]
    server_errors = [record for record in records if record["logger"] == "uvicorn.error"]
    assert len(server_errors) == 1
    assert server_errors[0]["exception"]["type"] == "builtins.RuntimeError"
    assert any(record["logger"] == "app.main" for record in records)


@pytest.mark.parametrize("configured", [False, True], ids=["bootstrap", "application"])
@pytest.mark.parametrize("phase", ["startup", "shutdown"])
async def test_real_lifespan_failures_do_not_log_preformatted_tracebacks(
    worker, capsys, configured, phase
):
    """Starlette sends exception text as an ASGI message, not as LogRecord.exc_info."""
    setup_bootstrap_logging()

    @asynccontextmanager
    async def lifespan(_app):
        """Optionally configure JSON logging, then fail during the selected lifespan phase."""
        if configured:
            setup_logging(log_format="json")
        if phase == "startup":
            raise RuntimeError(_SENTINEL)
        yield
        raise RuntimeError(_SENTINEL)

    app = FastAPI(lifespan=lifespan)
    config = UvicornConfig(_worker_app(worker, app), log_config=None, lifespan="on")
    lifecycle = LifespanOn(config)
    await lifecycle.startup()
    if phase == "shutdown":
        await lifecycle.shutdown()

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert _SENTINEL not in output
    records = [json.loads(line) for line in output.splitlines()]
    assert any(
        record.get("exception_type") == "RuntimeError"
        or record.get("exception", {}).get("type") == "builtins.RuntimeError"
        for record in records
    )
    assert lifecycle.startup_failed if phase == "startup" else lifecycle.shutdown_failed
    assert any(
        record["logger"] == "uvicorn.error" and record["level"] == "ERROR" for record in records
    )


def test_bootstrap_import_needs_no_settings_or_third_party_packages(tmp_path):
    """Check bootstrap import needs no settings or third party packages."""
    source = """
import sys
sys.path.insert(0, sys.argv[1])
import app.bootstrap_logging
assert 'config' not in sys.modules
assert 'pydantic' not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", source, str(PROJECT_ROOT / "src")],
        cwd=tmp_path,
        env={},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_actual_gunicorn_config_failure_prints_only_categorical_error(tmp_path):
    """Check actual gunicorn config failure prints only categorical error."""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    environment["DATABASE_URL"] = "postgresql:/app:" + _SENTINEL + "@db/archive"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "gunicorn",
            "--check-config",
            "--config",
            str(PROJECT_ROOT / "gunicorn.conf.py"),
            "app.main:app",
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert _SENTINEL not in result.stdout + result.stderr
    assert "postgresql:/app:" not in result.stderr
    assert '"startup_phase": "settings_import"' in result.stderr
    assert '"exception_type": "ValidationError"' in result.stderr


def test_real_worker_import_failure_cannot_escape_via_supervisor_print(tmp_path):
    """Execute the pinned init_process/load_wsgi ordering in an isolated interpreter."""
    source = """
'''Probe safe worker import failures using PROBE_FAILURE and argv[1] as the temp directory.'''
import os, sys
from types import SimpleNamespace
from gunicorn.config import Config
from gunicorn.glogging import Logger
from app.server_worker import SafeUvicornWorker

def broken_import():
    '''Raise RuntimeError containing the required PROBE_FAILURE environment value.'''
    raise RuntimeError(os.environ['PROBE_FAILURE'])

config = Config()
config.set('worker_tmp_dir', sys.argv[1])
worker = SafeUvicornWorker(1, os.getpid(), [], SimpleNamespace(wsgi=broken_import), 30,
                           config, Logger(config))
try:
    worker.init_process()
except RuntimeError as error:
    # Gunicorn Arbiter.spawn_worker prints str(error) outside the logging API.
    print(str(error), file=sys.stderr)
    assert 'config.settings' not in sys.modules
else:
    raise AssertionError('Broken application import unexpectedly succeeded')
finally:
    worker.tmp.close()
"""
    environment = {"PYTHONPATH": str(PROJECT_ROOT / "src"), "PROBE_FAILURE": _SENTINEL}
    result = subprocess.run(
        [sys.executable, "-c", source, str(tmp_path)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert _SENTINEL not in result.stdout + result.stderr
    assert '"startup_phase": "worker_startup"' in result.stderr
    assert '"exception_type": "RuntimeError"' in result.stderr
    assert "Server startup failed; inspect structured bootstrap diagnostics" in result.stderr

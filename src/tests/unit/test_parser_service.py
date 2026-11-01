"""Transport, bootstrap and role regression tests; host sandbox proof is separate."""

import hashlib
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest
from pydantic import SecretBytes, SecretStr, ValidationError

from app.ingestion_contracts import HarvestCancelled, harvest_result_to_json
from app.sources import (
    JsonFeedConfig,
    JsonFeedCredentials,
    json_feed_fetch,
    oai_client,
    parser_sandbox,
    parser_service,
    parser_transport,
)
from config.settings import Settings
from tests.unit.settings_builders import base_kwargs, staging_kwargs


@pytest.fixture(autouse=True)
def clear_runtime_selection(monkeypatch):
    """Clear parser transport selection for each test without changing executable settings."""
    monkeypatch.setattr(parser_transport, "_runtime_selection", None)


def test_startup_freezes_explicit_settings_only_after_success(monkeypatch):
    """Check startup freezes explicit settings only after success (OSError)."""
    monkeypatch.setenv("ENV_STATE", "dev")
    monkeypatch.setenv("PARSER_EXECUTION_MODE", "local")
    with patch.object(parser_transport, "request_parser", autospec=True, return_value=b"ready"):
        parser_transport.validate_parser_service(environment="production", mode="service")
    assert parser_transport.use_parser_service()
    with pytest.raises(parser_transport.ParserServiceError):
        parser_transport.validate_parser_service(environment="production", mode="local")
    assert parser_transport.use_parser_service()
    with (
        patch.object(parser_transport, "request_parser", autospec=True, side_effect=OSError),
        pytest.raises(OSError),
    ):
        parser_transport.validate_parser_service(environment="dev", mode="service")
    assert parser_transport._runtime_selection == ("production", "service")


def test_development_dotenv_choice_is_passed_explicitly_without_environment_mutation(monkeypatch):
    """Check development dotenv choice is passed explicitly without environment mutation."""
    monkeypatch.delenv("PARSER_EXECUTION_MODE", raising=False)
    parser_transport.validate_parser_service(environment="dev", mode="local")
    assert not parser_transport.use_parser_service()
    assert "PARSER_EXECUTION_MODE" not in os.environ


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_hardened_runtime_cannot_select_local_worker(monkeypatch, environment):
    """Check hardened runtime cannot select local worker."""
    monkeypatch.setenv("ENV_STATE", environment)
    monkeypatch.setenv("PARSER_EXECUTION_MODE", "local")
    with pytest.raises(parser_transport.ParserServiceError, match="configuration"):
        parser_transport.use_parser_service()


def test_service_is_default_and_dev_local_requires_explicit_choice(monkeypatch):
    """Check service is default and dev local requires explicit choice."""
    monkeypatch.setenv("ENV_STATE", "dev")
    monkeypatch.delenv("PARSER_EXECUTION_MODE", raising=False)
    assert parser_transport.use_parser_service()
    monkeypatch.setenv("PARSER_EXECUTION_MODE", "local")
    assert not parser_transport.use_parser_service()


def test_missing_service_never_starts_scheduler_owned_oai_worker(monkeypatch):
    """Check missing service never starts scheduler owned OAI worker."""
    monkeypatch.setenv("PARSER_EXECUTION_MODE", "service")
    with (
        patch.object(
            oai_client,
            "request_parser",
            autospec=True,
            side_effect=parser_transport.ParserServiceError,
        ),
        patch.object(oai_client.multiprocessing, "get_context", autospec=True) as spawn,
        pytest.raises(oai_client.OAIProtocolError, match="service failed"),
    ):
        oai_client.fetch_updates_isolated(
            "https://archive.example.edu/oai",
            "2026-01-01",
            "Archive",
            source="archive",
            log_level="INFO",
            log_format="json",
        )
    spawn.assert_not_called()


@pytest.mark.parametrize("uid", [0, 12345])
def test_credentials_reject_root_or_scheduler_identity(monkeypatch, uid):
    """Check credentials reject root or scheduler identity."""
    monkeypatch.setattr(os, "getuid", lambda: 12345)
    connection = Mock(spec=socket.socket)
    connection.recvmsg.return_value = (
        b"P",
        [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("3i", 99, uid, 40))],
        0,
        None,
    )
    with pytest.raises(parser_transport.ParserServiceError, match="separate"):
        parser_transport._verify_worker_identity(
            connection, deadline=time.monotonic() + 1, cancel_event=None
        )


def test_credentials_accept_kernel_authenticated_distinct_identity(monkeypatch):
    """Check credentials accept kernel authenticated distinct identity."""
    monkeypatch.setattr(os, "getuid", lambda: 12345)
    connection = Mock(spec=socket.socket)
    connection.recvmsg.return_value = (
        b"P",
        [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("3i", 99, 61234, 61234))],
        0,
        None,
    )
    parser_transport._verify_worker_identity(
        connection, deadline=time.monotonic() + 1, cancel_event=None
    )


def test_worker_identity_failure_sends_no_request_credentials():
    """Check worker identity failure sends no request credentials."""
    connection = Mock(spec=socket.socket)
    with (
        patch.object(
            parser_transport, "_socket_path", autospec=True, return_value="/run/proof.sock"
        ),
        patch.object(parser_transport.socket, "socket", autospec=True) as factory,
        patch.object(
            parser_transport,
            "_verify_worker_identity",
            autospec=True,
            side_effect=parser_transport.ParserServiceError,
        ),
        patch.object(parser_transport, "send_bytes", autospec=True) as send,
        pytest.raises(parser_transport.ParserServiceError),
    ):
        factory.return_value.__enter__.return_value = connection
        parser_transport.request_parser(
            {"operation": "json", "bearer": "synthetic-secret"},
            maximum=32,
            deadline=time.monotonic() + 1,
        )
    send.assert_not_called()


def test_real_kernel_credentials_cannot_impersonate_separate_identity():
    """Check real kernel credentials cannot impersonate separate identity."""
    sender, receiver = socket.socketpair()
    with sender, receiver:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        sender.send(b"P")
        with pytest.raises(parser_transport.ParserServiceError, match="separate"):
            parser_transport._verify_worker_identity(
                receiver, deadline=time.monotonic() + 1, cancel_event=None
            )


def test_length_is_rejected_before_reading_oversized_body():
    """Check length is rejected before reading oversized body."""
    sender, receiver = socket.socketpair()
    with sender, receiver:
        sender.send(struct.pack("!I", 1025))
        with pytest.raises(parser_transport.ParserServiceError, match="bound"):
            parser_transport.receive_bytes(receiver, maximum=1024, deadline=time.monotonic() + 1)


def test_partial_frame_observes_deadline_and_cancellation():
    """Check partial frame observes deadline and cancellation (HarvestCancelled)."""
    sender, receiver = socket.socketpair()
    with sender, receiver:
        sender.send(struct.pack("!I", 1024) + b"x")
        with pytest.raises(parser_transport.ParserServiceError, match="deadline"):
            parser_transport.receive_bytes(receiver, maximum=1024, deadline=time.monotonic() + 0.05)
    cancellation = threading.Event()
    cancellation.set()
    sender, receiver = socket.socketpair()
    with sender, receiver, pytest.raises(HarvestCancelled):
        parser_transport.receive_bytes(
            receiver, maximum=1024, deadline=time.monotonic() + 1, cancel_event=cancellation
        )


def test_disconnect_revokes_job_ownership():
    """Check disconnect revokes job ownership."""
    sender, receiver = socket.socketpair()
    cancellation, finished = threading.Event(), threading.Event()
    thread = threading.Thread(
        target=parser_service._watch_disconnect, args=(receiver, cancellation, finished)
    )
    try:
        thread.start()
        sender.close()
        assert cancellation.wait(1)
    finally:
        finished.set()
        thread.join(1)
        receiver.close()


def test_ineffective_sandbox_releases_no_hello_or_job_inputs():
    """Check ineffective sandbox releases no hello or job inputs (RuntimeError)."""
    connection = Mock(spec=socket.socket)
    with (
        patch.object(
            parser_service, "validate_effective_sandbox", autospec=True, side_effect=RuntimeError
        ),
        patch.object(parser_service, "receive_bytes", autospec=True) as receive,
        pytest.raises(RuntimeError),
    ):
        parser_service.serve(connection)
    connection.sendmsg.assert_not_called()
    receive.assert_not_called()


def test_network_sandbox_probe_rejects_an_unrestricted_live_loopback():
    """Check network sandbox probe rejects an unrestricted live loopback (RuntimeError)."""
    with pytest.raises(RuntimeError, match="loopback"):
        parser_sandbox._require_network_denial(socket.AF_INET, "127.0.0.1")


def test_worker_import_and_logging_need_no_settings_or_secrets():
    """Check worker import and logging need no settings or secrets."""
    code = """
import os, sys
os.environ.clear()
from app.sources.oai_client import _configure_worker_logging
from app.sources import parser_service
_configure_worker_logging(source='archive', log_level='WARNING', log_format='json')
assert 'config' not in sys.modules
assert 'app.services.crypto' not in sys.modules
assert 'app.services.totp_crypto' not in sys.modules
"""
    subprocess.run([sys.executable, "-I", "-c", code], check=True, timeout=15)


def test_settings_free_worker_logging_omits_upstream_arguments_and_exception_values():
    """Check settings free worker logging omits upstream arguments and exception values."""
    error = ValueError("private-upstream-value")
    record = logging.LogRecord(
        "worker",
        logging.WARNING,
        __file__,
        1,
        "Rejected URL %s",
        ("https://feed.invalid/private?token=secret",),
        (ValueError, error, None),
    )
    oai_client._HarvestLogContext("archive").filter(record)
    text = oai_client._WorkerJSONFormatter().format(record)
    assert "private" not in text and "secret" not in text
    assert record.exc_info is None
    assert json.loads(text)["source"] == "archive"


def test_scheduler_settings_forbid_totp_key_custody():
    """Check scheduler settings forbid TOTP key custody (ValidationError)."""
    without_totp = base_kwargs(app_process_role="scheduler", totp_encryption_keys=[])
    assert Settings(_env_file=None, **without_totp).totp_encryption_keys == []
    with pytest.raises(ValidationError, match="TOTP"):
        Settings(_env_file=None, **base_kwargs(app_process_role="scheduler"))
    for role in ("web", "maintenance"):
        with pytest.raises(ValidationError, match="TOTP"):
            Settings(_env_file=None, **base_kwargs(app_process_role=role, totp_encryption_keys=[]))


def test_scheduler_mail_import_does_not_import_totp_crypto():
    """Check scheduler mail import does not import TOTP crypto."""
    environment = {
        name.upper(): value if isinstance(value, str) else json.dumps(value)
        for name, value in staging_kwargs(
            app_process_role="scheduler",
            totp_encryption_keys=[],
            health_detail_token="scheduler-health-0123456789abcdefghijklmnopq",
        ).items()
        if value is not None
    }
    code = """
import sys
from config import settings
from app.services import create_scheduler, deliver_email_outbox_batch
assert settings.totp_encryption_keys == []
assert settings.env_state == 'staging'
assert 'app.services.totp_crypto' not in sys.modules
"""
    subprocess.run([sys.executable, "-I", "-c", code], env=environment, check=True, timeout=15)


def test_oai_broker_request_has_only_job_inputs(monkeypatch):
    """Check OAI broker request has only job inputs."""
    monkeypatch.setenv("PARSER_EXECUTION_MODE", "service")
    expected = oai_client.HarvestResult(source_cursor=datetime(2026, 1, 1, tzinfo=UTC))
    with patch.object(
        oai_client,
        "request_parser",
        autospec=True,
        return_value=b"S" + oai_client.encode_harvest_result(expected),
    ) as request:
        assert (
            oai_client.fetch_updates_isolated(
                "https://archive.example.edu/oai",
                "2026-01-01",
                "Archive",
                source="archive",
                log_level="INFO",
                log_format="json",
            )
            == expected
        )
    body = request.call_args.args[0]
    assert set(body) == {"operation", "url", "since", "institution", "source", "max_pages"}
    assert "SECRET" not in json.dumps(body)


def test_json_broker_roundtrip_passes_only_selected_feed_inputs(monkeypatch):
    """Check JSON broker roundtrip passes only selected feed inputs."""
    monkeypatch.setenv("PARSER_EXECUTION_MODE", "service")
    monkeypatch.setenv("OTHER_FEED_SECRET", "not-selected")
    config = JsonFeedConfig.model_validate(
        {
            "name": "private_archive",
            "display": {"label": "Archive"},
            "endpoint": "https://archive.example.edu/feed",
            "credential_env": "FEED_BEARER",
            "signing_key_env": "FEED_SIGNING_KEY",
        }
    )
    credentials = JsonFeedCredentials(
        config.name,
        SecretStr("kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8"),
        SecretBytes(hashlib.sha256(b"synthetic selected feed signing material").digest()),
    )
    expected = oai_client.HarvestResult(source_cursor=datetime(2026, 1, 1, tzinfo=UTC))
    frame = b"S" + harvest_result_to_json(expected)
    with patch.object(
        json_feed_fetch, "request_parser", autospec=True, return_value=frame
    ) as request:
        assert json_feed_fetch.fetch_json_feed_isolated(config, credentials, since=None) == expected
    body = request.call_args.args[0]
    assert set(body) == {"operation", "config", "bearer", "signing_key", "since"}
    assert "not-selected" not in json.dumps(body)
    with patch.object(
        parser_service, "run_feed_process", autospec=True, return_value=frame
    ) as launch:
        assert parser_service._json_job(body, threading.Event()) == frame
    passed_config, passed_credentials, since, _deadline = launch.call_args.args[1]
    assert passed_config == config
    assert passed_credentials == credentials
    assert since is None

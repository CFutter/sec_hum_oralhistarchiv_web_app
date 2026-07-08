"""Direct unit tests for the audit-event helpers (services/audit.py).

Route-level tests pin the canonical events end-to-end; these pin the two
helper functions' own branch logic — in particular the tamper-evidence
branch that no route can easily reach:

- TEST-056: audit_admin_action with request.state.user is None must emit a
  CRITICAL 'admin_action_no_actor' record and SUPPRESS the intended event —
  it must never 500 mid-request, and never log the real event with a null
  actor (which would put an unattributable privilege change in the trail).

The audit logger has propagate=False after setup_logging runs, so caplog
(root-attached) can miss it; these attach a handler to the 'audit' logger
directly, exercised via a minimal fake Request (the helpers only read
request.state and request.client).
"""
import logging
from types import SimpleNamespace

import pytest

from app.services import audit


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def audit_capture():
    """Attach a capturing handler straight to the 'audit' logger (propagate
    is False, so caplog on root would miss these records), and force its
    level to INFO for the duration (setup_logging hasn't run in the unit
    tier, so the logger defaults to WARNING and would drop .info records)."""
    handler = _Capture()
    logger = logging.getLogger("audit")
    saved_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved_level)


def _fake_request(user):
    """Minimal Request stand-in: the helpers read request.state.user,
    request.state.request_id, request.client and (via get_client_ip)
    request.scope['server'] + request.headers."""
    return SimpleNamespace(
        state=SimpleNamespace(user=user, request_id="req-abc123"),
        client=SimpleNamespace(host="203.0.113.7"),
        scope={"server": ("testserver", 80)},
        headers={},
    )


def test_audit_admin_action_records_normal_event_with_actor(audit_capture):
    """Baseline: with an admin actor present, the intended event is logged at
    INFO with actor_admin_id + target_user_id + the extra fields."""
    admin = SimpleNamespace(id=42)
    audit.audit_admin_action(
        _fake_request(admin),
        "admin_user_tier_changed",
        target_user_id=7,
        old_value="public",
        new_value="vetted",
    )

    assert len(audit_capture.records) == 1
    rec = audit_capture.records[0]
    assert rec.levelno == logging.INFO
    assert rec.event_type == "admin_user_tier_changed"
    assert rec.actor_admin_id == 42
    assert rec.target_user_id == 7
    assert rec.new_value == "vetted"


def test_audit_admin_action_no_actor_is_critical_and_suppresses_event(
    audit_capture,
):
    """TEST-056: request.state.user is None → a CRITICAL 'admin_action_no_actor'
    record (attempted_event names the suppressed event), and the intended
    event is NOT logged. A regression that emitted the real event with
    actor=None would put an unattributable privilege change in the audit
    trail; a regression that raised would 500 the admin route mid-action."""
    audit.audit_admin_action(
        _fake_request(None),
        "admin_user_admin_changed",
        target_user_id=7,
        old_value=False,
        new_value=True,
    )

    assert len(audit_capture.records) == 1
    rec = audit_capture.records[0]
    assert rec.levelno == logging.CRITICAL
    assert rec.event_type == "admin_action_no_actor"
    assert rec.attempted_event == "admin_user_admin_changed"
    assert rec.target_user_id == 7
    # The real event's own name must NOT have been logged.
    assert not any(
        r.event_type == "admin_user_admin_changed" for r in audit_capture.records
    )


def test_audit_user_event_carries_ip_and_request_id(audit_capture):
    """audit_user_event stamps event_type, user_id, the resolved client ip,
    and request_id, plus caller-supplied fields."""
    audit.audit_user_event(
        _fake_request(None),
        "password_reset_requested",
        user_id=None,
        email_attempted_hash="abcd",
    )

    assert len(audit_capture.records) == 1
    rec = audit_capture.records[0]
    assert rec.event_type == "password_reset_requested"
    assert rec.user_id is None
    assert rec.request_id == "req-abc123"
    assert rec.email_attempted_hash == "abcd"
    # get_client_ip resolves from the peer when proxy trust is off.
    assert rec.ip == "203.0.113.7"

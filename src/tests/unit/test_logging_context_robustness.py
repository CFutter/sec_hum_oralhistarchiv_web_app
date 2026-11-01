"""Malformed structured context must not escape from logging calls."""

import io
import json
import logging

import pytest

import config.logging as log_config

_EXPECTED_CONTEXT_NODE_BUDGET = 512


class _BrokenText:
    """Raise when converted to text."""

    def __str__(self):
        """Raise ValueError instead of producing log text."""
        raise ValueError("UNPRINTABLE-EXCEPTION-CANARY")


class _CountingText:
    """Count conversions to ordinary text."""

    def __init__(self):
        """Initialize the text-conversion count to zero."""
        self.calls = 0

    def __str__(self):
        """Count the conversion and return a fixed ordinary value."""
        self.calls += 1
        return "ordinary value"


class _BrokenItems(dict[str, str]):
    """Fail after yielding one mapping entry."""

    def items(self):
        """Yield one valid entry, then raise a private ValueError."""
        yield "first", "already processed"
        raise ValueError("CONTAINER-EXCEPTION-CANARY")


class _IntWithBrokenCopy(int):
    """Raise when deepcopy attempts to copy the numeric value."""

    def __deepcopy__(self, _memo):
        """Raise ValueError instead of copying the numeric value."""
        raise ValueError("NUMERIC-COPY-CANARY")


class _FloatWithBrokenCopy(float):
    """Raise when deepcopy attempts to copy the numeric value."""

    def __deepcopy__(self, _memo):
        """Raise ValueError instead of copying the numeric value."""
        raise ValueError("NUMERIC-COPY-CANARY")


@pytest.fixture(params=["app", "audit"])
def log_capture(request, monkeypatch):
    """Use real logging calls with no formatter sanitizer to hide filter faults."""
    monkeypatch.setattr(log_config, "_audit_email_hasher", lambda _email: "stable-hash")
    logger = logging.getLogger("context-robustness")
    previous_level = logger.level
    logger.setLevel(logging.INFO)
    monkeypatch.setattr(logger, "handlers", [])
    monkeypatch.setattr(logger, "filters", [])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logger, "disabled", False)
    stream = io.StringIO()
    records = []
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    if request.param == "audit":
        channel_filter = log_config.AuditEmailAutoHash()
        # Match setup_logging: audit hashing runs at the logger boundary.
        logger.addFilter(channel_filter)
    else:
        channel_filter = log_config.SensitiveDataFilter()
        handler.addFilter(channel_filter)
    handler.addFilter(lambda record: records.append(record) or True)
    logger.addHandler(handler)
    try:
        yield logger, records, stream, channel_filter
    finally:
        logger.removeHandler(handler)
        handler.close()
        logger.setLevel(previous_level)


def _emit_context(log_capture, value):
    """Log context and a following event; require both messages and return JSON-round-tripped
    context.
    """
    logger, records, stream, _channel_filter = log_capture
    logger.info("operation completed", extra={"context": value})
    logger.info("following event")
    assert stream.getvalue().splitlines() == ["operation completed", "following event"]
    # No default=str: successful filtering must leave serializable values.
    return json.loads(json.dumps(records[0].context))


@pytest.mark.parametrize("shape", ["dict", "list", "mutual"])
def test_cyclic_context_is_replaced_and_following_event_is_emitted(log_capture, shape):
    """Cyclic context is replaced and following event is emitted."""
    if shape == "dict":
        value = {}
        value["self"] = value
    elif shape == "list":
        value = []
        value.append(value)
    else:
        value = {"items": []}
        value["items"].append(value)

    payload = _emit_context(log_capture, value)

    assert "<cycle>" in json.dumps(payload)
    if shape == "dict":
        assert value["self"] is value
    elif shape == "list":
        assert value[0] is value
    else:
        assert value["items"][0] is value


@pytest.mark.parametrize("shape", ["dict", "list", "tuple"])
def test_excessive_depth_is_truncated(log_capture, shape):
    """Excessive depth is truncated."""
    value = "leaf"
    for _ in range(1500):
        if shape == "dict":
            value = {"child": value}
        elif shape == "list":
            value = [value]
        else:
            value = (value,)

    payload = _emit_context(log_capture, value)

    assert "<truncated>" in json.dumps(payload)
    assert "leaf" not in json.dumps(payload)


@pytest.mark.parametrize("shape", ["dict", "list"])
def test_wide_context_stops_visiting_values_at_the_budget(log_capture, shape):
    """Wide context stops visiting values at the budget."""
    item = _CountingText()
    size = _EXPECTED_CONTEXT_NODE_BUDGET * 4
    value = {f"item_{index}": item for index in range(size)} if shape == "dict" else [item] * size

    payload = _emit_context(log_capture, value)

    assert 0 < item.calls <= _EXPECTED_CONTEXT_NODE_BUDGET
    assert len(payload) < size
    assert "<truncated>" in json.dumps(payload)


def test_node_budget_is_shared_across_top_level_extra_fields(log_capture):
    """Node budget is shared across top level extra fields."""
    logger, records, _stream, _channel_filter = log_capture
    item = _CountingText()
    size = _EXPECTED_CONTEXT_NODE_BUDGET * 4

    logger.info("operation completed", extra={f"field_{index}": item for index in range(size)})
    logger.info("following event")

    assert 0 < item.calls <= _EXPECTED_CONTEXT_NODE_BUDGET
    assert records[0].log_context_truncated is True
    assert not hasattr(records[0], f"field_{size - 1}")
    assert records[1].getMessage() == "following event"


def test_broken_string_conversion_uses_a_static_marker(log_capture):
    """Broken string conversion uses a static marker."""
    payload = _emit_context(log_capture, {"value": _BrokenText()})

    assert payload == {"value": "<unprintable>"}
    assert "UNPRINTABLE-EXCEPTION-CANARY" not in json.dumps(payload)


def test_broken_dictionary_key_conversion_uses_a_static_marker(log_capture):
    """Broken dictionary key conversion uses a static marker."""
    payload = _emit_context(log_capture, {_BrokenText(): "retained"})

    assert payload == {"<unprintable>": "retained"}


def test_shared_sibling_references_are_preserved_and_normal_values_are_unchanged(log_capture):
    """Shared sibling references are preserved and normal values are unchanged."""
    shared = {"values": [None, True, 42, 1.5, "ordinary"]}
    value = {"left": shared, "right": shared, "tuple": ("a", "b")}

    payload = _emit_context(log_capture, value)

    assert payload == {"left": shared, "right": shared, "tuple": ["a", "b"]}
    assert value["left"] is value["right"]
    assert isinstance(value["tuple"], tuple)


def test_nested_email_values_keep_the_channel_policy(log_capture):
    """Nested email values keep the channel policy."""
    _logger, _records, _stream, channel_filter = log_capture
    expected = (
        "[email:stable-hash]"
        if isinstance(channel_filter, log_config.AuditEmailAutoHash)
        else "[REDACTED:email]"
    )

    payload = _emit_context(log_capture, {"items": ["actor@example.org"]})

    assert payload == {"items": [expected]}


@pytest.mark.parametrize("value", [_IntWithBrokenCopy(42), _FloatWithBrokenCopy(1.5)])
def test_numeric_subclasses_retain_their_json_type_without_copy_hooks(log_capture, value):
    """Numeric subclasses retain their JSON type without copy hooks."""
    _logger, records, _stream, _channel_filter = log_capture

    payload = _emit_context(log_capture, value)

    assert payload == value
    assert type(payload) is (int if isinstance(value, int) else float)
    assert type(records[0].context) is type(payload)


def _assert_fixed_failure(log_capture):
    """Require a constant sanitized record with cleared private fields and a surviving following
    event.
    """
    _logger, records, stream, _channel_filter = log_capture
    failed = records[0]
    assert failed.getMessage() == "<log sanitization failed>"
    assert failed.log_sanitization_failed is True
    assert not hasattr(failed, "context")
    assert not hasattr(failed, "private_detail")
    assert failed.args == ()
    assert failed.exc_info is None
    assert failed.exc_text is None
    assert failed.stack_info is None
    assert "CANARY" not in json.dumps(vars(failed), default=str)
    assert stream.getvalue().splitlines() == [
        "<log sanitization failed>",
        "following event",
    ]


def test_unexpected_transform_failure_replaces_the_whole_context(log_capture, monkeypatch):
    """Unexpected transform failure replaces the whole context."""
    logger, _records, _stream, channel_filter = log_capture
    attribute = "_apply" if isinstance(channel_filter, log_config.AuditEmailAutoHash) else "apply"

    def fail(_value):
        """Raise a private ValueError while transforming context."""
        raise ValueError("TRANSFORM-EXCEPTION-CANARY")

    with monkeypatch.context() as patch:
        patch.setattr(channel_filter, attribute, fail)
        logger.info("MESSAGE-CANARY %s", "ARGUMENT-CANARY", extra={"context": "CONTEXT-CANARY"})
    logger.info("following event")

    _assert_fixed_failure(log_capture)


def test_broken_container_discards_partially_sanitized_context(log_capture):
    """Broken container discards partially sanitized context."""
    logger, _records, _stream, _channel_filter = log_capture

    logger.info(
        "MESSAGE-CANARY",
        extra={"private_detail": "PRIVATE-CANARY", "context": _BrokenItems()},
        exc_info=(ValueError, ValueError("EXCEPTION-CANARY"), None),
        stack_info=True,
    )
    logger.info("following event")

    _assert_fixed_failure(log_capture)


@pytest.mark.parametrize("log_capture", ["app"], indirect=True)
def test_snapshot_failure_cannot_escape_from_the_filter(log_capture, monkeypatch):
    """Snapshot failure cannot escape from the filter."""
    logger, _records, _stream, channel_filter = log_capture

    def fail(_record):
        """Raise a private ValueError while snapshotting context."""
        raise ValueError("SNAPSHOT-EXCEPTION-CANARY")

    with monkeypatch.context() as patch:
        patch.setattr(channel_filter, "_remember_sanitization", fail)
        logger.info("MESSAGE-CANARY", extra={"context": {"value": "ordinary"}})
    logger.info("following event")

    _assert_fixed_failure(log_capture)


def test_process_control_exceptions_are_not_swallowed(log_capture, monkeypatch):
    """Process control exceptions are not swallowed."""
    logger, _records, _stream, channel_filter = log_capture
    attribute = "_apply" if isinstance(channel_filter, log_config.AuditEmailAutoHash) else "apply"

    def interrupt(_value):
        """Raise KeyboardInterrupt during context sanitization."""
        raise KeyboardInterrupt

    monkeypatch.setattr(channel_filter, attribute, interrupt)
    with pytest.raises(KeyboardInterrupt):
        logger.info("operation completed")

"""Unit tests for the bounded exception-diagnostic machinery in
src/config/logging.py: `_safe_exception_tree` (node budget, depth cap,
cycle detection, cause/context chains, exception-group members, errno and
sqlstate extraction), `_render_exception_text` (how a diagnostic node
renders to the text formatter), and the formatter-level failure paths that
must fail closed instead of leaking a formatting exception or a raw value.

Pins, against src/config/logging.py:
- the node budget (`_MAX_EXCEPTION_TREE_NODES`) and depth cap
  (`_MAX_EXCEPTION_TREE_DEPTH`) are enforced across the WHOLE tree (root,
  causes, contexts, and exception-group members share one counter), so a
  wide or deep exception cannot make the diagnostic unbounded;
- a cause/context/member that does not fit the remaining budget is recorded
  as "omitted" (with a count/reason), never silently dropped or left to
  raise;
- `_safe_sqlstate` and the OSError `errno` extraction fail closed to "not
  present" rather than propagating an unexpected attribute-access error;
- `RedactingFormatter`/`JSONFormatter` catch a formatting-time fault and
  return a fixed placeholder instead of ever emitting an unhandled traceback
  or the un-redacted record that triggered the fault.

No database is touched anywhere in this file.
"""

import itertools
import json
import logging
import sys
from unittest.mock import patch

import pytest

import config.logging as config_logging
from config.logging import JSONFormatter, RedactingFormatter


def _tree(exc: BaseException, root_traceback=None) -> dict:
    return config_logging._safe_exception_tree(exc, root_traceback=root_traceback)


def _raise_runtime_error(message: str) -> None:
    raise RuntimeError(message)


def _record(msg: str = "event", **extra) -> logging.LogRecord:
    record = logging.LogRecord(
        name="app.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


class TestSafeTracebackFramesFailsClosed:
    """A traceback that cannot be formatted degrades to a placeholder frame
    instead of raising out of the diagnostic builder."""

    def test_unformattable_traceback_yields_a_placeholder_frame(self):
        """`traceback.format_tb` raising must not propagate; the node keeps a
        single, fixed placeholder frame instead."""
        exc = RuntimeError("boom")
        with patch("config.logging.traceback.format_tb", autospec=True) as mock_format_tb:
            mock_format_tb.side_effect = ValueError("cannot format")
            node = _tree(exc, root_traceback=None)

        assert node["frames"] == ["<traceback unavailable>"]

    def test_a_real_traceback_renders_actual_frame_text(self):
        """Positive control: an ordinary traceback is NOT replaced by the
        placeholder — real frame lines make it into the node."""
        try:
            _raise_runtime_error("boom")
        except RuntimeError as exc:
            node = _tree(exc, root_traceback=exc.__traceback__)

        assert node["frames"] != ["<traceback unavailable>"]
        assert any("test_logging_exception_diagnostics.py" in frame for frame in node["frames"])


class TestSafeSqlstateFailsClosed:
    """Only a well-formed, readable SQLSTATE is ever surfaced."""

    def test_an_attribute_access_failure_is_treated_as_absent(self):
        """A `.sqlstate` property that raises must not propagate; the safe
        accessor reports "no sqlstate" rather than crashing the log call."""

        class _BoomOnSqlstateAccess(RuntimeError):
            @property
            def sqlstate(self):
                raise ValueError("driver internals are not readable here")

        assert config_logging._safe_sqlstate(_BoomOnSqlstateAccess("db failed")) is None

    def test_a_well_formed_sqlstate_is_returned(self):
        """Positive control: a valid 5-character alnum SQLSTATE passes through."""
        exc = RuntimeError("db failed")
        exc.sqlstate = "42501"

        assert config_logging._safe_sqlstate(exc) == "42501"

    def test_an_exception_without_a_sqlstate_attribute_reports_none(self):
        """Positive control for the ordinary case: most exceptions carry no
        SQLSTATE at all, and that must not be mistaken for a failure."""
        assert config_logging._safe_sqlstate(RuntimeError("db failed")) is None


class TestErrnoDiagnosticOnlyForOSError:
    """The `errno` diagnostic is added only for a real, integer-valued
    OSError.errno — never inferred for other exception types."""

    def test_an_oserror_with_an_integer_errno_is_recorded(self):
        exc = OSError(13, "Permission denied")

        node = _tree(exc, root_traceback=None)

        assert node["errno"] == 13

    def test_a_non_oserror_exception_carries_no_errno_diagnostic(self):
        """Positive control: the permitted case (no OSError, no errno key)."""
        node = _tree(RuntimeError("boom"), root_traceback=None)

        assert "errno" not in node


class TestExceptionTreeSqlstate:
    """The diagnostic NODE (not just the `_safe_sqlstate` accessor in
    isolation) carries a well-formed SQLSTATE when the exception has one."""

    def test_a_valid_sqlstate_attribute_is_recorded_on_the_node(self):
        exc = RuntimeError("db failed")
        exc.sqlstate = "42501"

        node = _tree(exc, root_traceback=None)

        assert node["sqlstate"] == "42501"

    def test_an_exception_without_a_sqlstate_carries_no_sqlstate_key(self):
        """Positive control: the ordinary case adds no key at all."""
        node = _tree(RuntimeError("db failed"), root_traceback=None)

        assert "sqlstate" not in node


class TestExceptionTreeCauseChain:
    """`__cause__` (an explicit `raise ... from ...`) is preserved as a
    nested diagnostic node under the "cause" key."""

    def test_an_explicit_cause_is_recorded_as_a_nested_node(self):
        inner = ValueError("root cause")
        outer = RuntimeError("outer failure")
        outer.__cause__ = inner

        node = _tree(outer, root_traceback=None)

        assert node["cause"]["type"] == "builtins.ValueError"
        assert "cause_omitted" not in node

    def test_an_exception_without_a_cause_carries_no_cause_key(self):
        """Positive control: the ordinary, uncaused exception has neither key."""
        node = _tree(RuntimeError("outer failure"), root_traceback=None)

        assert "cause" not in node
        assert "cause_omitted" not in node

    def test_a_cause_that_exceeds_the_node_budget_is_marked_omitted(self, monkeypatch):
        """When the shared node budget is already spent, the cause is recorded
        as omitted (with the budget reason) instead of silently vanishing or
        raising."""
        monkeypatch.setattr(config_logging, "_MAX_EXCEPTION_TREE_NODES", 1)
        inner = ValueError("root cause")
        outer = RuntimeError("outer failure")
        outer.__cause__ = inner

        node = _tree(outer, root_traceback=None)

        assert node["cause_omitted"] == config_logging._EXCEPTION_NODE_BUDGET_REASON
        assert "cause" not in node

    def test_a_cause_chain_deeper_than_the_depth_cap_is_truncated_not_omitted(self):
        """A cause chain that exceeds `_MAX_EXCEPTION_TREE_DEPTH` stops with a
        depth-truncation placeholder, distinct from a budget omission."""
        depth_limit = config_logging._MAX_EXCEPTION_TREE_DEPTH
        chain = [RuntimeError(f"level-{i}") for i in range(depth_limit + 1)]
        for shallow, deep in itertools.pairwise(chain):
            shallow.__cause__ = deep

        node = _tree(chain[0], root_traceback=None)

        deepest = node
        for _ in range(depth_limit - 1):
            deepest = deepest["cause"]
        assert deepest["cause"] == {
            "type": "<exception details truncated>",
            "truncated": "maximum depth reached",
        }

    def test_a_self_referential_cause_is_truncated_as_a_cycle(self):
        """A cause cycle (however it arose) is caught by identity tracking and
        rendered as a cycle placeholder rather than recursing forever."""
        exc = RuntimeError("self-caused")
        exc.__cause__ = exc

        node = _tree(exc, root_traceback=None)

        assert node["cause"] == {
            "type": "<exception details truncated>",
            "truncated": "cycle detected",
        }


class TestExceptionTreeContextChain:
    """`__context__` (an implicit "during handling of") is preserved unless
    explicitly suppressed, mirroring `raise ... from ...`/`raise ... from
    None` semantics."""

    def test_an_unsuppressed_context_is_recorded_as_a_nested_node(self):
        inner = ValueError("earlier failure")
        outer = RuntimeError("later failure")
        outer.__context__ = inner
        outer.__suppress_context__ = False

        node = _tree(outer, root_traceback=None)

        assert node["context"]["type"] == "builtins.ValueError"
        assert "context_omitted" not in node

    def test_a_suppressed_context_is_never_recorded(self):
        """The `raise ... from None` shape: a present `__context__` must not
        leak once the exception marks it suppressed."""
        inner = ValueError("earlier failure")
        outer = RuntimeError("later failure")
        outer.__context__ = inner
        outer.__suppress_context__ = True

        node = _tree(outer, root_traceback=None)

        assert "context" not in node
        assert "context_omitted" not in node

    def test_a_context_that_exceeds_the_node_budget_is_marked_omitted(self, monkeypatch):
        monkeypatch.setattr(config_logging, "_MAX_EXCEPTION_TREE_NODES", 1)
        inner = ValueError("earlier failure")
        outer = RuntimeError("later failure")
        outer.__context__ = inner
        outer.__suppress_context__ = False

        node = _tree(outer, root_traceback=None)

        assert node["context_omitted"] == config_logging._EXCEPTION_NODE_BUDGET_REASON
        assert "context" not in node

    def test_a_cause_takes_priority_over_a_simultaneously_present_context(self):
        """When both are present, the cause branch is taken (elif), so the
        context is neither recorded nor counted against the budget twice."""
        cause = ValueError("explicit cause")
        context = TypeError("incidental context")
        outer = RuntimeError("later failure")
        outer.__cause__ = cause
        outer.__context__ = context
        outer.__suppress_context__ = False

        node = _tree(outer, root_traceback=None)

        assert node["cause"]["type"] == "builtins.ValueError"
        assert "context" not in node
        assert "context_omitted" not in node


class TestExceptionTreeGroupMembers:
    """`BaseExceptionGroup` members are each rendered as their own node,
    subject to the same shared node budget as causes and contexts."""

    def test_members_within_budget_are_all_rendered(self):
        group = ExceptionGroup(
            "problems", [RuntimeError("a"), RuntimeError("b"), RuntimeError("c")]
        )

        node = _tree(group, root_traceback=None)

        assert [member["type"] for member in node["members"]] == ["builtins.RuntimeError"] * 3
        assert "members_omitted" not in node

    def test_members_exceeding_the_node_budget_are_counted_as_omitted(self):
        group = ExceptionGroup("problems", [RuntimeError(f"m{i}") for i in range(20)])

        node = _tree(group, root_traceback=None)

        rendered = len(node["members"])
        assert rendered < 20
        assert node["members_omitted"] == 20 - rendered

    def test_a_group_carries_no_members_key_when_none_fit_the_budget(self, monkeypatch):
        """When the root itself exhausts the budget, not even the first
        member is rendered: `members` must stay ABSENT (never an empty
        list under a truthy key) while `members_omitted` still reports the
        full count."""
        monkeypatch.setattr(config_logging, "_MAX_EXCEPTION_TREE_NODES", 1)
        group = ExceptionGroup("problems", [RuntimeError("a"), RuntimeError("b")])

        node = _tree(group, root_traceback=None)

        assert "members" not in node
        assert node["members_omitted"] == 2


class TestExceptionTreeNodeBudgetGuard:
    """The root call itself is bound by the node budget: if the budget does
    not even allow one node, the builder fails loudly instead of returning a
    diagnostic that silently has no root."""

    def test_a_zero_node_budget_raises_instead_of_returning_an_empty_tree(self, monkeypatch):
        monkeypatch.setattr(config_logging, "_MAX_EXCEPTION_TREE_NODES", 0)

        with pytest.raises(RuntimeError, match="exception-tree node budget"):
            _tree(RuntimeError("boom"), root_traceback=None)


class TestRenderExceptionTextDiagnosticFields:
    """`_render_exception_text` turns each diagnostic field into one line of
    the text-formatter output, using the SAME dict shape `_safe_exception_tree`
    produces."""

    def test_errno_is_rendered_as_a_diagnostic_suffix(self):
        text = config_logging._render_exception_text({"type": "OSError", "frames": [], "errno": 13})

        assert "errno=13" in text

    def test_sqlstate_is_rendered_as_a_diagnostic_suffix(self):
        text = config_logging._render_exception_text(
            {"type": "DatabaseError", "frames": [], "sqlstate": "42501"}
        )

        assert "sqlstate=42501" in text

    def test_a_truncated_node_is_rendered_with_its_reason(self):
        text = config_logging._render_exception_text(
            {"type": "<exception details truncated>", "frames": [], "truncated": "cycle detected"}
        )

        assert "<exception details truncated>" in text
        assert "truncated=cycle detected" in text

    def test_a_cause_is_rendered_under_a_caused_by_heading_and_indented(self):
        text = config_logging._render_exception_text(
            {
                "type": "RuntimeError",
                "frames": [],
                "cause": {"type": "ValueError", "frames": []},
            }
        )

        assert "caused by:" in text
        lines = text.splitlines()
        cause_heading = next(i for i, line in enumerate(lines) if line.strip() == "caused by:")
        assert lines[cause_heading + 1].endswith("ValueError")
        assert lines[cause_heading + 1].startswith("  ")

    def test_an_omitted_cause_is_rendered_with_its_reason(self):
        text = config_logging._render_exception_text(
            {"type": "RuntimeError", "frames": [], "cause_omitted": "maximum node count reached"}
        )

        assert "caused by: <omitted: maximum node count reached>" in text

    def test_a_context_is_rendered_under_a_during_handling_heading(self):
        text = config_logging._render_exception_text(
            {
                "type": "RuntimeError",
                "frames": [],
                "context": {"type": "ValueError", "frames": []},
            }
        )

        assert "during handling of:" in text
        lines = text.splitlines()
        context_heading = next(
            i for i, line in enumerate(lines) if line.strip() == "during handling of:"
        )
        assert lines[context_heading + 1].endswith("ValueError")

    def test_an_omitted_context_is_rendered_with_its_reason(self):
        text = config_logging._render_exception_text(
            {"type": "RuntimeError", "frames": [], "context_omitted": "maximum node count reached"}
        )

        assert "during handling of: <omitted: maximum node count reached>" in text

    def test_group_members_are_rendered_as_numbered_indented_sections(self):
        text = config_logging._render_exception_text(
            {
                "type": "ExceptionGroup",
                "frames": [],
                "members": [
                    {"type": "RuntimeError", "frames": []},
                    {"type": "ValueError", "frames": []},
                ],
            }
        )

        assert "exception-group member 1:" in text
        assert "exception-group member 2:" in text

    def test_omitted_members_are_rendered_with_their_count(self):
        text = config_logging._render_exception_text(
            {"type": "ExceptionGroup", "frames": [], "members_omitted": 5}
        )

        assert "exception-group members omitted: 5" in text


class TestExceptionDiagnosticForAnAbsentException:
    """`formatException` given `(None, None, None)` — no active exception —
    must not raise or fabricate a fake exception; it renders a fixed
    placeholder."""

    def test_a_none_exc_info_tuple_renders_as_unavailable(self):
        record = logging.LogRecord(
            name="app.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="event",
            args=(),
            exc_info=(None, None, None),
        )
        formatter = RedactingFormatter("%(levelname)s %(message)s")

        output = formatter.format(record)

        assert "<exception unavailable>" in output

    def test_a_real_exc_info_tuple_never_renders_the_unavailable_placeholder(self):
        """Positive control: a genuine exception is never mistaken for the
        "no exception" case."""
        try:
            _raise_runtime_error("boom")
        except RuntimeError:
            record = logging.LogRecord(
                name="app.test",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="event",
                args=(),
                exc_info=sys.exc_info(),
            )
        formatter = RedactingFormatter("%(levelname)s %(message)s")

        output = formatter.format(record)

        assert "<exception unavailable>" not in output
        assert "RuntimeError" in output


class TestFormatterFailureFallbacks:
    """Every formatter entry point fails closed to a fixed placeholder
    instead of propagating a formatting-time exception or an un-redacted
    fragment of the record that triggered it."""

    def test_formatexception_failure_falls_back_to_the_constant_placeholder(self, monkeypatch):
        canary = "RAW-EXCEPTION-VALUE-CANARY"
        try:
            _raise_runtime_error(canary)
        except RuntimeError:
            record = logging.LogRecord(
                name="app.test",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="event",
                args=(),
                exc_info=sys.exc_info(),
            )
        formatter = RedactingFormatter("%(levelname)s %(message)s")

        def fail_diagnostic(_exc_info):
            raise TypeError("diagnostic builder exploded")

        monkeypatch.setattr(formatter, "_exception_diagnostic", fail_diagnostic)

        output = formatter.format(record)

        assert output.endswith(RedactingFormatter._EXCEPTION_FORMATTING_FAILED)
        assert canary not in output

    def test_a_healthy_exception_never_shows_the_formatting_failed_placeholder(self):
        """Positive control: ordinary exception formatting does not fall back."""
        try:
            _raise_runtime_error("boom")
        except RuntimeError:
            record = logging.LogRecord(
                name="app.test",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="event",
                args=(),
                exc_info=sys.exc_info(),
            )
        formatter = RedactingFormatter("%(levelname)s %(message)s")

        output = formatter.format(record)

        assert RedactingFormatter._EXCEPTION_FORMATTING_FAILED not in output

    def test_formatstack_redacts_stack_info_text(self):
        """`formatStack` output goes through the same redactor as the message
        and the exception text — a secret embedded in captured stack text
        must not survive formatting."""
        record = logging.LogRecord(
            name="app.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="slow query",
            args=(),
            exc_info=None,
            sinfo="Stack (most recent call last):\n  called with Bearer abc123token",
        )
        formatter = RedactingFormatter("%(levelname)s %(message)s")

        output = formatter.format(record)

        assert "abc123token" not in output
        assert "Bearer ***" in output

    def test_formatstack_leaves_non_secret_stack_text_intact(self):
        """Positive control: ordinary stack text is not mangled by redaction."""
        record = logging.LogRecord(
            name="app.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="slow query",
            args=(),
            exc_info=None,
            sinfo="Stack (most recent call last):\n  File 'x.py', line 1, in f",
        )
        formatter = RedactingFormatter("%(levelname)s %(message)s")

        output = formatter.format(record)

        assert "File 'x.py', line 1, in f" in output

    def test_format_failure_falls_back_to_the_constant_placeholder(self):
        """A format string referencing a missing record attribute raises
        inside the base `logging.Formatter.format`; the wrapper must not let
        that escape."""
        record = _record("event")
        formatter = RedactingFormatter("%(this_attribute_does_not_exist)s")

        output = formatter.format(record)

        assert output == RedactingFormatter._LOG_FORMATTING_FAILED

    def test_a_well_formed_format_string_never_falls_back(self):
        """Positive control: a format string whose fields all exist renders
        normally."""
        record = _record("event")
        formatter = RedactingFormatter("%(levelname)s %(message)s")

        output = formatter.format(record)

        assert output != RedactingFormatter._LOG_FORMATTING_FAILED
        assert "event" in output

    def test_json_format_failure_falls_back_to_a_constant_json_payload(self):
        """A fault inside `_format_json` (here: a non-numeric `created`
        timestamp) must not raise or emit a partial/un-redacted JSON body."""
        record = _record("event")
        record.created = "not-a-timestamp"
        formatter = JSONFormatter()

        output = formatter.format(record)

        assert json.loads(output) == {"message": JSONFormatter._LOG_FORMATTING_FAILED}

    def test_a_well_formed_record_never_falls_back_to_the_json_placeholder(self):
        """Positive control: an ordinary record formats to real JSON, not the
        failure placeholder."""
        record = _record("event")
        formatter = JSONFormatter()

        output = formatter.format(record)

        parsed = json.loads(output)
        assert parsed["message"] == "event"
        assert parsed != {"message": JSONFormatter._LOG_FORMATTING_FAILED}
